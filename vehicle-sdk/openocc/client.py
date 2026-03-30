import asyncio
import json
import logging
from av import VideoFrame
import requests
from typing import List, Optional, Union

from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCConfiguration,
    RTCIceServer,
    VideoStreamTrack,
    RTCDataChannel,
)
from aiortc.sdp import candidate_from_sdp
from openocc.webtransport import WebTransportClient
from openocc.vehicle import Vehicle


class VehicleVideoStream(VideoStreamTrack):
    def __init__(self, vehicle: Vehicle) -> None:
        super().__init__()
        self.vehicle = vehicle

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        frame = await self.vehicle.get_frame()
        frame.pts = pts
        frame.time_base = time_base
        return frame


class OccClient:

    def __init__(
        self, host: str, port: int, path: str, insecure: bool, vehicle: Vehicle
    ) -> None:
        self._host = host
        self._port = port
        self._insecure = insecure
        self._webtransport = WebTransportClient(host, port, path, insecure)
        self._vehicle = vehicle
        self._rtc_connection: Optional[RTCPeerConnection] = None
        self._ice_servers: List[RTCIceServer] = []

    async def loop(self):
        self.fetch_ice_servers()
        asyncio.create_task(self._process_datagram())
        asyncio.create_task(self._process_stream())
        await self._webtransport.loop()

    def fetch_ice_servers(self):
        response = requests.get(
            f"https://{self._host}:{self._port}/iceServers", verify=not self._insecure
        )
        response.raise_for_status()
        data = response.json()["iceServers"]
        assert isinstance(data, list)
        self._ice_servers = [
            RTCIceServer(
                urls=i["urls"], username=i["username"], credential=i["credential"]
            )
            for i in data
        ]

    def _send_stream(self, message: dict):
        # TODO: ensure that message does not contain \0 already
        data = json.dumps(message).encode()
        data += b"\0"  # delimiter
        self._webtransport.send_stream(data)

    async def _process_stream(self):
        buffer = bytearray()
        while True:
            data = await self._webtransport.stream.get()
            for value in data:
                if value == 0:
                    await self._process_stream_message(bytes(buffer))
                    buffer = bytearray()
                else:
                    buffer.append(value)

    async def _process_datagram(self):
        while True:
            data = await self._webtransport.datagrams.get()
            logging.info(f"Received datagram: {len(data)} bytes")

    async def _process_stream_message(self, message):
        assert isinstance(message, bytes)
        try:
            data = json.loads(message.decode())
        except json.decoder.JSONDecodeError as e:
            logging.error(f"Received invalid message: {e}")
            return
        assert isinstance(data, dict)
        logging.info("Received stream msg")
        type_ = data.get("Type")
        if type_ == "offer":
            await self._process_offer(data)
        elif type_ == "ice":
            await self._process_ice(data)
        else:
            logging.error(f"Received message with unknown type {type_}")

    async def _process_offer(self, offer: dict):
        if self._rtc_connection:
            logging.error("Cannot process offer: WebRTC connection already established")
            return

        self._rtc_connection = RTCPeerConnection(
            RTCConfiguration(iceServers=self._ice_servers)
        )

        @self._rtc_connection.on("connectionstatechange")
        def connection_state_changed():
            assert self._rtc_connection
            if self._rtc_connection.connectionState in ["closed", "failed"]:
                logging.info("Connection closed")
                self._rtc_connection = None

        @self._rtc_connection.on("icecandidate")
        async def on_icecandidate(candidate):
            if candidate is None:
                # ICE gathering finished
                return
            raise Exception("Trickle ICE not expected!")

        @self._rtc_connection.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logging.info(f"Data channel received: {channel.label}")
            if channel.label != "ping":
                logging.error("Invalid channel id")
                return

            @channel.on("message")
            def on_message(message: str):
                self._vehicle.ping(message)

        self._rtc_connection.addTrack(VehicleVideoStream(self._vehicle))

        connected_occ = offer["OccId"]
        logging.info(f"Received offer from {connected_occ}")
        await self._rtc_connection.setRemoteDescription(
            RTCSessionDescription(type="offer", sdp=offer["Sdp"])
        )
        answer = await self._rtc_connection.createAnswer()
        assert answer.type == "answer"
        await self._rtc_connection.setLocalDescription(answer)
        assert self._rtc_connection.iceGatheringState == "complete"
        logging.info("Sending answer")
        self._send_stream(
            {
                "Type": "answer",
                "Sdp": self._rtc_connection.localDescription.sdp,
                "Recipient": connected_occ,
            }
        )

    async def _process_ice(self, ice: dict):
        if self._rtc_connection is None:
            logging.error("Cannot process ice candidate: no offer received")
            return
        logging.info("New ice candidate")
        payload = ice["Candidate"]
        assert isinstance(payload, dict)
        sdp = payload["candidate"]
        if not sdp:
            logging.warning("Discarding empty candidate")
            return

        try:
            candidate = candidate_from_sdp(sdp)
        except ValueError as e:
            logging.error(f"Invalid candidate: {e}")
            return
        candidate.sdpMid = payload.get("sdpMid")
        candidate.sdpMLineIndex = payload.get("sdpMLineIndex")
        await self._rtc_connection.addIceCandidate(candidate)
