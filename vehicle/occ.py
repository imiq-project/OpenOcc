import argparse
import asyncio
import json
import logging
import requests
from typing import List, Optional
from abc import ABC, abstractmethod

from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCConfiguration,
    RTCIceServer,
    MediaStreamTrack,
    RTCDataChannel,
)
from aiortc.sdp import candidate_from_sdp
from aiortc.contrib.media import MediaPlayer
from webtransport import WebTransportClient


class Vehicle(ABC):

    @abstractmethod
    def create_streams(self) -> List[MediaStreamTrack]:
        pass

    @abstractmethod
    def ping(self, msg: str):
        pass


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

        for stream in self._vehicle.create_streams():
            self._rtc_connection.addTrack(stream)

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


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/wt-vehicle?VehicleId=tugger_train")
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    class DummyVehilce(Vehicle):
        def create_streams(self) -> List[MediaStreamTrack]:
            player = MediaPlayer(
                "http://download.tsi.telecom-paristech.fr/gpac/dataset/dash/uhd/mux_sources/hevcds_720p30_2M.mp4"
            )
            assert player.video
            return [player.video]
        
        def ping(self, msg: str):
            pass

    client = OccClient(args.host, args.port, args.path, args.insecure, DummyVehilce())
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
