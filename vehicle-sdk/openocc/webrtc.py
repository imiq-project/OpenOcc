import logging
import asyncio
from typing import List, Optional, Union
import time

from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCConfiguration,
    RTCIceServer,
    RTCDataChannel,
    MediaStreamTrack,
)
from aiortc.sdp import candidate_from_sdp


class WebRtcClient:

    def __init__(
        self,
        ice_servers: List[RTCIceServer],
        outgoing_tracks: List[MediaStreamTrack],
        num_incoming_tracks: int,
        timeout_secs: int = 3,
    ) -> None:
        logging.info("Creating new WebRTC connection...")
        self._rtc_connection = RTCPeerConnection(
            RTCConfiguration(iceServers=ice_servers)
        )

        self.timeout = timeout_secs
        self._last_message = time.monotonic()
        self._datagram_channel: Optional[RTCDataChannel] = None
        self._messages_channel: Optional[RTCDataChannel] = None
        self.datagrams = asyncio.Queue()
        self.messages = asyncio.Queue()
        self.connected = asyncio.Event()
        self.closed = asyncio.Event()

        @self._rtc_connection.on("connectionstatechange")
        def connection_state_changed():
            assert self._rtc_connection
            logging.info(
                f"WebRTC connection state changed: {self._rtc_connection.connectionState}"
            )
            if self._rtc_connection.connectionState == "connected":
                asyncio.create_task(self.check_timeout())
            if self._rtc_connection.connectionState == "closed":
                self.closed.set()

        @self._rtc_connection.on("icecandidate")
        async def on_icecandidate(candidate):
            if candidate is None:
                # ICE gathering finished
                return
            raise Exception("Trickle ICE not expected!")

        logging.info(
            f"Tracks: {len(outgoing_tracks)} outgoing, {num_incoming_tracks} incoming"
        )
        for track in outgoing_tracks:
            self._rtc_connection.addTrack(track)
        for _ in range(num_incoming_tracks):
            self._rtc_connection.addTransceiver("video", "recvonly")

    async def check_timeout(self):
        while self._rtc_connection.connectionState != "closed":
            await asyncio.sleep(1)
            if self._last_message + self.timeout < time.monotonic():
                logging.error(f"No messages since {self.timeout}s, closing session")
                await self._rtc_connection.close()

    async def add_ice_candidate(self, sdp: str, sdp_mid, sdp_mline_index):
        logging.info("New ice candidate")
        if not sdp:
            logging.warning("Discarding empty candidate")
            return
        try:
            candidate = candidate_from_sdp(sdp)
        except ValueError as e:
            logging.error(f"Invalid candidate: {e}")
            return
        candidate.sdpMid = sdp_mid
        candidate.sdpMLineIndex = sdp_mline_index
        await self._rtc_connection.addIceCandidate(candidate)

    async def generate_offer(self):
        logging.info("Generating offer...")
        self._datagram_channel = self._rtc_connection.createDataChannel(
            "datagrams",
            ordered=False,
            maxRetransmits=0,
        )
        self._datagram_channel.on("message", self.handle_datagram)

        self._messages_channel = self._rtc_connection.createDataChannel("messages")
        self._messages_channel.on("message", self.handle_message)

        @self._datagram_channel.on("open")
        @self._messages_channel.on("open")
        def set_connected():
            if (
                self._datagram_channel.readyState == "open"
                and self._messages_channel.readyState == "open"
            ):
                self.connected.set()

        offer = await self._rtc_connection.createOffer()
        assert offer.type == "offer"
        await self._rtc_connection.setLocalDescription(offer)
        logging.info("...done")
        return self._rtc_connection.localDescription.sdp

    async def process_offer(self, offer: str) -> str:
        logging.info("Received offer")

        @self._rtc_connection.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logging.info(f"Data channel received: {channel.label}")
            if channel.label == "datagrams":
                self._datagram_channel = channel
                channel.on("message", self.handle_datagram)
            elif channel.label == "messages":
                self._messages_channel = channel
                channel.on("message", self.handle_message)
            else:
                logging.error("Invalid channel id")

            if self._messages_channel and self._datagram_channel:
                self.connected.set()

        await self._rtc_connection.setRemoteDescription(
            RTCSessionDescription(type="offer", sdp=offer)
        )
        answer = await self._rtc_connection.createAnswer()
        assert answer.type == "answer"
        await self._rtc_connection.setLocalDescription(answer)
        return self._rtc_connection.localDescription.sdp

    async def process_answer(self, answer: str):
        logging.info("Processing answer")
        await self._rtc_connection.setRemoteDescription(
            RTCSessionDescription(type="answer", sdp=answer)
        )

    def handle_datagram(self, datagram: bytes | str):
        self._last_message = time.monotonic()
        if isinstance(datagram, str):
            datagram = datagram.encode()
        self.datagrams.put_nowait(datagram)

    def handle_message(self, message: bytes):
        self._last_message = time.monotonic()
        self.messages.put_nowait(message)

    def send_datagram(self, datagram: Union[str, bytes]):
        assert self._datagram_channel is not None
        self._datagram_channel.send(datagram)

    def send_message(self, message: bytes):
        assert self._messages_channel is not None
        self._messages_channel.send(message)

    async def close(self):
        await self._rtc_connection.close()
