import logging
import asyncio
from typing import List, Optional, Union, Callable
from av.frame import Frame
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


class ConnectionState:
    Initialized = "initialized"
    Connecting = "connecting"
    Connected = "connected"
    Closed = "closed"


class WebRtcClient:

    def __init__(
        self,
        ice_servers: List[RTCIceServer],
        outgoing_tracks: List[MediaStreamTrack],
        incoming_track_callbacks: List[Callable[[Frame], None]],
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
        self.connection_state = ConnectionState.Initialized

        @self._rtc_connection.on("connectionstatechange")
        def connection_state_changed():
            assert self._rtc_connection
            logging.info(
                f"WebRTC connection state changed: {self._rtc_connection.connectionState}"
            )

            if self._rtc_connection.connectionState == "new":
                pass
            elif self._rtc_connection.connectionState == "connecting":
                self.connection_state = ConnectionState.Connecting
            elif self._rtc_connection.connectionState == "connected":
                asyncio.create_task(self.check_timeout())
                # We set State.Connected after detection of two datachannels
            if self._rtc_connection.connectionState in ["failed", "closed"]:
                self.connection_state = ConnectionState.Closed
                self.closed.set()

        @self._rtc_connection.on("icecandidate")
        async def on_icecandidate(candidate):
            if candidate is None:
                # ICE gathering finished
                return
            raise Exception("Trickle ICE not expected!")

        num_received_tracks = 0
        @self._rtc_connection.on("track")
        def on_track(track: MediaStreamTrack):
            nonlocal num_received_tracks
            logging.info(f"Received new track {track.id} {track.kind}")
            asyncio.create_task(self.forward_incoming_track(incoming_track_callbacks[num_received_tracks], track))
            num_received_tracks += 1

        logging.info(
            f"Tracks: {len(outgoing_tracks)} outgoing, {len(incoming_track_callbacks)} incoming"
        )

        for track in outgoing_tracks:
            self._rtc_connection.addTrack(track)
        for _ in incoming_track_callbacks:
            self._rtc_connection.addTransceiver("video", "recvonly")

    async def check_timeout(self):
        while self._rtc_connection.connectionState != "closed":
            await asyncio.sleep(1)
            if self._last_message + self.timeout < time.monotonic():
                logging.error(f"No messages since {self.timeout}s, closing session")
                await self._rtc_connection.close()

    async def forward_incoming_track(self, callback: Callable[[Frame], None], track: MediaStreamTrack):
        logging.info(f"Forwarding track {track.id} to {callback}")
        while True:
            frame = await track.recv()
            assert isinstance(frame, Frame)
            callback(frame)

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
            assert self._datagram_channel and self._messages_channel
            if (
                self._datagram_channel.readyState == "open"
                and self._messages_channel.readyState == "open"
            ):
                self.connection_state = ConnectionState.Connected
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
                self.connection_state = ConnectionState.Connected
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
