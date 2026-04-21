import logging
import asyncio
from typing import List, Optional, Callable

from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCConfiguration,
    RTCIceServer,
    RTCDataChannel,
    MediaStreamTrack,
)
from aiortc.sdp import candidate_from_sdp
from enum import Enum


class SignalingState(Enum):
    Initialized = 0
    WaitingForAnswer = 1
    Done = 2


class WebRtcClient:

    def __init__(
        self,
        ice_servers: List[RTCIceServer],
        outgoing_tracks: List[MediaStreamTrack],
        num_incoming_tracks: int,
        on_message: Callable[[bytes], None],
        on_datagram: Callable[[bytes], None],
    ) -> None:
        logging.info("Creating new WebRTC connection...")
        self._rtc_connection = RTCPeerConnection(
            RTCConfiguration(iceServers=ice_servers)
        )

        @self._rtc_connection.on("connectionstatechange")
        def connection_state_changed():
            assert self._rtc_connection
            logging.info(
                f"WebRTC connection state changed: {self._rtc_connection.connectionState}"
            )
            if self._rtc_connection.connectionState == "connected":
                self.connected.set()
            if self._rtc_connection.connectionState in ["closed", "failed"]:
                self._rtc_connection = None

        @self._rtc_connection.on("icecandidate")
        async def on_icecandidate(candidate):
            if candidate is None:
                # ICE gathering finished
                return
            raise Exception("Trickle ICE not expected!")

        self._signaling_state = SignalingState.Initialized
        self.datagram_channel: Optional[RTCDataChannel] = None
        self.messages_channel: Optional[RTCDataChannel] = None
        self.connected = asyncio.Event()
        self._on_datagram = on_datagram
        self._on_message = on_message

        logging.info(f"Tracks: {len(outgoing_tracks)} outgoing, {num_incoming_tracks} incoming")
        for track in outgoing_tracks:
            self._rtc_connection.addTrack(track)
        for _ in range(num_incoming_tracks):
            self._rtc_connection.addTransceiver('video', 'recvonly')

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
        logging.info("Generating offer")
        assert self._signaling_state == SignalingState.Initialized
        self.datagram_channel = self._rtc_connection.createDataChannel(
            "datagrams", ordered=False, maxRetransmits=0,
        )
        self.messages_channel = self._rtc_connection.createDataChannel("messages")
        offer = await self._rtc_connection.createOffer()
        assert offer.type == "offer"
        await self._rtc_connection.setLocalDescription(offer)
        self._signaling_state = SignalingState.WaitingForAnswer
        return self._rtc_connection.localDescription.sdp

    async def process_offer(self, offer: str) -> str:
        logging.info("Received offer")
        assert self._signaling_state == SignalingState.Initialized

        @self._rtc_connection.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logging.info(f"Data channel received: {channel.label}")
            if channel.label == "datagrams":
                self.datagram_channel = channel

                @channel.on("message")
                def on_message(message: bytes|str):
                    if isinstance(message, str):
                        message = message.encode()
                    self._on_datagram(message)

            elif channel.label == "messages":
                self.messages_channel = channel

                @channel.on("message")
                def on_message(message: bytes|str):
                    if isinstance(message, str):
                        message = message.encode()
                    self._on_message(message)

            else:
                logging.error("Invalid channel id")
                return

        await self._rtc_connection.setRemoteDescription(
            RTCSessionDescription(type="offer", sdp=offer)
        )
        answer = await self._rtc_connection.createAnswer()
        assert answer.type == "answer"
        await self._rtc_connection.setLocalDescription(answer)
        self._signaling_state = SignalingState.Done
        return self._rtc_connection.localDescription.sdp

    async def process_answer(self, answer: str):
        logging.info("Processing answer")
        assert self._signaling_state == SignalingState.WaitingForAnswer
        await self._rtc_connection.setRemoteDescription(
            RTCSessionDescription(type="answer", sdp=answer)
        )
        self._signaling_state = SignalingState.Done

    def send_datagram(self, datagram: bytes):
        assert self._signaling_state == SignalingState.Done
        assert self.datagram_channel is not None
        self.datagram_channel.send(datagram)

    def send_message(self, message: bytes):
        assert self._signaling_state == SignalingState.Done
        assert self.messages_channel is not None
        self.messages_channel.send(message)
