import logging
from typing import List

from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCConfiguration,
    RTCIceServer,
    RTCDataChannel,
)
from aiortc.sdp import candidate_from_sdp
from enum import Enum

class SignalingState(Enum):
    Initialized = 0
    WaitingForAnswer = 1
    Done = 2

class WebRtcClient:

    def __init__(self, ice_servers: List[RTCIceServer]) -> None:
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
            if self._rtc_connection.connectionState in ["closed", "failed"]:
                self._rtc_connection = None

        @self._rtc_connection.on("icecandidate")
        async def on_icecandidate(candidate):
            if candidate is None:
                # ICE gathering finished
                return
            raise Exception("Trickle ICE not expected!")

        self._signaling_state = SignalingState.Initialized

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
        channel = self._rtc_connection.createDataChannel("ping")
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
            if channel.label == "ping":

                @channel.on("message")
                def on_message(message: str):
                    pass
                    # self._vehicle.ping(message)

            elif channel.label == "command":
                pass
            else:
                logging.error("Invalid channel id")
                return

        # self._rtc_connection.addTrack(VehicleVideoStream(self._vehicle))

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
