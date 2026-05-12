import argparse
import asyncio
import json
import logging
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
from aiortc.rtcicetransport import candidate_from_aioice
from aioice import Candidate
from imiq_vehicle.webtransport import WebTransportClient


class Vehicle(ABC):

    @abstractmethod
    def create_streams(self) -> List[MediaStreamTrack]:
        pass

    @abstractmethod
    def ping(self, msg: str):
        pass

    def handle_command(self, msg: str) -> Optional[str]:
        """Process a DataChannel command. Return a response or None."""
        return None


class OccClient:

    def __init__(
        self, host: str, port: int, path: str, insecure: bool, vehicle: Vehicle
    ) -> None:
        self._webtransport = WebTransportClient(host, port, path, insecure)
        self._vehicle = vehicle
        self._rtc_connection: Optional[RTCPeerConnection] = None
        self._telemetry_channel: Optional[RTCDataChannel] = None
        self._status_channel: Optional[RTCDataChannel] = None

    async def loop(self):
        asyncio.create_task(self._process_datagram())
        asyncio.create_task(self._process_stream())
        asyncio.create_task(self._telemetry_loop())
        asyncio.create_task(self._status_loop())

        # Start vehicle data-forwarding loops if available
        if hasattr(self._vehicle, "position_loop"):
            asyncio.create_task(self._vehicle.position_loop())
        if hasattr(self._vehicle, "diagnostics_loop"):
            asyncio.create_task(self._vehicle.diagnostics_loop())

        await self._webtransport.loop()

    async def _telemetry_loop(self):
        """Send position telemetry via WebRTC DataChannel."""
        while True:
            if self._telemetry_channel and self._telemetry_channel.readyState == "open":
                if hasattr(self._vehicle, '_node'):
                    data = self._vehicle._node.get_position_json()
                    if data:
                        telemetry = {
                            "timestamp": int(asyncio.get_event_loop().time() * 1000),
                            "latitude": data.get("Latitude", 0),
                            "longitude": data.get("Longitude", 0),
                            "elevation": data.get("Altitude", 0),
                            "yaw": data.get("Yaw", 0),
                            "vx": data.get("Vx", 0),
                            "vy": data.get("Vy", 0),
                            "utm_x": data.get("X", 0),
                            "utm_y": data.get("Y", 0),
                        }
                        try:
                            self._telemetry_channel.send(json.dumps(telemetry))
                        except Exception as e:
                            logging.warning(f"Failed to send telemetry: {e}")
            await asyncio.sleep(0.1)

    async def _status_loop(self):
        """Send status info via WebRTC DataChannel."""
        while True:
            if self._status_channel and self._status_channel.readyState == "open":
                status = {
                    "robot_state": "READY",
                    "battery_pct": 85,
                    "battery_voltage": 24.5,
                    "active_behavior": "teleop",
                }
                try:
                    self._status_channel.send(json.dumps(status))
                except Exception as e:
                    logging.warning(f"Failed to send status: {e}")
            await asyncio.sleep(2.0)

    def send_stream_message(self, message: dict):
        """Send a JSON message on the WebTransport stream (reliable)."""
        data = json.dumps(message).encode()
        data += b"\0"  # delimiter
        self._webtransport.send_stream(data)

    def send_datagram(self, payload: bytes):
        """Send raw bytes as a WebTransport datagram (unreliable)."""
        self._webtransport.send_datagram(payload)

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
            logging.info("Closing existing WebRTC connection for new offer")
            await self._rtc_connection.close()
            self._rtc_connection = None
        self._rtc_connection = RTCPeerConnection(
            RTCConfiguration(
                iceServers=[
                    RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
                ]
            )
        )

        @self._rtc_connection.on("connectionstatechange")
        def connection_state_changed():
            assert self._rtc_connection
            if self._rtc_connection.connectionState in ["closed", "failed"]:
                logging.info("Connection closed")
                self._rtc_connection = None

        @self._rtc_connection.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logging.info(f"Data channel received: {channel.label}")

            if channel.label == "telemetry":
                self._telemetry_channel = channel
                return

            if channel.label == "status":
                self._status_channel = channel
                return

            if channel.label not in ("ping", "commands"):
                logging.error(f"Unknown data channel: {channel.label}")
                return

            @channel.on("message")
            def on_message(message: str):
                if channel.label == "ping":
                    self._vehicle.ping(message)
                    return

                # "commands" channel — handle twist + ping/pong
                response = self._vehicle.handle_command(message)
                if response is not None:
                    channel.send(response)

        connected_occ = offer["OccId"]
        logging.info(f"Received offer from {connected_occ}")
        await self._rtc_connection.setRemoteDescription(
            RTCSessionDescription(type="offer", sdp=offer["Sdp"])
        )

        streams = self._vehicle.create_streams()
        if streams:
            self._rtc_connection.addTrack(streams[0])

        answer = await self._rtc_connection.createAnswer()
        await self._rtc_connection.setLocalDescription(answer)
        logging.info("Sending answer")
        self.send_stream_message(
            {"Type": "answer", "Sdp": answer.sdp, "Recipient": connected_occ}
        )

    async def _process_ice(self, ice: dict):
        if self._rtc_connection is None:
            logging.error("Cannot process ice candidate: no offer received")
            return
        logging.info("New ice candidate")
        c = ice["Candidate"]
        assert isinstance(c, dict)
        try:
            candidate = candidate_from_aioice(Candidate.from_sdp(c["candidate"]))
        except ValueError as e:
            logging.error(f"Invalid candidate: {e}")
            return
        candidate.sdpMid = c.get("sdpMid")
        candidate.sdpMLineIndex = c.get("sdpMLineIndex")
        await self._rtc_connection.addIceCandidate(candidate)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(module)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/wt-vehicle?VehicleId=husky")
    parser.add_argument("--insecure", action="store_true", default=False)
    parser.add_argument(
        "--dummy", action="store_true", default=False,
        help="Use dummy video instead of ROS 2 topics",
    )
    args = parser.parse_args()

    if args.dummy:
        from aiortc.contrib.media import MediaPlayer

        class DummyVehicle(Vehicle):
            def create_streams(self) -> List[MediaStreamTrack]:
                player = MediaPlayer(
                    "http://download.tsi.telecom-paristech.fr/gpac/dataset/dash/uhd/"
                    "mux_sources/hevcds_720p30_2M.mp4"
                )
                assert player.video
                return [player.video]

            def ping(self, msg: str):
                pass

        vehicle = DummyVehicle()
    else:
        from imiq_vehicle.ros_vehicle import RosVehicle

        vehicle = RosVehicle()

    client = OccClient(args.host, args.port, args.path, args.insecure, vehicle)

    # Give RosVehicle access to the client for sending data
    if hasattr(vehicle, "set_occ_client"):
        vehicle.set_occ_client(client)

    try:
        asyncio.run(client.loop())
    finally:
        if hasattr(vehicle, "shutdown"):
            vehicle.shutdown()


if __name__ == "__main__":
    main()
