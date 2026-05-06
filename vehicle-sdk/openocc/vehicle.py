from abc import ABC
from openocc.ioconf import outgoing, incoming, command, DataType
from av.frame import Frame
from abc import ABC, abstractmethod
from .ioconf import IoConf, binding_for
from .webrtc import WebRtcClient, ConnectionState
from .client import ClientBase
from typing import List, Any, Tuple, Dict, Optional
import logging
import json
import asyncio


class Vehicle(ABC):

    VEHICLE_ID = ""

    @incoming("motion", [DataType.Int8, DataType.Int8])
    def set_motion(self, speed, angle) -> None:
        raise NotImplemented()

    @outgoing("front_camera", [DataType.Video])
    def get_front_camera(self) -> Frame:
        raise NotImplemented()

    @outgoing("back_camera", [DataType.Video])
    def get_back_camera(self) -> Frame:
        raise NotImplemented()

    @outgoing("left_camera", [DataType.Video])
    def get_left_camera(self) -> Frame:
        raise NotImplemented()

    @outgoing("right_camera", [DataType.Video])
    def get_right_camera(self) -> Frame:
        raise NotImplemented()

    @outgoing("position", [DataType.UInt64, DataType.UInt64])
    def get_position(self) -> None:
        raise NotImplemented()

    @outgoing("battery_level", [DataType.UInt8])
    def get_battery_level(self) -> int:
        raise NotImplemented()

    @command("emergency_halt")
    def emergency_halt(self, enable: bool) -> None:
        raise NotImplemented()

    @command("move_to")
    def move_to(self, lat, lon) -> None:
        raise NotImplemented()


class VehicleClient(ClientBase):

    def __init__(self, host: str, port: int, insecure: bool, vehicle: Vehicle) -> None:
        self._vehicle = vehicle
        self._binding = binding_for(vehicle, Vehicle, True)
        path = f"/wt-vehicle?VehicleId={vehicle.VEHICLE_ID}&IoConf={json.dumps(self._binding.io_conf.to_json())}"
        super().__init__(vehicle.VEHICLE_ID, host, port, insecure, path)
        self._rtc_connection: Optional[WebRtcClient] = None

    async def process_rpc_request(self, from_: str, method: str, params):
        if method == "_webRtcOffer":
            result = await self._process_webrtc_offer(*params)
        elif method == "_iceCandidate":
            result = await self._process_ice_candidate(*params)
        else:
            result = self._binding.invoke_command(method, params)
        return result

    async def _process_ice_candidate(self, payload: dict):
        if self._rtc_connection is None:
            logging.error("Cannot process ice candidate: no offer received")
            return
        logging.info("New ice candidate")
        sdp = payload["candidate"]
        sdp_mid = payload.get("sdpMid")
        sdp_mline_index = payload.get("sdpMLineIndex")
        await self._rtc_connection.add_ice_candidate(sdp, sdp_mid, sdp_mline_index)

    async def _process_webrtc_offer(self, offer: str):
        if self._rtc_connection is not None:
            if self._rtc_connection.connection_state == ConnectionState.Connected:
                logging.error("Cannot process offer: WebRTC connection already established")
                return
            else:
                await self._rtc_connection.close()

        self._rtc_connection = WebRtcClient(
            self._ice_servers,
            self._binding.get_outgoing_tracks(),
            self._binding.get_incoming_track_callbacks(),
        )

        async def handle_close():
            assert self._rtc_connection
            await self._rtc_connection.closed.wait()
            self._rtc_connection = None

        asyncio.create_task(handle_close())

        async def send_rtc_ping():
            assert self._rtc_connection
            await self._rtc_connection.connected.wait()
            while self._rtc_connection:
                payload = self._binding.encode_outgoing()
                self._rtc_connection.send_datagram(payload)
                await asyncio.sleep(1)

        asyncio.create_task(send_rtc_ping())

        async def handle_datagrams():
            while self._rtc_connection:
                datagram = await self._rtc_connection.datagrams.get()
                self._binding.decode_incoming(datagram)

        asyncio.create_task(handle_datagrams())

        return await self._rtc_connection.process_offer(offer)
