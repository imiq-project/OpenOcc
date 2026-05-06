from abc import ABC, abstractmethod
from .ioconf import IoConf, binding_for, outgoing, incoming, DataType
from .webrtc import WebRtcClient
from .client import ClientBase, RpcException
from typing import List, Any, Tuple, Dict, Optional
import logging
import random
import asyncio
from av.frame import Frame


class RemoteVehicle(ABC):
    def __init__(self, client: "OperatorClient", id: str, io_conf: IoConf) -> None:
        self.client = client
        self.id = id
        self._rtc_connection: Optional[WebRtcClient] = None
        self._binding = binding_for(self, RemoteVehicle, False)
        self._binding.narrow_down(io_conf)

    @outgoing("motion", [DataType.Int8, DataType.Int8])
    def get_motion(self) -> Tuple[int, int]:
        return 0, 0

    @incoming("front_camera", [DataType.Video])
    def set_front_camera(self, frame: Frame) -> None:
        pass

    @incoming("back_camera", [DataType.Video])
    def set_back_camera(self, frame: Frame) -> None:
        pass

    @incoming("left_camera", [DataType.Video])
    def set_left_camera(self, frame: Frame) -> None:
        pass

    @incoming("right_camera", [DataType.Video])
    def set_right_camera(self, frame: Frame) -> None:
        pass

    @incoming("position", [DataType.UInt64, DataType.UInt64])
    def set_position(self, lat: int, lon: int) -> None:
        pass

    @incoming("battery_level", [DataType.UInt8])
    def set_battery_level(self, level: int) -> None:
        pass

    def process_rpc_request(self, method: str, params: List[Any]):
        pass

    async def start_webrtc(self):
        if self._rtc_connection is not None:
            logging.error("Cannot process offer: WebRTC connection already established")
            return

        self._rtc_connection = WebRtcClient(
            self.client._ice_servers,
            self._binding.get_outgoing_tracks(),
            self._binding.get_incoming_track_callbacks(),
        )
        offer = await self._rtc_connection.generate_offer()
        answer = await self.client.send_rpc_request(self.id, "_webRtcOffer", [offer])
        await self._rtc_connection.process_answer(answer)

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
                await asyncio.sleep(.02)

        asyncio.create_task(send_rtc_ping())

        async def handle_datagrams():
            while self._rtc_connection:
                datagram = await self._rtc_connection.datagrams.get()
                self._binding.decode_incoming(datagram)

        asyncio.create_task(handle_datagrams())

        logging.info("WebRTC started")


class Operator(ABC):

    @abstractmethod
    def on_new_vehicle(
        self, client: "OperatorClient", id: str, io_conf: IoConf
    ) -> RemoteVehicle:
        return RemoteVehicle(client, id, io_conf)


class OperatorClient(ClientBase):

    def __init__(
        self, host: str, port: int, insecure: bool, operator: Operator
    ) -> None:
        self._operator = operator
        self._operator_id = random.randint(0, 10**4)
        path = f"/wt-operator?OperatorId={self._operator_id}"
        super().__init__(str(self._operator_id), host, port, insecure, path)
        self.message_handlers["status"] = self._process_status_message
        self._remote_vehicles: Dict[str, RemoteVehicle] = {}

    async def _process_status_message(self, data):
        vehicles = data["Vehicles"]
        assert isinstance(vehicles, list)
        for i in vehicles:
            id_ = i["Id"]
            assert isinstance(id_, str)
            io_conf = IoConf.from_json(i["IoConf"] or {})
            try:
                vehicle = self._remote_vehicles[id_]
            except KeyError:
                logging.info(f"New vehicle '{id_}'")
                vehicle = self._operator.on_new_vehicle(self, id_, io_conf)
                self._remote_vehicles[id_] = vehicle

    async def process_rpc_request(self, from_: str, method: str, params):
        try:
            vehicle = self._remote_vehicles[from_]
        except KeyError:
            raise RpcException(f"Unknown vehicle {from_}", -1)
        result = vehicle.process_rpc_request(method, params)
        return result
