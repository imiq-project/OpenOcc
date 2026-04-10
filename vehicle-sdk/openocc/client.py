import asyncio
import json
import logging
import random
from typing import List, Optional, Dict, Callable, Coroutine, Any
from abc import ABC, abstractmethod
from asyncio import Future

from aiortc import (
    RTCIceServer,
    VideoStreamTrack,
)
from aiortc.sdp import candidate_from_sdp
from openocc.webtransport import WebTransportClient
from openocc.vehicle import Vehicle
from openocc.operator import Operator
from openocc.ioconf import IoConf, io_conf_for
from openocc.webrtc import WebRtcClient


def _dump(data: Any, max_len=80) -> str:
    if isinstance(data, list):
        if len(data) == 0:
            return "[]"
        item_len = max_len // len(data)  # TODO: does not take delimiter into account
        return "[" + ", ".join(_dump(i, item_len) for i in data) + "]"
    stringified = str(data)
    stringified = stringified.replace("\n", "\\n").replace("\r", "\\r")
    if len(stringified) > max_len:
        return stringified[: max_len - 3] + "..."
    else:
        return stringified


class RpcException(Exception):

    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.message = message
        self.code = code


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


class ClientBase(ABC):

    def __init__(
        self, client_id: str, host: str, port: int, insecure: bool, path: str
    ) -> None:
        self._client_id = client_id
        self._webtransport = WebTransportClient(host, port, path, insecure)
        self._rtc_connection: Optional[WebRtcClient] = None
        self._ice_servers: List[RTCIceServer] = []
        self.message_handlers: Dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {
            "iceServers": self._process_ice_servers,
            "iceCandidate": self._process_ice_candidate,
            "rpcRequest": self._process_rpc_request,
            "rpcResponse": self._process_rpc_response,
        }
        self._next_rpc_id = 1
        self._rpc_waiters: Dict[int, Future[Any]] = {}

    async def loop(self):
        asyncio.create_task(self._process_datagrams())
        asyncio.create_task(self._process_messages())
        asyncio.create_task(self._webtransport.loop())
        await self._webtransport.connected.wait()
        logging.info("WebTransport connected")
        await self._send_outgoing()

    async def _send_outgoing(self):
        while True:
            await asyncio.sleep(5)
            self._webtransport.send_datagram(b"")

    async def _process_datagrams(self):
        while True:
            data = await self._webtransport.datagrams.get()
            logging.info(f"Received datagram: {len(data)} bytes")

    async def _process_messages(self):
        while True:
            message = await self._webtransport.messages.get()
            try:
                data = json.loads(message.decode())
            except json.decoder.JSONDecodeError as e:
                logging.error(f"Received invalid message: {e}")
                return
            assert isinstance(data, dict)
            type_ = data.get("Type")
            logging.info(f"Received stream msg '{type_}'")
            assert isinstance(type_, str)
            try:
                handler = self.message_handlers[type_]
            except KeyError:
                logging.error(f"Received message with unknown type {type_}")
                return

            await handler(data)

    async def _process_ice_servers(self, data: dict):
        servers = data["iceServers"]
        assert isinstance(servers, list)
        self._ice_servers = [
            RTCIceServer(
                urls=i["urls"], username=i["username"], credential=i["credential"]
            )
            for i in servers
        ]
        logging.info(f"Received {len(self._ice_servers)} ICE servers")

    async def _process_ice_candidate(self, ice: dict):
        if self._rtc_connection is None:
            logging.error("Cannot process ice candidate: no offer received")
            return
        logging.info("New ice candidate")
        payload = ice["Candidate"]
        assert isinstance(payload, dict)
        sdp = payload["candidate"]
        sdp_mid = payload.get("sdpMid")
        sdp_mline_index = payload.get("sdpMLineIndex")
        await self._rtc_connection.add_ice_candidate(sdp, sdp_mid, sdp_mline_index)

    async def send_rpc_request(self, to: str, method: str, params: List[Any]):
        self._next_rpc_id += 1
        future = asyncio.Future()
        self._rpc_waiters[self._next_rpc_id] = future
        self._webtransport.send_message(
            json.dumps(
                {
                    "Type": "rpcRequest",
                    "From": self._client_id,
                    "To": to,
                    "Payload": {
                        "jsonrpc": "2.0",
                        "method": method,
                        "params": params,
                        "id": self._next_rpc_id,
                    },
                }
            )
        )
        # TODO: timeout
        # Will be set in _process_rpc_response
        result = await future
        return result

    async def _process_rpc_response(self, data):
        payload = data["Payload"]
        assert isinstance(payload, dict)
        id_ = payload["id"]
        assert isinstance(id_, int)
        try:
            future = self._rpc_waiters[id_]
        except KeyError:
            logging.error(f"Received unknown rpc response: {data}")
            return
        try:
            result = payload["result"]
            logging.info(f"Received result for id={id_}: {_dump(result)}")
            future.set_result(result)
        except KeyError:
            error = payload["error"]
            logging.error(f"received error for id={id_}: {_dump(error)}")
            future.set_exception(RpcException(error["message"], error["code"]))

    async def _process_rpc_request(self, data):
        to = data["To"]
        assert isinstance(to, str)
        assert to == self._client_id
        from_ = data["From"]
        assert isinstance(from_, str)
        payload = data["Payload"]
        assert isinstance(payload, dict)

        method = payload["method"]
        assert isinstance(method, str)
        params = payload["params"]
        assert isinstance(params, list)
        id_ = payload["id"]
        assert isinstance(id_, int)

        logging.info(
            f"Received rpc request: method={method}, id={id_}, params={_dump(params)}"
        )

        try:
            if method == "_webrtcOffer":
                result = await self._process_webrtc_offer(*params)
            else:
                result = await self.process_rpc_request(method, params)
            logging.info(f"Sending result for id={id_}: {_dump(result)}")
            payload = {"jsonrpc": "2.0", "result": result, "id": id_}
        except RpcException as e:
            # TODO: proper error code
            logging.info(f"Sending error for id={id_}: '{e}'")
            payload = {
                "jsonrpc": "2.0",
                "error": {"code": e.code, "message": e.message},
                "id": id_,
            }

        self._webtransport.send_message(
            json.dumps(
                {
                    "Type": "rpcResponse",
                    "To": from_,  # return to sender
                    "From": to,
                    "Payload": payload,
                }
            )
        )

    @abstractmethod
    async def process_rpc_request(self, method: str, params: List[Any]):
        pass

    async def _process_webrtc_offer(self, offer: str):
        if self._rtc_connection is not None:
            logging.error("Cannot process offer: WebRTC connection already established")
            return
        self._rtc_connection = WebRtcClient(self._ice_servers)
        return await self._rtc_connection.process_offer(offer)

    async def start_webrtc(self, vehicle_id: str):
        if self._rtc_connection is not None:
            logging.error("Cannot process offer: WebRTC connection already established")
            return
        self._rtc_connection = WebRtcClient(self._ice_servers)
        offer = await self._rtc_connection.generate_offer()
        answer = await self.send_rpc_request(vehicle_id, "_webrtcOffer", [offer])
        await self._rtc_connection.process_answer(answer)
        logging.info("WebRTC started")


class VehicleClient(ClientBase):

    def __init__(self, host: str, port: int, insecure: bool, vehicle: Vehicle) -> None:
        self._vehicle = vehicle
        self._io_conf = io_conf_for(vehicle)
        path = f"/wt-vehicle?VehicleId={vehicle.VEHICLE_ID}&IoConf={json.dumps(self._io_conf.to_json())}"
        super().__init__(vehicle.VEHICLE_ID, host, port, insecure, path)
        self.message_handlers["offer"] = self._process_webrtc_offer

    async def process_rpc_request(self, method: str, params):
        result = self._io_conf.invoke_command(self._vehicle, method, params)
        return result


class OperatorClient(ClientBase):

    def __init__(
        self, host: str, port: int, insecure: bool, operator: Operator
    ) -> None:
        self._operator = operator
        self._operator_id = random.randint(0, 10**4)
        self._io_conf = io_conf_for(operator)
        path = f"/wt-operator?OccId={self._operator_id}"
        super().__init__(str(self._operator_id), host, port, insecure, path)
        self.message_handlers["status"] = self._process_status_message

    async def _process_status_message(self, data):
        vehicles = data["Vehicles"]
        assert isinstance(vehicles, list)
        for i in vehicles:
            io_conf = IoConf.from_json(i["IoConf"])
            self._operator.on_vehicle_changed(
                i["Id"], i["Name"], i["Connected"], io_conf
            )

    async def process_rpc_request(self, method: str, params):
        result = self._io_conf.invoke_command(self._operator, method, params)
        return result
