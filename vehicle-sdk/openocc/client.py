import asyncio
import json
import logging
import random
from typing import List, Optional, Dict, Callable, Coroutine, Any
from abc import ABC, abstractmethod
from asyncio import Future

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
from openocc.operator import Operator
from openocc.ioconf import IoConf, io_conf_for


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
        self._rtc_connection: Optional[RTCPeerConnection] = None
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
        asyncio.create_task(self._process_datagram())
        asyncio.create_task(self._process_stream())
        asyncio.create_task(self._webtransport.loop())
        await self._webtransport.connected.wait()
        logging.info("WebTransport connected")
        await self._send_outgoing()

    def _send_stream(self, message: dict):
        # TODO: ensure that message does not contain \0 already
        data = json.dumps(message).encode()
        data += b"\0"  # delimiter
        self._webtransport.send_stream(data)

    async def _send_outgoing(self):
        while True:
            await asyncio.sleep(5)
            self._webtransport.send_datagram(b"")

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

    async def send_rpc(self, to: str, method: str, params: List):
        self._next_rpc_id += 1
        future = asyncio.Future()
        self._rpc_waiters[self._next_rpc_id] = future
        self._send_stream(
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
        # TODO: timeout
        # Will be set in _process_rpc_response
        result = await future
        return result

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

        result = await self.process_rpc(method, params)
        self._send_stream(
            {
                "Type": "rpcResponse",
                "To": from_,  # switched on purpose
                "From": to,
                "Payload": {"jsonrpc": "2.0", "result": result, "id": id_},
            }
        )

    async def _process_rpc_response(self, data):
        payload = data["Payload"]
        assert isinstance(payload, dict)
        id_ = payload["id"]
        assert isinstance(id_, int)
        result = payload["result"]

        try:
            future = self._rpc_waiters[id_]
        except KeyError:
            logging.error(f"Received unknown rpc response: {data}")
            return

        future.set_result(result)

    @abstractmethod
    async def process_rpc(self, method, params):
        pass


class VehicleClient(ClientBase):

    def __init__(self, host: str, port: int, insecure: bool, vehicle: Vehicle) -> None:
        self._vehicle = vehicle
        self._io_conf = io_conf_for(vehicle)
        path = f"/wt-vehicle?VehicleId={vehicle.VEHICLE_ID}&IoConf={json.dumps(self._io_conf.to_json())}"
        super().__init__(vehicle.VEHICLE_ID, host, port, insecure, path)
        self.message_handlers["offer"] = self._process_offer

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
            if channel.label == "ping":

                @channel.on("message")
                def on_message(message: str):
                    self._vehicle.ping(message)

            elif channel.label == "command":
                pass
            else:
                logging.error("Invalid channel id")
                return

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
                "To": connected_occ,
            }
        )

    async def process_rpc(self, method, params):
        result = self._io_conf.invoke_command(self._vehicle, method, params)
        return result


class OperatorClient(ClientBase):

    def __init__(
        self, host: str, port: int, insecure: bool, operator: Operator
    ) -> None:
        self._operator = operator
        self._operator_id = random.randint(0, 10**4)
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

    async def process_rpc(self, method, params):
        print(method, params)
        return None
