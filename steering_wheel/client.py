import asyncio
import json
import logging
from typing import List, Optional, Dict, Callable, Coroutine, Any, Tuple
from abc import ABC, abstractmethod
from asyncio import Future

from aiortc import (
    RTCIceServer,
    VideoStreamTrack,
)
from av.frame import Frame

from steering_wheel.webtransport import WebTransportClient


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


class ClientBase(ABC):

    def __init__(
        self, client_id: str, host: str, port: int, insecure: bool, path: str
    ) -> None:
        self._client_id = client_id
        self._webtransport = WebTransportClient(host, port, path, insecure)
        self._ice_servers: List[RTCIceServer] = []
        self.message_handlers: Dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {
            "iceServers": self._process_ice_servers,
            "rpcRequest": self._process_rpc_request,
            "rpcResponse": self._process_rpc_response,
        }
        self._next_rpc_id = 1
        # TODO: each sender must have its own queue as ids are not coordinated
        self._rpc_waiters: Dict[int, Future[Any]] = {}

    async def loop(self):
        asyncio.create_task(self._process_datagrams())
        asyncio.create_task(self._process_messages())
        asyncio.create_task(self._webtransport.loop())
        await self._webtransport.connected.wait()
        logging.info("WebTransport connected")
        await self._send_ping()

    async def _send_ping(self):
        while True:
            await asyncio.sleep(5)
            self._webtransport.send_datagram(
                b""
            )  # TODO: get this from the operator / vehicle

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
            result = await self.process_rpc_request(from_, method, params)
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
    async def process_rpc_request(
        self, from_: str, method: str, params: List[Any]
    ) -> Any:
        pass
