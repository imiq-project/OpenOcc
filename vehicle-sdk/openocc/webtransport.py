import argparse
import asyncio
import logging
import json

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.events import StreamDataReceived, DatagramFrameReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

from typing import Optional


# Patch asyncio.StreamWriter.__del__ to avoid the NotImplementedError spam
def safe_del(self):
    try:
        if self._transport and not self._transport.is_closing():
            pass
    except NotImplementedError:
        pass
    except Exception:
        pass


asyncio.StreamWriter.__del__ = safe_del


class H3ClientProtocol(QuicConnectionProtocol):
    """
    QUIC protocol subclass that also manages an H3Connection.

    Important:
      - Accept *args/**kwargs in __init__ because aioquic.connect() will call
        the factory with signature: create_protocol(connection, stream_handler=...)
      - Call super().__init__(*args, **kwargs) so the base class sets up self._quic.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic, enable_webtransport=True)
        self._wt_stream_id = None
        self._stream_id = None
        self.stream = asyncio.Queue()
        self.datagrams = asyncio.Queue()

    def request_webtransport(self, path):
        assert self._quic.configuration.server_name
        self._stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=self._stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":protocol", b"webtransport"),
                (b":path", path),
                (b":authority", self._quic.configuration.server_name.encode()),
                (b"sec-webtransport-http3-draft02", b"1"),
            ],
        )
        self.transmit()
        self._wt_stream_id = self._http.create_webtransport_stream(self._stream_id)
        self.transmit()

    def quic_event_received(self, event: QuicEvent):
        """
        Called by aioquic when QUIC-level events arrive.
        Hand them to H3Connection, and handle resulting H3 events.
        """
        super().quic_event_received(event)
        if isinstance(event, StreamDataReceived):
            if event.stream_id == self._wt_stream_id:
                self.stream.put_nowait(event.data)
            else:
                logging.warning(f"Received data from uknown stream {event.stream_id}")
        elif isinstance(event, DatagramFrameReceived):
            self.datagrams.put_nowait(event.data)

    def send_datagram(self, data: bytes):
        assert self._wt_stream_id is not None
        self._http.send_datagram(self._wt_stream_id, data)
        self.transmit()

    def send_stream(self, data: bytes):
        assert self._wt_stream_id is not None
        self._quic.send_stream_data(self._wt_stream_id, data, False)
        self.transmit()


async def forward_queue(source: asyncio.Queue, target: asyncio.Queue):
    while True:
        item = await source.get()
        await target.put(item)
        source.task_done()


class WebTransportClient:
    def __init__(self, host: str, port: int, path: str, insecure: bool) -> None:
        self.messages = asyncio.Queue()
        self.datagrams = asyncio.Queue()
        self.host = host
        self.port = port
        self.path = path
        self.insecure = insecure
        self._protocol: Optional[H3ClientProtocol] = None
        self.connected = asyncio.Event()
        self._stop_event = asyncio.Event()

    async def loop(self):
        config = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            max_datagram_frame_size=65536,
        )

        if self.insecure:
            config.verify_mode = False

        async with connect(
            self.host,
            self.port,
            configuration=config,
            create_protocol=H3ClientProtocol,
        ) as protocol:
            assert isinstance(protocol, H3ClientProtocol)
            self._protocol = protocol
            self._protocol.request_webtransport(self.path.encode())

            asyncio.create_task(self._process_stream())
            asyncio.create_task(forward_queue(self._protocol.datagrams, self.datagrams))
            self.connected.set()
            await self._stop_event.wait()

        self._protocol = None

    async def _process_stream(self):
        assert self._protocol
        buffer = bytearray()
        while True:
            data = await self._protocol.stream.get()
            for value in data:
                if value == 0:
                    await self.messages.put(bytes(buffer))
                    buffer = bytearray()
                else:
                    # TODO: is there a more efficient way?
                    buffer.append(value)

    def stop(self):
        self._stop_event.set()

    def send_datagram(self, datagram: bytes):
        assert self._protocol
        self._protocol.send_datagram(datagram)

    def send_message(self, message: str):
        assert self._protocol
        # TODO: ensure that message does not contain \0 already
        data = message.encode()
        data += b"\0"  # delimiter
        self._protocol.send_stream(data)


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/wt-vehicle?VehicleId=tugger_train")
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()
    client = WebTransportClient(args.host, args.port, args.path, args.insecure)

    async def dump_queue(q: asyncio.Queue):
        while True:
            data = await q.get()
            print(data)

    asyncio.create_task(dump_queue(client.datagrams))
    asyncio.create_task(dump_queue(client.messages))
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
