# client_fixed.py
import argparse
import asyncio
import logging
import json
from typing import Optional

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection, HeadersState
from aioquic.quic.events import StreamDataReceived, DatagramFrameReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aiortc import (
    RTCPeerConnection,
    VideoStreamTrack,
    RTCSessionDescription,
    RTCConfiguration,
    RTCIceServer,
    RTCIceCandidate,
)
from aiortc.contrib.media import MediaPlayer
from aiortc.rtcicetransport import candidate_from_aioice
from aioice import Candidate


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

from av import VideoFrame
import cv2


class CameraStreamTrack(VideoStreamTrack):
    """A track that returns frames from the webcam."""

    def __init__(self):
        super().__init__()
        self.cap = cv2.VideoCapture(0)

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        ret, frame = self.cap.read()
        if not ret:
            print("No Frame!")
            return None
        frame = VideoFrame.from_ndarray(frame, format="bgr24")
        frame.pts = pts
        frame.time_base = time_base
        return frame


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
        self.wt_stream_id = None
        self.stream_id = None
        self.buffer = bytearray()
        self.messages = asyncio.Queue()

    def request_webtransport(self, path):
        self.stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=self.stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":protocol", b"webtransport"),
                (b":path", path),
                (b":authority", f"imiq-occ.et.uni-magdeburg.de:443".encode()), # TODO: adapt
                (b"sec-webtransport-http3-draft02", b"1"),
            ],
        )
        self.transmit()
        self.wt_stream_id = self._http.create_webtransport_stream(self.stream_id)
        self.transmit()

    def quic_event_received(self, event: QuicEvent):
        """
        Called by aioquic when QUIC-level events arrive.
        Hand them to H3Connection, and handle resulting H3 events.
        """
        super().quic_event_received(event)
        if isinstance(event, StreamDataReceived):
            if event.stream_id == self.wt_stream_id:
                for value in event.data:
                    if value == 0:
                        self.messages.put_nowait(bytes(self.buffer))
                        self.buffer = bytearray()
                    else:
                        self.buffer.append(value)
        elif isinstance(event, DatagramFrameReceived):
            print(event)

    def send_datagram(self, data: bytes):
        assert self.wt_stream_id is not None
        self._http.send_datagram(self.wt_stream_id, data)
        self.transmit()

    def send_message(self, data: bytes):
        assert self.wt_stream_id is not None
        self._quic.send_stream_data(self.wt_stream_id, data + b"\0", False)
        self.transmit()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--insecure", action="store_true", default=True)
    args = parser.parse_args()

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )
    if args.insecure:
        # Only for dev/testing
        config.verify_mode = False

    peer_conn = RTCPeerConnection(RTCConfiguration(
        iceServers=[
            RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
        ]
    ))
    peer_conn.addTrack(CameraStreamTrack())
    # player = MediaPlayer(
    # 'http://download.tsi.telecom-paristech.fr/'
    # 'gpac/dataset/dash/uhd/mux_sources/hevcds_720p30_2M.mp4')
    # peer_conn.addTrack(player.video)

    # @peer_conn.on("icecandidate")
    # def on_ice_candidate(*args):
    #     print(args)

    connected_occ = None

    async with connect(
        args.host,
        args.port,
        configuration=config,
        create_protocol=H3ClientProtocol,
    ) as protocol:
        assert isinstance(protocol, H3ClientProtocol)

        async def process_msg():
            while True:
                msg = await protocol.messages.get()
                j = json.loads(msg)
                assert isinstance(j, dict)
                type = j.get("Type")
                if type == "offer":
                    connected_occ = j["OccId"]
                    print(f"Received offer from {connected_occ}")
                    await peer_conn.setRemoteDescription(
                        RTCSessionDescription(type="offer", sdp=j["Sdp"])
                    )
                    answer = await peer_conn.createAnswer()
                    assert answer.type == "answer"
                    await peer_conn.setLocalDescription(answer)
                    print("Sending answer")
                    protocol.send_message(json.dumps({"Type": "answer", "Sdp": answer.sdp, "Recipient": connected_occ}).encode())
                    print("...done")
                elif type == "ice":
                    print("New ice candidate")
                    c = j["Candidate"]
                    assert isinstance(c, dict)
                    candidate = candidate_from_aioice(
                        Candidate.from_sdp(c["candidate"])
                    )
                    candidate.sdpMid = c.get("sdpMid")
                    candidate.sdpMLineIndex=c.get("sdpMLineIndex")
                    await peer_conn.addIceCandidate(candidate)
                else:
                    print(f"Unknown type {type}")

        asyncio.create_task(process_msg())
        protocol.request_webtransport(b"/wt-vehicle?VehicleId=tugger_train")
        while True:
            protocol.send_datagram(b"")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
