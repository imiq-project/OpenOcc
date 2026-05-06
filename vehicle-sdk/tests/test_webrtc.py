import unittest

from av.frame import Frame
from openocc.webrtc import WebRtcClient
import asyncio
import time
from aiortc import VideoStreamTrack
from av.video import VideoFrame


class TestWebRtc(unittest.IsolatedAsyncioTestCase):

    async def test_communicate(self):
        sender = WebRtcClient([], [], [])
        receiver = WebRtcClient([], [], [])

        offer = await sender.generate_offer()
        answer = await receiver.process_offer(offer)
        await sender.process_answer(answer)

        # Wait for connection
        await sender.connected.wait()
        await receiver.connected.wait()

        # Send 10 datagrams
        for _ in range(10):
            sender.send_datagram(b"")
        for _ in range(10):
            await receiver.datagrams.get()

        # Send 10 datagrams
        for _ in range(10):
            receiver.send_datagram("")
        for _ in range(10):
            await sender.datagrams.get()

        # Send 10 messages
        for _ in range(10):
            sender.send_message(b"")
        for _ in range(10):
            await receiver.messages.get()

        # Send 10 messages
        for _ in range(10):
            receiver.send_message(b"")
        for _ in range(10):
            await sender.messages.get()

        # Close
        await asyncio.gather(sender.close(), receiver.close())
        await sender.closed.wait()
        await receiver.closed.wait()

        self.assertEqual(sender.datagrams.qsize(), 0)
        self.assertEqual(receiver.datagrams.qsize(), 0)

    async def test_timeout(self):
        sender_timeout = 2
        receiver_timeout = 3

        sender = WebRtcClient([], [], [], sender_timeout)
        receiver = WebRtcClient([], [], [], receiver_timeout)

        offer = await sender.generate_offer()
        answer = await receiver.process_offer(offer)
        await sender.process_answer(answer)

        # Wait for connection
        await sender.connected.wait()
        await receiver.connected.wait()

        # Wait for timeouts
        now = time.monotonic()
        await sender.closed.wait()
        self.assertAlmostEqual(time.monotonic() - now, sender_timeout, places=1)
        await receiver.closed.wait()
        self.assertAlmostEqual(time.monotonic() - now, sender_timeout, places=1)

    async def test_media_tracks(self):
        class DummyStream(VideoStreamTrack):
            async def recv(self) -> Frame:
                return VideoFrame(width=640, height=480)

        sender = WebRtcClient([], [DummyStream()], [])
        receiver = WebRtcClient([], [], [lambda _: None])

        offer = await sender.generate_offer()
        answer = await receiver.process_offer(offer)
        await sender.process_answer(answer)

        # Wait for connection
        await sender.connected.wait()
        await receiver.connected.wait()

        await asyncio.sleep(1)
        await asyncio.gather(sender.close(), receiver.close())
