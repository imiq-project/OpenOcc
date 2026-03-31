import logging
import argparse
import asyncio

from av.frame import Frame
from av.packet import Packet
from openocc.vehicle import Vehicle
from openocc.client import OccClient

from aiortc.contrib.media import MediaPlayer


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-10.10s - %(levelname)-8.8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/wt-vehicle?VehicleId=tugger_train")
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    class DummyVehicle(Vehicle):
        def __init__(self):
            self.player = MediaPlayer(
                "http://download.tsi.telecom-paristech.fr/gpac/dataset/dash/uhd/mux_sources/hevcds_720p30_2M.mp4"
            )

        async def get_frame(self) -> Frame | Packet:
            assert self.player.video
            return await self.player.video.recv()

        def ping(self, msg: str):
            pass

    client = OccClient(args.host, args.port, args.path, args.insecure, DummyVehicle())
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
