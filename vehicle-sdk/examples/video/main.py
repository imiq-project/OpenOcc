import logging
import argparse
import asyncio

from openocc.vehicle import Vehicle
from openocc.client import VehicleClient

from aiortc.contrib.media import MediaPlayer


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-10.10s - %(levelname)-8.8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--vehicle_id", default="tugger_train")
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    class DummyVehicle(Vehicle):
        VEHICLE_ID = args.vehicle_id

        def __init__(self):
            self.player = MediaPlayer(
                "http://download.tsi.telecom-paristech.fr/gpac/dataset/dash/uhd/mux_sources/hevcds_720p30_2M.mp4"
            )

        def set_motion(self, speed, angle):
            print(speed, angle)

        def get_frame(self):
            assert self.player.video
            return asyncio.run(self.player.video.recv())

        def emergency_halt(self, enable: bool):
            logging.info("Emergency halt triggered!")

    client = VehicleClient(args.host, args.port, args.insecure, DummyVehicle())
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
