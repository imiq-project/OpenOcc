import logging
import argparse
import asyncio

from aiortc import MediaStreamTrack
from openocc.client import Vehicle, OccClient

from aiortc.contrib.media import MediaPlayer
from typing import List

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

    class DummyVehilce(Vehicle):
        def create_streams(self) -> List[MediaStreamTrack]:
            player = MediaPlayer(
                "http://download.tsi.telecom-paristech.fr/gpac/dataset/dash/uhd/mux_sources/hevcds_720p30_2M.mp4"
            )
            assert player.video
            return [player.video]
        
        def ping(self, msg: str):
            pass

    client = OccClient(args.host, args.port, args.path, args.insecure, DummyVehilce())
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
