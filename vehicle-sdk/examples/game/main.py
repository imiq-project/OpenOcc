from typing import List

from av.frame import Frame
from game import Game
from openocc.client import OccClient, Vehicle
import threading
import logging
import argparse
import asyncio
import av


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(module)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/wt-vehicle?VehicleId=tugger_train")
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    game = Game()

    class GameVehicle(Vehicle):
        async def get_frame(self):
            np_image = game.get_window_frame()
            return av.VideoFrame.from_ndarray(np_image, format="bgra")

        def ping(self, msg: str):
            game.ping(msg)

    client = OccClient(args.host, args.port, args.path, args.insecure, GameVehicle())

    t = threading.Thread(target=lambda: asyncio.run(client.loop()))
    t.start()
    game.run()
    t.join()


if __name__ == "__main__":
    main()
