from typing import List
from game import Game
from occ import OccClient, Vehicle
import threading
import logging
import argparse
import asyncio
from aiortc import MediaStreamTrack, VideoStreamTrack
import av

class GameStreamTrack(VideoStreamTrack):

    def __init__(self, game: Game):
        super().__init__()
        self.game = game

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        np_image = self.game.get_window_frame()
        frame = av.VideoFrame.from_ndarray(np_image, format="bgra")
        frame.pts = pts
        frame.time_base = time_base
        return frame


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
        def create_streams(self) -> List[MediaStreamTrack]:
            return [GameStreamTrack(game)]
        
        def ping(self, msg: str):
            game.ping(msg)

    client = OccClient(args.host, args.port, args.path, args.insecure, GameVehicle())

    t = threading.Thread(target=lambda: asyncio.run(client.loop()))
    t.start()
    game.run()
    t.join()


if __name__ == "__main__":
    main()
