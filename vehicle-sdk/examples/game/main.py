from av.frame import Frame

from game import Game
import threading
import logging
import argparse
import asyncio
import av

from openocc.vehicle import Vehicle, VehicleClient


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-20s - %(levelname)-8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    game = Game()

    class GameVehicle(Vehicle):
        VEHICLE_ID = "tugger_train"

        def get_front_camera(self) -> Frame:
            np_image = game.get_window_frame()
            return av.VideoFrame.from_ndarray(np_image, format="bgra")

        def set_motion(self, speed, angle) -> None:
            game.set_motion(speed, angle)

        def emergency_halt(self, enable: bool) -> None:
            if enable:
                game.set_motion(0, 0)

    client = VehicleClient(args.host, args.port, args.insecure, GameVehicle())
    t = threading.Thread(target=lambda: asyncio.run(client.loop()))
    t.start()
    game.run()
    t.join()


if __name__ == "__main__":
    main()
