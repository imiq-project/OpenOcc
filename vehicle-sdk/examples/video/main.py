import logging
import argparse
import asyncio
from av import VideoFrame
import numpy as np
import time

from openocc.vehicle import Vehicle
from openocc.client import VehicleClient

from aiortc.contrib.media import MediaPlayer

def animate_rainbow(phase):
    width, height = 640, 480
    frame = VideoFrame(width=width, height=height, format='rgba')

    t = time.time()

    # coordinate grid
    x = np.linspace(0, 2 * np.pi, width, dtype=np.float32)
    y = np.linspace(0, 2 * np.pi, height, dtype=np.float32)

    X, Y = np.meshgrid(x, y)

    # rainbow channels using sine waves
    r = (np.sin(X + phase) + 1.0) * 127.5
    g = (np.sin(Y + phase * 1.3) + 1.0) * 127.5
    b = (np.sin(X + Y + phase * 0.7) + 1.0) * 127.5

    rgba = np.stack((r, g, b, np.zeros(r.shape)), axis=-1).astype(np.uint8)

    # write into frame buffer
    for p in frame.planes:
        p.update(rgba.tobytes())

    return frame


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
            self.front_phase = 0
            self.back_phase = 0

        def set_motion(self, speed, angle):
            print(speed, angle)

        def get_front_camera(self):
            self.front_phase += .1
            return animate_rainbow(self.front_phase)

        def get_back_camera(self):
            self.back_phase -= .1
            return animate_rainbow(self.back_phase)

        def emergency_halt(self, enable: bool):
            logging.info("Emergency halt triggered!")

    client = VehicleClient(args.host, args.port, args.insecure, DummyVehicle())
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
