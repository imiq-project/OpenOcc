import logging
import argparse
import asyncio

from openocc.vehicle import Vehicle, VehicleClient
from openocc.util import animate_rainbow


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
            pass

        def get_front_camera(self):
            self.front_phase += 0.1
            return animate_rainbow(self.front_phase)

        def get_back_camera(self):
            self.back_phase -= 0.1
            return animate_rainbow(self.back_phase)
        
        def get_battery_level(self):
            return 42,

        def emergency_halt(self, enable: bool):
            logging.info("Emergency halt triggered!")

    client = VehicleClient(args.host, args.port, args.insecure, DummyVehicle())
    await client.loop()


if __name__ == "__main__":
    asyncio.run(main())
