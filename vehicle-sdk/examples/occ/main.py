import logging
import argparse
import asyncio
import threading
import json

from openocc.operator import Operator, OperatorClient, RemoteVehicle
from openocc.ioconf import IoConf
from openocc.util import Gamepad


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-10.10s - %(levelname)-8.8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--insecure", action="store_true", default=False)
    parser.add_argument("target_vehicle")
    args = parser.parse_args()
    target_vehicle: str = args.target_vehicle

    class DummyOperator(Operator):
        def __init__(self) -> None:
            self.vehicle_found = asyncio.Future()

        def on_new_vehicle(
            self, client: OperatorClient, id: str, io_conf: IoConf
        ) -> RemoteVehicle:
            vehicle = super().on_new_vehicle(client, id, io_conf)
            if id == target_vehicle:
                self.vehicle_found.set_result(vehicle)
            return vehicle

    operator = DummyOperator()
    client = OperatorClient(args.host, args.port, args.insecure, operator)
    asyncio.create_task(client.loop())
    logging.info(f"Waiting for a vehicle {target_vehicle}...")
    vehicle = await operator.vehicle_found
    assert isinstance(vehicle, RemoteVehicle)
    result = await client.send_rpc_request(target_vehicle, "emergency_halt", [False])
    logging.info(f"Result: {result}")
    await vehicle.start_webrtc()

    while True:
        await asyncio.sleep(1)

    gamepad = Gamepad(angle_axis=0, speed_axis=5)
    threading.Thread(target=gamepad.loop, daemon=True).start()


if __name__ == "__main__":
    asyncio.run(main())
