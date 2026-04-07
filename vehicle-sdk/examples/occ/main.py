import logging
import argparse
import asyncio

from openocc.operator import Operator
from openocc.client import OperatorClient


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-10.10s - %(levelname)-8.8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--insecure", action="store_true", default=False)
    parser.add_argument("command")
    args = parser.parse_args()

    class DummyOperator(Operator):
        def __init__(self) -> None:
            self.vehicle_found = asyncio.Future()

        def on_vehicle_changed(self, id, name, connected, io_conf):
            conn = "CONNECTED" if connected else "disconnected"
            logging.info(f"Vehicle: {id} - {name} - {conn}")
            for i in io_conf.commands:
                logging.info(f"  command: {i.name}")
                if i.name == args.command:
                    self.vehicle_found.set_result(id)

    operator = DummyOperator()
    client = OperatorClient(args.host, args.port, args.insecure, operator)
    asyncio.create_task(client.loop())
    vehicle = await operator.vehicle_found
    print(vehicle)
    


if __name__ == "__main__":
    asyncio.run(main())
