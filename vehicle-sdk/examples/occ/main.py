import logging
import argparse
import asyncio

from openocc.operator import Operator
from openocc.client import OperatorClient
from openocc.ioconf import IoConf


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

        def on_vehicle_changed(self, id, name, connected, io_conf: IoConf):
            conn = "CONNECTED" if connected else "disconnected"
            logging.info(f"Vehicle: {id} - {name} - {conn}")
            for i in io_conf.commands:
                logging.info(f"  command: {i.name}")
                if i.name == args.command:
                    self.vehicle_found.set_result((id, io_conf))

    operator = DummyOperator()
    client = OperatorClient(args.host, args.port, args.insecure, operator)
    asyncio.create_task(client.loop())
    logging.info(f"Waiting for a vehicle with command {args.command}...")
    vehicle_id, io_conf = await operator.vehicle_found
    assert isinstance(io_conf, IoConf)
    result = await client.send_rpc_request(vehicle_id, args.command, [])
    logging.info(f"Result: {result}")
    await client.start_webrtc(vehicle_id)
    while True:
        await asyncio.sleep(1)
        payload = io_conf.make_incoming({'speed': 10, 'angle': 20})
        client.send_webrtc_datagram(payload)


if __name__ == "__main__":
    asyncio.run(main())
