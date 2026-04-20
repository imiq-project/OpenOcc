import logging
import argparse
import asyncio
import threading
import json

from openocc.operator import Operator
from openocc.client import OperatorClient
from openocc.ioconf import IoConf
import struct


class Gamepad:

    def __init__(self) -> None:
        self.speed = 0
        self.angle = 0

    def loop(self):
        JS_EVENT_FORMAT = "IhBB"
        JS_EVENT_SIZE = struct.calcsize(JS_EVENT_FORMAT)

        JS_EVENT_BUTTON = 0x01
        JS_EVENT_AXIS = 0x02
        JS_EVENT_INIT = 0x80

        with open("/dev/input/js0", "rb") as js:
            while True:
                event = js.read(JS_EVENT_SIZE)
                if not event:
                    break

                time, value, type_, number = struct.unpack(JS_EVENT_FORMAT, event)

                if type_ & JS_EVENT_INIT:
                    continue

                if type_ & JS_EVENT_BUTTON:
                    print(f"Button {number} {'pressed' if value else 'released'}")

                elif type_ & JS_EVENT_AXIS:
                    if number == 0:
                        self.angle = value / 32767.0
                    elif number == 5:
                        self.speed = (value + 32767) / 2 / 32767.0
                    else:
                        print(f"Axis {number} value: {value}")


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

        def on_vehicle_changed(self, id, name, connected, io_conf: IoConf):
            conn = "CONNECTED" if connected else "disconnected"
            logging.info(f"Vehicle: {id} - {name} - {conn}")
            print(json.dumps(io_conf.to_json(), indent=4))
            if id == target_vehicle:
                self.vehicle_found.set_result(io_conf)

    operator = DummyOperator()
    client = OperatorClient(args.host, args.port, args.insecure, operator)
    asyncio.create_task(client.loop())
    logging.info(f"Waiting for a vehicle {target_vehicle}...")
    io_conf = await operator.vehicle_found
    assert isinstance(io_conf, IoConf)
    result = await client.send_rpc_request(target_vehicle, "emergency_halt", [False])
    logging.info(f"Result: {result}")
    await client.start_webrtc(target_vehicle)

    gamepad = Gamepad()
    threading.Thread(target=gamepad.loop, daemon=True).start()

    while True:
        await asyncio.sleep(1)
        payload = io_conf.make_incoming(
            {"motion": [-int(gamepad.speed * 127), int(gamepad.angle * 127)]}
        )
        client.send_webrtc_datagram(payload)


if __name__ == "__main__":
    asyncio.run(main())
