import logging
import argparse
import asyncio
import threading
from typing import Tuple

from av.frame import Frame

from openocc.operator import Operator, OperatorClient, RemoteVehicle
from openocc.ioconf import IoConf
from openocc.util import Gamepad
import tkinter as tk
from PIL import ImageTk


class VideoApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        tk.Label(self.root, text="OCC").pack()
        self.label = tk.Label(self.root)
        self.label.pack()

        self.image = None  # latest PIL image

        self.update_gui()

    def update_gui(self):
        if self.image is not None:
            imgtk = ImageTk.PhotoImage(self.image)
            self.label.imgtk = imgtk
            self.label.configure(image=imgtk)

        self.root.after(15, self.update_gui)


async def start_async_loop(app: VideoApp):
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

    gamepad = Gamepad(angle_axis=0, speed_axis=5)
    threading.Thread(target=gamepad.loop, daemon=True).start()

    class MyVehicle(RemoteVehicle):

        def set_front_camera(self, frame: Frame) -> None:
            app.image = frame.to_image()

        def get_motion(self) -> Tuple[int, int]:
            return int(gamepad.speed * 127), int(gamepad.angle * 127)

    class DummyOperator(Operator):
        def __init__(self) -> None:
            self.vehicle_found = asyncio.Future()

        def on_new_vehicle(
            self, client: OperatorClient, id: str, io_conf: IoConf
        ) -> RemoteVehicle:
            vehicle = MyVehicle(client, id, io_conf)
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



if __name__ == "__main__":
    root = tk.Tk()
    root.title("OCC")
    app = VideoApp(root)
    threading.Thread(
        target=lambda: asyncio.run(start_async_loop(app)), daemon=True
    ).start()
    root.mainloop()
