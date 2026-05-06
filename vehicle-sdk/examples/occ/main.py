import logging
import argparse
import asyncio
import threading
from typing import Tuple

from av.video import VideoFrame

from openocc.operator import Operator, OperatorClient, RemoteVehicle
from openocc.ioconf import IoConf
from openocc.util import Gamepad
import tkinter as tk
from PIL import ImageTk
import math

class VideoApp:
    def __init__(self, num_images: int):
        self.root = tk.Tk()
        self.root.geometry("800x600")
        self.root.title("OpenOcc")
        tk.Label(self.root, text="OpenOcc").pack()
        cols = math.ceil(math.sqrt(num_images))
        rows = math.ceil(num_images / cols)

        self.frame = tk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

        # make grid responsive
        for r in range(rows):
            self.frame.rowconfigure(r, weight=1)
        for c in range(cols):
            self.frame.columnconfigure(c, weight=1)

        self.cells = []   # list of labels
        self.images = [None for _ in range(num_images)]

        # create grid cells
        for r in range(rows):
            for c in range(cols):
                lbl = tk.Label(self.frame, bg="black")
                lbl.grid(row=r, column=c, sticky="nsew")
                self.cells.append(lbl)

        self.update_gui()

    def mainloop(self):
        self.root.mainloop()

    def update_gui(self):
        for i, image in enumerate(self.images):
            cell = self.cells[i]
            w = cell.winfo_width()
            h = cell.winfo_height()
            if w > 1 and h > 1 and image is not None:
                resized = self.resize_keep_aspect(image, w, h)
                imgtk = ImageTk.PhotoImage(resized)
                cell.imgtk = imgtk
                cell.configure(image=imgtk)

        self.root.after(15, self.update_gui)

    @staticmethod
    def resize_keep_aspect(img, max_w, max_h):
        w, h = img.size
        scale = min(max_w / w, max_h / h)
        return img.resize((int(w * scale), int(h * scale)))

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

    gamepad = Gamepad(angle_axis=0, speed_axis=5, backwards_button=4, forwards_button=5)
    threading.Thread(target=gamepad.loop, daemon=True).start()

    class MyVehicle(RemoteVehicle):

        def set_front_camera(self, frame: VideoFrame) -> None:
            app.images[0] = frame.to_image()

        def set_back_camera(self, frame: VideoFrame) -> None:
            app.images[1] = frame.to_image()

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
    app = VideoApp(num_images=2)
    threading.Thread(
        target=lambda: asyncio.run(start_async_loop(app)), daemon=True
    ).start()
    app.mainloop()
