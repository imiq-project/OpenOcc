import logging
import argparse
import asyncio
import threading
from typing import Tuple, Optional
import json

from av.video import VideoFrame

from steering_wheel.operator import Operator, OperatorClient, RemoteVehicle
from steering_wheel.vehicle import SoundIntend
from steering_wheel.ioconf import IoConf
from steering_wheel.util import Gamepad
import tkinter as tk
from PIL import ImageTk
import math


class VideoApp:
    def __init__(self, num_images: int):
        self.root = tk.Tk()
        self.root.geometry("800x600")
        self.root.title("SteeringWheel")
        self.status = tk.Label(self.root, text="SteeringWheel")
        self.status.pack()
        cols = math.ceil(math.sqrt(num_images))
        rows = math.ceil(num_images / cols)

        self.frame = tk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

        # make grid responsive
        for r in range(rows):
            self.frame.rowconfigure(r, weight=1)
        for c in range(cols):
            self.frame.columnconfigure(c, weight=1)

        self.cells = []  # list of labels
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


class MyVehicle(RemoteVehicle):

    def __init__(self, client: OperatorClient, id: str, io_conf: IoConf) -> None:
        super().__init__(client, id, io_conf)
        self.speed = 0.0
        self.angle = 0.0

    def set_front_camera(self, frame: VideoFrame) -> None:
        app.images[0] = frame.to_image()

    def set_back_camera(self, frame: VideoFrame) -> None:
        app.images[1] = frame.to_image()

    def set_left_camera(self, frame: VideoFrame) -> None:
        app.images[2] = frame.to_image()

    def set_right_camera(self, frame: VideoFrame) -> None:
        app.images[3] = frame.to_image()

    def get_motion(self) -> Tuple[int, int]:
        return int(self.speed * 127), int(self.angle * 127)

    def set_battery_level(self, level: int) -> None:
        app.status.config(text=f"Battery Level: {level}%")


class MyGamepad(Gamepad):
    my_angle_axis = 0
    my_peed_axis = 5
    backwards_button = 4
    forwards_button = 5

    def __init__(self, remote_vehicle: MyVehicle) -> None:
        super().__init__(self.my_peed_axis, self.my_angle_axis)
        self.remote_vehicle = remote_vehicle
        self._forwards = True

    async def on_button_pressed(self, number: int):
        if number == self.backwards_button:
            self._forwards = False
        elif number == self.forwards_button:
            self._forwards = True
        elif number == 0:
            await self.remote_vehicle.invoke_command(
                "play_sound", [SoundIntend.SHORT_HONK.value]
            )
        elif number == 1:
            await self.remote_vehicle.invoke_command(
                "play_sound", [SoundIntend.LONG_HONK.value]
            )
        elif number == 3:
            await self.remote_vehicle.invoke_command(
                "play_sound", [SoundIntend.FIND_ME.value]
            )
        elif number == 4:
            await self.remote_vehicle.invoke_command(
                "play_sound", [SoundIntend.ALARM.value]
            )
        else:
            print(f"Unknown button {number} pressed")

    def on_angle_changed(self, angle: float):
        self.remote_vehicle.angle = angle

    def on_speed_changed(self, speed: float):
        self.remote_vehicle.speed = speed if self._forwards else -speed


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

    class DummyOperator(Operator):
        def __init__(self) -> None:
            self.vehicle_found = asyncio.Future()

        def on_new_vehicle(
            self, client: OperatorClient, id: str, io_conf: IoConf
        ) -> MyVehicle:
            vehicle = MyVehicle(client, id, io_conf)
            if id == target_vehicle:
                print(json.dumps(io_conf.to_json(), indent=4))
                self.vehicle_found.set_result(vehicle)
            return vehicle

    operator = DummyOperator()
    client = OperatorClient(args.host, args.port, args.insecure, operator)
    asyncio.create_task(client.loop())
    logging.info(f"Waiting for a vehicle {target_vehicle}...")
    vehicle = await operator.vehicle_found
    assert isinstance(vehicle, MyVehicle)
    result = await vehicle.invoke_command("emergency_halt", [False])
    logging.info(f"Result: {result}")

    gamepad = MyGamepad(vehicle)
    asyncio.create_task(gamepad.loop())
    await vehicle.start_webrtc()

    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    app = VideoApp(num_images=4)
    threading.Thread(
        target=lambda: asyncio.run(start_async_loop(app)), daemon=True
    ).start()
    app.mainloop()
