from av import VideoFrame
import struct


def animate_rainbow(phase):
    # We do not force numpy as dependency
    # so lazy import it
    import numpy as np

    width, height = 640, 480
    frame = VideoFrame(width=width, height=height, format="rgba")

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


class Gamepad:

    def __init__(self, speed_axis: int, angle_axis: int, forwards_button:int, backwards_button: int) -> None:
        self.speed: float = 0
        self.angle: float = 0
        self.speed_axis = speed_axis
        self.angle_axis = angle_axis
        self.forwards_button = forwards_button
        self.backwards_button = backwards_button
        self._forwards = True

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
                    if number == self.backwards_button:
                        if value:
                            self._forwards = False
                    elif number == self.forwards_button:
                        if value:
                            self._forwards = True
                    else:
                        print(f"Button {number} {'pressed' if value else 'released'}")

                if type_ & JS_EVENT_AXIS:
                    if number == self.angle_axis:
                        self.angle = value / -32767.0
                    elif number == self.speed_axis:
                        speed = (value + 32767) / 2 / 32767.0
                        self.speed = speed if self._forwards else -speed
                    else:
                        print(f"Axis {number} value: {value}")
