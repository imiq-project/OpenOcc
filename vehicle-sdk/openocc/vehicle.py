from abc import ABC
from typing import Union
from .ioconf import outgoing, incoming, command, DataType


class Vehicle(ABC):

    VEHICLE_ID = ""

    @incoming("motion", [DataType.Int8, DataType.Int8])
    def set_motion(self, speed, angle):
        pass

    @outgoing("front_camera", [DataType.Video])
    def get_front_camera(self):
        pass

    @outgoing("position", [DataType.UInt64, DataType.UInt64])
    def get_position(self):
        pass

    @command("emergency_halt")
    def emergency_halt(self, enable: bool):
        pass
