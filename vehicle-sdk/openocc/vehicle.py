from abc import ABC
from typing import Union
from .ioconf import outgoing, incoming, command, DataType


class Vehicle(ABC):

    VEHICLE_ID = ""

    @incoming("speed", DataType.Int8)
    def set_speed(self, value):
        pass

    @incoming("angle", DataType.Int8)
    def set_angle(self, value):
        pass

    @outgoing("front_camera", DataType.Video)
    def get_front_camera(self):
        pass

    @outgoing("position", DataType.LatLon)
    def get_position(self):
        pass

    @command("emergency_halt")
    def emergency_halt(self):
        pass
