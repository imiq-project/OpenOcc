from abc import ABC
from typing import Union
from .ioconf import outgoing, incoming, command, DataType
from av.frame import Frame

class Vehicle(ABC):

    VEHICLE_ID = ""

    @incoming("motion", [DataType.Int8, DataType.Int8])
    def set_motion(self, speed, angle) -> None:
        raise NotImplemented()

    @outgoing("front_camera", [DataType.Video])
    def get_front_camera(self) -> Frame:
        raise NotImplemented()

    @outgoing("back_camera", [DataType.Video])
    def get_back_camera(self) -> Frame:
        raise NotImplemented()

    @outgoing("position", [DataType.UInt64, DataType.UInt64])
    def get_position(self) -> None:
        raise NotImplemented()

    @command("emergency_halt")
    def emergency_halt(self, enable: bool) -> None:
        raise NotImplemented()
