from abc import ABC, abstractmethod
from av.frame import Frame
from av.packet import Packet
from typing import Union


class Vehicle(ABC):

    @abstractmethod
    async def get_frame(self) -> Union[Frame, Packet]:
        pass
