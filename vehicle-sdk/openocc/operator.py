from abc import ABC, abstractmethod
from .ioconf import IoConf


class Operator(ABC):

    @abstractmethod
    def on_vehicle_changed(self, id: str, name: str, connected: bool, io_conf: IoConf):
        pass
