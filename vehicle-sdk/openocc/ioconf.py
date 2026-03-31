from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable
from enum import Enum

_INPUT_PARAM = "_input_param"
_OUTPUT_PARAM = "_output_param"


class DataType(Enum):
    UInt64 = "uint64"
    Status = "status"


class IoConfException(Exception):
    pass


@dataclass
class IncomingParam:
    name: str
    data_type: DataType
    func: Callable[[Any, Any], Any]

    def to_json(self):
        return {"name": self.name, "type": self.data_type.value}


@dataclass
class OutgoingParam:
    name: str
    data_type: DataType
    func: Callable[[Any], Any]

    def to_json(self):
        return {"name": self.name, "type": self.data_type.value}


def incoming(name: str, data_type: DataType):
    def decorator(func):
        setattr(func, _INPUT_PARAM, IncomingParam(name, data_type, func))
        return func

    return decorator


def outgoing(name, data_type: DataType):
    def decorator(func):
        setattr(func, _OUTPUT_PARAM, OutgoingParam(name, data_type, func))
        return func

    return decorator


class IoConf:

    def __init__(self, instance: object):
        self._instance = instance
        self._incoming: List[IncomingParam] = []
        self._outgoing: List[OutgoingParam] = []
        for name in dir(instance):
            method = getattr(instance, name)
            input_param = getattr(method, _INPUT_PARAM, None)
            if input_param:
                self._incoming.append(input_param)
            output_param = getattr(method, _OUTPUT_PARAM, None)
            if output_param:
                self._outgoing.append(output_param)
        self._incoming.sort(key=lambda x: x.name)
        for idx, entry in enumerate(self._incoming[:-1]):
            if entry.name == self._incoming[idx + 1].name:
                raise IoConfException(f"Duplicate input '{entry.name}'")
        self._outgoing.sort(key=lambda x: x.name)
        for idx, entry in enumerate(self._outgoing[:-1]):
            if entry.name == self._outgoing[idx + 1].name:
                raise IoConfException(f"Duplicate output '{entry.name}'")

    def to_json(self):
        return {
            "incoming": [i.to_json() for i in self._incoming],
            "outgoing": [i.to_json() for i in self._outgoing],
        }

    def set_incoming(self, incoming_values: Dict[str, Any]):
        for param in self._incoming:
            try:
                value = incoming_values[param.name]
            except KeyError:
                continue
            param.func(self._instance, value)

    def get_outgoing(self, selected: List[str]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for param in self._outgoing:
            if param.name in selected:
                result[param.name] = param.func(self._instance)
        return result
