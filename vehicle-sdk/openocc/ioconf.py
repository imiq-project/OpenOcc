from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable
from enum import Enum

_INPUT_PARAM = "_input_param"
_OUTPUT_PARAM = "_output_param"
_COMMAND = "_command"


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

    @classmethod
    def from_json(cls, data: dict) -> "IncomingParam":
        return IncomingParam(data["name"], data["type"], lambda _, __: None)


def incoming(name: str, data_type: DataType):
    def decorator(func):
        setattr(func, _INPUT_PARAM, IncomingParam(name, data_type, func))
        return func

    return decorator


@dataclass
class OutgoingParam:
    name: str
    data_type: DataType
    func: Callable[[Any], Any]

    def to_json(self):
        return {"name": self.name, "type": self.data_type.value}

    @classmethod
    def from_json(cls, data: dict) -> "OutgoingParam":
        return OutgoingParam(data["name"], data["type"], lambda _: None)


def outgoing(name, data_type: DataType):
    def decorator(func):
        setattr(func, _OUTPUT_PARAM, OutgoingParam(name, data_type, func))
        return func

    return decorator


@dataclass
class Command:
    name: str
    func: Callable[[], Any]

    def to_json(self):
        return {"name": self.name}

    @classmethod
    def from_json(cls, data: dict) -> "Command":
        return Command(name=data["name"], func=lambda: None)


def command(name):
    def decorator(func):
        setattr(func, _COMMAND, Command(name, func))
        return func

    return decorator


@dataclass
class IoConf:

    incoming: List[IncomingParam] = field(default_factory=list)
    outgoing: List[OutgoingParam] = field(default_factory=list)
    commands: List[Command] = field(default_factory=list)

    def to_json(self):
        return {
            "incoming": [i.to_json() for i in self.incoming],
            "outgoing": [i.to_json() for i in self.outgoing],
            "commands": [i.to_json() for i in self.commands],
        }

    @classmethod
    def from_json(cls, data: dict) -> "IoConf":
        return IoConf(
            incoming=[IncomingParam.from_json(i) for i in data.get("incoming", [])],
            outgoing=[OutgoingParam.from_json(i) for i in data.get("outgoing", [])],
            commands=[Command.from_json(i) for i in data.get("commands", [])],
        )

    def set_incoming(self, instance: object, incoming_values: Dict[str, Any]):
        for param in self.incoming:
            try:
                value = incoming_values[param.name]
            except KeyError:
                continue
            param.func(instance, value)

    def get_outgoing(self, instance, selected: List[str]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for param in self.outgoing:
            if param.name in selected:
                result[param.name] = param.func(instance)
        return result


def io_conf_for(instance: object):
    result = IoConf()
    for name in dir(instance):
        method = getattr(instance, name)
        input_param = getattr(method, _INPUT_PARAM, None)
        if input_param:
            result.incoming.append(input_param)
        output_param = getattr(method, _OUTPUT_PARAM, None)
        if output_param:
            result.outgoing.append(output_param)
        command = getattr(method, _COMMAND, None)
        if command:
            result.commands.append(command)
    result.incoming.sort(key=lambda x: x.name)
    for idx, entry in enumerate(result.incoming[:-1]):
        if entry.name == result.incoming[idx + 1].name:
            raise IoConfException(f"Duplicate input '{entry.name}'")
    result.outgoing.sort(key=lambda x: x.name)
    for idx, entry in enumerate(result.outgoing[:-1]):
        if entry.name == result.outgoing[idx + 1].name:
            raise IoConfException(f"Duplicate output '{entry.name}'")
    result.commands.sort(key=lambda x: x.name)
    for idx, entry in enumerate(result.commands[:-1]):
        if entry.name == result.commands[idx + 1].name:
            raise IoConfException(f"Duplicate commands '{entry.name}'")
    return result
