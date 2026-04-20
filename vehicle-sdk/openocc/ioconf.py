from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Type
from enum import Enum
import struct

_INPUT_PARAM = "_input_param"
_OUTPUT_PARAM = "_output_param"
_COMMAND = "_command"


class DataType(Enum):
    Int8 = "int8"
    UInt8 = "uint8"
    Int64 = "int64"
    UInt64 = "uint64"
    Status = "status"
    LatLon = "latlon"
    Video = "video"
    Audio = "audio"


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
        return IncomingParam(data["name"], DataType(data["type"]), lambda _, __: None)


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
    func: Callable[[Any], Any]

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

    def set_incoming(self, instance: object, byte_array: bytes):
        i = 0

        def read(n):
            nonlocal i
            chunk = byte_array[i : i + n]
            i += n
            return chunk

        for param in self.incoming:
            dt = param.data_type
            if dt == DataType.Int8:
                value = struct.unpack("b", read(1))[0]
            elif dt == DataType.UInt8:
                value = struct.unpack("B", read(1))[0]
            elif dt == DataType.Int64:
                value = struct.unpack(">q", read(8))[0]  # big-endian
            elif dt == DataType.UInt64:
                value = struct.unpack(">Q", read(8))[0]
            else:
                raise ValueError(f"Invalid data type {dt}")
            param.func(value)

    def make_incoming(self, values: Dict[str, Any]):
        result = bytearray()
        for param in self.incoming:
            dt = param.data_type
            value = values[param.name]
            if dt == DataType.Int8:
                result += struct.pack("b", value)
            elif dt == DataType.UInt8:
                result += struct.pack("B", value)
            elif dt == DataType.Int64:
                result += struct.pack(">q", value)
            elif dt == DataType.UInt64:
                result += struct.pack(">Q", value)
            else:
                raise ValueError(f"Invalid data type {dt}")
        return bytes(result)

    def invoke_command(self, instance, method, params):
        for command in self.commands:
            if command.name == method:
                return command.func(*params)
        raise IoConfException(f"Command {method} does not exist")


def overrides(obj, method_name, base_class):
    cls = obj.__class__
    if cls is base_class:
        return True
    base_method = getattr(base_class, method_name)
    sub_method = getattr(cls, method_name, None)
    return sub_method is not base_method


def io_conf_for(instance: object, base_kls: Type):
    result = IoConf()
    if not isinstance(instance, base_kls):
        raise IoConfException("instance must inherit from base_kls")
    for name in dir(base_kls):
        method = getattr(base_kls, name)
        input_param = getattr(method, _INPUT_PARAM, None)
        if input_param and overrides(instance, name, base_kls):
            assert isinstance(input_param, IncomingParam)
            input_param.func = getattr(instance, name)  # TODO: deep copy
            result.incoming.append(input_param)
        output_param = getattr(method, _OUTPUT_PARAM, None)
        if output_param and overrides(instance, name, base_kls):
            assert isinstance(output_param, OutgoingParam)
            output_param.func = getattr(instance, name) # TODO: deep copy
            result.outgoing.append(output_param)
        command = getattr(method, _COMMAND, None)
        if command and overrides(instance, name, base_kls):
            assert isinstance(command, Command)
            command.func = getattr(instance, name) # TODO: deep copy
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
