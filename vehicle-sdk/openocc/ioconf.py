from dataclasses import dataclass
from typing import List, Dict, Any, Callable, Type
from enum import Enum
import struct

_INPUT_PARAM = "_input_param"
_OUTPUT_PARAM = "_output_param"
_COMMAND = "_command"

from typing import Callable


class DataType(Enum):
    Int8 = "int8"
    UInt8 = "uint8"
    Int16 = "int16"
    UInt16 = "uint16"
    Int32 = "uint32"
    UInt32 = "uint32"
    Int64 = "int64"
    UInt64 = "uint64"
    Video = "video"
    Audio = "audio"


def _struct_for(params: List["Param"]) -> struct.Struct:
    map = {
        DataType.Int8: "b",
        DataType.UInt8: "B",
        DataType.Int16: "h",
        DataType.UInt16: "H",
        DataType.Int32: "i",
        DataType.UInt32: "I",
        DataType.Int64: "q",
        DataType.UInt64: "Q",
        DataType.Video: None,  # These are only send via WebRTC streams
        DataType.Audio: None,
    }

    fmt_string = ">"  # big endian
    for param in params:
        for dt in param.data_types:
            fmt = map[dt]
            if fmt:
                fmt_string += fmt
    return struct.Struct(fmt_string)


class IoConfException(Exception):
    pass


@dataclass
class Param:
    name: str
    data_types: List[DataType]

    def to_json(self):
        return {"name": self.name, "types": [i.value for i in self.data_types]}

    def __post_init__(self):
        if len(self.data_types) == 0:
            raise IoConfException("Invalid param: data_types must not be empty")

        # We do not allow to mix media with non-media types as this would require
        # mixing WebRTC data channels with media channels
        if any([i in [DataType.Video, DataType.Audio] for i in self.data_types]):
            if len(self.data_types) != 1:
                raise IoConfException(
                    "Invalid param: if any data_type is audio/video it must be the only entry"
                )

    @classmethod
    def from_json(cls, data: dict) -> "Param":
        try:
            types = [DataType(i) for i in data["types"]]
        except ValueError as e:
            raise IoConfException(f"Invalid data type {e}")
        return Param(data["name"], types)

    def is_media(self):
        return self.data_types[0] in [DataType.Video, DataType.Audio]


def incoming(name: str, data_types: List[DataType]):
    def decorator(func):
        setattr(func, _INPUT_PARAM, Param(name, data_types))
        return func

    return decorator


def outgoing(name, data_types: List[DataType]):
    def decorator(func):
        setattr(func, _OUTPUT_PARAM, Param(name, data_types))
        return func

    return decorator


@dataclass
class Command:
    name: str

    def to_json(self):
        return {"name": self.name}

    @classmethod
    def from_json(cls, data: dict) -> "Command":
        return Command(name=data["name"])


def command(name):
    def decorator(func):
        setattr(func, _COMMAND, Command(name))
        return func

    return decorator


class IoConf:

    def __init__(self) -> None:
        self._incoming: List[Param] = []
        self._outgoing: List[Param] = []
        self._commands: List[Command] = []

    def to_json(self):
        return {
            "incoming": [i.to_json() for i in self._incoming],
            "outgoing": [i.to_json() for i in self._outgoing],
            "commands": [i.to_json() for i in self._commands],
        }

    @classmethod
    def from_json(cls, data: dict) -> "IoConf":
        result = IoConf()
        result._incoming = [Param.from_json(i) for i in data.get("incoming", [])]
        result._outgoing = [Param.from_json(i) for i in data.get("outgoing", [])]
        result._commands = [Command.from_json(i) for i in data.get("commands", [])]
        result._invalidate()
        return result

    def encode_incoming(self, values: Dict[str, List[Any]]):
        extracted_values = []
        for param in self._incoming:
            v = values[param.name]
            assert len(param.data_types) == len(v)
            extracted_values.extend(v)
        return self._incoming_struct.pack(*extracted_values)

    def decode_outgoing(self, payload: bytes) -> Dict[str, List[Any]]:
        values = list(self._incoming_struct.unpack(payload))
        result = {}
        idx = 0
        for param in self._outgoing:
            result[param.name] = values[idx : idx + len(param.data_types)]
            idx += len(param.data_types)
        return result

    def count_outgoing_tracks(self):
        result = 0
        for i in self._outgoing:
            if i.is_media():
                result += 1
        return result

    def count_incoming_tracks(self):
        result = 0
        for i in self._incoming:
            if i.is_media():
                result += 1
        return result

    def _invalidate(self):
        for idx, entry in enumerate(self._incoming[:-1]):
            if entry.name >= self._incoming[idx + 1].name:
                raise IoConfException(f"Duplicate or unsorted incoming '{entry.name}'")
        for idx, entry in enumerate(self._outgoing[:-1]):
            if entry.name >= self._outgoing[idx + 1].name:
                raise IoConfException(f"Duplicate or unsorted outgoing '{entry.name}'")
        for idx, entry in enumerate(self._commands[:-1]):
            if entry.name >= self._commands[idx + 1].name:
                raise IoConfException(f"Duplicate or unsorted command '{entry.name}'")

        self._incoming_struct = _struct_for(self._incoming)
        self._outgoing_struct = _struct_for(self._outgoing)


class Binding:

    def __init__(self) -> None:
        self.io_conf = IoConf()
        self._func_incoming: List[Callable[[Any], Any]] = []
        self._func_outgoing: List[Callable[[Any], Any]] = []
        self._func_commands: Dict[str, Callable[[Any], Any]] = {}

    def encode_outgoing(self) -> bytes:
        values = []
        for func, param in zip(self._func_outgoing, self.io_conf._outgoing):
            if not param.is_media():
                v = func()
                values.extend(v)
        return self.io_conf._outgoing_struct.pack(*values)

    def decode_incoming(self, byte_array: bytes):
        extracted_values = list(self.io_conf._incoming_struct.unpack(byte_array))
        idx = 0
        for func, param in zip(self._func_incoming, self.io_conf._incoming):
            if not param.is_media():
                func(*extracted_values[idx : idx + len(param.data_types)])
                idx += len(param.data_types)

    def invoke_command(self, method, params):
        try:
            func = self._func_commands[method]
        except KeyError:
            raise IoConfException(f"Command {method} does not exist")
        return func(*params)

    def get_outgoing_track_callbacks(self):
        result = []
        for func, param in zip(self._func_outgoing, self.io_conf._outgoing):
            for dt in param.data_types:
                if dt == DataType.Video or dt == DataType.Audio:
                    result.append(func)
        return result

    def narrow_down(self, sender_conf: IoConf):
        new_outgoing = []
        new_outgoing_funcs = []
        for i in sender_conf._incoming:
            try:
                idx = [i.name for i in self.io_conf._outgoing].index(i.name)
            except ValueError:
                raise IoConfException(
                    f"Cannot find sender's incoming in my outgoing: '{i.name}'"
                )
            new_outgoing.append(self.io_conf._outgoing[idx])
            new_outgoing_funcs.append(self._func_outgoing[idx])
        self.io_conf._outgoing = new_outgoing
        self._func_outgoing = new_outgoing_funcs

        new_incoming = []
        new_incoming_funcs = []
        for i in sender_conf._outgoing:
            try:
                idx = [i.name for i in self.io_conf._incoming].index(i.name)
            except ValueError:
                raise IoConfException(
                    f"Cannot find sender's outgoing in my incoming: '{i.name}'"
                )
            new_incoming.append(self.io_conf._incoming[idx])
            new_incoming_funcs.append(self._func_incoming[idx])
        self.io_conf._incoming = new_incoming
        self._func_incoming = new_incoming_funcs

        self.io_conf._invalidate()


def _overrides(obj, method_name, base_class):
    cls = obj.__class__
    if cls is base_class:
        return True
    base_method = getattr(base_class, method_name)
    sub_method = getattr(cls, method_name, None)
    return sub_method is not base_method


def binding_for(instance: object, base_kls: Type) -> Binding:
    result = Binding()
    if not isinstance(instance, base_kls):
        raise IoConfException("instance must inherit from base_kls")

    for name in dir(base_kls):
        base_method = getattr(base_kls, name)

        input_param = getattr(base_method, _INPUT_PARAM, None)
        if input_param and _overrides(instance, name, base_kls):
            assert isinstance(input_param, Param)
            child_method = getattr(instance, name)
            result.io_conf._incoming.append(input_param)
            result._func_incoming.append(child_method)

        output_param = getattr(base_method, _OUTPUT_PARAM, None)
        if output_param and _overrides(instance, name, base_kls):
            assert isinstance(output_param, Param)
            child_method = getattr(instance, name)
            result.io_conf._outgoing.append(output_param)
            result._func_outgoing.append(child_method)

        command = getattr(base_method, _COMMAND, None)
        if command and _overrides(instance, name, base_kls):
            assert isinstance(command, Command)
            command_method = getattr(instance, name)
            result.io_conf._commands.append(command)
            result._func_commands[name] = command_method

    result.io_conf._invalidate()
    return result
