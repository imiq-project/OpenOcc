import unittest
from openocc.ioconf import (
    incoming,
    outgoing,
    command,
    IoConfException,
    DataType,
    binding_for,
    IoConf,
)


class IoConfFromClass(unittest.TestCase):

    def test_empty(self):
        class MyVehicle:
            pass

        binding = binding_for(MyVehicle(), MyVehicle)
        expected_conf = {"incoming": [], "outgoing": [], "commands": []}
        self.assertEqual(expected_conf, binding.io_conf.to_json())

    def test_invalid_decorator(self):
        with self.assertRaises(IoConfException):

            @outgoing("empty", [])
            def return_nothing(self):
                pass

        with self.assertRaises(IoConfException):

            @outgoing("mixed", [DataType.Video, DataType.UInt16])
            def return_mixed(self):
                pass

    def test_full(self):
        class MyVehicle:
            @outgoing("position", [DataType.UInt64])
            def position(self):
                pass

            @outgoing("status", [DataType.UInt8])
            def status(self):
                pass

            @incoming("speed", [DataType.UInt64])
            def set_speed(self):
                pass

            @incoming("angle", [DataType.UInt64])
            def set_angle(self):
                pass

            @outgoing("cam", [DataType.Video])
            def get_cam(self):
                pass

            @command("alarm")
            def trigger_alarm(self):
                pass

        binding = binding_for(MyVehicle(), MyVehicle)
        expected_conf = {
            "incoming": [
                {"name": "angle", "types": ["uint64"]},
                {"name": "speed", "types": ["uint64"]},
            ],
            "outgoing": [
                {"name": "cam", "types": ["video"]},
                {"name": "position", "types": ["uint64"]},
                {"name": "status", "types": ["uint8"]},
            ],
            "commands": [
                {"name": "alarm"},
            ],
        }
        self.assertEqual(expected_conf, binding.io_conf.to_json())

    def test_duplicate_output(self):
        class MyVehicle:
            @outgoing("position", [DataType.UInt64])
            def get_position_1(self):
                pass

            @outgoing("position", [DataType.UInt64])
            def get_position_2(self):
                pass

        with self.assertRaises(IoConfException):
            binding_for(MyVehicle(), MyVehicle)

    def test_duplicate_input(self):
        class MyVehicle:
            @incoming("position", [DataType.UInt64])
            def set_position_1(self):
                pass

            @incoming("position", [DataType.UInt64])
            def set_position_2(self):
                pass

        with self.assertRaises(IoConfException):
            binding_for(MyVehicle(), MyVehicle)

    def test_duplicate_command(self):
        class MyVehicle:
            @command("foo")
            def foo_1(self):
                pass

            @command("foo")
            def foo(self):
                pass

        with self.assertRaises(IoConfException):
            binding_for(MyVehicle(), MyVehicle)

    def test_inheritance(self):
        class BaseVehicle:
            @outgoing("position", [DataType.UInt64])
            def position(self):
                pass

            @outgoing("status", [DataType.UInt8])
            def status(self):
                pass

            @incoming("speed", [DataType.UInt64])
            def set_speed(self):
                pass

            @incoming("angle", [DataType.UInt64])
            def set_angle(self):
                pass

            @command("alarm")
            def trigger_alarm(self):
                pass

            @command("halt")
            def emergency_halt(self):
                pass

        class MyVehicle(BaseVehicle):
            def position(self):
                pass

            def set_speed(self):
                pass

            def emergency_halt(self):
                pass

        binding = binding_for(MyVehicle(), BaseVehicle)
        expected_conf = {
            "incoming": [
                {"name": "speed", "types": ["uint64"]},
            ],
            "outgoing": [
                {"name": "position", "types": ["uint64"]},
            ],
            "commands": [
                {"name": "halt"},
            ],
        }
        self.assertEqual(expected_conf, binding.io_conf.to_json())

    def test_wrong_base_class(self):
        with self.assertRaises(IoConfException):

            class MyClass:
                pass

            binding_for(MyClass(), str)

    def test_media(self):
        class MyVehicle:
            @outgoing("cam", [DataType.Video])
            def get_cam(self):
                pass

            @outgoing("mic", [DataType.Audio])
            def get_mic(self):
                pass

            @incoming("announce", [DataType.Audio])
            def set_announcement(self, audio):
                pass

        binding = binding_for(MyVehicle(), MyVehicle)
        self.assertEqual(len(binding.get_incoming_track_callbacks()), 1)
        self.assertEqual(len(binding.get_outgoing_tracks()), 2)
        callbacks = binding.get_outgoing_tracks()
        self.assertEqual(len(callbacks), 2)
        for cb in callbacks:
            cb()


class FromJson(unittest.TestCase):
    def test_invalid_data_type(self):
        conf = {"incoming": [{"name": "foo", "types": "INVALID"}]}
        with self.assertRaises(IoConfException):
            IoConf.from_json(conf)

    def test_valid(self):
        conf = {
            "incoming": [{"name": "foo", "types": ["uint8"]}],
            "outgoing": [{"name": "bar", "types": ["int64"]}],
            "commands": [{"name": "cmd"}],
        }
        parsed = IoConf.from_json(conf)
        self.assertEqual(len(parsed._incoming), 1)
        self.assertEqual(len(parsed._outgoing), 1)
        self.assertEqual(len(parsed._commands), 1)


class ApplyBinding(unittest.TestCase):

    def test_full(self):
        class MyVehicle:
            @outgoing("position", [DataType.UInt64])
            def position(self):
                return [42]

            @outgoing("status", [DataType.UInt64])
            def status(self):
                return [100]

            @incoming("speed", [DataType.UInt64])
            def set_speed(self, value):
                self.speed = value

            @incoming("angle", [DataType.UInt64])
            def set_angle(self, value):
                self.angle = value

            @command("add")
            def add(self, a, b):
                return a + b

        instance = MyVehicle()
        conf = binding_for(instance, MyVehicle)

        payload = conf.io_conf.encode_incoming({"angle": [10], "speed": [123]})
        conf.decode_incoming(payload)
        self.assertEqual(instance.angle, 10)
        self.assertEqual(instance.speed, 123)

        payload = conf.encode_outgoing()
        result = conf.io_conf.decode_outgoing(payload)
        self.assertEqual(result, {"position": [42], "status": [100]})

        res = conf.invoke_command("add", [42, 100])
        self.assertEqual(res, 142)

        with self.assertRaises(IoConfException):
            conf.invoke_command("invalid", [])


class TransmitBinding(unittest.TestCase):
    def test_transmit_match(self):
        class MyVehicle:
            @outgoing("position", [DataType.UInt64])
            def get_position(self):
                return [42]

            @outgoing("cam", [DataType.Video])
            def get_cam(self):
                return None

        class MyOperator:
            @incoming("position", [DataType.UInt64])
            def set_position(self, pos):
                self.pos = pos

            @incoming("cam", [DataType.Video])
            def set_cam(self, cam):
                self.cam = cam

        sender = MyVehicle()
        binding_sender = binding_for(sender, MyVehicle)
        receiver = MyOperator()
        binding_receiver = binding_for(receiver, MyOperator)
        binding_receiver.narrow_down(binding_sender.io_conf)

        payload = binding_sender.encode_outgoing()
        binding_receiver.decode_incoming(payload)
        self.assertEqual(receiver.pos, 42)

    def test_transmit_outgoing_not_found(self):
        class MyVehicle:
            @outgoing("position", [DataType.UInt64])
            def get_position(self):
                return [42]

        class MyOperator:
            pass

        sender = MyVehicle()
        binding_sender = binding_for(sender, MyVehicle)
        receiver = MyOperator()
        binding_receiver = binding_for(receiver, MyOperator)
        with self.assertRaises(IoConfException):
            binding_receiver.narrow_down(binding_sender.io_conf)

    def test_transmit_incoming_not_found(self):
        class MyVehicle:
            @incoming("speed", [DataType.UInt64])
            def set_speed(self, speed):
                pass

        class MyOperator:
            pass

        sender = MyVehicle()
        binding_sender = binding_for(sender, MyVehicle)
        receiver = MyOperator()
        binding_receiver = binding_for(receiver, MyOperator)
        with self.assertRaises(IoConfException):
            binding_receiver.narrow_down(binding_sender.io_conf)

    def test_transmit_receiver_has_more(self):
        class MyVehicle:
            @incoming("speed", [DataType.UInt64])
            def set_speed(self, speed):
                self.speed = speed

            @outgoing("position", [DataType.UInt64])
            def get_position(self):
                return [42]

        class MyOperator:
            def __init__(self) -> None:
                self.battery = None

            @outgoing("speed", [DataType.UInt64])
            def get_speed(self):
                return [142]

            @outgoing("angle", [DataType.UInt64])
            def get_angle(self):
                return [100]

            @incoming("position", [DataType.UInt64])
            def set_position(self, pos):
                self.pos = pos

            @incoming("battery", [DataType.UInt64])
            def set_battery(self, battery):
                self.battery = battery  # not called

        sender = MyVehicle()
        binding_sender = binding_for(sender, MyVehicle)
        receiver = MyOperator()
        binding_receiver = binding_for(receiver, MyOperator)
        binding_receiver.narrow_down(binding_sender.io_conf)

        payload = binding_sender.encode_outgoing()
        binding_receiver.decode_incoming(payload)
        self.assertEqual(receiver.pos, 42)
        self.assertEqual(receiver.battery, None)

        payload = binding_receiver.encode_outgoing()
        binding_sender.decode_incoming(payload)
        self.assertEqual(sender.speed, 142)


if __name__ == "__main__":
    unittest.main()
