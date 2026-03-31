import unittest
from openocc.ioconf import (
    incoming,
    outgoing,
    IoConf,
    IoConfException,
    DataType,
)


class IoConfFromClass(unittest.TestCase):

    def test_empty(self):
        class MyVehicle:
            pass

        conf = IoConf(MyVehicle())
        expected_conf = {"incoming": [], "outgoing": []}
        self.assertEqual(expected_conf, conf.to_json())

    def test_simple(self):
        class MyVehicle:
            @outgoing("position", DataType.UInt64)
            def position(self):
                pass

            @outgoing("status", DataType.Status)
            def status(self):
                pass

            @incoming("speed", DataType.UInt64)
            def set_speed(self):
                pass

            @incoming("angle", DataType.UInt64)
            def set_angle(self):
                pass

        conf = IoConf(MyVehicle())
        expected_conf = {
            "incoming": [
                {"name": "angle", "type": "uint64"},
                {"name": "speed", "type": "uint64"},
            ],
            "outgoing": [
                {"name": "position", "type": "uint64"},
                {"name": "status", "type": "status"},
            ],
        }
        self.assertEqual(expected_conf, conf.to_json())

    def test_duplicate_output(self):
        class MyVehicle:
            @outgoing("position", DataType.UInt64)
            def get_position_1(self):
                pass

            @outgoing("position", DataType.UInt64)
            def get_position_2(self):
                pass

        with self.assertRaises(IoConfException):
            IoConf(MyVehicle())

    def test_duplicate_input(self):
        class MyVehicle:
            @incoming("position", DataType.UInt64)
            def set_position_1(self):
                pass

            @incoming("position", DataType.UInt64)
            def set_position_2(self):
                pass

        with self.assertRaises(IoConfException):
            IoConf(MyVehicle())


class ApplyIoConf(unittest.TestCase):
    def test_simple(self):
        class MyVehicle:
            @outgoing("position", DataType.UInt64)
            def position(self):
                return 42

            @outgoing("status", DataType.UInt64)
            def status(self):
                return 100

            @incoming("speed", DataType.UInt64)
            def set_speed(self, value):
                self.speed = value

            @incoming("angle", DataType.UInt64)
            def set_angle(self, value):
                self.angle = value

        instance = MyVehicle()
        conf = IoConf(instance)
        conf.set_incoming({"angle": 10, "speed": 123})
        self.assertEqual(instance.angle, 10)
        self.assertEqual(instance.speed, 123)
        out = conf.get_outgoing(["position", "status"])
        self.assertEqual(len(out), 2)
        self.assertEqual(out["position"], 42)
        self.assertEqual(out["status"], 100)


if __name__ == "__main__":
    unittest.main()
