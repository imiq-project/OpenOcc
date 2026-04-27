"""

Subscribes to ROS topics published by the Webots simulation and exposes them
through openocc.vehicle.Vehicle:

  /camera/image_raw   →  get_front_camera()
  /vehicle_pose       →  get_position()
  /diagnostics        →  get_battery_level()
  set_motion()        →  /cmd_vel

Run:
  pip install -e <vehicle-sdk-path>
  python3 ros_husky.py --vehicle_id husky
"""

import argparse
import asyncio
import logging
import threading

import numpy as np
import rclpy
from rclpy.node import Node
from av import VideoFrame
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from sensor_msgs.msg import Image, NavSatFix
from diagnostic_msgs.msg import DiagnosticArray

from openocc.vehicle import Vehicle, VehicleClient


class RosNode(Node):
    """ROS subscriptions/publishers for the Husky."""

    def __init__(self) -> None:
        super().__init__("openocc_husky")
        self.latest_image: Image | None = None
        self.latest_odom: Odometry | None = None
        self.latest_fix: NavSatFix | None = None
        self.latest_battery: int = 100

        self.create_subscription(Image, "/camera/image_raw", self._image_cb, 1)
        self.create_subscription(Odometry, "/vehicle_pose", self._odom_cb, 10)
        self.create_subscription(NavSatFix, "/gps/fix", self._fix_cb, 10)
        self.create_subscription(DiagnosticArray, "/diagnostics", self._diag_cb, 10)

        self.cmd_vel_pub = self.create_publisher(Twist, "/cmd_vel", 1)

    def _image_cb(self, msg: Image) -> None:
        self.latest_image = msg

    def _odom_cb(self, msg: Odometry) -> None:
        self.latest_odom = msg

    def _fix_cb(self, msg: NavSatFix) -> None:
        self.latest_fix = msg

    def _diag_cb(self, msg: DiagnosticArray) -> None:
        for s in msg.status:
            for kv in s.values:
                if kv.key.lower().startswith("battery"):
                    try:
                        self.latest_battery = int(float(kv.value))
                    except ValueError:
                        pass


def make_blank_frame(width: int = 640, height: int = 480) -> VideoFrame:
    """Return a black RGBA frame."""
    return VideoFrame(width=width, height=height, format="rgba")


def ros_image_to_av(msg: Image) -> VideoFrame:
    """Convert a ROS sensor_msgs/Image (rgb8) to an av.VideoFrame (rgba)."""
    arr = np.frombuffer(bytes(msg.data), dtype=np.uint8).reshape(
        (msg.height, msg.width, 3)
    )
    rgba = np.dstack([arr, np.full((msg.height, msg.width), 255, dtype=np.uint8)])
    frame = VideoFrame(width=msg.width, height=msg.height, format="rgba")
    for plane in frame.planes:
        plane.update(rgba.tobytes())
    return frame


class HuskyVehicle(Vehicle):

    def __init__(self, vehicle_id: str, node: RosNode) -> None:
        self.VEHICLE_ID = vehicle_id
        self._node = node

    def set_motion(self, speed: int, angle: int) -> None:
        # speed/angle are int8 in [-127, 127] from the joystick
        twist = Twist()
        twist.linear.x = float(speed) / 127.0
        twist.angular.z = float(angle) / 127.0
        self._node.cmd_vel_pub.publish(twist)

    def get_front_camera(self) -> VideoFrame:
        if self._node.latest_image is None:
            return make_blank_frame()
        return ros_image_to_av(self._node.latest_image)

    def get_back_camera(self) -> VideoFrame:
        return make_blank_frame()

    def get_position(self) -> tuple[int, int]:
        odom = self._node.latest_odom
        if odom is None:
            return (0, 0)
        # SDK expects UInt64 — encode lat/lon * 1e7 as ints
        fix = self._node.latest_fix
        if fix is not None:
            return (int(fix.latitude * 1e7), int(fix.longitude * 1e7))
        return (
            int(odom.pose.pose.position.x * 1e3),
            int(odom.pose.pose.position.y * 1e3),
        )

    def get_battery_level(self) -> int:
        return self._node.latest_battery

    def emergency_halt(self, enable: bool) -> None:
        if enable:
            twist = Twist()
            self._node.cmd_vel_pub.publish(twist)
        logging.info(f"Emergency halt: {enable}")


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(module)-10.10s - %(levelname)-8.8s - %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="imiq-occ.et.uni-magdeburg.de")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--vehicle_id", default="husky")
    parser.add_argument("--insecure", action="store_true", default=False)
    args = parser.parse_args()

    rclpy.init()
    node = RosNode()
    spin_thread = threading.Thread(
        target=rclpy.spin, args=(node,), daemon=True
    )
    spin_thread.start()

    vehicle = HuskyVehicle(args.vehicle_id, node)
    client = VehicleClient(args.host, args.port, args.insecure, vehicle)
    try:
        await client.loop()
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
