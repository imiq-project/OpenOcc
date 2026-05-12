"""
ROS 2 Vehicle implementation for the OCC client.

Bridges ROS 2 topics from the Webots simulation (or real robot) to the
OCC WebTransport/WebRTC pipeline:

  /camera/image_raw  →  aiortc VideoStreamTrack  →  WebRTC MediaTrack
  /depth/image_raw   →  colormapped VideoTrack   →  WebRTC MediaTrack
  /vehicle_pose      →  JSON position            →  WebTransport datagram (unreliable)
  /gps/fix           →  JSON position            →  WebTransport datagram (unreliable)
  /diagnostics       →  JSON diagnostics         →  WebTransport stream (reliable)
  WebRTC DataChannel →  /cmd_vel                 →  robot drives
"""

import asyncio
import json
import logging
import math
import threading
import time
from fractions import Fraction
from typing import List, Optional

import av
import numpy as np
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from sensor_msgs.msg import Image, NavSatFix
from diagnostic_msgs.msg import DiagnosticArray

from aiortc import MediaStreamTrack

from imiq_vehicle.occ import Vehicle


class RosVideoTrack(MediaStreamTrack):
    """Converts ROS 2 sensor_msgs/Image into aiortc video frames."""

    kind = "video"

    def __init__(self):
        super().__init__()
        self._queue: asyncio.Queue[av.VideoFrame] = asyncio.Queue(maxsize=1)
        self._frame_count = 0

    def push_ros_image(self, msg: Image):
        """Called from the ROS 2 callback thread. Drops old frames."""
        rgb = np.frombuffer(bytes(msg.data), dtype=np.uint8).reshape(
            (msg.height, msg.width, 3)
        )
        frame = av.VideoFrame.from_ndarray(rgb, format="rgb24")
        frame.pts = self._frame_count
        frame.time_base = Fraction(1, 30)
        self._frame_count += 1

        # Drop stale frame if queue is full
        if self._queue.full():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            pass

    async def recv(self) -> av.VideoFrame:
        return await self._queue.get()


class DepthVideoTrack(MediaStreamTrack):
    """Converts ROS 2 32FC1 depth images into colormapped RGB video frames."""

    kind = "video"

    # Turbo-like colormap LUT (256 entries, close → red/yellow, far → blue)
    _LUT = None

    @classmethod
    def _build_lut(cls) -> np.ndarray:
        if cls._LUT is not None:
            return cls._LUT
        # Simple turbo-inspired colormap: red → yellow → green → cyan → blue
        lut = np.zeros((256, 3), dtype=np.uint8)
        for i in range(256):
            t = i / 255.0
            if t < 0.25:
                s = t / 0.25
                lut[i] = [int(128 + 127 * s), int(0 + 255 * s), 0]
            elif t < 0.5:
                s = (t - 0.25) / 0.25
                lut[i] = [int(255 * (1 - s)), 255, int(255 * s)]
            elif t < 0.75:
                s = (t - 0.5) / 0.25
                lut[i] = [0, int(255 * (1 - s)), 255]
            else:
                s = (t - 0.75) / 0.25
                lut[i] = [0, 0, int(255 * (1 - 0.5 * s))]
        cls._LUT = lut
        return lut

    def __init__(self, max_range: float = 10.0):
        super().__init__()
        self._queue: asyncio.Queue[av.VideoFrame] = asyncio.Queue(maxsize=1)
        self._frame_count = 0
        self._max_range = max_range

    def push_depth_image(self, msg: Image):
        """Called from the ROS 2 callback thread with a 32FC1 depth image."""
        depth = np.frombuffer(bytes(msg.data), dtype=np.float32).reshape(
            (msg.height, msg.width)
        )

        # Clamp and normalize to 0-255
        clamped = np.clip(depth, 0.0, self._max_range)
        normalized = (clamped / self._max_range * 255).astype(np.uint8)

        # Apply colormap via LUT
        lut = self._build_lut()
        rgb = lut[normalized]

        # Mark invalid/inf pixels as black
        invalid = ~np.isfinite(depth) | (depth <= 0)
        rgb[invalid] = 0

        frame = av.VideoFrame.from_ndarray(rgb, format="rgb24")
        frame.pts = self._frame_count
        frame.time_base = Fraction(1, 30)
        self._frame_count += 1

        if self._queue.full():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            pass

    async def recv(self) -> av.VideoFrame:
        return await self._queue.get()


class RosVehicleNode(Node):
    """ROS 2 node that collects sensor data and publishes cmd_vel."""

    def __init__(self, video_track: RosVideoTrack, depth_track: DepthVideoTrack):
        super().__init__("occ_vehicle")
        self._video_track = video_track
        self._depth_track = depth_track

        # Latest sensor data
        self._latest_odom: Optional[Odometry] = None
        self._latest_fix: Optional[NavSatFix] = None
        self._latest_diag: Optional[DiagnosticArray] = None

        # Subscriptions
        self.create_subscription(Image, "/camera/image_raw", self._camera_cb, 1)
        self.create_subscription(Image, "/depth/image_raw", self._depth_cb, 1)
        self.create_subscription(Odometry, "/vehicle_pose", self._odom_cb, 10)
        self.create_subscription(NavSatFix, "/gps/fix", self._fix_cb, 10)
        self.create_subscription(
            DiagnosticArray, "/diagnostics", self._diag_cb, 10
        )

        # Publisher
        self._cmd_vel_pub = self.create_publisher(Twist, "/cmd_vel", 1)

        self.get_logger().info("OCC vehicle ROS 2 node started")

    def _camera_cb(self, msg: Image):
        self._video_track.push_ros_image(msg)

    def _depth_cb(self, msg: Image):
        self._depth_track.push_depth_image(msg)

    def _odom_cb(self, msg: Odometry):
        self._latest_odom = msg

    def _fix_cb(self, msg: NavSatFix):
        self._latest_fix = msg

    def _diag_cb(self, msg: DiagnosticArray):
        self._latest_diag = msg

    def publish_cmd_vel(self, linear_x: float, angular_z: float):
        msg = Twist()
        msg.linear.x = linear_x
        msg.angular.z = angular_z
        self._cmd_vel_pub.publish(msg)

    def get_position_json(self) -> Optional[dict]:
        """Build position payload for WebTransport datagram."""
        fix = self._latest_fix
        if fix is None:
            return None

        data = {
            "Type": "position",
            "Latitude": fix.latitude,
            "Longitude": fix.longitude,
            "Altitude": fix.altitude,
        }

        odom = self._latest_odom
        if odom is not None:
            q = odom.pose.pose.orientation
            yaw = 2.0 * math.atan2(q.z, q.w)
            data["X"] = odom.pose.pose.position.x
            data["Y"] = odom.pose.pose.position.y
            data["Yaw"] = yaw
            data["Vx"] = odom.twist.twist.linear.x
            data["Vy"] = odom.twist.twist.linear.y
            data["Vyaw"] = odom.twist.twist.angular.z

        return data

    def get_diagnostics_json(self) -> Optional[dict]:
        """Build diagnostics payload for WebTransport stream (reliable)."""
        diag = self._latest_diag
        if diag is None:
            return None

        statuses = []
        for s in diag.status:
            statuses.append(
                {
                    "name": s.name,
                    "level": s.level if isinstance(s.level, int) else s.level[0],
                    "message": s.message,
                    "values": {kv.key: kv.value for kv in s.values},
                }
            )
        return {"Type": "diagnostics", "Statuses": statuses}


class RosVehicle(Vehicle):
    """Vehicle implementation backed by ROS 2 subscriptions."""

    def __init__(self):
        self._video_track = RosVideoTrack()
        self._depth_track = DepthVideoTrack(max_range=10.0)

        rclpy.init()
        self._node = RosVehicleNode(self._video_track, self._depth_track)
        self._spin_thread = threading.Thread(
            target=rclpy.spin, args=(self._node,), daemon=True
        )
        self._spin_thread.start()

        # Set by OccClient after construction
        self._occ_client = None

    def set_occ_client(self, client):
        self._occ_client = client

    def create_streams(self) -> List[MediaStreamTrack]:
        return [self._video_track, self._depth_track]

    def ping(self, msg: str):
        # Handled in OccClient — pong sent back via DataChannel
        pass

    def handle_command(self, msg: str) -> Optional[str]:
        """Process a message from the WebRTC 'commands' DataChannel.

        Returns a response string to send back, or None.
        """
        # Latency ping → echo pong
        if msg.startswith("ping:"):
            return f"pong:{msg[5:]}"

        # Twist command
        try:
            data = json.loads(msg)
            if "linear_x" in data and "angular_z" in data:
                self._node.publish_cmd_vel(
                    float(data["linear_x"]), float(data["angular_z"])
                )
        except (json.JSONDecodeError, ValueError):
            logging.warning(f"Invalid command message: {msg}")

        return None

    # ------ async loops (started by OccClient) ------

    async def position_loop(self):
        """Send position via WebTransport datagram every 1 s (unreliable)."""
        while True:
            if self._occ_client is not None:
                data = self._node.get_position_json()
                if data is not None:
                    try:
                        payload = json.dumps(data).encode()
                        self._occ_client.send_datagram(payload)
                    except Exception as e:
                        logging.warning(f"Failed to send position: {e}")
            await asyncio.sleep(1.0)

    async def diagnostics_loop(self):
        """Send diagnostics via WebTransport stream every 5 s (reliable)."""
        while True:
            if self._occ_client is not None:
                data = self._node.get_diagnostics_json()
                if data is not None:
                    try:
                        self._occ_client.send_stream_message(data)
                    except Exception as e:
                        logging.warning(f"Failed to send diagnostics: {e}")
            await asyncio.sleep(5.0)

    def shutdown(self):
        self._node.destroy_node()
        rclpy.shutdown()
