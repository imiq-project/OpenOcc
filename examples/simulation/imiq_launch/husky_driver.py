import math
import struct
import time

import numpy as np
import rclpy
from geometry_msgs.msg import Twist, Quaternion, TransformStamped
from nav_msgs.msg import Odometry
from sensor_msgs.msg import Image, NavSatFix, NavSatStatus
from diagnostic_msgs.msg import DiagnosticArray, DiagnosticStatus, KeyValue
from tf2_ros import TransformBroadcaster

# TODO: update for Husky dimensions
WHEEL_BASE = 0.494
TRACK_WIDTH = 0.56
WHEEL_RADIUS = 0.165
HALF_WHEELBASE = WHEEL_BASE / 2.0
HALF_TRACK = TRACK_WIDTH / 2.0

# Must match WorldInfo.gpsReference in the .wbt file
REF_LAT = 52.144
REF_LON = 11.654
M_PER_DEG_LAT = 111_320.0
M_PER_DEG_LON = 111_320.0 * math.cos(math.radians(REF_LAT))

BATTERY_START_PCT = 87.0
BATTERY_DRAIN_PER_MIN = 0.5
WATCHDOG_TIMEOUT_S = 0.150


def compute_double_ackermann(linear_vel: float, angular_vel: float):
    if abs(angular_vel) < 1e-6:
        return [0.0] * 4, [linear_vel] * 4

    turning_radius = linear_vel / angular_vel
    R = abs(turning_radius)

    if turning_radius > 0:
        fl = math.atan2(HALF_WHEELBASE, R - HALF_TRACK)
        fr = math.atan2(HALF_WHEELBASE, R + HALF_TRACK)
        rl = -math.atan2(HALF_WHEELBASE, R - HALF_TRACK)
        rr = -math.atan2(HALF_WHEELBASE, R + HALF_TRACK)
    else:
        fl = -math.atan2(HALF_WHEELBASE, R + HALF_TRACK)
        fr = -math.atan2(HALF_WHEELBASE, R - HALF_TRACK)
        rl = math.atan2(HALF_WHEELBASE, R + HALF_TRACK)
        rr = math.atan2(HALF_WHEELBASE, R - HALF_TRACK)

    aw = abs(angular_vel)
    if turning_radius > 0:
        fl_v = aw * math.hypot(HALF_WHEELBASE, R - HALF_TRACK)
        fr_v = aw * math.hypot(HALF_WHEELBASE, R + HALF_TRACK)
        rl_v = aw * math.hypot(HALF_WHEELBASE, R - HALF_TRACK)
        rr_v = aw * math.hypot(HALF_WHEELBASE, R + HALF_TRACK)
    else:
        fl_v = aw * math.hypot(HALF_WHEELBASE, R + HALF_TRACK)
        fr_v = aw * math.hypot(HALF_WHEELBASE, R - HALF_TRACK)
        rl_v = aw * math.hypot(HALF_WHEELBASE, R + HALF_TRACK)
        rr_v = aw * math.hypot(HALF_WHEELBASE, R - HALF_TRACK)

    sign = 1.0 if linear_vel >= 0 else -1.0
    return [fl, fr, rl, rr], [fl_v * sign, fr_v * sign, rl_v * sign, rr_v * sign]


def compute_parallel(linear_x: float, linear_y: float):
    angle = math.atan2(linear_y, linear_x)
    speed = math.hypot(linear_x, linear_y)
    return [angle] * 4, [speed] * 4


def yaw_to_quaternion(yaw: float) -> Quaternion:
    q = Quaternion()
    q.z = math.sin(yaw / 2.0)
    q.w = math.cos(yaw / 2.0)
    return q


class HuskyDriver:

    def init(self, webots_node, properties):
        self.__robot = webots_node.robot

        if not rclpy.ok():
            rclpy.init(args=None)
        self.__node = rclpy.create_node('husky_driver')

        self.__steer = [
            self.__robot.getDevice('fl_steering_motor'),
            self.__robot.getDevice('fr_steering_motor'),
            self.__robot.getDevice('rl_steering_motor'),
            self.__robot.getDevice('rr_steering_motor'),
        ]
        for m in self.__steer:
            m.setPosition(0.0)

        self.__drive = [
            self.__robot.getDevice('fl_wheel_motor'),
            self.__robot.getDevice('fr_wheel_motor'),
            self.__robot.getDevice('rl_wheel_motor'),
            self.__robot.getDevice('rr_wheel_motor'),
        ]
        for m in self.__drive:
            m.setPosition(float('inf'))
            m.setVelocity(0.0)

        timestep = int(self.__robot.getBasicTimeStep())
        self.__gps = self.__robot.getDevice('gps')
        self.__imu = self.__robot.getDevice('inertial unit')
        self.__gyro = self.__robot.getDevice('gyro')
        self.__camera = self.__robot.getDevice('camera')
        self.__depth = self.__robot.getDevice('depth')

        self.__gps.enable(timestep)
        self.__imu.enable(timestep)
        self.__gyro.enable(timestep)
        self.__camera.enable(timestep)
        self.__depth.enable(timestep)

        self.__cam_w = self.__camera.getWidth()
        self.__cam_h = self.__camera.getHeight()
        self.__depth_w = self.__depth.getWidth()
        self.__depth_h = self.__depth.getHeight()

        self.__odom_pub = self.__node.create_publisher(Odometry, '/vehicle_pose', 10)
        self.__fix_pub = self.__node.create_publisher(NavSatFix, '/gps/fix', 10)
        self.__cam_pub = self.__node.create_publisher(Image, '/camera/image_raw', 10)
        self.__depth_pub = self.__node.create_publisher(Image, '/depth/image_raw', 10)
        self.__diag_pub = self.__node.create_publisher(DiagnosticArray, '/diagnostics', 10)
        self.__tf_broadcaster = TransformBroadcaster(self.__node)

        self.__node.create_subscription(Twist, '/cmd_vel', self.__cmd_vel_cb, 1)

        self.__linear_x = 0.0
        self.__linear_y = 0.0
        self.__angular_z = 0.0
        self.__last_cmd_vel_time = 0.0

        self.__battery_pct = BATTERY_START_PCT
        self.__battery_start_time = time.monotonic()

        self.__node.get_logger().info('HuskyDriver initialized')

    def __cmd_vel_cb(self, msg: Twist):
        self.__linear_x = msg.linear.x
        self.__linear_y = msg.linear.y
        self.__angular_z = msg.angular.z
        self.__last_cmd_vel_time = time.monotonic()

    def __get_cmd_vel(self):
        elapsed = time.monotonic() - self.__last_cmd_vel_time
        if self.__last_cmd_vel_time == 0.0 or elapsed > WATCHDOG_TIMEOUT_S:
            return 0.0, 0.0, 0.0
        return self.__linear_x, self.__linear_y, self.__angular_z

    def step(self):
        lx, ly, az = self.__get_cmd_vel()

        if abs(ly) > 1e-6:
            angles, speeds = compute_parallel(lx, ly)
        else:
            angles, speeds = compute_double_ackermann(lx, -az)

        for i in range(4):
            self.__steer[i].setPosition(angles[i])
            self.__drive[i].setVelocity(speeds[i] / WHEEL_RADIUS)

        gps_vals = self.__gps.getValues()
        lat, lon, alt = gps_vals[0], gps_vals[1], gps_vals[2]
        roll, pitch, yaw = self.__imu.getRollPitchYaw()
        gyro_vals = self.__gyro.getValues()

        x = (lat - REF_LAT) * M_PER_DEG_LAT
        y = (lon - REF_LON) * M_PER_DEG_LON

        vel_vec = self.__gps.getSpeedVector()
        vx = vel_vec[0] if vel_vec else 0.0
        vy = vel_vec[1] if vel_vec else 0.0
        vyaw = gyro_vals[2] if gyro_vals else 0.0

        stamp = self.__node.get_clock().now().to_msg()

        odom = Odometry()
        odom.header.stamp = stamp
        odom.header.frame_id = 'odom'
        odom.child_frame_id = 'base_link'
        odom.pose.pose.position.x = x
        odom.pose.pose.position.y = y
        odom.pose.pose.orientation = yaw_to_quaternion(yaw)
        odom.twist.twist.linear.x = vx
        odom.twist.twist.linear.y = vy
        odom.twist.twist.angular.z = vyaw
        self.__odom_pub.publish(odom)

        t = TransformStamped()
        t.header.stamp = stamp
        t.header.frame_id = 'odom'
        t.child_frame_id = 'base_link'
        t.transform.translation.x = x
        t.transform.translation.y = y
        t.transform.rotation = yaw_to_quaternion(yaw)
        self.__tf_broadcaster.sendTransform(t)

        fix = NavSatFix()
        fix.header.stamp = stamp
        fix.header.frame_id = 'gps_link'
        fix.status.status = NavSatStatus.STATUS_FIX
        fix.status.service = NavSatStatus.SERVICE_GPS
        fix.latitude = lat
        fix.longitude = lon
        fix.altitude = alt
        self.__fix_pub.publish(fix)

        cam_data = self.__camera.getImage()
        if cam_data:
            img = Image()
            img.header.stamp = stamp
            img.header.frame_id = 'camera_link'
            img.width = self.__cam_w
            img.height = self.__cam_h
            img.encoding = 'rgb8'
            img.step = self.__cam_w * 3
            img.is_bigendian = False
            bgra = np.frombuffer(cam_data, dtype=np.uint8).reshape(
                (self.__cam_h, self.__cam_w, 4))
            img.data = bgra[:, :, [2, 1, 0]].tobytes()
            self.__cam_pub.publish(img)

        depth_data = self.__depth.getRangeImage()
        if depth_data:
            dim = Image()
            dim.header.stamp = stamp
            dim.header.frame_id = 'depth_link'
            dim.width = self.__depth_w
            dim.height = self.__depth_h
            dim.encoding = '32FC1'
            dim.step = self.__depth_w * 4
            dim.is_bigendian = False
            dim.data = struct.pack(
                f'{self.__depth_w * self.__depth_h}f', *depth_data)
            self.__depth_pub.publish(dim)

        elapsed_min = (time.monotonic() - self.__battery_start_time) / 60.0
        self.__battery_pct = max(
            0.0, BATTERY_START_PCT - BATTERY_DRAIN_PER_MIN * elapsed_min)

        battery = DiagnosticStatus()
        battery.name = 'Battery'
        battery.hardware_id = 'husky_battery'
        if self.__battery_pct < 20.0:
            battery.level = DiagnosticStatus.ERROR
            battery.message = 'Critical'
        elif self.__battery_pct < 40.0:
            battery.level = DiagnosticStatus.WARN
            battery.message = 'Low'
        else:
            battery.level = DiagnosticStatus.OK
            battery.message = 'Normal'
        battery.values = [
            KeyValue(key='percentage', value=f'{self.__battery_pct:.1f}'),
            KeyValue(key='voltage',
                     value=f'{self.__battery_pct / 100.0 * 25.2:.1f}'),
        ]

        diag = DiagnosticArray()
        diag.header.stamp = stamp
        diag.status = [battery]
        self.__diag_pub.publish(diag)

        rclpy.spin_once(self.__node, timeout_sec=0)
