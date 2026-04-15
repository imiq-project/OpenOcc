import os
import pathlib
import launch
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, ExecuteProcess
from launch.conditions import IfCondition
from launch.substitutions import LaunchConfiguration
from ament_index_python.packages import get_package_share_directory
from webots_ros2_driver.webots_launcher import WebotsLauncher
from webots_ros2_driver.webots_controller import WebotsController


def generate_launch_description():
    pkg_share = get_package_share_directory('imiq_launch')
    world_path = os.path.join(pkg_share, 'worlds', 'wissenschaftshafen.wbt')

    robot_description = pathlib.Path(
        os.path.join(pkg_share, 'resource', 'husky.urdf')).read_text()

    webots = WebotsLauncher(
        world=world_path,
        ros2_supervisor=True,
    )

    husky_controller = WebotsController(
        robot_name='husky',
        parameters=[{'robot_description': robot_description}],
        respawn=True,
    )

    # Vehicle OCC bridge — connects ROS 2 topics to Go server via WebTransport/WebRTC
    occ_bridge = ExecuteProcess(
        cmd=['ros2', 'run', 'imiq_vehicle', 'occ',
             '--host', 'imiq-occ.et.uni-magdeburg.de',
             '--port', '443',
             '--path', '/wt-vehicle?VehicleId=husky'],
        output='screen',
        condition=IfCondition(LaunchConfiguration('with_occ')),
    )

    return LaunchDescription([
        DeclareLaunchArgument(
            'with_occ',
            default_value='false',
            description='Also launch the vehicle OCC WebRTC bridge node',
        ),
        webots,
        webots._supervisor,
        husky_controller,
        occ_bridge,
        launch.actions.RegisterEventHandler(
            event_handler=launch.event_handlers.OnProcessExit(
                target_action=webots,
                on_exit=[launch.actions.EmitEvent(
                    event=launch.events.Shutdown())],
            )
        ),
    ])
