export interface Vector2 {
    x: number;
    y: number;
}

export interface Vector3 {
    x: number;
    y: number;
    z: number;
}

export interface String {
    data: string;
}

export interface VehiclePose {
    timestamp: number;
    longitude: number;
    latitude: number;
    utm_position: Vector2;
    elevation: number;
    yaw: number;
    roll: number;
    pitch: number;
    velocity: Vector2;
    accelaration: Vector2;
}

export interface TrajectoryPose {
    utm_position: Vector2;
    yaw: number;
    safe_left: number;
    safe_right: number;
    max_velocity: number;
    motion_type: number;
}

export interface Trajectory {
    timestamp: number;
    poses: TrajectoryPose[];
}

export interface BehaviorDefinition {
    id: string;
    name: string;
    recordable: boolean,
    descendants: BehaviorDefinition[];
}

export interface EvaluationResult {
    behavior_id: String;
    timestamp: number;
    sequence_number: number;
    applicability: number;
    risk: number;
    comfort: number;
    desire: number;
}

export interface ObjectList3DInfo {
    objects: Object3DInfo[];
    timestamp: number;
}

export interface Object3DInfo {
    x: number;
    y: number;
    z: number;
    width: number;
    height: number;
    length: number;
    yaw: number;
    pitch: number;
    roll: number;
    class_id: number;
    confidence: number;
}

export interface ObjectList3D {
    objects: Object3D[];
    timestamp: number;
}

export interface Object3D {
    timestamp: number;
    id: number;
    utm_position: {
        x: number;
        y: number;
        z: number;
    };
    reference_point: number;
    yaw: number;
    width: number;
    height: number;
    length: number;
    velocity: {
        x: number;
        y: number;
    };
    class_id: number;
    variances: {
        utm_position: {
            x: number;
            y: number;
            z: number;
        };
        yaw: number;
        width: number;
        height: number;
        length: number;
        velocity: {
            x: number;
            y: number;
        };
    };
}

export interface GatewayStatus {
    status: number;
    reason: number;
}

export interface CostMap {
    id: String;
    utm_position: Vector2;
    diameter: number;
    depth: number;
    resolution: number;
    layers: CostMapLayer[];
}

export interface CostMapLayer {
    data: number[];
    maximum_value: number;
    minimum_value: number;
    default_value: number;
    allow_interpolation: boolean;
}

export interface ActiveTarget {
    behavior_id: string;
    distance: number;
    target: Object3D;
}

export interface Time {
    sec: number;
    nanosec: number;
}

export interface Pose {
    position: {
        x: number;
        y: number;
        z: number;
    };
    orientation: {
        x: number;
        y: number;
        z: number;
        w: number;
    };
}

export interface Header {
    seq: number;
    stamp: Time;
    frame_id: string;
}

export interface OccupancyGrid {
    header: Header;
    info: {
        map_load_time: Time;
        resolution: number;
        width: number;
        height: number;
        origin: Pose;
    };
    data: number[];
}

export interface PointCloud {
    id: string;
    points: number[];
}

export interface Twist {
    linear: Vector3;
    angular: Vector3;
}
