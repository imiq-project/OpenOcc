import {Vector3} from "three";

export enum Behavior {
    AdaptiveCruiseControl = 'adaptive-cruise-control',
    AdaptiveCruiseControlUnderscore = 'adaptive_cruise_control',
    ForwardCollisionAvoidance = 'forward-collision-avoidance',
    ForwardCollisionAvoidanceUnderscore = 'forward_collision_avoidance',
    DynamicStopRepositioning = 'dynamic-stop-repositioning',
}

export interface DrivenTrajectoryPose {
    timestamp: number;
    pose: Vector3;
}
