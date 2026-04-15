export enum RobotState {
    AUTONOMOUS = "AUTONOMOUS",
    READY = "READY",
    PAUSED = "PAUSED",
    REMOTE_ASSIST = "REMOTE_ASSIST",
    EMERGENCY_STOP = "EMERGENCY_STOP",
    CHARGING = "CHARGING",
    OFFLINE = "OFFLINE",
}

export enum AlertSeverity {
    CRITICAL = "CRITICAL",
    WARNING = "WARNING",
    INFO = "INFO",
}

export type AlertType =
    | "CONNECTION_LOST"
    | "CRITICAL_BATTERY"
    | "LOW_BATTERY"
    | "ROBOT_STALLED"
    | "COLLISION_AVOIDANCE"
    | "GEOFENCE_VIOLATION"
    | "NAVIGATION_LOOP"
    | "SENSOR_DEGRADED"
    | "E_STOP_ACTIVE"
    | "RTT_EXCEEDED";

export interface Alert {
    id: string;
    type: AlertType;
    severity: AlertSeverity;
    title: string;
    description: string;
    timestamp: number;
    robotId: string;
    dismissed: boolean;
    acknowledged: boolean;
    actionRequired: string;
}

export interface AlertThresholds {
    batteryWarning: number;
    batteryCritical: number;
    latencyWarning: number;
    connectionTimeout: number;
    stallTimeout: number;
}

export interface OCCMission {
    id: string;
    description: string;
    priority: "LOW" | "NORMAL" | "HIGH";
    pickup: { latitude: number; longitude: number; name: string };
    delivery: { latitude: number; longitude: number; name: string };
    cargoNotes: string;
    assignedRobot: string;
    status: "PENDING" | "DISPATCHED" | "EN_ROUTE" | "DELIVERED" | "FAILED" | "CANCELLED";
    createdAt: number;
    dispatchedAt?: number;
    completedAt?: number;
    progress: number;
    eta?: number;
}

export enum TeleoperationMode {
    TRAJECTORY_GUIDANCE = "TRAJECTORY_GUIDANCE",
    DIRECT_CONTROL = "DIRECT_CONTROL",
}

export interface EventLogEntry {
    id: string;
    timestamp: number;
    severity: AlertSeverity;
    category: string;
    robotId: string;
    message: string;
    payload?: any;
}

export interface BatteryState {
    percentage: number;
    voltage: number;
    estimatedMinutes: number;
}

export interface RobotSummary {
    id: string;
    name: string;
    state: RobotState;
    battery: BatteryState;
    speed: number;
    heading: number;
    position: { latitude: number; longitude: number };
    activeMission?: string;
    missionProgress?: number;
    lastHeartbeat: number;
    connected: boolean;
}

export interface Geofence {
    name: string;
    polygon: Array<{ latitude: number; longitude: number }>;
}

export interface OCCUser {
    username: string;
    role: "admin" | "operator";
    displayName: string;
}

/* ── Shared UI color maps ────────────────────────────────────────── */

export type HeroColor = "success" | "warning" | "primary" | "danger" | "secondary" | "default";

export const STATE_COLORS: Record<RobotState, HeroColor> = {
    [RobotState.AUTONOMOUS]: "success",
    [RobotState.READY]: "success",
    [RobotState.PAUSED]: "warning",
    [RobotState.REMOTE_ASSIST]: "primary",
    [RobotState.EMERGENCY_STOP]: "danger",
    [RobotState.CHARGING]: "secondary",
    [RobotState.OFFLINE]: "default",
};

export function batteryColor(percentage: number): "success" | "warning" | "danger" {
    if (percentage > 25) return "success";
    if (percentage > 10) return "warning";
    return "danger";
}

export const BATTERY_TEXT_CLASS: Record<"success" | "warning" | "danger", string> = {
    success: "text-success",
    warning: "text-warning",
    danger: "text-danger",
};
