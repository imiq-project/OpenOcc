'use client';

import { useEffect, useRef } from "react";
import { useOCCBridge } from "@/context/OCCBridgeContext";
import { useAlertContext } from "@/context/AlertContext";
import {
    Alert,
    AlertSeverity,
    AlertType,
    RobotState,
} from "@/model/OCCMessages";

function generateId(): string {
    return `alert-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

function createAlert(
    type: AlertType,
    severity: AlertSeverity,
    title: string,
    description: string,
    actionRequired: string,
    robotId: string,
): Alert {
    return {
        id: generateId(),
        type,
        severity,
        title,
        description,
        timestamp: Date.now(),
        robotId,
        dismissed: false,
        acknowledged: false,
        actionRequired,
    };
}

export function useAlerts() {
    const bridge = useOCCBridge();
    const { thresholds, pushAlert, dismissAlert, activeAlerts } = useAlertContext();
    const robotName = bridge.selectedVehicleId ?? process.env.NEXT_PUBLIC_ROBOT_NAME ?? "unknown";

    const stallStartRef = useRef<number | null>(null);
    const replanCountRef = useRef<{ count: number; windowStart: number }>({
        count: 0,
        windowStart: Date.now(),
    });
    const prevEventLogLenRef = useRef(0);

    const pushAlertRef = useRef(pushAlert);
    pushAlertRef.current = pushAlert;
    const dismissAlertRef = useRef(dismissAlert);
    dismissAlertRef.current = dismissAlert;
    const activeAlertsRef = useRef(activeAlerts);
    activeAlertsRef.current = activeAlerts;
    const thresholdsRef = useRef(thresholds);
    thresholdsRef.current = thresholds;

    const isActive = (type: AlertType) =>
        activeAlertsRef.current.some(a => a.type === type);
    const findActiveByType = (type: AlertType) =>
        activeAlertsRef.current.find(a => a.type === type);

    useEffect(() => {
        if (!bridge.connected && !isActive("CONNECTION_LOST")) {
            pushAlertRef.current(createAlert(
                "CONNECTION_LOST",
                AlertSeverity.CRITICAL,
                "CONNECTION LOST",
                `No heartbeat from ${robotName} for more than 5 seconds.`,
                "Check network connection or trigger E-STOP.",
                robotName,
            ));
        }
        if (bridge.connected) {
            const existing = findActiveByType("CONNECTION_LOST");
            if (existing) dismissAlertRef.current(existing.id);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.connected]);

    useEffect(() => {
        const pct = bridge.battery.percentage;
        const t = thresholdsRef.current;

        if (pct <= t.batteryCritical && !isActive("CRITICAL_BATTERY")) {
            pushAlertRef.current(createAlert(
                "CRITICAL_BATTERY",
                AlertSeverity.CRITICAL,
                "CRITICAL BATTERY",
                `Battery at ${pct.toFixed(0)}% — below critical threshold (${t.batteryCritical}%).`,
                "Abort mission and return to depot.",
                robotName,
            ));
        } else if (
            pct <= t.batteryWarning &&
            pct > t.batteryCritical &&
            !isActive("LOW_BATTERY")
        ) {
            pushAlertRef.current(createAlert(
                "LOW_BATTERY",
                AlertSeverity.WARNING,
                "LOW BATTERY",
                `Battery at ${pct.toFixed(0)}% — below warning threshold (${t.batteryWarning}%).`,
                "Consider aborting mission or returning to depot.",
                robotName,
            ));
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [Math.floor(bridge.battery.percentage)]);

    useEffect(() => {
        if (bridge.robotState === RobotState.EMERGENCY_STOP && !isActive("E_STOP_ACTIVE")) {
            pushAlertRef.current(createAlert(
                "E_STOP_ACTIVE",
                AlertSeverity.CRITICAL,
                "E-STOP ACTIVE",
                `Emergency stop has been triggered on ${robotName}.`,
                "Clear E-Stop when safe to resume.",
                robotName,
            ));
        }
        if (bridge.robotState !== RobotState.EMERGENCY_STOP) {
            const existing = findActiveByType("E_STOP_ACTIVE");
            if (existing) dismissAlertRef.current(existing.id);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.robotState]);

    useEffect(() => {
        const isRunning = bridge.activeMission &&
            (bridge.activeMission.status === "EN_ROUTE" || bridge.activeMission.status === "DISPATCHED");
        const isStopped = bridge.speed < 0.05;
        const isAutonomous = bridge.robotState === RobotState.AUTONOMOUS;

        if (isRunning && isStopped && isAutonomous) {
            if (stallStartRef.current === null) {
                stallStartRef.current = Date.now();
            } else {
                const elapsed = (Date.now() - stallStartRef.current) / 1000;
                if (elapsed >= thresholdsRef.current.stallTimeout && !isActive("ROBOT_STALLED")) {
                    pushAlertRef.current(createAlert(
                        "ROBOT_STALLED",
                        AlertSeverity.WARNING,
                        "ROBOT STALLED",
                        `No movement detected for ${thresholdsRef.current.stallTimeout} seconds while mission is active.`,
                        "Inspect camera feed or resume robot.",
                        robotName,
                    ));
                    stallStartRef.current = null;
                }
            }
        } else {
            stallStartRef.current = null;
            if (!isStopped) {
                const existing = findActiveByType("ROBOT_STALLED");
                if (existing) dismissAlertRef.current(existing.id);
            }
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.speed, bridge.activeMission?.status, bridge.robotState]);

    useEffect(() => {
        if (bridge.activeBehavior === "collision_avoidance" && !isActive("COLLISION_AVOIDANCE")) {
            pushAlertRef.current(createAlert(
                "COLLISION_AVOIDANCE",
                AlertSeverity.CRITICAL,
                "COLLISION AVOIDANCE",
                "Robot has entered collision avoidance mode — immediate obstacle detected.",
                "Open camera feed, resume when safe, or trigger E-STOP.",
                robotName,
            ));
        }
        if (bridge.activeBehavior !== "collision_avoidance") {
            const existing = findActiveByType("COLLISION_AVOIDANCE");
            if (existing) dismissAlertRef.current(existing.id);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.activeBehavior]);

    useEffect(() => {
        if (bridge.rttExceeded && !isActive("RTT_EXCEEDED")) {
            pushAlertRef.current(createAlert(
                "RTT_EXCEEDED",
                AlertSeverity.WARNING,
                "RTT EXCEEDED",
                `Round-trip time exceeded 150 ms (${bridge.rtt.toFixed(0)} ms) — teleoperation paused.`,
                "Wait for latency to improve or switch to trajectory mode.",
                robotName,
            ));
        }
        if (!bridge.rttExceeded) {
            const existing = findActiveByType("RTT_EXCEEDED");
            if (existing) dismissAlertRef.current(existing.id);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.rttExceeded, bridge.rtt]);

    // --- WebRTC disconnect while in DIRECT mode ---
    const prevWebrtcRef = useRef(bridge.webrtcConnected);
    useEffect(() => {
        const wasConnected = prevWebrtcRef.current;
        prevWebrtcRef.current = bridge.webrtcConnected;

        if (wasConnected && !bridge.webrtcConnected && bridge.mode === "DIRECT") {
            // Force STANDBY — cannot teleoperate without WebRTC
            bridge.requestMode("STANDBY");

            if (!isActive("CONNECTION_LOST")) {
                pushAlertRef.current(createAlert(
                    "CONNECTION_LOST",
                    AlertSeverity.CRITICAL,
                    "WEBRTC DISCONNECTED",
                    "WebRTC connection lost during DIRECT control — forced transition to STANDBY.",
                    "Reconnect or switch to trajectory guidance.",
                    bridge.selectedVehicleId ?? "unknown",
                ));
            }
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.webrtcConnected, bridge.mode]);

    // --- Process eventLog for WebTransport alerts, replanning, sensor degradation ---
    useEffect(() => {
        const events = bridge.eventLog;
        if (events.length <= prevEventLogLenRef.current) return;

        const newEvents = events.slice(prevEventLogLenRef.current);
        prevEventLogLenRef.current = events.length;

        for (const evt of newEvents) {
            // --- WebTransport alert events (category "robot", formatted as "[CODE] Message") ---
            if (evt.category === "robot" && evt.message.startsWith("[")) {
                const codeMatch = evt.message.match(/^\[([^\]]+)\]\s*(.*)/);
                if (codeMatch) {
                    const code = codeMatch[1];
                    const msg = codeMatch[2];
                    const severity = evt.severity;

                    // Map known codes to AlertType; unknown codes get a generic alert
                    const codeToType: Record<string, AlertType> = {
                        "COLLISION_AVOIDANCE": "COLLISION_AVOIDANCE",
                        "GEOFENCE_VIOLATION": "GEOFENCE_VIOLATION",
                        "SENSOR_DEGRADED": "SENSOR_DEGRADED",
                        "CRITICAL_BATTERY": "CRITICAL_BATTERY",
                        "LOW_BATTERY": "LOW_BATTERY",
                        "E_STOP_ACTIVE": "E_STOP_ACTIVE",
                        "NAVIGATION_LOOP": "NAVIGATION_LOOP",
                        "CONNECTION_LOST": "CONNECTION_LOST",
                        "ROBOT_STALLED": "ROBOT_STALLED",
                        "RTT_EXCEEDED": "RTT_EXCEEDED",
                    };

                    const alertType = codeToType[code];
                    if (alertType && !isActive(alertType)) {
                        pushAlertRef.current(createAlert(
                            alertType,
                            severity === AlertSeverity.CRITICAL
                                ? AlertSeverity.CRITICAL
                                : severity === AlertSeverity.WARNING
                                    ? AlertSeverity.WARNING
                                    : AlertSeverity.INFO as AlertSeverity,
                            code.replace(/_/g, " "),
                            msg,
                            `Respond to ${code.replace(/_/g, " ").toLowerCase()} alert.`,
                            evt.robotId,
                        ));
                    }
                }
            }

            if (evt.message.toLowerCase().includes("replanning")) {
                const now = Date.now();
                const ref = replanCountRef.current;

                if (now - ref.windowStart > 60_000) {
                    ref.count = 0;
                    ref.windowStart = now;
                }

                ref.count++;

                if (ref.count >= 3 && !isActive("NAVIGATION_LOOP")) {
                    pushAlertRef.current(createAlert(
                        "NAVIGATION_LOOP",
                        AlertSeverity.WARNING,
                        "NAVIGATION LOOP",
                        "Robot has replanned 3+ times in 60 seconds — possible navigation loop.",
                        "Open teleoperation to guide the robot.",
                        robotName,
                    ));
                    ref.count = 0;
                }
            }

            if (
                evt.message.toLowerCase().includes("sensor degradation") &&
                !isActive("SENSOR_DEGRADED")
            ) {
                pushAlertRef.current(createAlert(
                    "SENSOR_DEGRADED",
                    AlertSeverity.WARNING,
                    "SENSOR DEGRADED",
                    evt.message,
                    "Consider pausing mission until sensor is restored.",
                    robotName,
                ));
            }
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [bridge.eventLog.length]);
}
