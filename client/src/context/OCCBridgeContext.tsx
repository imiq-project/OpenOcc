'use client';

import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import { VehiclePose, Trajectory, Object3D } from "@/model/ROSMessages";
import {
    RobotState,
    BatteryState,
    OCCMission,
    EventLogEntry,
    AlertSeverity,
} from "@/model/OCCMessages";
import { WebTransportClient, type Vehicle } from "@/bridge/WebTransportClient";
import { WebRTCClient, type ConnectionState } from "@/bridge/WebRTCClient";
import { StateMachine, type Mode } from "@/bridge/StateMachine";
import { LatencyMonitor } from "@/bridge/LatencyMonitor";
import { TwistSender } from "@/bridge/TwistSender";
import { getActiveMission } from "@/helper/missions";

export type { Vehicle } from "@/bridge/WebTransportClient";


export interface OCCBridgeContextData {
    connected: boolean;
    lastHeartbeat: number;

    vehicles: Vehicle[];
    selectedVehicleId: string | null;
    selectVehicle: (vehicleId: string | null) => void;

    vehiclePose: VehiclePose | null;
    trajectory: Trajectory | null;
    objects: Object3D[];
    robotState: RobotState;
    activeBehavior: string;
    battery: BatteryState;
    speed: number;

    mode: Mode;
    rtt: number;
    rttExceeded: boolean;
    videoStreams: MediaStream[];
    webrtcConnected: boolean;
    webrtcState: ConnectionState;
    selectedVehicleName: string;

    missions: OCCMission[];
    activeMission: OCCMission | null;

    eventLog: EventLogEntry[];

    triggerEStop: () => void;
    clearEStop: () => void;
    resumeAutonomous: () => void;
    pauseRobot: () => void;
    enterRemoteAssist: () => void;
    sendCmdVel: (linear: number, angular: number) => void;
    requestMode: (target: Mode) => void;
    addMission: (mission: OCCMission) => void;
    cancelMission: (missionId: string) => void;
}

const defaultContext: OCCBridgeContextData = {
    connected: false,
    lastHeartbeat: 0,
    vehicles: [],
    selectedVehicleId: null,
    selectVehicle: () => {},
    vehiclePose: null,
    trajectory: null,
    objects: [],
    robotState: RobotState.OFFLINE,
    activeBehavior: "idle",
    battery: { percentage: 0, voltage: 0, estimatedMinutes: 0 },
    speed: 0,
    mode: "STANDBY",
    rtt: 0,
    rttExceeded: false,
    videoStreams: [],
    webrtcConnected: false,
    webrtcState: "closed",
    selectedVehicleName: "No Vehicle",
    missions: [],
    activeMission: null,
    eventLog: [],
    triggerEStop: () => {},
    clearEStop: () => {},
    resumeAutonomous: () => {},
    pauseRobot: () => {},
    enterRemoteAssist: () => {},
    sendCmdVel: () => {},
    requestMode: () => {},
    addMission: () => {},
    cancelMission: () => {},
};

const OCCBridgeContext = createContext<OCCBridgeContextData>(defaultContext);

export const useOCCBridge = () => useContext(OCCBridgeContext);


export const OCCBridgeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [vehicles, setVehicles] = useState<Vehicle[]>([]);
    const [selectedVehicleId, setSelectedVehicleId] = useState<string | null>(null);
    const [vehiclePose, setVehiclePose] = useState<VehiclePose | null>(null);
    const [trajectory, setTrajectory] = useState<Trajectory | null>(null);
    const [objects, setObjects] = useState<Object3D[]>([]);
    const [robotState, setRobotState] = useState<RobotState>(RobotState.OFFLINE);
    const [activeBehavior, setActiveBehavior] = useState("idle");
    const [battery, setBattery] = useState<BatteryState>({ percentage: 0, voltage: 0, estimatedMinutes: 0 });
    const [speed, setSpeed] = useState(0);
    const [connected, setConnected] = useState(false);
    const [lastHeartbeat, setLastHeartbeat] = useState(0);
    const [mode, setMode] = useState<Mode>("STANDBY");
    const [rtt, setRtt] = useState(0);
    const [rttExceeded, setRttExceeded] = useState(false);
    const [videoStreams, setVideoStreams] = useState<MediaStream[]>([]);
    const [webrtcConnected, setWebrtcConnected] = useState(false);
    const [webrtcState, setWebrtcState] = useState<ConnectionState>("closed");
    const [missions, setMissions] = useState<OCCMission[]>([]);
    const [eventLog, setEventLog] = useState<EventLogEntry[]>([]);

    const wtRef = useRef<WebTransportClient | null>(null);
    const rtcRef = useRef<WebRTCClient | null>(null);
    const smRef = useRef<StateMachine | null>(null);
    const latencyRef = useRef<LatencyMonitor | null>(null);
    const twistRef = useRef<TwistSender | null>(null);
    const rtcCleanupsRef = useRef<(() => void)[]>([]);


    const logEvent = useCallback((severity: AlertSeverity | string, category: string, message: string) => {
        setEventLog(prev => [...prev, {
            id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            timestamp: Date.now(),
            severity: severity as AlertSeverity,
            category,
            robotId: selectedVehicleId ?? "unknown",
            message,
        }]);
    }, [selectedVehicleId]);


    // --- WebTransport (always-on to Go server) ---
    useEffect(() => {
        const host = window.location.hostname;
        const wt = new WebTransportClient(host);
        wtRef.current = wt;

        const unsubVehicles = wt.on("vehicleList", (list) => {
            setVehicles(list);
            setLastHeartbeat(Date.now());
        });
        const unsubConnected = wt.on("connected", () => {
            setConnected(true);
            logEvent("INFO", "system", "WebTransport connected to OCC server");
        });
        const unsubDisconnected = wt.on("disconnected", () => {
            setConnected(false);
            logEvent("WARNING", "system", "WebTransport disconnected from OCC server");
        });
        const unsubAlert = wt.on("alert", (alert) => {
            logEvent(
                alert.Severity.toUpperCase(),
                "robot",
                `[${alert.Code}] ${alert.Message}`,
            );
        });

        wt.connect();

        return () => {
            unsubVehicles();
            unsubConnected();
            unsubDisconnected();
            unsubAlert();
            wt.disconnect();
            wtRef.current = null;
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);


    // --- StateMachine ---
    useEffect(() => {
        const sm = new StateMachine();
        smRef.current = sm;

        const unsubMode = sm.on((newMode) => {
            setMode(newMode);
        });

        return () => {
            unsubMode();
            smRef.current = null;
        };
    }, []);


    // --- WebRTC teardown ---
    const teardownRtc = useCallback(() => {
        latencyRef.current?.stop();
        latencyRef.current = null;
        twistRef.current = null;
        rtcRef.current?.disconnect();
        rtcRef.current = null;
        for (const unsub of rtcCleanupsRef.current) unsub();
        rtcCleanupsRef.current = [];
        setVideoStreams([]);
        setWebrtcConnected(false);
        setWebrtcState("closed");
        setRtt(0);
        setRttExceeded(false);
    }, []);


    // --- Map WebRTC telemetry to React state ---
    const mapTelemetryToState = useCallback((data: Record<string, unknown>) => {
        if (data.type === "pong") return;

        if (data.latitude !== undefined && data.longitude !== undefined) {
            setVehiclePose({
                timestamp: (data.timestamp as number) ?? Date.now(),
                longitude: data.longitude as number,
                latitude: data.latitude as number,
                utm_position: {
                    x: (data.utm_x as number) ?? 0,
                    y: (data.utm_y as number) ?? 0,
                },
                elevation: (data.elevation as number) ?? 0,
                yaw: (data.yaw as number) ?? 0,
                roll: (data.roll as number) ?? 0,
                pitch: (data.pitch as number) ?? 0,
                velocity: {
                    x: (data.vx as number) ?? 0,
                    y: (data.vy as number) ?? 0,
                },
                accelaration: { x: 0, y: 0 },
            });

            const vx = (data.vx as number) ?? 0;
            const vy = (data.vy as number) ?? 0;
            setSpeed(Math.sqrt(vx * vx + vy * vy));
            setLastHeartbeat(Date.now());
        }
    }, []);

    const mapStatusToState = useCallback((data: Record<string, unknown>) => {
        if (data.battery_pct !== undefined) {
            setBattery({
                percentage: data.battery_pct as number,
                voltage: (data.battery_voltage as number) ?? 0,
                estimatedMinutes: (data.estimated_minutes as number) ?? 0,
            });
        }

        if (data.robot_state !== undefined) {
            const stateStr = data.robot_state as string;
            if (stateStr in RobotState) {
                setRobotState(stateStr as RobotState);
            }
        }

        if (data.active_behavior !== undefined) {
            setActiveBehavior(data.active_behavior as string);
        }

        if (data.alert_type !== undefined) {
            logEvent(
                (data.severity as string) ?? AlertSeverity.INFO,
                "robot",
                (data.message as string) ?? `Alert: ${data.alert_type}`,
            );
        }
    }, [logEvent]);


    // --- Vehicle selection: setup/teardown WebRTC ---
    const selectVehicle = useCallback((vehicleId: string | null) => {
        setSelectedVehicleId(vehicleId);
        teardownRtc();

        if (!vehicleId) return;

        const wt = wtRef.current;
        const sm = smRef.current;
        if (!wt || !sm) {
            console.warn("[OCCBridge] Cannot connect — WebTransport or StateMachine not ready");
            return;
        }

        const rtc = new WebRTCClient(vehicleId, wt);
        rtcRef.current = rtc;

        const latency = new LatencyMonitor(rtc, sm);
        latencyRef.current = latency;
        twistRef.current = new TwistSender(rtc, sm);

        const unsubs: (() => void)[] = [];

        unsubs.push(rtc.on("connectionState", (state) => {
            const isConnected = state === "connected";
            setWebrtcConnected(isConnected);
            setWebrtcState(state);
            if (isConnected) {
                logEvent("INFO", "system", `WebRTC connected to vehicle ${vehicleId}`);
                latency.start();
            } else if (state === "failed" || state === "closed") {
                logEvent("WARNING", "system", `WebRTC ${state} for vehicle ${vehicleId}`);
                latency.stop();
            }
        }));

        unsubs.push(rtc.on("track", (stream) => {
            setVideoStreams(prev => [...prev, stream]);
        }));

        unsubs.push(rtc.on("telemetry", (data) => {
            mapTelemetryToState(data);
        }));

        unsubs.push(rtc.on("status", (data) => {
            mapStatusToState(data);
        }));

        unsubs.push(latency.onRtt((rttMs) => {
            setRtt(rttMs);
            setRttExceeded(rttMs > 150);
        }));

        unsubs.push(latency.onRttExceeded((rttMs) => {
            logEvent("WARNING", "system", `RTT exceeded threshold: ${rttMs.toFixed(0)}ms — forced Standby`);
        }));

        rtcCleanupsRef.current = unsubs;
        rtc.connect();
    }, [teardownRtc, mapTelemetryToState, mapStatusToState, logEvent]);


    // --- Actions ---
    const handleTriggerEStop = useCallback(() => {
        smRef.current?.triggerEStop();
    }, []);

    const handleClearEStop = useCallback(() => {
        try { smRef.current?.clearEStop(); } catch { /* not in ESTOP */ }
    }, []);

    const handleResumeAutonomous = useCallback(() => {
        try { smRef.current?.requestMode("TRAJECTORY"); } catch { /* invalid transition */ }
    }, []);

    const handlePauseRobot = useCallback(() => {
        try { smRef.current?.requestMode("STANDBY"); } catch { /* invalid transition */ }
    }, []);

    const handleEnterRemoteAssist = useCallback(() => {
        try { smRef.current?.requestMode("DIRECT"); } catch { /* invalid transition */ }
    }, []);

    const handleSendCmdVel = useCallback((linear: number, angular: number) => {
        twistRef.current?.send(linear, angular);
    }, []);

    const requestMode = useCallback((target: Mode) => {
        try {
            smRef.current?.requestMode(target);
        } catch (e) {
            console.warn("[OCCBridge] Mode transition rejected:", e);
        }
    }, []);


    // --- Missions ---
    const addMission = useCallback((mission: OCCMission) => {
        setMissions(prev => [...prev, mission]);
        logEvent("INFO", "mission", `Mission ${mission.id} created — ${mission.description}`);
    }, [logEvent]);

    const cancelMission = useCallback((missionId: string) => {
        setMissions(prev =>
            prev.map(m =>
                m.id === missionId ? { ...m, status: "CANCELLED" as const, completedAt: Date.now() } : m
            )
        );
        logEvent("WARNING", "operator", `Mission ${missionId} cancelled by operator`);
    }, [logEvent]);

    const activeMission = getActiveMission(missions) ?? null;

    const selectedVehicleName = vehicles.find(v => v.Id === selectedVehicleId)?.Name ?? "No Vehicle";

    const value: OCCBridgeContextData = {
        connected,
        lastHeartbeat,
        vehicles,
        selectedVehicleId,
        selectVehicle,
        vehiclePose,
        trajectory,
        objects,
        robotState,
        activeBehavior,
        battery,
        speed,
        mode,
        rtt,
        rttExceeded,
        videoStreams,
        webrtcConnected,
        webrtcState,
        selectedVehicleName,
        missions,
        activeMission,
        eventLog,
        triggerEStop: handleTriggerEStop,
        clearEStop: handleClearEStop,
        resumeAutonomous: handleResumeAutonomous,
        pauseRobot: handlePauseRobot,
        enterRemoteAssist: handleEnterRemoteAssist,
        sendCmdVel: handleSendCmdVel,
        requestMode,
        addMission,
        cancelMission,
    };

    return (
        <OCCBridgeContext.Provider value={value}>
            {children}
        </OCCBridgeContext.Provider>
    );
};

export default OCCBridgeContext;
