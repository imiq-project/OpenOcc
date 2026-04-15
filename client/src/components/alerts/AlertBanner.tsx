'use client';

import React, { useEffect, useRef, useState } from "react";
import { Button, Chip } from "@heroui/react";
import {
    IconAlertTriangle,
    IconAlertCircle,
    IconHandStop,
    IconCamera,
    IconPlayerPlay,
    IconPlugConnected,
    IconRoute,
    IconSteeringWheel,
    IconBatteryOff,
    IconX,
} from "@tabler/icons-react";
import { useAlertContext } from "@/context/AlertContext";
import { useOCCBridge } from "@/context/OCCBridgeContext";
import { AlertSeverity, AlertType } from "@/model/OCCMessages";
import { useRouter } from "next/navigation";

function getQuickActions(
    alertType: AlertType,
    handlers: {
        onEStop: () => void;
        onResume: () => void;
        onOpenCamera: () => void;
        onOpenTeleoperation: () => void;
        onAbortMission: () => void;
        onReconnect: () => void;
        onClearEStop: () => void;
        onDismiss: () => void;
        onContinue: () => void;
    },
): Array<{ label: string; icon: React.ReactNode; color: "danger" | "warning" | "primary" | "success" | "default"; action: () => void }> {
    switch (alertType) {
        case "CONNECTION_LOST":
            return [
                { label: "Reconnect", icon: <IconPlugConnected size={16} />, color: "primary", action: handlers.onReconnect },
                { label: "E-STOP", icon: <IconHandStop size={16} />, color: "danger", action: handlers.onEStop },
            ];
        case "COLLISION_AVOIDANCE":
            return [
                { label: "Open Camera", icon: <IconCamera size={16} />, color: "primary", action: handlers.onOpenCamera },
                { label: "Resume", icon: <IconPlayerPlay size={16} />, color: "success", action: handlers.onResume },
                { label: "E-STOP", icon: <IconHandStop size={16} />, color: "danger", action: handlers.onEStop },
            ];
        case "ROBOT_STALLED":
            return [
                { label: "Open Camera", icon: <IconCamera size={16} />, color: "primary", action: handlers.onOpenCamera },
                { label: "Resume", icon: <IconPlayerPlay size={16} />, color: "success", action: handlers.onResume },
            ];
        case "CRITICAL_BATTERY":
            return [
                { label: "Abort Mission", icon: <IconBatteryOff size={16} />, color: "danger", action: handlers.onAbortMission },
            ];
        case "LOW_BATTERY":
            return [
                { label: "Abort Mission", icon: <IconBatteryOff size={16} />, color: "warning", action: handlers.onAbortMission },
                { label: "Continue", icon: <IconPlayerPlay size={16} />, color: "default", action: handlers.onContinue },
            ];
        case "GEOFENCE_VIOLATION":
            return [
                { label: "E-STOP", icon: <IconHandStop size={16} />, color: "danger", action: handlers.onEStop },
            ];
        case "NAVIGATION_LOOP":
            return [
                { label: "Open Teleoperation", icon: <IconSteeringWheel size={16} />, color: "primary", action: handlers.onOpenTeleoperation },
            ];
        case "E_STOP_ACTIVE":
            return [
                { label: "Clear E-Stop", icon: <IconHandStop size={16} />, color: "warning", action: handlers.onClearEStop },
            ];
        case "SENSOR_DEGRADED":
            return [
                { label: "Pause Mission", icon: <IconRoute size={16} />, color: "warning", action: () => { handlers.onDismiss(); } },
            ];
        case "RTT_EXCEEDED":
            return [
                { label: "Open Teleoperation", icon: <IconSteeringWheel size={16} />, color: "primary", action: handlers.onOpenTeleoperation },
            ];
        default:
            return [];
    }
}

export const AlertBanner: React.FC = () => {
    const { activeAlerts, dismissAlert, acknowledgeAlert } = useAlertContext();
    const bridge = useOCCBridge();
    const router = useRouter();
    const warningTimerRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
    const [confirmingAck, setConfirmingAck] = useState<string | null>(null);
    const confirmTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    useEffect(() => {
        for (const alert of activeAlerts) {
            if (
                alert.severity === AlertSeverity.WARNING &&
                !warningTimerRef.current.has(alert.id)
            ) {
                const timer = setTimeout(() => {
                    dismissAlert(alert.id);
                    warningTimerRef.current.delete(alert.id);
                }, 30_000);
                warningTimerRef.current.set(alert.id, timer);
            }
        }
        const activeIds = new Set(activeAlerts.map(a => a.id));
        warningTimerRef.current.forEach((timer, id) => {
            if (!activeIds.has(id)) {
                clearTimeout(timer);
                warningTimerRef.current.delete(id);
            }
        });
    }, [activeAlerts, dismissAlert]);

    useEffect(() => {
        const timers = warningTimerRef.current;
        return () => {
            timers.forEach(t => clearTimeout(t));
        };
    }, []);

    if (activeAlerts.length === 0) return null;

    const topAlert = activeAlerts[0];
    const isCritical = topAlert.severity === AlertSeverity.CRITICAL;
    const bgColor = isCritical ? "bg-red-900/90" : "bg-orange-800/90";
    const Icon = isCritical ? IconAlertCircle : IconAlertTriangle;

    const handlers = {
        onEStop: () => {
            bridge.triggerEStop();
            dismissAlert(topAlert.id);
        },
        onResume: () => {
            bridge.resumeAutonomous();
            dismissAlert(topAlert.id);
        },
        onOpenCamera: () => {
            router.push("/teleoperation");
            dismissAlert(topAlert.id);
        },
        onOpenTeleoperation: () => {
            router.push("/teleoperation");
            dismissAlert(topAlert.id);
        },
        onAbortMission: () => {
            if (bridge.activeMission) {
                bridge.cancelMission(bridge.activeMission.id);
            }
            dismissAlert(topAlert.id);
        },
        onReconnect: () => {
            acknowledgeAlert(topAlert.id);
        },
        onClearEStop: () => {
            bridge.clearEStop();
            dismissAlert(topAlert.id);
        },
        onDismiss: () => {
            dismissAlert(topAlert.id);
        },
        onContinue: () => {
            dismissAlert(topAlert.id);
        },
    };

    const actions = getQuickActions(topAlert.type, handlers);
    const timeStr = new Date(topAlert.timestamp).toLocaleTimeString();

    return (
        <div className={`${bgColor} px-4 py-2 flex items-center gap-3 text-white`}>
            <Icon size={20} className="flex-shrink-0" />

            <div className="flex-1 min-w-0">
                <span className="font-bold mr-2">{topAlert.title}</span>
                <span className="text-white/80 text-sm">{topAlert.description}</span>
                <span className="text-white/60 text-xs ml-2">{timeStr}</span>
            </div>

            {activeAlerts.length > 1 && (
                <Chip size="sm" variant="flat" className="text-white bg-white/20 flex-shrink-0">
                    +{activeAlerts.length - 1} more
                </Chip>
            )}

            <div className="flex items-center gap-2 flex-shrink-0">
                {actions.map((action) => (
                    <Button
                        key={action.label}
                        size="sm"
                        color={action.color}
                        variant="flat"
                        startContent={action.icon}
                        onPress={action.action}
                        className="text-white"
                    >
                        {action.label}
                    </Button>
                ))}

                {topAlert.severity === AlertSeverity.CRITICAL ? (
                    confirmingAck === topAlert.id ? (
                        <Button
                            size="sm"
                            color="warning"
                            variant="solid"
                            onPress={() => {
                                acknowledgeAlert(topAlert.id);
                                setConfirmingAck(null);
                                if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
                            }}
                            className="animate-pulse"
                        >
                            Confirm Acknowledge
                        </Button>
                    ) : (
                        <Button
                            size="sm"
                            color="warning"
                            variant="flat"
                            className="text-white"
                            onPress={() => {
                                setConfirmingAck(topAlert.id);
                                if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current);
                                confirmTimerRef.current = setTimeout(() => setConfirmingAck(null), 5000);
                            }}
                        >
                            Acknowledge
                        </Button>
                    )
                ) : (
                    <Button
                        isIconOnly
                        size="sm"
                        variant="light"
                        onPress={() => dismissAlert(topAlert.id)}
                        className="text-white/60"
                    >
                        <IconX size={16} />
                    </Button>
                )}
            </div>
        </div>
    );
};
