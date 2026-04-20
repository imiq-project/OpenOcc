'use client';

import React from "react";
import { Card, CardBody, Chip } from "@heroui/react";
import { IconCircleFilled, IconHeartbeat, IconWifi, IconServer } from "@tabler/icons-react";
import { useOCCBridge } from "@/context/OCCBridgeContext";

const HealthRow: React.FC<{
    icon: React.ReactNode;
    label: string;
    status: "online" | "offline" | "unconfigured";
    detail?: string;
}> = ({ icon, label, status, detail }) => {
    const statusColor = status === "online" ? "text-success" : status === "offline" ? "text-danger" : "text-default-400";
    const statusLabel = status === "online" ? "Connected" : status === "offline" ? "Disconnected" : "Not configured";
    const chipColor = status === "online" ? "success" : status === "offline" ? "danger" : "default";

    return (
        <Card>
            <CardBody className="flex flex-row items-center justify-between py-3">
                <div className="flex items-center gap-3">
                    <div className={statusColor}>{icon}</div>
                    <div>
                        <p className="text-sm font-medium">{label}</p>
                        {detail && <p className="text-xs text-default-400">{detail}</p>}
                    </div>
                </div>
                <Chip size="sm" variant="dot" color={chipColor}>
                    {statusLabel}
                </Chip>
            </CardBody>
        </Card>
    );
};

const SystemHealth: React.FC = () => {
    const { connected, lastHeartbeat } = useOCCBridge();

    const lastHBStr = lastHeartbeat > 0
        ? new Date(lastHeartbeat).toLocaleTimeString("en-GB")
        : "Never";

    return (
        <div className="flex flex-col gap-4 max-w-lg">
            <h3 className="text-lg font-semibold">System Health</h3>

            <div className="flex flex-col gap-3">
                <HealthRow
                    icon={<IconHeartbeat size={20} />}
                    label="DELIVERY-01"
                    status={connected ? "online" : "offline"}
                    detail={`Last heartbeat: ${lastHBStr}`}
                />

                <HealthRow
                    icon={<IconWifi size={20} />}
                    label="Bridge Connection"
                    status={connected ? "online" : "offline"}
                    detail={connected ? "WebSocket active" : "WebSocket disconnected"}
                />

                <HealthRow
                    icon={<IconServer size={20} />}
                    label="DWLZ API"
                    status="unconfigured"
                    detail="Endpoint not configured"
                />
            </div>
        </div>
    );
};

export default SystemHealth;
