'use client';

import React from "react";
import { Input, Chip } from "@heroui/react";
import { IconPlugConnected } from "@tabler/icons-react";
import { useOCCBridge } from "@/context/OCCBridgeContext";

const ConnectionSettings: React.FC = () => {
    const { connected, vehicles, selectedVehicleId, rtt } = useOCCBridge();

    const serverUrl = `https://${window.location.host}`;

    return (
        <div className="flex flex-col gap-6 max-w-lg">
            <h3 className="text-lg font-semibold">Connection</h3>

            <div className="flex flex-col gap-4">
                <Input
                    label="OCC Server (WebTransport)"
                    value={serverUrl}
                    isReadOnly
                    description="WebTransport endpoint — set via NEXT_PUBLIC_OCC_SERVER environment variable"
                    endContent={
                        <Chip size="sm" variant="dot" color={connected ? "success" : "danger"}>
                            {connected ? "Connected" : "Disconnected"}
                        </Chip>
                    }
                />

                <div className="flex items-center gap-3 flex-wrap">
                    <Chip size="sm" variant="flat" color={connected ? "success" : "default"}>
                        <IconPlugConnected size={14} className="inline mr-1" />
                        WebTransport: {connected ? "Active" : "Inactive"}
                    </Chip>
                    <Chip size="sm" variant="flat" color="default">
                        Vehicles: {vehicles.length}
                    </Chip>
                    {selectedVehicleId && (
                        <Chip size="sm" variant="flat" color="primary">
                            RTT: {rtt.toFixed(0)} ms
                        </Chip>
                    )}
                </div>
            </div>

            <div className="border-t border-default-200 pt-4 flex flex-col gap-4">
                <p className="text-xs text-default-500">
                    The OCC server URL is configured at build time through the <code className="text-default-300">NEXT_PUBLIC_OCC_SERVER</code> environment variable.
                    WebRTC signaling is handled through the WebTransport connection once a vehicle is selected.
                </p>
            </div>
        </div>
    );
};

export default ConnectionSettings;
