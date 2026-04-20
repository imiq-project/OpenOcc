'use client';

import React from "react";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {
    IconSteeringWheel,
    IconWifi,
    IconCarSuv,
    IconParking,
    IconAlertTriangle,
    IconRoute,
    IconHandStop,
    IconPlayerPause,
} from "@tabler/icons-react";
import type {Mode} from "@/bridge/StateMachine";

interface HUDOverlayProps {
    onToggleControls?: () => void;
}

const MODE_CONFIG: Record<Mode, { label: string; color: string; icon: React.ReactNode }> = {
    STANDBY: {label: "STANDBY", color: "text-white/60", icon: <IconPlayerPause size={16} />},
    DIRECT: {label: "DIRECT", color: "text-primary", icon: <IconSteeringWheel size={16} />},
    TRAJECTORY: {label: "TRAJECTORY", color: "text-blue-400", icon: <IconRoute size={16} />},
    ESTOP: {label: "E-STOP", color: "text-red-400", icon: <IconHandStop size={16} />},
};

const StatusPanel: React.FC = () => {
    const bridge = useOCCBridge();
    const modeConfig = MODE_CONFIG[bridge.mode];

    return (
        <div className="bg-black/50 backdrop-blur-sm rounded-lg px-4 py-2.5 text-sm space-y-1.5">
            <div className="flex items-center gap-2">
                <span className="text-white/90 font-medium">{bridge.selectedVehicleName}</span>
            </div>
            <div className="flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${
                    bridge.webrtcState === 'connected' ? 'bg-green-400' :
                    bridge.webrtcState === 'connecting' || bridge.webrtcState === 'new' ? 'bg-yellow-400 animate-pulse' :
                    'bg-red-400'
                }`} />
                <span className="text-white/70">{
                    bridge.webrtcState === 'connected' ? 'Connected' :
                    bridge.webrtcState === 'connecting' || bridge.webrtcState === 'new' ? 'Connecting' :
                    'Disconnected'
                }</span>
            </div>
            <div className="text-white/50">{bridge.robotState}</div>
            <div className={`flex items-center gap-1.5 font-medium ${modeConfig.color}`}>
                {modeConfig.icon}
                {modeConfig.label}
            </div>
        </div>
    );
};

const SpeedDisplay: React.FC = () => {
    const bridge = useOCCBridge();
    const speedKmh = bridge.speed * 3.6;

    return (
        <div className="bg-black/50 backdrop-blur-sm rounded-xl px-5 py-3 flex flex-col items-center">
            <p className="text-6xl font-bold font-mono text-white leading-none drop-shadow-lg">
                {speedKmh.toFixed(0)}
            </p>
            <p className="text-base text-white/60 mt-1">km/h</p>
        </div>
    );
};

const LatencyPanel: React.FC = () => {
    const bridge = useOCCBridge();
    const speedKmh = bridge.speed * 3.6;
    const rttMs = Math.round(bridge.rtt);
    const exceeded = bridge.rttExceeded;

    return (
        <div className="flex flex-col items-end gap-2">
            {exceeded && (
                <div className="flex items-center gap-1.5 bg-red-600/80 backdrop-blur-sm px-3 py-1.5 rounded-lg text-sm font-bold text-white animate-pulse">
                    <IconAlertTriangle size={18} />
                    RTT EXCEEDED
                </div>
            )}

            <div className="flex items-center gap-3">
                <span className={`bg-black/50 backdrop-blur-sm px-3 py-1.5 rounded-lg text-base font-bold flex items-center gap-1.5 ${
                    speedKmh > 0.5 ? 'text-green-400' : 'text-white'
                }`}>
                    {speedKmh > 0.5
                        ? <><IconCarSuv size={20} /> D</>
                        : <><IconParking size={20} /> P</>
                    }
                </span>
                <span className={`bg-black/50 backdrop-blur-sm px-3 py-1.5 rounded-lg text-base flex items-center gap-1.5 ${
                    exceeded ? 'text-red-400 font-bold' : 'text-white/80'
                }`}>
                    <IconWifi size={18} />
                    {rttMs > 0 ? `${rttMs} ms` : '-- ms'}
                </span>
            </div>
        </div>
    );
};

const HUDOverlay: React.FC<HUDOverlayProps> = ({onToggleControls}) => {
    return (
        <div className="absolute inset-0 pointer-events-none">
            <div className="absolute bottom-4 left-4 pointer-events-auto">
                <StatusPanel />
            </div>

            <div className="absolute bottom-4 left-1/2 -translate-x-1/2">
                <SpeedDisplay />
            </div>

            <div className="absolute bottom-4 right-4 pointer-events-auto">
                <LatencyPanel />
            </div>

            {onToggleControls && (
                <div className="absolute top-3 left-3 pointer-events-auto">
                    <button
                        onClick={onToggleControls}
                        className="w-10 h-10 rounded-full bg-black/50 backdrop-blur-sm hover:bg-black/70 text-white flex items-center justify-center transition-colors shadow-lg"
                        title="Toggle Controls"
                    >
                        <IconSteeringWheel size={22} stroke={1.5} />
                    </button>
                </div>
            )}
        </div>
    );
};

export default HUDOverlay;
