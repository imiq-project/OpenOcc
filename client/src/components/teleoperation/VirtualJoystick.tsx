'use client';

import React, {useRef, useState, useCallback, useEffect} from "react";
import {useOCCBridge} from "@/context/OCCBridgeContext";

interface JoystickOutput {
    linear: number;  // -1 to 1 (forward/back)
    angular: number; // -1 to 1 (left/right)
}

interface VirtualJoystickProps {
    size?: number;
    maxLinear?: number;  // m/s
    maxAngular?: number; // rad/s
    disabled?: boolean;
    onMove?: (output: JoystickOutput) => void;
}

const VirtualJoystick: React.FC<VirtualJoystickProps> = ({
    size = 180,
    maxLinear = 1.4,
    maxAngular = 1.0,
    disabled: disabledProp,
    onMove,
}) => {
    const bridge = useOCCBridge();
    const isDirectMode = bridge.mode === "DIRECT";
    const disabled = disabledProp ?? !isDirectMode;
    const containerRef = useRef<HTMLDivElement>(null);
    const [dragging, setDragging] = useState(false);
    const [offset, setOffset] = useState({x: 0, y: 0});
    const publishInterval = useRef<NodeJS.Timeout | null>(null);
    const currentOutput = useRef<JoystickOutput>({linear: 0, angular: 0});

    const radius = size / 2;
    const handleRadius = size * 0.18;
    const maxDisplacement = radius - handleRadius;

    const calcOutput = useCallback((clientX: number, clientY: number) => {
        if (!containerRef.current) return;
        const rect = containerRef.current.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;

        let dx = clientX - cx;
        let dy = clientY - cy;

        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > maxDisplacement) {
            dx = (dx / dist) * maxDisplacement;
            dy = (dy / dist) * maxDisplacement;
        }

        setOffset({x: dx, y: dy});

        const normX = dx / maxDisplacement; // right positive
        const normY = -dy / maxDisplacement; // up positive

        currentOutput.current = {
            linear: normY,
            angular: -normX,
        };
    }, [maxDisplacement]);

    const handlePointerDown = useCallback((e: React.PointerEvent) => {
        if (disabled) return;
        e.preventDefault();
        (e.target as HTMLElement).setPointerCapture(e.pointerId);
        setDragging(true);
        calcOutput(e.clientX, e.clientY);

        publishInterval.current = setInterval(() => {
            const out = currentOutput.current;
            onMove?.(out);
            bridge.sendCmdVel(out.linear * maxLinear, out.angular * maxAngular);
        }, 100);
    }, [disabled, calcOutput, onMove, bridge, maxLinear, maxAngular]);

    const handlePointerMove = useCallback((e: React.PointerEvent) => {
        if (!dragging) return;
        calcOutput(e.clientX, e.clientY);
    }, [dragging, calcOutput]);

    const handlePointerUp = useCallback(() => {
        setDragging(false);
        setOffset({x: 0, y: 0});
        currentOutput.current = {linear: 0, angular: 0};
        onMove?.({linear: 0, angular: 0});
        bridge.sendCmdVel(0, 0);

        if (publishInterval.current) {
            clearInterval(publishInterval.current);
            publishInterval.current = null;
        }
    }, [onMove, bridge]);

    useEffect(() => {
        return () => {
            if (publishInterval.current) clearInterval(publishInterval.current);
        };
    }, []);

    const linearDisplay = (currentOutput.current.linear * maxLinear).toFixed(1);
    const angularDisplay = (currentOutput.current.angular * maxAngular).toFixed(1);

    return (
        <div className="flex flex-col items-center gap-2">
            <div
                ref={containerRef}
                className={`relative rounded-full border-2 ${
                    disabled
                        ? "border-default-300 bg-default-100 cursor-not-allowed opacity-50"
                        : dragging
                            ? "border-primary bg-primary/10 cursor-grabbing"
                            : "border-default-400 bg-default-100 cursor-grab"
                }`}
                style={{width: size, height: size}}
                onPointerDown={handlePointerDown}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerUp}
                onPointerCancel={handlePointerUp}
            >
                {/* Crosshair lines */}
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                    <div className="absolute w-full h-px bg-default-300/50" />
                    <div className="absolute h-full w-px bg-default-300/50" />
                </div>

                {/* Handle */}
                <div
                    className={`absolute rounded-full shadow-lg transition-colors ${
                        dragging ? "bg-primary" : "bg-default-500"
                    }`}
                    style={{
                        width: handleRadius * 2,
                        height: handleRadius * 2,
                        left: radius + offset.x - handleRadius,
                        top: radius + offset.y - handleRadius,
                        transition: dragging ? "none" : "all 0.15s ease-out",
                    }}
                />
            </div>

            {/* Readout */}
            <div className="text-xs text-default-500 font-mono text-center">
                <span>Linear: {linearDisplay} m/s</span>
                <span className="mx-2">|</span>
                <span>Angular: {angularDisplay} rad/s</span>
            </div>
        </div>
    );
};

export default VirtualJoystick;
