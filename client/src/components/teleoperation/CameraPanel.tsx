'use client';

import React, {useRef, useEffect} from "react";
import {IconCameraOff} from "@tabler/icons-react";
import {useOCCBridge} from "@/context/OCCBridgeContext";

interface CameraFeedProps {
    label: string;
    stream: MediaStream | null;
}

const CameraFeed: React.FC<CameraFeedProps> = ({label, stream}) => {
    const videoRef = useRef<HTMLVideoElement>(null);

    useEffect(() => {
        if (!videoRef.current) return;
        if (stream) {
            videoRef.current.srcObject = stream;
        } else {
            videoRef.current.srcObject = null;
        }
    }, [stream]);

    return (
        <div className="flex-1 min-w-0 bg-occ-deep flex flex-col items-center justify-center text-default-500 gap-2 border border-occ-border relative overflow-hidden">
            {/* Label overlay */}
            <div className="absolute top-2 left-2 bg-black/50 px-2 py-0.5 rounded text-[10px] text-white/80 font-medium z-10">
                {label}
            </div>

            {stream ? (
                <video
                    ref={videoRef}
                    autoPlay
                    playsInline
                    muted
                    className="w-full h-full object-cover"
                />
            ) : (
                <>
                    <video ref={videoRef} className="hidden" />
                    <IconCameraOff size={32} stroke={1.5} />
                    <p className="text-xs">No Video Feed</p>
                </>
            )}
        </div>
    );
};

const CameraRow: React.FC = () => {
    const bridge = useOCCBridge();
    const streams = bridge.videoStreams;
    const isActive = bridge.mode === "DIRECT" && bridge.webrtcConnected;

    return (
        <div className="flex gap-[1px] h-full bg-occ-deep">
            <CameraFeed label="Front Camera" stream={isActive ? (streams[0] ?? null) : null} />
            <CameraFeed label="Depth View" stream={isActive ? (streams[1] ?? null) : null} />
        </div>
    );
};

export default CameraRow;
