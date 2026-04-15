'use client';

import React from "react";
import {NavBar} from "./NavBar";
import {StatusStrip} from "./StatusStrip";
import {AlertBanner} from "@/components/alerts/AlertBanner";
import {AlertMonitor} from "@/components/alerts/AlertMonitor";
import {useAuth} from "@/context/AuthContext";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {usePathname} from "next/navigation";

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({children}) => {
    const {user} = useAuth();
    const bridge = useOCCBridge();
    const pathname = usePathname();

    if (!user || pathname === "/login") return <>{children}</>;

    const activeMission = bridge.activeMission;

    return (
        <div className="h-screen flex flex-col bg-[#373a44]">
            <AlertMonitor />
            <NavBar />
            <div className="h-[2px]" />
            <StatusStrip
                robotName={bridge.selectedVehicleName}
                state={bridge.robotState}
                batteryPercent={bridge.battery.percentage}
                missionId={activeMission?.id ?? null}
                missionProgress={activeMission?.progress ?? 0}
                eta={activeMission?.eta ?? null}
            />
            <AlertBanner />
            <div className="h-[2px]" />
            <main className="flex-1 overflow-auto p-[2px]">
                {children}
            </main>
        </div>
    );
};
