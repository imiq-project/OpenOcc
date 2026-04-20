'use client';

import React from "react";
import {Chip, Progress} from "@heroui/react";
import {
    IconBattery4,
    IconBattery3,
    IconBattery2,
    IconBattery1,
    IconBatteryOff,
    IconGauge,
    IconRoute,
} from "@tabler/icons-react";
import {RobotState, STATE_COLORS, batteryColor, BATTERY_TEXT_CLASS} from "@/model/OCCMessages";
import {EStopButton} from "./EStopButton";

interface StatusStripProps {
    robotName: string;
    state: RobotState;
    batteryPercent: number;
    missionId: string | null;
    missionProgress: number;
    eta: number | null;
}

export const StatusStrip: React.FC<StatusStripProps> = ({
    robotName,
    state,
    batteryPercent,
    missionId,
    missionProgress,
    eta,
}) => {
    const bColor = batteryColor(batteryPercent);
    const bTextClass = BATTERY_TEXT_CLASS[bColor];

    const BatteryIcon =
        batteryPercent > 75 ? IconBattery4 :
        batteryPercent > 50 ? IconBattery3 :
        batteryPercent > 25 ? IconBattery2 :
        batteryPercent > 10 ? IconBattery1 :
        IconBatteryOff;

    return (
        <div className="w-full bg-occ-surface px-4 py-1.5 flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
                <span className="occ-section-label">Robot:</span>
                <span className="text-sm font-bold text-default-200">{robotName}</span>
            </div>

            <Chip color={STATE_COLORS[state]} variant="flat" size="sm">
                {state.replace("_", " ")}
            </Chip>

            <div className="flex items-center gap-0.5">
                <BatteryIcon size={28} className={bTextClass} />
                <span className={`text-sm font-bold font-mono ${bTextClass}`}>
                    {batteryPercent.toFixed(0)}%
                </span>
            </div>

            <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-[400px]">
                <IconRoute size={16} className="text-default-500" />
                <span className="text-sm text-default-500">
                    {missionId ? `${missionId}` : "No Active Mission"}
                </span>
                {missionId && (
                    <Progress
                        value={missionProgress}
                        size="sm"
                        color="primary"
                        className="flex-1"
                    />
                )}
            </div>

            <div className="flex items-center gap-1">
                <IconGauge size={16} className="text-default-500" />
                <span className="text-sm text-default-500">
                    ETA: {eta !== null ? `${Math.ceil(eta / 60)} min` : "—"}
                </span>
            </div>

            <div className="ml-auto">
                <EStopButton />
            </div>
        </div>
    );
};
