'use client';

import React from "react";
import { OCCMission } from "@/model/OCCMessages";
import {
    IconCircleCheck,
    IconCircleDot,
    IconCircle,
    IconCircleX,
    IconBan,
} from "@tabler/icons-react";

interface MissionTimelineProps {
    mission: OCCMission;
}

const STEPS = ["PENDING", "DISPATCHED", "EN_ROUTE", "DELIVERED"] as const;

const STEP_LABELS: Record<string, string> = {
    PENDING: "Created",
    DISPATCHED: "Dispatched",
    EN_ROUTE: "En Route",
    DELIVERED: "Delivered",
};

function getStepIndex(status: OCCMission["status"]): number {
    if (status === "FAILED" || status === "CANCELLED") {
        return 2;
    }
    return STEPS.indexOf(status as typeof STEPS[number]);
}

function formatTime(ts?: number): string {
    if (!ts) return "—";
    return new Date(ts).toLocaleTimeString("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
    });
}

const MissionTimeline: React.FC<MissionTimelineProps> = ({ mission }) => {
    const currentIndex = getStepIndex(mission.status);
    const isFailed = mission.status === "FAILED";
    const isCancelled = mission.status === "CANCELLED";
    const isTerminal = isFailed || isCancelled;

    const timestamps: (number | undefined)[] = [
        mission.createdAt,
        mission.dispatchedAt,
        mission.dispatchedAt ? mission.dispatchedAt : undefined, // EN_ROUTE starts after dispatch
        mission.completedAt,
    ];

    return (
        <div className="flex flex-col gap-0">
            {STEPS.map((step, i) => {
                const isCompleted = i < currentIndex || (i === currentIndex && mission.status === "DELIVERED");
                const isCurrent = i === currentIndex && !isTerminal && mission.status !== "DELIVERED";
                const isFutureOrTerminal = i > currentIndex || (isTerminal && i === currentIndex);

                let icon;
                if (isTerminal && i === currentIndex) {
                    icon = isFailed
                        ? <IconCircleX size={20} className="text-danger" />
                        : <IconBan size={20} className="text-warning" />;
                } else if (isCompleted) {
                    icon = <IconCircleCheck size={20} className="text-success" />;
                } else if (isCurrent) {
                    icon = <IconCircleDot size={20} className="text-primary animate-pulse" />;
                } else {
                    icon = <IconCircle size={20} className="text-default-300" />;
                }

                const label = isTerminal && i === currentIndex
                    ? (isFailed ? "Failed" : "Cancelled")
                    : STEP_LABELS[step];

                return (
                    <div key={step} className="flex items-start gap-3">
                        <div className="flex flex-col items-center">
                            {icon}
                            {i < STEPS.length - 1 && (
                                <div className={`w-0.5 h-6 ${isCompleted ? "bg-success" : "bg-default-200"}`} />
                            )}
                        </div>
                        <div className="flex-1 -mt-0.5">
                            <p className={`text-sm font-medium ${
                                isCompleted ? "text-foreground" :
                                isCurrent ? "text-primary" :
                                "text-default-400"
                            }`}>
                                {label}
                            </p>
                            <p className="text-xs text-default-500">{formatTime(timestamps[i])}</p>
                        </div>
                    </div>
                );
            })}
        </div>
    );
};

export default MissionTimeline;
