'use client';

import React, { useMemo } from "react";
import { Card, CardBody, Chip, Tabs, Tab, Button } from "@heroui/react";
import { IconPlus, IconArrowUp, IconArrowDown, IconMinus } from "@tabler/icons-react";
import { OCCMission } from "@/model/OCCMessages";

interface MissionQueueProps {
    missions: OCCMission[];
    selectedMissionId: string | null;
    onSelectMission: (id: string) => void;
    onNewMission: () => void;
}

const PRIORITY_CONFIG = {
    HIGH: { color: "danger" as const, icon: <IconArrowUp size={12} /> },
    NORMAL: { color: "primary" as const, icon: <IconMinus size={12} /> },
    LOW: { color: "default" as const, icon: <IconArrowDown size={12} /> },
};

const STATUS_COLOR: Record<OCCMission["status"], "default" | "primary" | "success" | "warning" | "danger" | "secondary"> = {
    PENDING: "default",
    DISPATCHED: "primary",
    EN_ROUTE: "primary",
    DELIVERED: "success",
    FAILED: "danger",
    CANCELLED: "warning",
};

function formatTime(ts: number): string {
    return new Date(ts).toLocaleTimeString("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
    });
}

const MissionCard: React.FC<{
    mission: OCCMission;
    isSelected: boolean;
    onSelect: () => void;
}> = ({ mission, isSelected, onSelect }) => {
    const priority = PRIORITY_CONFIG[mission.priority];

    return (
        <Card
            isPressable
            onPress={onSelect}
            className={`transition-colors ${isSelected ? "border-primary border-2" : "border-transparent border-2"}`}
        >
            <CardBody className="py-2.5 px-3 gap-1.5">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">{mission.id}</span>
                        <Chip size="sm" variant="flat" color={priority.color} startContent={priority.icon}>
                            {mission.priority}
                        </Chip>
                    </div>
                    <Chip size="sm" variant="dot" color={STATUS_COLOR[mission.status]}>
                        {mission.status.replace("_", " ")}
                    </Chip>
                </div>
                <p className="text-xs text-default-500 line-clamp-1">{mission.description}</p>
                <div className="flex items-center justify-between text-xs text-default-400">
                    <span>{mission.pickup.name} → {mission.delivery.name}</span>
                    <span>{formatTime(mission.createdAt)}</span>
                </div>
                {mission.progress > 0 && mission.progress < 100 && (
                    <div className="w-full bg-default-100 rounded-full h-1 mt-0.5">
                        <div
                            className="bg-primary h-1 rounded-full transition-all"
                            style={{ width: `${mission.progress}%` }}
                        />
                    </div>
                )}
            </CardBody>
        </Card>
    );
};

const MissionQueue: React.FC<MissionQueueProps> = ({
    missions,
    selectedMissionId,
    onSelectMission,
    onNewMission,
}) => {
    const pending = useMemo(
        () => missions.filter(m => m.status === "PENDING"),
        [missions]
    );
    const active = useMemo(
        () => missions.filter(m => m.status === "DISPATCHED" || m.status === "EN_ROUTE"),
        [missions]
    );
    const completed = useMemo(
        () => missions.filter(m =>
            m.status === "DELIVERED" || m.status === "FAILED" || m.status === "CANCELLED"
        ),
        [missions]
    );

    const renderList = (list: OCCMission[], emptyMessage: string) => (
        <div className="flex flex-col gap-2 overflow-y-auto flex-1">
            {list.length === 0 ? (
                <p className="text-sm text-default-400 text-center py-8">{emptyMessage}</p>
            ) : (
                list.map(m => (
                    <MissionCard
                        key={m.id}
                        mission={m}
                        isSelected={m.id === selectedMissionId}
                        onSelect={() => onSelectMission(m.id)}
                    />
                ))
            )}
        </div>
    );

    return (
        <div className="flex flex-col h-full gap-3">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Missions</h2>
                <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    onPress={onNewMission}
                    className="gap-1.5"
                >
                    <IconPlus size={16} />
                    <span>New Mission</span>
                </Button>
            </div>

            <Tabs
                aria-label="Mission tabs"
                variant="underlined"
                classNames={{ tabList: "w-full", tab: "flex-1" }}
            >
                <Tab
                    key="pending"
                    title={
                        <div className="flex items-center gap-1.5">
                            <span>Pending</span>
                            {pending.length > 0 && (
                                <Chip size="sm" variant="flat" color="default">{pending.length}</Chip>
                            )}
                        </div>
                    }
                >
                    {renderList(pending, "No pending missions")}
                </Tab>
                <Tab
                    key="active"
                    title={
                        <div className="flex items-center gap-1.5">
                            <span>Active</span>
                            {active.length > 0 && (
                                <Chip size="sm" variant="flat" color="primary">{active.length}</Chip>
                            )}
                        </div>
                    }
                >
                    {renderList(active, "No active missions")}
                </Tab>
                <Tab
                    key="completed"
                    title={
                        <div className="flex items-center gap-1.5">
                            <span>Completed</span>
                            {completed.length > 0 && (
                                <Chip size="sm" variant="flat" color="success">{completed.length}</Chip>
                            )}
                        </div>
                    }
                >
                    {renderList(completed, "No completed missions")}
                </Tab>
            </Tabs>
        </div>
    );
};

export default MissionQueue;
