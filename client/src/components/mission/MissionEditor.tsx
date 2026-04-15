'use client';

import React, { useState, useCallback } from "react";
import {
    Card,
    CardBody,
    CardHeader,
    Input,
    Textarea,
    Select,
    SelectItem,
    Button,
    ButtonGroup,
    Chip,
    Divider,
    Progress,
} from "@heroui/react";
import {
    IconSend,
    IconDeviceFloppy,
    IconX,
    IconMapPin,
    IconTruckDelivery,
    IconClock,
    IconRoute,
} from "@tabler/icons-react";
import { OCCMission } from "@/model/OCCMessages";

import MissionTimeline from "./MissionTimeline";

interface MissionEditorProps {
    mission: OCCMission | null;
    mode: "create" | "detail";
    onSave: (mission: OCCMission) => void;
    onCancel: () => void;
    onCancelMission: (id: string) => void;
}

function generateMissionId(): string {
    const num = Math.floor(Math.random() * 900) + 100;
    return `M-${num}`;
}

const MissionEditor: React.FC<MissionEditorProps> = ({
    mission,
    mode,
    onSave,
    onCancel,
    onCancelMission,
}) => {
    const [draft, setDraft] = useState<OCCMission>(() => {
        const emptyMission: OCCMission = {
            id: "",
            description: "",
            priority: "NORMAL",
            pickup: { latitude: 52.14170, longitude: 11.64030, name: "" },
            delivery: { latitude: 52.14400, longitude: 11.65250, name: "" },
            cargoNotes: "",
            assignedRobot: "DELIVERY-01",
            status: "PENDING",
            createdAt: Date.now(),
            progress: 0,
        };
        if (mode === "create") {
            return { ...emptyMission, id: generateMissionId() };
        }
        return mission ?? { ...emptyMission, id: generateMissionId() };
    });

    const updateField = useCallback(<K extends keyof OCCMission>(key: K, value: OCCMission[K]) => {
        setDraft(prev => ({ ...prev, [key]: value }));
    }, []);

    const handleDispatch = () => {
        const dispatched: OCCMission = {
            ...draft,
            status: "DISPATCHED",
            dispatchedAt: Date.now(),
            createdAt: draft.createdAt || Date.now(),
        };
        onSave(dispatched);
    };

    const handleSaveDraft = () => {
        const saved: OCCMission = {
            ...draft,
            status: "PENDING",
            createdAt: draft.createdAt || Date.now(),
        };
        onSave(saved);
    };

    const isValid = draft.description.trim() !== "" &&
        draft.pickup.name.trim() !== "" &&
        draft.delivery.name.trim() !== "";

    if (mode === "create") {
        return (
            <div className="flex flex-col h-full gap-3 overflow-y-auto p-1">
                <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold">New Mission</h2>
                    <Chip size="sm" variant="flat">{draft.id}</Chip>
                </div>

                <Card>
                    <CardBody className="gap-3">
                        <Input
                            label="Description"
                            labelPlacement="outside"
                            placeholder="What needs to be delivered?"
                            value={draft.description}
                            onValueChange={v => updateField("description", v)}
                            isRequired
                        />

                        <Select
                            label="Priority"
                            labelPlacement="outside"
                            selectedKeys={[draft.priority]}
                            onSelectionChange={keys => {
                                const val = Array.from(keys)[0] as OCCMission["priority"];
                                if (val) updateField("priority", val);
                            }}
                        >
                            <SelectItem key="LOW">Low</SelectItem>
                            <SelectItem key="NORMAL">Normal</SelectItem>
                            <SelectItem key="HIGH">High</SelectItem>
                        </Select>

                        <Divider />

                        <div className="flex items-center gap-2">
                            <IconMapPin size={16} className="text-success" />
                            <span className="text-sm font-medium">Pickup Location</span>
                        </div>
                        <Input
                            label="Pickup name"
                            labelPlacement="outside"
                            placeholder="e.g., Warehouse A"
                            value={draft.pickup.name}
                            onValueChange={v => updateField("pickup", { ...draft.pickup, name: v })}
                            isRequired
                        />

                        <div className="flex items-center gap-2">
                            <IconTruckDelivery size={16} className="text-warning" />
                            <span className="text-sm font-medium">Delivery Location</span>
                        </div>
                        <Input
                            label="Delivery name"
                            labelPlacement="outside"
                            placeholder="e.g., Building C - Lab 201"
                            value={draft.delivery.name}
                            onValueChange={v => updateField("delivery", { ...draft.delivery, name: v })}
                            isRequired
                        />

                        <Divider />

                        <Textarea
                            label="Cargo Notes"
                            labelPlacement="outside"
                            placeholder="Special handling instructions..."
                            value={draft.cargoNotes}
                            onValueChange={v => updateField("cargoNotes", v)}
                            minRows={2}
                        />

                        <Select
                            label="Assigned Robot"
                            labelPlacement="outside"
                            selectedKeys={[draft.assignedRobot]}
                            isDisabled
                        >
                            <SelectItem key="DELIVERY-01">DELIVERY-01</SelectItem>
                        </Select>
                    </CardBody>
                </Card>

                <div className="flex gap-2 mt-auto pb-2">
                    <Button
                        variant="flat"
                        onPress={onCancel}
                        className="flex-1"
                    >
                        Cancel
                    </Button>
                    <Button
                        variant="flat"
                        color="default"
                        startContent={<IconDeviceFloppy size={16} />}
                        onPress={handleSaveDraft}
                        isDisabled={!isValid}
                        className="flex-1"
                    >
                        Save Draft
                    </Button>
                    <Button
                        color="primary"
                        startContent={<IconSend size={16} />}
                        onPress={handleDispatch}
                        isDisabled={!isValid}
                        className="flex-1"
                    >
                        Dispatch
                    </Button>
                </div>
            </div>
        );
    }

    if (!mission) return null;

    const canCancel = mission.status === "PENDING" || mission.status === "DISPATCHED" || mission.status === "EN_ROUTE";

    return (
        <div className="flex flex-col h-full gap-3 overflow-y-auto p-1">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">{mission.id}</h2>
                <div className="flex items-center gap-2">
                    <Chip
                        size="sm"
                        variant="flat"
                        color={
                            mission.priority === "HIGH" ? "danger" :
                            mission.priority === "LOW" ? "default" : "primary"
                        }
                    >
                        {mission.priority}
                    </Chip>
                    <Button size="sm" variant="light" isIconOnly onPress={onCancel}>
                        <IconX size={16} />
                    </Button>
                </div>
            </div>

            {/* Description */}
            <Card>
                <CardBody className="gap-2 py-3">
                    <p className="text-sm">{mission.description}</p>
                    {mission.cargoNotes && (
                        <p className="text-xs text-default-500 italic">{mission.cargoNotes}</p>
                    )}
                </CardBody>
            </Card>

            {/* Route */}
            <Card>
                <CardHeader className="pb-1 pt-3 px-4">
                    <div className="flex items-center gap-2">
                        <IconRoute size={16} className="text-primary" />
                        <span className="text-sm font-medium">Route</span>
                    </div>
                </CardHeader>
                <CardBody className="gap-2 py-2">
                    <div className="flex items-center gap-2">
                        <IconMapPin size={14} className="text-success" />
                        <span className="text-sm">{mission.pickup.name}</span>
                    </div>
                    <div className="w-0.5 h-3 bg-default-300 ml-[6px]" />
                    <div className="flex items-center gap-2">
                        <IconTruckDelivery size={14} className="text-warning" />
                        <span className="text-sm">{mission.delivery.name}</span>
                    </div>
                </CardBody>
            </Card>

            {/* Progress */}
            {(mission.status === "EN_ROUTE" || mission.status === "DISPATCHED") && (
                <Card>
                    <CardBody className="gap-2 py-3">
                        <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">Progress</span>
                            <span className="text-sm font-bold">{mission.progress.toFixed(0)}%</span>
                        </div>
                        <Progress
                            value={mission.progress}
                            color="primary"
                            size="sm"
                        />
                        {mission.eta !== undefined && (
                            <div className="flex items-center gap-1 text-xs text-default-500">
                                <IconClock size={14} />
                                <span>ETA: {Math.ceil(mission.eta / 60)} min</span>
                            </div>
                        )}
                    </CardBody>
                </Card>
            )}

            {/* Timeline */}
            <Card>
                <CardHeader className="pb-1 pt-3 px-4">
                    <span className="text-sm font-medium">Status Timeline</span>
                </CardHeader>
                <CardBody className="py-2">
                    <MissionTimeline mission={mission} />
                </CardBody>
            </Card>

            {/* Info */}
            <Card>
                <CardBody className="gap-1 py-3">
                    <div className="flex justify-between text-xs">
                        <span className="text-default-500">Assigned Robot</span>
                        <span>{mission.assignedRobot}</span>
                    </div>
                    <div className="flex justify-between text-xs">
                        <span className="text-default-500">Created</span>
                        <span>{new Date(mission.createdAt).toLocaleString("en-GB", {
                            day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
                        })}</span>
                    </div>
                    {mission.dispatchedAt && (
                        <div className="flex justify-between text-xs">
                            <span className="text-default-500">Dispatched</span>
                            <span>{new Date(mission.dispatchedAt).toLocaleString("en-GB", {
                                day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
                            })}</span>
                        </div>
                    )}
                    {mission.completedAt && (
                        <div className="flex justify-between text-xs">
                            <span className="text-default-500">Completed</span>
                            <span>{new Date(mission.completedAt).toLocaleString("en-GB", {
                                day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
                            })}</span>
                        </div>
                    )}
                </CardBody>
            </Card>

            {/* Actions */}
            {canCancel && (
                <div className="mt-auto pb-2">
                    <Button
                        color="danger"
                        variant="flat"
                        fullWidth
                        startContent={<IconX size={16} />}
                        onPress={() => onCancelMission(mission.id)}
                    >
                        Cancel Mission
                    </Button>
                </div>
            )}
        </div>
    );
};

export default MissionEditor;
