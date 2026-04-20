'use client';

import React from "react";
import {Card, CardBody, Chip, Progress, Button, ButtonGroup, Divider} from "@heroui/react";
import {
    IconRoute,
    IconClock,
    IconPlayerPause,
    IconPlayerPlay,
    IconX,
} from "@tabler/icons-react";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {RobotState, STATE_COLORS} from "@/model/OCCMessages";

const RobotDetailPanel: React.FC = () => {
    const bridge = useOCCBridge();

    return (
        <div className="flex flex-col gap-2">
            {/* Robot ID + State */}
            <Card className="occ-card">
                <CardBody className="p-3 gap-3">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-base font-semibold text-default-100">{bridge.selectedVehicleName}</p>
                            <p className="text-xs text-default-500">Delivery Robot</p>
                        </div>
                        <Chip
                            color={STATE_COLORS[bridge.robotState]}
                            variant="flat"
                            size="sm">
                            {bridge.robotState}
                        </Chip>
                    </div>

                </CardBody>
            </Card>

            {/* Mission */}
            <Card className="occ-card">
                <CardBody className="p-3 gap-2">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <IconRoute size={18} className="text-primary"/>
                            <span className="text-sm font-medium text-default-200">Mission</span>
                        </div>
                        {bridge.activeMission ? (
                            <Chip size="sm" variant="flat" color="primary">
                                {bridge.activeMission.id}
                            </Chip>
                        ) : (
                            <span className="text-xs text-default-500">No Active Mission</span>
                        )}
                    </div>
                    {bridge.activeMission && (
                        <>
                            <p className="text-xs text-default-400">{bridge.activeMission.description}</p>
                            <Progress
                                value={bridge.activeMission.progress}
                                color="primary"
                                size="sm"
                                showValueLabel
                                className="w-full"/>
                            <div className="flex items-center gap-1 text-xs text-default-500">
                                <IconClock size={14}/>
                                <span>ETA: {bridge.activeMission.eta !== undefined
                                    ? `${Math.ceil(bridge.activeMission.eta / 60)} min`
                                    : "—"}</span>
                            </div>
                        </>
                    )}

                    <Divider className="bg-occ-border"/>

                    <ButtonGroup size="sm" fullWidth>
                        {bridge.robotState === RobotState.AUTONOMOUS ? (
                            <Button
                                color="warning"
                                variant="flat"
                                startContent={<IconPlayerPause size={16}/>}
                                onPress={() => bridge.pauseRobot()}>
                                Pause
                            </Button>
                        ) : (
                            <Button
                                color="success"
                                variant="flat"
                                startContent={<IconPlayerPlay size={16}/>}
                                onPress={() => bridge.resumeAutonomous()}>
                                Resume
                            </Button>
                        )}
                        {bridge.activeMission && (
                            <Button
                                color="danger"
                                variant="flat"
                                startContent={<IconX size={16}/>}
                                onPress={() => bridge.cancelMission(bridge.activeMission!.id)}>
                                Abort
                            </Button>
                        )}
                    </ButtonGroup>
                </CardBody>
            </Card>

            {/* Recent Events */}
            <Card className="occ-card shrink-0">
                <CardBody className="p-3 gap-1">
                    <p className="occ-section-label mb-1">Recent Events</p>
                    <div className="max-h-[120px] overflow-y-auto">
                        {bridge.eventLog.slice(-5).reverse().map(event => (
                            <div key={event.id} className="flex gap-2 text-xs py-0.5">
                                <span className="text-default-500 whitespace-nowrap font-mono">
                                    {new Date(event.timestamp).toLocaleTimeString("en-GB", {
                                        hour: "2-digit",
                                        minute: "2-digit",
                                        second: "2-digit",
                                    })}
                                </span>
                                <span className={
                                    event.severity === "CRITICAL" ? "text-danger" :
                                    event.severity === "WARNING" ? "text-warning" :
                                    "text-default-400"
                                }>
                                    {event.message}
                                </span>
                            </div>
                        ))}
                        {bridge.eventLog.length === 0 && (
                            <p className="text-xs text-default-500">No events yet</p>
                        )}
                    </div>
                </CardBody>
            </Card>
        </div>
    );
};

export default RobotDetailPanel;
