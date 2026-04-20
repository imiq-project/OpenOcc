'use client';

import React, {useCallback} from "react";
import {
    IconRoute,
    IconSteeringWheel,
    IconArrowBack,
    IconHandStop,
    IconX,
} from "@tabler/icons-react";
import {RobotState} from "@/model/OCCMessages";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import VirtualJoystick from "./VirtualJoystick";
import {Button, Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, useDisclosure} from "@heroui/react";

interface FloatingControlsProps {
    open: boolean;
    onClose: () => void;
}

const FloatingControls: React.FC<FloatingControlsProps> = ({open, onClose}) => {
    const bridge = useOCCBridge();
    const eStopModal = useDisclosure();

    const isDirectControl = bridge.mode === "DIRECT";
    const isTrajectory = bridge.mode === "TRAJECTORY";
    const isRemoteActive = bridge.robotState === RobotState.REMOTE_ASSIST;
    const isEStopped = bridge.mode === "ESTOP";

    const handleDirectControl = useCallback(() => {
        bridge.sendCmdVel(0, 0);
        bridge.requestMode("DIRECT");
        bridge.enterRemoteAssist();
    }, [bridge]);

    const handleTrajectoryMode = useCallback(() => {
        bridge.sendCmdVel(0, 0);
        bridge.requestMode("TRAJECTORY");
        bridge.resumeAutonomous();
    }, [bridge]);

    const handleHandBack = useCallback(() => {
        bridge.sendCmdVel(0, 0);
        bridge.requestMode("STANDBY");
    }, [bridge]);

    const handleJoystickMove = useCallback((output: {linear: number; angular: number}) => {
        bridge.sendCmdVel(output.linear, output.angular);
    }, [bridge]);

    const handleEStop = useCallback(() => {
        bridge.triggerEStop();
        eStopModal.onClose();
    }, [bridge, eStopModal]);

    if (!open) return null;

    return (
        <>
            <div className="absolute bottom-36 left-3 w-[260px] pointer-events-auto z-10">
                <div className="bg-black/70 backdrop-blur-md rounded-xl p-4 space-y-4 border border-white/10">
                    <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-white/80">Controls</span>
                        <button
                            onClick={onClose}
                            className="text-white/40 hover:text-white/80 transition-colors"
                        >
                            <IconX size={18} />
                        </button>
                    </div>

                    <div className="flex gap-1.5">
                        <button
                            onClick={handleTrajectoryMode}
                            disabled={isEStopped}
                            className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                                isTrajectory
                                    ? 'bg-primary/80 text-white'
                                    : isEStopped
                                        ? 'bg-white/5 text-white/30 cursor-not-allowed'
                                        : 'bg-white/10 text-white hover:bg-white/20'
                            }`}
                        >
                            <IconRoute size={18} />
                            Trajectory
                        </button>
                        <button
                            onClick={handleDirectControl}
                            disabled={isEStopped}
                            className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                                isDirectControl
                                    ? 'bg-primary/80 text-white'
                                    : isEStopped
                                        ? 'bg-white/5 text-white/30 cursor-not-allowed'
                                        : 'bg-white/10 text-white hover:bg-white/20'
                            }`}
                        >
                            <IconSteeringWheel size={18} />
                            Direct
                        </button>
                    </div>

                    {isEStopped && (
                        <div className="text-center text-xs text-red-400 font-bold py-1 bg-red-600/20 rounded-lg animate-pulse">
                            EMERGENCY STOP ACTIVE
                        </div>
                    )}

                    {isRemoteActive && !isEStopped && (
                        <div className="text-center text-xs text-primary font-medium py-1 bg-primary/10 rounded-lg">
                            Remote Assist Active
                        </div>
                    )}

                    {isDirectControl && (
                        <div className="flex justify-center">
                            <VirtualJoystick
                                size={160}
                                maxLinear={1.4}
                                maxAngular={1.0}
                                disabled={!isDirectControl || isEStopped}
                                onMove={handleJoystickMove}
                            />
                        </div>
                    )}

                    <button
                        onClick={handleHandBack}
                        disabled={isEStopped}
                        className={`w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                            isEStopped
                                ? 'bg-white/5 text-white/30 cursor-not-allowed'
                                : 'bg-primary/20 text-white hover:bg-primary/30'
                        }`}
                    >
                        <IconArrowBack size={18} />
                        Hand Back to Automation
                    </button>

                    <button
                        onClick={eStopModal.onOpen}
                        className={`w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-sm font-bold transition-colors ${
                            isEStopped
                                ? 'bg-red-600 text-white'
                                : 'bg-red-600/30 text-red-400 hover:bg-red-600/50'
                        }`}
                    >
                        <IconHandStop size={20} />
                        E-STOP
                    </button>
                </div>
            </div>

            <Modal isOpen={eStopModal.isOpen} onClose={eStopModal.onClose} placement="center">
                <ModalContent>
                    <ModalHeader className="text-danger">Emergency Stop</ModalHeader>
                    <ModalBody>
                        <p>
                            Are you sure you want to trigger Emergency Stop on <strong>{bridge.selectedVehicleName}</strong>?
                            The robot will halt immediately.
                        </p>
                    </ModalBody>
                    <ModalFooter>
                        <Button variant="light" onPress={eStopModal.onClose}>Cancel</Button>
                        <Button color="danger" onPress={handleEStop}>Confirm E-STOP</Button>
                    </ModalFooter>
                </ModalContent>
            </Modal>
        </>
    );
};

export default FloatingControls;
