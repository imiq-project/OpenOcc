'use client';

import React from "react";
import {Button, Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, useDisclosure} from "@heroui/react";
import {IconHandStop} from "@tabler/icons-react";
import {useOCCBridge} from "@/context/OCCBridgeContext";

export const EStopButton: React.FC = () => {
    const triggerModal = useDisclosure();
    const clearModal = useDisclosure();
    const bridge = useOCCBridge();
    const isEStopped = bridge.mode === "ESTOP";

    const handleTriggerConfirm = () => {
        bridge.triggerEStop();
        triggerModal.onClose();
    };

    const handleClearConfirm = () => {
        bridge.clearEStop();
        clearModal.onClose();
    };

    const handlePress = () => {
        if (isEStopped) {
            clearModal.onOpen();
        } else {
            triggerModal.onOpen();
        }
    };

    return (
        <>
            <Button
                color="danger"
                variant={isEStopped ? "solid" : "flat"}
                onPress={handlePress}
                startContent={<IconHandStop size={18} />}
                size="sm"
                className="font-bold"
            >
                {isEStopped ? "CLEAR E-STOP" : "E-STOP"}
            </Button>

            {/* Trigger confirmation */}
            <Modal isOpen={triggerModal.isOpen} onClose={triggerModal.onClose} placement="center">
                <ModalContent>
                    <ModalHeader className="text-danger">Emergency Stop</ModalHeader>
                    <ModalBody>
                        <p>
                            Are you sure you want to trigger Emergency Stop on <strong>{bridge.selectedVehicleName}</strong>?
                            The robot will halt immediately.
                        </p>
                    </ModalBody>
                    <ModalFooter>
                        <Button variant="light" onPress={triggerModal.onClose}>Cancel</Button>
                        <Button color="danger" onPress={handleTriggerConfirm}>Confirm E-STOP</Button>
                    </ModalFooter>
                </ModalContent>
            </Modal>

            {/* Clear confirmation (two-click: press button + confirm dialog) */}
            <Modal isOpen={clearModal.isOpen} onClose={clearModal.onClose} placement="center">
                <ModalContent>
                    <ModalHeader className="text-warning">Clear Emergency Stop</ModalHeader>
                    <ModalBody>
                        <p>
                            Are you sure you want to clear Emergency Stop on <strong>{bridge.selectedVehicleName}</strong>?
                            The robot will return to standby mode. Verify the area is safe before proceeding.
                        </p>
                    </ModalBody>
                    <ModalFooter>
                        <Button variant="light" onPress={clearModal.onClose}>Cancel</Button>
                        <Button color="warning" onPress={handleClearConfirm}>Confirm Clear</Button>
                    </ModalFooter>
                </ModalContent>
            </Modal>
        </>
    );
};
