'use client';

import React, { useState, useCallback } from "react";
import { Card, CardBody } from "@heroui/react";
import { IconTruckDelivery } from "@tabler/icons-react";
import { useOCCBridge } from "@/context/OCCBridgeContext";
import { OCCMission } from "@/model/OCCMessages";
import MissionQueue from "@/components/mission/MissionQueue";
import MissionEditor from "@/components/mission/MissionEditor";

type EditorMode = "none" | "create" | "detail";

export default function MissionPage() {
    const bridge = useOCCBridge();
    const [selectedMissionId, setSelectedMissionId] = useState<string | null>(null);
    const [editorMode, setEditorMode] = useState<EditorMode>("none");

    const selectedMission = selectedMissionId
        ? bridge.missions.find(m => m.id === selectedMissionId) ?? null
        : null;

    const handleSelectMission = useCallback((id: string) => {
        setSelectedMissionId(id);
        setEditorMode("detail");
    }, []);

    const handleNewMission = useCallback(() => {
        setSelectedMissionId(null);
        setEditorMode("create");
    }, []);

    const handleSave = useCallback((mission: OCCMission) => {
        bridge.addMission(mission);
        setSelectedMissionId(mission.id);
        setEditorMode("detail");
    }, [bridge]);

    const handleCancelMission = useCallback((id: string) => {
        bridge.cancelMission(id);
    }, [bridge]);

    const handleClose = useCallback(() => {
        setEditorMode("none");
        setSelectedMissionId(null);
    }, []);

    return (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-2 h-full">
            <Card className="lg:col-span-4 xl:col-span-3 occ-card">
                <CardBody className="p-2">
                    <MissionQueue
                        missions={bridge.missions}
                        selectedMissionId={selectedMissionId}
                        onSelectMission={handleSelectMission}
                        onNewMission={handleNewMission}
                    />
                </CardBody>
            </Card>

            <Card className="lg:col-span-8 xl:col-span-9 occ-card">
                <CardBody className="p-3">
                    {editorMode === "none" ? (
                        <div className="flex flex-col items-center justify-center h-full text-default-400">
                            <IconTruckDelivery size={48} />
                            <p className="text-lg mt-3">Select a mission or create a new one</p>
                            <p className="text-sm">Use the queue on the left to browse missions</p>
                        </div>
                    ) : (
                        <MissionEditor
                            key={editorMode === "create" ? "create" : selectedMissionId}
                            mission={selectedMission}
                            mode={editorMode === "create" ? "create" : "detail"}
                            onSave={handleSave}
                            onCancel={handleClose}
                            onCancelMission={handleCancelMission}
                        />
                    )}
                </CardBody>
            </Card>
        </div>
    );
}
