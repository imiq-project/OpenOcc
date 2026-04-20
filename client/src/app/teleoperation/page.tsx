'use client';

import React, {useState} from "react";
import dynamic from "next/dynamic";
import CameraRow from "@/components/teleoperation/CameraPanel";
import RobotDetailPanel from "@/components/dashboard/RobotDetailPanel";
import {IconInfoCircle, IconX} from "@tabler/icons-react";
import {Spinner} from "@heroui/react";

const TeleoperationScene = dynamic(() => import("@/components/teleoperation/TeleoperationScene"), {
    ssr: false,
    loading: () => (
        <div className="flex items-center justify-center h-full bg-occ-deep">
            <Spinner size="lg" label="Loading 3D scene..."/>
        </div>
    ),
});

const MiniMap = dynamic(() => import("@/components/teleoperation/MiniMap"), {ssr: false});

export default function TeleoperationPage() {
    const [infoPanelOpen, setInfoPanelOpen] = useState(false);

    return (
        <div className="flex h-full overflow-hidden gap-[2px]">
            <div className="flex-1 flex flex-col min-w-0 gap-[2px]">
                <div className="flex-[40] min-h-0 bg-occ-surface">
                    <CameraRow />
                </div>

                <div className="flex-[60] min-h-0 relative bg-occ-surface">
                    <TeleoperationScene />

                    <button
                        onClick={() => setInfoPanelOpen(prev => !prev)}
                        className="absolute top-16 right-3 w-10 h-10 rounded-full bg-black/50 backdrop-blur-sm hover:bg-black/70 text-white flex items-center justify-center transition-colors shadow-lg z-20"
                        title={infoPanelOpen ? "Close info panel" : "Open info panel"}
                    >
                        {infoPanelOpen
                            ? <IconX size={20} />
                            : <IconInfoCircle size={20} />
                        }
                    </button>
                </div>
            </div>

            <div className={`transition-all duration-300 ease-in-out overflow-hidden bg-occ-surface ${
                infoPanelOpen ? 'w-[340px] min-w-[340px]' : 'w-0 min-w-0'
            }`}>
                <div className="w-[340px] h-full p-2 pb-6 flex flex-col gap-2 overflow-hidden">
                    <RobotDetailPanel />
                    <MiniMap />
                </div>
            </div>
        </div>
    );
}
