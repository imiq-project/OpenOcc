'use client';

import React from "react";
import { Card, CardBody, Chip } from "@heroui/react";
import {
    IconCircleFilled,
    IconMapPin,
    IconChevronRight,
} from "@tabler/icons-react";
import { useOCCBridge } from "@/context/OCCBridgeContext";

const VehicleListPanel: React.FC = () => {
    const { vehicles, selectedVehicleId, selectVehicle } = useOCCBridge();

    return (
        <div className="flex flex-col gap-2 h-full overflow-y-auto">
            <p className="occ-section-label px-1 mb-1">
                Vehicles ({vehicles.length})
            </p>
            {vehicles.map((v) => {
                const selected = v.Id === selectedVehicleId;
                return (
                    <Card
                        key={v.Id}
                        isPressable
                        onPress={() => selectVehicle(selected ? null : v.Id)}
                        className={`border bg-occ-surface cursor-pointer transition-colors ${
                            selected
                                ? "border-primary"
                                : "border-occ-border hover:border-default-400"
                        }`}
                    >
                        <CardBody className="p-2.5 gap-1">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <IconCircleFilled
                                        size={10}
                                        className={v.Connected ? "text-success" : "text-default-400"}
                                    />
                                    <span className="text-sm font-medium text-default-100">
                                        {v.Name}
                                    </span>
                                </div>
                                <div className="flex items-center gap-1.5">
                                    <Chip
                                        size="sm"
                                        variant="flat"
                                        color={v.Connected ? "success" : "default"}
                                    >
                                        {v.Connected ? "Online" : "Offline"}
                                    </Chip>
                                    {selected && (
                                        <IconChevronRight size={14} className="text-primary" />
                                    )}
                                </div>
                            </div>
                            <div className="flex items-center gap-1 text-xs text-default-500">
                                <IconMapPin size={12} />
                                <span className="font-mono">
                                    {v.Lat.toFixed(4)}, {v.Lon.toFixed(4)}
                                </span>
                            </div>
                        </CardBody>
                    </Card>
                );
            })}
            {vehicles.length === 0 && (
                <p className="text-xs text-default-500 text-center py-4">
                    No vehicles connected
                </p>
            )}
        </div>
    );
};

export default VehicleListPanel;
