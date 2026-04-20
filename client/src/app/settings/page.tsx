'use client';

import React, { useState } from "react";
import { Card, CardBody, Listbox, ListboxItem } from "@heroui/react";
import {
    IconCar,
    IconPlugConnected,
    IconMapPin,
    IconUsers,
    IconBell,
    IconHeartRateMonitor,
} from "@tabler/icons-react";
import VehicleSettings from "@/components/settings/VehicleSettings";
import ConnectionSettings from "@/components/settings/ConnectionSettings";
import GeofenceSettings from "@/components/settings/GeofenceSettings";
import UserSettings from "@/components/settings/UserSettings";
import AlertSettings from "@/components/settings/AlertSettings";
import SystemHealth from "@/components/settings/SystemHealth";

const TABS = [
    { key: "vehicles", label: "Vehicles", icon: <IconCar size={18} /> },
    { key: "connection", label: "Connection", icon: <IconPlugConnected size={18} /> },
    { key: "geofence", label: "Geofence", icon: <IconMapPin size={18} /> },
    { key: "users", label: "Users", icon: <IconUsers size={18} /> },
    { key: "alerts", label: "Alerts", icon: <IconBell size={18} /> },
    { key: "health", label: "System Health", icon: <IconHeartRateMonitor size={18} /> },
];

const PANEL_MAP: Record<string, React.FC> = {
    vehicles: VehicleSettings,
    connection: ConnectionSettings,
    geofence: GeofenceSettings,
    users: UserSettings,
    alerts: AlertSettings,
    health: SystemHealth,
};

export default function SettingsPage() {
    const [activeTab, setActiveTab] = useState("vehicles");
    const ActivePanel = PANEL_MAP[activeTab];

    return (
        <div className="flex flex-col md:flex-row gap-2 h-full">
            <Card className="md:w-48 shrink-0 occ-card">
                <CardBody className="p-2">
                    <Listbox
                        aria-label="Settings tabs"
                        selectionMode="single"
                        selectedKeys={new Set([activeTab])}
                        onSelectionChange={keys => {
                            const key = Array.from(keys)[0] as string;
                            if (key) setActiveTab(key);
                        }}
                    >
                        {TABS.map(tab => (
                            <ListboxItem
                                key={tab.key}
                                startContent={tab.icon}
                            >
                                {tab.label}
                            </ListboxItem>
                        ))}
                    </Listbox>
                </CardBody>
            </Card>

            <Card className="flex-1 occ-card">
                <CardBody className="p-4">
                    {ActivePanel && <ActivePanel />}
                </CardBody>
            </Card>
        </div>
    );
}
