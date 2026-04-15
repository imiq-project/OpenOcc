'use client';

import React from "react";
import {
    Table,
    TableHeader,
    TableColumn,
    TableBody,
    TableRow,
    TableCell,
    Chip,
} from "@heroui/react";
import { IconMapPin } from "@tabler/icons-react";
import { GEOFENCE_POLYGON } from "@/helper/geofence";

const GeofenceSettings: React.FC = () => {
    return (
        <div className="flex flex-col gap-4">
            <h3 className="text-lg font-semibold">Geofence</h3>

            <div className="flex items-center gap-2">
                <IconMapPin size={18} className="text-primary" />
                <span className="text-sm font-medium">Wissenschaftshafen Magdeburg</span>
                <Chip size="sm" variant="flat" color="warning">Hardcoded</Chip>
            </div>

            <Table aria-label="Geofence coordinates" removeWrapper>
                <TableHeader>
                    <TableColumn>Point</TableColumn>
                    <TableColumn>Latitude</TableColumn>
                    <TableColumn>Longitude</TableColumn>
                </TableHeader>
                <TableBody>
                    {GEOFENCE_POLYGON.map((point, i) => (
                        <TableRow key={i}>
                            <TableCell className="font-medium">P{i + 1}</TableCell>
                            <TableCell className="font-mono text-sm">{point.latitude.toFixed(5)}</TableCell>
                            <TableCell className="font-mono text-sm">{point.longitude.toFixed(5)}</TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>

            <div className="bg-default-100 rounded-lg p-6 flex items-center justify-center h-48">
                <p className="text-sm text-default-400">
                    Map preview — Geofence editor will be available in a future update
                </p>
            </div>
        </div>
    );
};

export default GeofenceSettings;
