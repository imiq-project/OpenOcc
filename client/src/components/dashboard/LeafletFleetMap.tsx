'use client';

import React, { useMemo } from "react";
import dynamic from "next/dynamic";
import { useOCCBridge } from "@/context/OCCBridgeContext";

const MapContainer = dynamic(
    () => import("react-leaflet").then((m) => m.MapContainer),
    { ssr: false },
);
const TileLayer = dynamic(
    () => import("react-leaflet").then((m) => m.TileLayer),
    { ssr: false },
);
const Marker = dynamic(
    () => import("react-leaflet").then((m) => m.Marker),
    { ssr: false },
);
const Popup = dynamic(
    () => import("react-leaflet").then((m) => m.Popup),
    { ssr: false },
);

import "leaflet/dist/leaflet.css";
import "leaflet-defaulticon-compatibility/dist/leaflet-defaulticon-compatibility.css";
import "leaflet-defaulticon-compatibility";

import type { Vehicle } from "@/bridge/WebTransportClient";

interface VehicleMarkerProps {
    vehicle: Vehicle;
    isSelected: boolean;
    onSelect: (id: string) => void;
}

function VehicleMarkerInner({ vehicle, isSelected, onSelect }: VehicleMarkerProps) {
    const icon = useMemo(() => {
        const L = require("leaflet");
        const color = !vehicle.Connected
            ? "#71717a"
            : isSelected
              ? "#006FEE"
              : "#17c964";

        return L.divIcon({
            className: "custom-vehicle-marker",
            html: `
                <div style="
                    width: 28px; height: 28px;
                    background: ${color};
                    border: 2px solid white;
                    border-radius: 50%;
                    display: flex; align-items: center; justify-content: center;
                    box-shadow: 0 2px 6px rgba(0,0,0,0.4);
                    cursor: pointer;
                    font-size: 11px; font-weight: 600; color: white;
                ">${vehicle.Name.charAt(0)}</div>
            `,
            iconSize: [28, 28],
            iconAnchor: [14, 14],
        });
    }, [vehicle.Connected, vehicle.Name, isSelected]);

    return (
        <Marker
            position={[vehicle.Lat, vehicle.Lon]}
            icon={icon}
            eventHandlers={{ click: () => onSelect(vehicle.Id) }}
        >
            <Popup>
                <div className="text-xs">
                    <p className="font-semibold">{vehicle.Name}</p>
                    <p>{vehicle.Connected ? "Connected" : "Offline"}</p>
                    <p className="font-mono text-[10px]">
                        {vehicle.Lat.toFixed(5)}, {vehicle.Lon.toFixed(5)}
                    </p>
                </div>
            </Popup>
        </Marker>
    );
}

const LeafletFleetMap: React.FC = () => {
    const { vehicles, selectedVehicleId, selectVehicle } = useOCCBridge();

    const center = useMemo<[number, number]>(() => {
        if (vehicles.length > 0) {
            return [vehicles[0].Lat, vehicles[0].Lon];
        }
        return [52.1396, 11.6452]; // Otto von Guericke University
    }, [vehicles]);

    return (
        <div className="w-full h-full rounded-lg overflow-hidden border border-occ-border">
            <MapContainer
                center={center}
                zoom={17}
                className="w-full h-full"
                style={{ background: "rgb(14 15 20)" }}
            >
                <TileLayer
                    url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>'
                />
                {vehicles.map((v) => (
                    <VehicleMarkerInner
                        key={v.Id}
                        vehicle={v}
                        isSelected={v.Id === selectedVehicleId}
                        onSelect={(id) =>
                            selectVehicle(id === selectedVehicleId ? null : id)
                        }
                    />
                ))}
            </MapContainer>
        </div>
    );
};

export default LeafletFleetMap;
