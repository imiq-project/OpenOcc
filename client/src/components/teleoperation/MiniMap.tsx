'use client';

import React, {useEffect, useRef} from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "leaflet-defaulticon-compatibility/dist/leaflet-defaulticon-compatibility.css";
import "leaflet-defaulticon-compatibility";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {GEOFENCE_POLYGON} from "@/helper/geofence";

const MAGDEBURG_CENTER: [number, number] = [52.1430, 11.6500];

/** Google-Maps-style blue arrow marker as an SVG DivIcon */
function createDirectionIcon(yawDeg: number): L.DivIcon {
    return L.divIcon({
        className: "",
        iconSize: [40, 40],
        iconAnchor: [20, 20],
        html: `
            <svg width="40" height="40" viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg">
                <circle cx="20" cy="20" r="16" fill="#4285F4" fill-opacity="0.18" stroke="#4285F4" stroke-width="2.5"/>
                <circle cx="20" cy="20" r="7" fill="#4285F4" stroke="#fff" stroke-width="2.5"/>
                <polygon points="20,3 25,14 15,14" fill="#4285F4" stroke="#fff" stroke-width="1"
                         transform="rotate(${yawDeg}, 20, 20)"/>
            </svg>
        `,
    });
}

const MiniMap: React.FC = () => {
    const mapRef = useRef<HTMLDivElement>(null);
    const leafletMap = useRef<L.Map | null>(null);
    const robotMarker = useRef<L.Marker | null>(null);
    const trailLine = useRef<L.Polyline | null>(null);
    const trailPoints = useRef<[number, number][]>([]);
    const bridge = useOCCBridge();

    useEffect(() => {
        if (!mapRef.current || leafletMap.current) return;

        const map = L.map(mapRef.current, {
            center: MAGDEBURG_CENTER,
            zoom: 18,
            zoomControl: false,
            attributionControl: false,
        });

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
        }).addTo(map);

        const geofenceLatLngs = GEOFENCE_POLYGON.map(p => [p.latitude, p.longitude] as [number, number]);
        L.polygon(geofenceLatLngs, {
            color: '#f59e0b',
            weight: 2,
            fillColor: '#f59e0b',
            fillOpacity: 0.08,
            dashArray: '6 4',
        }).addTo(map);

        robotMarker.current = L.marker(MAGDEBURG_CENTER, {
            icon: createDirectionIcon(0),
        }).addTo(map);

        trailLine.current = L.polyline([], {
            color: '#4285F4',
            weight: 2,
            opacity: 0.5,
        }).addTo(map);

        leafletMap.current = map;

        const ro = new ResizeObserver(() => map.invalidateSize());
        ro.observe(mapRef.current);

        return () => {
            ro.disconnect();
            map.remove();
            leafletMap.current = null;
        };
    }, []);

    useEffect(() => {
        if (!bridge.vehiclePose || !robotMarker.current || !leafletMap.current) return;

        const lat = bridge.vehiclePose.latitude;
        const lng = bridge.vehiclePose.longitude;
        const pos: [number, number] = [lat, lng];

        // Convert yaw (radians, 0=East, CCW positive) to degrees (0=North, CW positive)
        const yawDeg = -(bridge.vehiclePose.yaw * 180 / Math.PI) + 90;
        robotMarker.current.setLatLng(pos);
        robotMarker.current.setIcon(createDirectionIcon(yawDeg));

        trailPoints.current.push(pos);
        if (trailPoints.current.length > 200) trailPoints.current.shift();
        trailLine.current?.setLatLngs(trailPoints.current);

        leafletMap.current.panTo(pos, {animate: true, duration: 0.3});
    }, [bridge.vehiclePose]);

    useEffect(() => {
        if (!leafletMap.current || !bridge.activeMission) return;

        const pickup = L.circleMarker(
            [bridge.activeMission.pickup.latitude, bridge.activeMission.pickup.longitude],
            {radius: 6, fillColor: '#00cc66', color: '#fff', weight: 2, fillOpacity: 1}
        ).addTo(leafletMap.current);

        const delivery = L.circleMarker(
            [bridge.activeMission.delivery.latitude, bridge.activeMission.delivery.longitude],
            {radius: 6, fillColor: '#ff6600', color: '#fff', weight: 2, fillOpacity: 1}
        ).addTo(leafletMap.current);

        return () => {
            pickup.remove();
            delivery.remove();
        };
    }, [bridge.activeMission]);

    return (
        <div className="w-full flex-1 min-h-0 rounded-lg overflow-hidden border border-occ-border flex flex-col">
            <div className="bg-occ-surface-raised px-3 py-1.5 text-xs text-default-500 font-medium uppercase tracking-wider border-b border-occ-border shrink-0">
                Live Map
            </div>
            <div ref={mapRef} className="w-full flex-1 min-h-[200px]" />
        </div>
    );
};

export default MiniMap;
