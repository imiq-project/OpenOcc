import React, {useMemo, useRef, useEffect} from "react";
import {OpenStreetMap} from "@/model/OpenStreetMap";
import * as THREE from "three";

export type GeofenceOverlayProps = {
    map: OpenStreetMap;
    polygon: Array<{latitude: number; longitude: number}>;
};

const GeofenceOverlay: React.FC<GeofenceOverlayProps> = ({map, polygon}) => {
    const lineRef = useRef<THREE.Line>(null);

    const geometry = useMemo(() => {
        const points = polygon.map(p => {
            const pos = map.convertAndNormalize({latitude: p.latitude, longitude: p.longitude});
            return new THREE.Vector3(pos.x, pos.y, 0.3);
        });
        if (points.length > 0) {
            points.push(points[0].clone());
        }
        return new THREE.BufferGeometry().setFromPoints(points);
    }, [map, polygon]);

    const material = useMemo(() => {
        return new THREE.LineDashedMaterial({
            color: "#ff3333",
            dashSize: 2,
            gapSize: 1,
        });
    }, []);

    useEffect(() => {
        if (lineRef.current) {
            lineRef.current.computeLineDistances();
        }
    }, [geometry]);

    return (
        <primitive ref={lineRef} object={new THREE.Line(geometry, material)}/>
    );
};

export default GeofenceOverlay;
