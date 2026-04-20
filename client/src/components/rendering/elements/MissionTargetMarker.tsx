import React, {useMemo} from "react";
import {OpenStreetMap} from "@/model/OpenStreetMap";
import {Vector3} from "three";

export type MissionTargetMarkerProps = {
    map: OpenStreetMap;
    latitude: number;
    longitude: number;
    label: string;
    color: string;
};

const MissionTargetMarker: React.FC<MissionTargetMarkerProps> = ({map, latitude, longitude, label, color}) => {
    const position = useMemo(() => {
        const normalizedPos = map.convertAndNormalize({latitude, longitude});
        return new Vector3(normalizedPos.x, normalizedPos.y, 0);
    }, [map, latitude, longitude]);

    const poleHeight = 4.0;
    const poleRadius = 0.1;
    const sphereRadius = 0.5;

    return (
        <group position={position}>
            <mesh position={[0, 0, poleHeight / 2]} castShadow>
                <cylinderGeometry args={[poleRadius, poleRadius, poleHeight, 8]}/>
                <meshPhongMaterial color="#444444"/>
            </mesh>
            <mesh position={[0, 0, poleHeight + sphereRadius * 0.5]} castShadow>
                <sphereGeometry args={[sphereRadius, 16, 12]}/>
                <meshPhongMaterial color={color} emissive={color} emissiveIntensity={0.3}/>
            </mesh>
            <mesh position={[0, 0, poleHeight - 0.3]} rotation={[Math.PI, 0, 0]} castShadow>
                <coneGeometry args={[0.4, 0.8, 16]}/>
                <meshPhongMaterial color={color} emissive={color} emissiveIntensity={0.3}/>
            </mesh>
        </group>
    );
};

export default MissionTargetMarker;
