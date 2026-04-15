import React, {useMemo, useRef} from "react";
import {OpenStreetMap} from "@/model/OpenStreetMap";
import {PointCloud} from "@/model/ROSMessages";
import {BufferAttribute, Points} from "three";
import {useFrame} from "@react-three/fiber";

export interface PointCloudsProps {
    map: OpenStreetMap;
    pointCloud: PointCloud;
}

const POINT_COLOR = 0xe040e0; // magenta/pink

const PointClouds: React.FC<PointCloudsProps> = ({map, pointCloud}) => {
    const pointsRef = useRef<Points>(null);

    const positions = useMemo(() => {
        const pts = pointCloud.points;
        const count = Math.floor(pts.length / 3);
        const arr = new Float32Array(count * 3);

        for (let i = 0; i < count; i++) {
            const utmX = pts[i * 3];
            const utmY = pts[i * 3 + 1];
            const z = pts[i * 3 + 2];

            const normalized = map.normalize({x: utmX, y: utmY});
            arr[i * 3] = normalized.x;
            arr[i * 3 + 1] = normalized.y;
            arr[i * 3 + 2] = z;
        }

        return arr;
    }, [pointCloud, map]);

    useFrame(() => {
        if (pointsRef.current) {
            const geom = pointsRef.current.geometry;
            const attr = geom.getAttribute("position") as BufferAttribute;
            if (attr && attr.array !== positions) {
                geom.setAttribute("position", new BufferAttribute(positions, 3));
            }
        }
    });

    return (
        <points ref={pointsRef}>
            <bufferGeometry>
                <bufferAttribute
                    attach="attributes-position"
                    array={positions}
                    count={positions.length / 3}
                    itemSize={3}
                />
            </bufferGeometry>
            <pointsMaterial
                color={POINT_COLOR}
                size={0.15}
                sizeAttenuation
                transparent
                opacity={0.8}
            />
        </points>
    );
};

export default PointClouds;
