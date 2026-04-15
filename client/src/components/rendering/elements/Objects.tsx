import {OpenStreetMap} from "@/model/OpenStreetMap";
import {Object3D} from "@/model/ROSMessages";
import {ExtrudeGeometry, Shape} from "three";
import React, {useMemo} from "react";
// @ts-ignore
import {mergeGeometries} from "three/examples/jsm/utils/BufferGeometryUtils.js";
import {rotateZ} from "@/helper/CoordinateConversions";

export type ObjectsProps = {
    map: OpenStreetMap;
    objects: Object3D[];
};

const Objects: React.FC<ObjectsProps> = ({map, objects}) => {
    const geometry = useMemo(() => mergeGeometries(objects.map(obstacle => {
        const shape = new Shape();
        const centerPosition = map.normalize({x: obstacle.utm_position.x, y: obstacle.utm_position.y});

        const positionDeltas = [
            {x: obstacle.width / 2, y: obstacle.length / 2},
            {x: -obstacle.width / 2, y: obstacle.length / 2},
            {x: -obstacle.width / 2, y: -obstacle.length / 2},
            {x: obstacle.width / 2, y: -obstacle.length / 2},
        ];

        positionDeltas.forEach((position, index) => {
            const rotatedDelta = rotateZ(position.x, position.y, obstacle.yaw);
            if (index === 0) {
                shape.moveTo(centerPosition.x + rotatedDelta.x, centerPosition.y + rotatedDelta.y);
            } else {
                shape.lineTo(centerPosition.x + rotatedDelta.x, centerPosition.y + rotatedDelta.y);
            }
        });

        const extrudeGeometry = new ExtrudeGeometry(shape, {
            curveSegments: 1,
            depth: obstacle.height,
            bevelEnabled: false,
        });

        extrudeGeometry.translate(0, 0, obstacle.utm_position.z);
        return extrudeGeometry;
    })), [objects]);

    return (
        <mesh geometry={geometry} castShadow>
            <meshPhongMaterial color="#ff6b35" transparent opacity={0.7}/>
        </mesh>
    );
};

export default Objects;
