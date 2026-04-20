import {Entity, OpenStreetMap} from "@/model/OpenStreetMap";
import React, {useMemo} from "react";
// @ts-ignore
import {mergeGeometries} from "three/examples/jsm/utils/BufferGeometryUtils";
import {ExtrudeGeometry, Shape} from "three";
import {AttributeKeys, EntityDefaults, EntityDimensions} from "@/model/RendererConfiguration";

export type BuildingsProps = {
    map: OpenStreetMap;
};

const Buildings: React.FC<BuildingsProps> = ({map}) => {
    const computeBuildingHeight = (building: Entity): number => {
        return (building.properties[AttributeKeys.LEVELS] ?? EntityDefaults.LEVELS) * EntityDimensions.LEVEL
            + (building.properties[AttributeKeys.ROOF_LEVELS] ?? EntityDefaults.ROOF_LEVELS) * EntityDimensions.ROOF;
    };

    const geometry = useMemo(() => mergeGeometries(map.getBuildings().map(building => {
        const shape = new Shape();
        building.nodes.forEach((node, index) => {
            const normalizedPosition = map.normalize(node.position.utm);
            if (index === 0) {
                shape.moveTo(normalizedPosition.x, normalizedPosition.y);
            } else {
                shape.lineTo(normalizedPosition.x, normalizedPosition.y);
            }
        });

        return new ExtrudeGeometry(shape, {
            curveSegments: 1,
            depth: computeBuildingHeight(building),
            bevelEnabled: false,
        });
    })), [map]);

    return (
        <mesh geometry={geometry} castShadow>
            <meshPhongMaterial color="#dbdbdb" transparent opacity={0.8}/>
        </mesh>
    );
};

export default Buildings;
