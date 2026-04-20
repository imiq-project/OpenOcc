import {OpenStreetMap} from "@/model/OpenStreetMap";
import React, {useMemo} from "react";
import {Vector3} from "three";
// @ts-ignore
import {mergeGeometries} from "three/examples/jsm/utils/BufferGeometryUtils";
import {computeCurve} from "@/helper/ThreeUtils";
import {EntityDimensions} from "@/model/RendererConfiguration";

export type StreetsProps = {
    map: OpenStreetMap;
};

const Streets: React.FC<StreetsProps> = ({map}) => {
    const geometry = useMemo(() => mergeGeometries(map.getStreets().map(street => computeCurve(
        street.nodes.map(node => map.normalize(node.position.utm)),
        EntityDimensions.STREET,
        0.01,
        false,
    ))), [map]);

    return (
        <mesh
            geometry={geometry}
            castShadow
            position={new Vector3(0, 0, 0.1)}>
            <meshPhongMaterial color="white"/>
        </mesh>
    );
};

export default Streets;
