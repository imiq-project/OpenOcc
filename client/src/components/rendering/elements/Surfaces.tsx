import {OpenStreetMap} from "@/model/OpenStreetMap";
import React, {useMemo} from "react";
// @ts-ignore
import {mergeGeometries} from "three/examples/jsm/utils/BufferGeometryUtils";
import {Shape, ShapeGeometry} from "three";

export type SurfacesProps = {
    map: OpenStreetMap;
};

const Surfaces: React.FC<SurfacesProps> = ({map}) => {
    const geometry = useMemo(() => mergeGeometries(map.getLanduses().map(landuse => {
        const shape = new Shape();
        landuse.nodes.forEach((node, index) => {
            const normalizedPosition = map.normalize(node.position.utm);
            if (index === 0) {
                shape.moveTo(normalizedPosition.x, normalizedPosition.y);
            } else {
                shape.lineTo(normalizedPosition.x, normalizedPosition.y);
            }
        });

        return new ShapeGeometry(shape);
    })), [map]);

    return (
        <mesh geometry={geometry} castShadow>
            <meshPhongMaterial color="#5fc278"/>
        </mesh>
    );
};

export default Surfaces;
