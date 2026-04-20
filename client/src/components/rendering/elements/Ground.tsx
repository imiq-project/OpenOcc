import {OpenStreetMap} from "@/model/OpenStreetMap";
import React from "react";
import {DoubleSide, Vector3} from "three";

export type GroundProps = {
    map: OpenStreetMap;
};

const Ground: React.FC<GroundProps> = ({map}) => {
    return (
        <mesh position={new Vector3(0, 0, -0.1)} castShadow>
            <meshPhongMaterial color="#c7c7c7" side={DoubleSide}/>
            <planeGeometry args={[
                (map.getBounds().maximum.utm.x - map.getBounds().minimum.utm.x) * 2,
                (map.getBounds().maximum.utm.y - map.getBounds().minimum.utm.y) * 2,
            ]}/>
        </mesh>
    );
};

export default Ground;
