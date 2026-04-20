import {OpenStreetMap} from "@/model/OpenStreetMap";
import {Trajectory as ROSTrajectory} from "@/model/ROSMessages";
import React, {useMemo, useRef} from "react";
import {computeCurve} from "@/helper/ThreeUtils";
import * as THREE from "three";
import {BufferAttribute, Color, InterleavedBufferAttribute, ShaderMaterial, Vector3} from "three";
import {useFrame} from "@react-three/fiber";

export type TrajectoryProps = {
    map: OpenStreetMap;
    trajectory: ROSTrajectory;
    vehicleWidth: number;
};

const positionToVector = (position: BufferAttribute | InterleavedBufferAttribute, index: number): Vector3 => new Vector3(
    position.getX(index),
    position.getY(index),
    position.getZ(index),
);

const Trajectory: React.FC<TrajectoryProps> = ({map, trajectory, vehicleWidth}) => {
    const materialRef = useRef<ShaderMaterial | null>(null);

    const geometry = useMemo(() => {
        if (trajectory.poses.length === 1) {
            const pointGeometry = new THREE.BufferGeometry();
            const normalizedPoint = map.normalize({
                x: trajectory.poses[0].utm_position.x,
                y: trajectory.poses[0].utm_position.y,
            });
            const vertices = new Float32Array([normalizedPoint.x, normalizedPoint.y, 0]);
            pointGeometry.setAttribute('position', new THREE.BufferAttribute(vertices, 3));
            return pointGeometry;
        }

        const curveGeometry = computeCurve(trajectory.poses.map(pose => map.normalize({
            x: pose.utm_position.x,
            y: pose.utm_position.y,
        })), vehicleWidth, 0.05, false);
        curveGeometry.computeBoundingBox();

        if (curveGeometry.boundingBox) {
            if (curveGeometry.boundingBox.min.equals(curveGeometry.boundingBox.max)) {
                curveGeometry.boundingBox.min.subScalar(0.1);
                curveGeometry.boundingBox.max.addScalar(0.1);
            }
        }

        const positionAttribute = curveGeometry.getAttribute('position');
        const vertexCount = positionAttribute.count;
        const progress = new Float32Array(vertexCount);

        let totalLength = 0;
        let lengths = [0];

        for (let i = 1; i < vertexCount; i++) {
            const previous = positionToVector(positionAttribute, i - 1);
            const current = positionToVector(positionAttribute, i);
            totalLength += previous.distanceTo(current);
            lengths.push(totalLength);
        }

        for (let i = 0; i < vertexCount; i++) {
            progress[i] = lengths[i] / totalLength;
        }

        curveGeometry.setAttribute('aProgress', new BufferAttribute(progress, 1));
        return curveGeometry;
    }, [map, trajectory]);

    useFrame((_, delta) => {
        if (materialRef.current) {
            materialRef.current.uniforms.time.value += delta;
        }
    });

    const shaderMaterial = useMemo(() => {
        return new ShaderMaterial({
            uniforms: {
                time: {value: 0.0},
                startColor: {value: new Color("#2d53d6")},
                endColor: {value: new Color("#446DF6")},
            },
            vertexShader: `
                attribute float aProgress;
                varying float vProgress;
                void main() {
                    vProgress = aProgress;
                    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
                }
            `,
            fragmentShader: `
                uniform vec3 startColor;
                uniform vec3 endColor;
                uniform float time;
                varying float vProgress;
                void main() {
                    vec3 baseColor = mix(startColor, endColor, vProgress);
                    float wave = sin(vProgress * 40.0 - time * 5.0);
                    float mask = (wave * 0.5 + 0.5) * 0.3;
                    gl_FragColor = vec4(baseColor + mask * vec3(1.0), 1.0);
                }
            `
        });
    }, []);

    return (
        <mesh geometry={geometry} position={new Vector3(0, 0, 0.2)}>
            <primitive object={shaderMaterial} ref={materialRef}/>
        </mesh>
    );
};

export default Trajectory;
