import React, {useMemo, useRef} from "react";
import {useFrame, useLoader} from "@react-three/fiber";
// @ts-ignore
import {FBXLoader} from "three/examples/jsm/loaders/FBXLoader";
import {Euler, Object3D, Vector3} from "three";
import {OpenStreetMap} from "@/model/OpenStreetMap";
import {VehiclePose} from "@/model/ROSMessages";
import {OrbitControls} from "@react-three/drei";
import {State} from "@/model/ReactTypes";
import {VehicleConfigurations, VehicleModel} from "@/model/Configuration";

export type EgoVehicleProps = {
    map: OpenStreetMap;
    pose: VehiclePose | null;
    cameraTracking: State<boolean>;
};

const EgoVehicle: React.FC<EgoVehicleProps> = ({map, pose, cameraTracking}) => {
    const configuration = VehicleConfigurations[VehicleModel.Husky];

    const rawModel = useLoader(FBXLoader, "api/model");
    const model = useMemo(() => configuration.modelLoaded(rawModel), [rawModel]);

    const vehicleRef = useRef<Object3D>(null);
    const controlsRef = useRef<any>(null);
    const wasTrackingRef = useRef(false);

    const cameraWidth = 300;

    useFrame(({camera}) => {
        if (vehicleRef.current) {
            if (map && pose) {
                const position = map.convertAndNormalize({
                    latitude: pose.latitude,
                    longitude: pose.longitude,
                });

                vehicleRef.current.rotation.z = pose.yaw;
                vehicleRef.current.position.lerp(
                    new Vector3(position.x, position.y, vehicleRef.current.position.z),
                    0.09
                );
            }

            if (cameraTracking.value) {
                const cameraVector = new Vector3(
                    Math.cos(vehicleRef.current.rotation.z),
                    Math.sin(vehicleRef.current.rotation.z),
                    0
                );
                cameraVector.normalize();

                const viewConfig = configuration.viewportParameters.moving;

                const lookAtVector = cameraVector.clone()
                    .multiplyScalar(viewConfig.lookAhead)
                    .add(vehicleRef.current.position);

                const offsetVector = cameraVector.clone()
                    .multiplyScalar(-viewConfig.backupDistance)
                    .add(vehicleRef.current.position)
                    .setZ(viewConfig.zOffset);

                // Snap camera on first frame after re-center, then smooth follow
                const justStartedTracking = !wasTrackingRef.current;
                const lerpFactor = justStartedTracking ? 1.0 : 0.05;

                camera.position.lerp(offsetVector, lerpFactor);
                camera.lookAt(lookAtVector);
                controlsRef.current?.target.lerp(lookAtVector, lerpFactor);
            }

            wasTrackingRef.current = cameraTracking.value;
        }
    });

    return (
        <>
            <orthographicCamera
                left={cameraWidth / -4}
                right={cameraWidth / 4}
                top={cameraWidth / 4}
                bottom={cameraWidth / -4}
                near={0}
                far={4000}/>
            <OrbitControls
                ref={controlsRef}
                onStart={() => cameraTracking.setValue(false)}
                enableDamping
                dampingFactor={0.25}
                screenSpacePanning={false}
                maxDistance={800}/>
            <primitive
                ref={vehicleRef}
                castShadow={true}
                rotation={new Euler(0, 0, 0)}
                object={model}/>
        </>
    );
};

export default EgoVehicle;
