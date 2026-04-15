'use client';

import React, {useState} from "react";
import {Canvas} from "@react-three/fiber";
import {Color, Object3D, Vector3} from "three";
import useOpenStreetMap from "@/hooks/useOpenStreetMap";
import Streets from "@/components/rendering/elements/Streets";
import Buildings from "@/components/rendering/elements/Buildings";
import Surfaces from "@/components/rendering/elements/Surfaces";
import Ground from "@/components/rendering/elements/Ground";
import EgoVehicle from "@/components/rendering/elements/EgoVehicle";
import Trajectory from "@/components/rendering/elements/Trajectory";
import Objects from "@/components/rendering/elements/Objects";
import GeofenceOverlay from "@/components/rendering/elements/GeofenceOverlay";
import MissionTargetMarker from "@/components/rendering/elements/MissionTargetMarker";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {GEOFENCE_POLYGON} from "@/helper/geofence";
import {VehicleConfigurations, VehicleModel} from "@/model/Configuration";
import {kilometresPerHour} from "@/helper/UnitConversions";
import {Spinner} from "@heroui/react";
import {IconLocation, IconLocationOff} from "@tabler/icons-react";

Object3D.DEFAULT_UP = new Vector3(0, 0, 1);

const FleetMap: React.FC = () => {
    const [map, mapLoading] = useOpenStreetMap();
    const bridge = useOCCBridge();
    const [cameraTracking, setCameraTracking] = useState(true);
    const vehicleConfig = VehicleConfigurations[VehicleModel.Husky];

    if (!map) {
        return (
            <div className="flex items-center justify-center h-full">
                <Spinner size="lg" label="Loading map..."/>
            </div>
        );
    }

    return (
        <div className="h-full w-full">
            <Canvas shadows scene={{background: new Color().setHSL(0.6, 0, 1)}}>
                <hemisphereLight
                    args={[0xffffff, 0xffffff, 2.0]}
                    color={new Color().setHSL(0.6, 1, 0.6)}
                    groundColor={new Color().setHSL(0.095, 1, 0.75)}
                    position={new Vector3(0, 50, 0)}/>
                <directionalLight
                    args={[0xffffff, 3]}
                    color={new Color().setHSL(0.6, 1, 0.6)}
                    position={new Vector3(-1, 1.75, 1).multiplyScalar(30)}
                    castShadow/>
                <ambientLight intensity={0.4}/>

                <Ground map={map}/>
                <Streets map={map}/>
                <Buildings map={map}/>
                <Surfaces map={map}/>

                {bridge.objects.length > 0 && (
                    <Objects map={map} objects={bridge.objects}/>
                )}

                <EgoVehicle
                    map={map}
                    pose={bridge.vehiclePose}
                    cameraTracking={{value: cameraTracking, setValue: setCameraTracking}}/>

                {bridge.trajectory && bridge.vehiclePose && (bridge.trajectory?.poses?.length ?? 0) > 0 && (
                    <Trajectory
                        map={map}
                        trajectory={bridge.trajectory}
                        vehicleWidth={vehicleConfig.dimensions[0]}/>
                )}

                {/* Fleet vehicle markers */}
                {bridge.vehicles
                    .filter((v) => v.Id !== bridge.selectedVehicleId && v.Lat !== 0 && v.Lon !== 0)
                    .map((v) => (
                        <MissionTargetMarker
                            key={v.Id}
                            map={map}
                            latitude={v.Lat}
                            longitude={v.Lon}
                            label={v.Name}
                            color={v.Connected ? "#22c55e" : "#6b7280"}
                        />
                    ))}

                <GeofenceOverlay map={map} polygon={GEOFENCE_POLYGON}/>

                {bridge.activeMission && (
                    <>
                        <MissionTargetMarker
                            map={map}
                            latitude={bridge.activeMission.pickup.latitude}
                            longitude={bridge.activeMission.pickup.longitude}
                            label="P"
                            color="#00cc66"/>
                        <MissionTargetMarker
                            map={map}
                            latitude={bridge.activeMission.delivery.latitude}
                            longitude={bridge.activeMission.delivery.longitude}
                            label="D"
                            color="#ff6600"/>
                    </>
                )}
            </Canvas>

            {/* Speed overlay — bottom center, like shuttle debug UI */}
            <div className="absolute bottom-3 left-1/2 -translate-x-1/2 pointer-events-none">
                <div className="bg-black/50 backdrop-blur-sm rounded-xl px-5 py-3 flex flex-col items-center">
                    <span className="text-5xl font-bold font-mono text-white leading-none">
                        {kilometresPerHour(bridge.speed).toFixed(0)}
                    </span>
                    <span className="text-sm text-white/60 mt-1">km/h</span>
                </div>
            </div>

            {/* Re-center button — top right, like shuttle debug UI */}
            <button
                onClick={() => setCameraTracking(!cameraTracking)}
                className="absolute top-3 right-3 w-10 h-10 rounded-full bg-primary hover:bg-primary-400 flex items-center justify-center transition-colors shadow-lg"
                title={cameraTracking ? "Free camera" : "Track robot"}
            >
                {cameraTracking
                    ? <IconLocationOff size={20} className="text-white"/>
                    : <IconLocation size={20} className="text-white"/>
                }
            </button>
        </div>
    );
};

export default FleetMap;
