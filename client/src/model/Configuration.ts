import {Group, Object3D} from "three";

export enum VehicleModel {
    Shuttle = 'shuttle',
    Husky = 'husky',
}

export interface ViewportParameters {
    lookAhead: number;
    backupDistance: number;
    zOffset: number;
}

export interface VehicleConfiguration {
    dimensions: [number, number];
    modelLoaded: (model: Group) => Group;
    viewportParameters: {
        idle: ViewportParameters;
        moving: ViewportParameters;
    };
    featureFlags: {
        cloudConnectivity: boolean;
        destinationYaw: boolean;
        behaviorSystem: boolean;
        targetObjects: boolean;
        systemHealth: boolean;
    },
}

export const VehicleConfigurations: Record<VehicleModel, VehicleConfiguration> = {
    [VehicleModel.Shuttle]: {
        dimensions: [1.5, 6.0],
        featureFlags: {
            cloudConnectivity: true,
            destinationYaw: false,
            behaviorSystem: true,
            targetObjects: true,
            systemHealth: true,
        },
        modelLoaded: shuttle => {
            const transformParent = new Object3D();
            transformParent.add(shuttle);
            shuttle.position.x = 0.0;
            shuttle.position.y = -1.0;
            shuttle.position.z = 1.3;
            shuttle.rotation.x = 0.0;
            return transformParent as Group;
        },
        viewportParameters: {
            idle: {
                lookAhead: 3,
                backupDistance: 10,
                zOffset: 10,
            },
            moving: {
                lookAhead: 10,
                backupDistance: 10,
                zOffset: 20,
            },
        },
    },
    [VehicleModel.Husky]: {
        dimensions: [0.67, 0.99],
        featureFlags: {
            cloudConnectivity: false,
            destinationYaw: true,
            behaviorSystem: false,
            targetObjects: false,
            systemHealth: false,
        },
        modelLoaded: husky => {
            const transformParent = new Object3D();
            transformParent.add(husky);
            husky.scale.set(0.01, 0.01, 0.01);
            husky.rotation.x = Math.PI / 2;
            husky.position.set(0, 0, 0.35);
            return transformParent as Group;
        },
        viewportParameters: {
            idle: {
                lookAhead: 0.5,
                backupDistance: 2.5,
                zOffset: 2.0,
            },
            moving: {
                lookAhead: 1.3,
                backupDistance: 4.0,
                zOffset: 4.0,
            },
        },
    }
};
