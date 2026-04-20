import {wgs84ToUTMPosition} from "@/helper/CoordinateConversions";

export class OpenStreetMap {

    public _bounds: MapBounds;
    public _entities: Entity[];

    public _center: UTMPosition;

    constructor(bounds: MapBounds, entities: Entity[]) {
        this._bounds = bounds;
        this._entities = entities;

        this._center = {
            x: (this._bounds.maximum.utm.x + this._bounds.minimum.utm.x) / 2,
            y: (this._bounds.maximum.utm.y + this._bounds.minimum.utm.y) / 2,
        };
    }

    public getBounds(): MapBounds {
        return this._bounds;
    }

    public normalize(position: UTMPosition): UTMPosition {
        return {
            x: position.x - this._center.x,
            y: position.y - this._center.y,
        };
    }

    public convertAndNormalize(position: WGSPosition): UTMPosition {
        return this.normalize(wgs84ToUTMPosition(position));
    }

    public getCenter(): UTMPosition {
        return this._center;
    }

    public getEntities(): Entity[] {
        return this._entities;
    }

    public getBuildings(): Entity[] {
        return this._entities.filter(entity => entity.type === EntityType.BUILDING);
    }

    public getLanduses(): Entity[] {
        return this._entities.filter(entity => entity.type === EntityType.LANDUSE);
    }

    public getStreets(): Entity[] {
        return this._entities.filter(entity => entity.type === EntityType.STREET);
    }

}

export interface MapBounds {
    minimum: {
        wgs: WGSPosition;
        utm: UTMPosition;
    };
    maximum: {
        wgs: WGSPosition;
        utm: UTMPosition;
    };
}

export interface Entity {
    id: string;
    type: EntityType;
    nodes: Node[];
    properties: { [key: string]: any };
    descendants: string[];
}

export enum EntityType {
    BUILDING = "BUILDING",
    STREET = "STREET",
    LANDUSE = "LANDUSE",
    UNKNOWN = "UNKNOWN"
}

export interface Node {
    id: string;
    position: Position;
}

export interface WGSPosition {
    latitude: number;
    longitude: number;
}

export interface UTMPosition {
    x: number;
    y: number;
}

export interface Position {
    wgs: WGSPosition;
    utm: UTMPosition;
}