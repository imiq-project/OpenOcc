import {wgs84ToUTMPosition} from "@/helper/CoordinateConversions";
import {Entity, EntityType, MapBounds, Node, OpenStreetMap, WGSPosition} from "@/model/OpenStreetMap";

export const parseMapData = (xml: string): OpenStreetMap => {
    const parser = new DOMParser();
    const mapDocument = parser.parseFromString(xml, "text/xml");

    const boundsObject = mapDocument.getElementsByTagName("bounds")[0];
    const minBounds: WGSPosition = {
        latitude: parseCoordinate(boundsObject?.getAttribute("minlat")),
        longitude: parseCoordinate(boundsObject?.getAttribute("minlon"))
    };

    const maxBounds: WGSPosition = {
        latitude: parseCoordinate(boundsObject?.getAttribute("maxlat")),
        longitude: parseCoordinate(boundsObject?.getAttribute("maxlon")),
    };

    const mapBounds: MapBounds = {
        minimum: {
            wgs: minBounds,
            utm: wgs84ToUTMPosition(minBounds),
        },
        maximum: {
            wgs: maxBounds,
            utm: wgs84ToUTMPosition(maxBounds),
        },
    };

    const entities = [
        // @ts-ignore
        ...mapDocument.getElementsByTagName("way"),
        // @ts-ignore
        ...mapDocument.getElementsByTagName("relation"),
    ].map(way => {
        const attributes = [...way.getElementsByTagName("tag")].reduce((cur, acc) => ({
            [acc.getAttribute("k")]: acc.getAttribute("v"),
            ...cur,
        }), {});

        const nodes = [...way.getElementsByTagName("nd")].map(node => {
            const nodeReference = mapDocument.querySelector(`node[id="${node.getAttribute("ref")}"]`);
            const wgs = {
                latitude: parseCoordinate(nodeReference?.getAttribute("lat")),
                longitude: parseCoordinate(nodeReference?.getAttribute("lon")),
            } as WGSPosition;

            return {
                id: nodeReference?.getAttribute("id") ?? "",
                position: {
                    wgs: wgs,
                    utm: wgs84ToUTMPosition(wgs),
                }
            } as Node;
        })

        const descendants = [...way.getElementsByTagName("member")].map(member => member.getAttribute("ref"));

        return {
            id: way.getAttribute("id"),
            type: "building" in attributes ? EntityType.BUILDING : "highway" in attributes ? EntityType.STREET : "landuse" in attributes ? EntityType.LANDUSE : EntityType.UNKNOWN,
            nodes,
            properties: attributes,
            descendants: descendants,
        } as Entity;
    });

    entities.forEach(entity => {
        if (entity.descendants.length > 0) {
            entity.descendants.forEach(descendant => {
                const descendantEntity = entities.find(element => element.id === descendant);
                entity.nodes.push(...descendantEntity?.nodes ?? []);
            });
        }
    });

    return new OpenStreetMap(mapBounds, entities);
};

const parseCoordinate = (value?: string | null): number => parseFloat(value ?? "0");
