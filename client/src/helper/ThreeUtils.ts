import {UTMPosition} from "@/model/OpenStreetMap";
import {CatmullRomCurve3, ExtrudeGeometry, Shape, Vector2, Vector3} from "three";

export const computeCurve = (coordinates: UTMPosition[], width: number, tension: number = 0.01, closed: boolean = true): ExtrudeGeometry => {
    const roadCurve = new CatmullRomCurve3(coordinates.map(coordinate =>
        new Vector3(coordinate.x, coordinate.y, 0)));
    roadCurve.closed = closed;
    roadCurve.curveType = "catmullrom";
    roadCurve.tension = tension;

    const shape = new Shape([
        new Vector2(0, -width / 2),
        new Vector2(0, width / 2),
    ]);

    return new ExtrudeGeometry(shape, {
        steps: 120,
        bevelEnabled: false,
        extrudePath: roadCurve,
    });
};

export const interpolateAngles = (value: number, targetValue: number, alpha: number = 1): number => {
    const distance = (targetValue - value) & (Math.PI * 2);
    const shortestDistance = 2 * distance % (Math.PI * 2) - distance;
    return value + shortestDistance * alpha;
};
