export function isInsideGeofence(
    point: { latitude: number; longitude: number },
    polygon: Array<{ latitude: number; longitude: number }>,
): boolean {
    let inside = false;
    for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
        const xi = polygon[i].longitude, yi = polygon[i].latitude;
        const xj = polygon[j].longitude, yj = polygon[j].latitude;
        const intersect = ((yi > point.latitude) !== (yj > point.latitude))
            && (point.longitude < (xj - xi) * (point.latitude - yi) / (yj - yi) + xi);
        if (intersect) inside = !inside;
    }
    return inside;
}

export const GEOFENCE_POLYGON: Array<{ latitude: number; longitude: number }> = [
    { latitude: 52.1391948556427, longitude: 11.6401853755473 },
    { latitude: 52.1375881422277, longitude: 11.6537466243266 },
    { latitude: 52.1495923282473, longitude: 11.6660633281230 },
    { latitude: 52.1513302683766, longitude: 11.6616001323222 },
    { latitude: 52.1412308347445, longitude: 11.6549160674571 },
    { latitude: 52.1425016195719, longitude: 11.6523304179667 },
    { latitude: 52.1411790010348, longitude: 11.6475741492668 },
    { latitude: 52.1417057562354, longitude: 11.6402785407463 },
];
