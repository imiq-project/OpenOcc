import {UTMPosition, WGSPosition} from "@/model/OpenStreetMap";
import {Vector2} from "@/model/ROSMessages";

const UTM_K0 = 0.9996;

const UTM_E = 0.00669438;
const UTM_E2 = UTM_E * UTM_E;
const UTM_E3 = UTM_E2 * UTM_E;
const UTM_EP2 = UTM_E / (1 - UTM_E);

const UTM_M1 = 1 - UTM_E / 4 - 3 * UTM_E2 / 64 - 5 * UTM_E3 / 256;
const UTM_M2 = 3 * UTM_E / 8 + 3 * UTM_E2 / 32 + 45 * UTM_E3 / 1024;
const UTM_M3 = 15 * UTM_E2 / 256 + 45 * UTM_E3 / 1024;
const UTM_M4 = 35 * UTM_E3 / 3072;

const UTM_R = 6378137;

const toRadians = (degrees: number): number => (Math.PI / 180) * degrees;

const normalizeAngle = (angle: number): number => (angle + Math.PI) % (2 * Math.PI) - Math.PI;

const zoneNumberFromWGS = (wgs: WGSPosition): number => {
    if (wgs.latitude >= 56 && wgs.latitude < 64 && wgs.longitude >= 3 && wgs.longitude < 12) {
        return 32;
    } else if (wgs.latitude >= 72 && wgs.latitude <= 84 && wgs.longitude >= 0) {
        if (wgs.longitude < 9) {
            return 32;
        } else if (wgs.longitude < 21) {
            return 33;
        } else if (wgs.longitude < 33) {
            return 35;
        } else if (wgs.longitude < 42) {
            return 37;
        }
    }

    return Math.trunc(((wgs.longitude + 180) / 6) + 1);
}

const centralLongitudeFromZoneNumber = (zoneNumber: number): number => (zoneNumber - 1) * 6 - 180 + 3;

export const wgs84ToUTMPosition = (wgs: WGSPosition): UTMPosition => {
    const latitudeRadians = toRadians(wgs.latitude);
    const latitudeSin = Math.sin(latitudeRadians);
    const latitudeCos = Math.cos(latitudeRadians);

    const latitudeTan = latitudeSin / latitudeCos;
    const latitudeTan2 = Math.pow(latitudeTan, 2);
    const latitudeTan4 = Math.pow(latitudeTan2, 2);

    const zoneNumber = zoneNumberFromWGS(wgs);

    const longitudeRadians = toRadians(wgs.longitude);
    const centralLongitude = centralLongitudeFromZoneNumber(zoneNumber);
    const centralLongitudeRadians = toRadians(centralLongitude);

    const n = UTM_R / Math.sqrt(1 - UTM_E * Math.pow(latitudeSin, 2));
    const c = UTM_EP2 * Math.pow(latitudeCos, 2);

    const a = latitudeCos * normalizeAngle(longitudeRadians - centralLongitudeRadians);
    const a2 = Math.pow(a, 2);
    const a3 = a2 * a;
    const a4 = a3 * a;
    const a5 = a4 * a;
    const a6 = a5 * a;

    const m = UTM_R * (UTM_M1 * latitudeRadians -
        UTM_M2 * Math.sin(2 * latitudeRadians) +
        UTM_M3 * Math.sin(4 * latitudeRadians) -
        UTM_M4 * Math.sin(6 * latitudeRadians));

    const easting = UTM_K0 * n * (a +
            a3 / 6 * (1 - latitudeTan2 + c) +
            a5 / 120 * (5 - 18 * latitudeTan2 + latitudeTan4 + 72 * c - 58 * UTM_EP2)) +
        500000;

    const northing = UTM_K0 * (m + n * latitudeTan * (a2 / 2 +
        a4 / 24 * (5 - latitudeTan2 + 9 * c + 4 * Math.pow(c, 2)) +
        a6 / 720 * (61 - 58 * latitudeTan2 + latitudeTan4 + 600 * c -
            330 * UTM_EP2))) + (wgs.latitude < 0 ? 10000000 : 0);

    return {
        x: easting,
        y: northing,
    };
};

export const rotateZ = (x: number, y: number, angle: number): Vector2 => {
    return {
        x: x * Math.cos(angle) - y * Math.sin(angle),
        y: x * Math.sin(angle) + y * Math.cos(angle),
    };
}