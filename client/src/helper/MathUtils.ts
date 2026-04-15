import {Vector2} from "@/model/ROSMessages";

export const vectorMagnitude = (vector: Vector2): number => Math.sqrt(Math.pow(vector.x, 2) + Math.pow(vector.y, 2));

export const zeroVector: Vector2 = {x: 0, y: 0};

export const toDegrees = (radians: number): number => (180 / Math.PI) * radians;

export const reshapeArray = <T>(array: T[], rows: number, columns: number, defaultValue: T): T[][] => {
    return Array.from({length: rows}, (_, rowIndex) =>
        Array.from({length: columns}, (_, columnIndex) =>
            (i => i < array.length ? array[i] : defaultValue)
            (rowIndex * columns + columnIndex)));
};

export const normalizeValue = (value: number, minimum: number, maximum: number): number => {
    if (maximum - minimum < 1e-6) return 0.0;
    return (value - minimum) / (maximum - minimum);
};
