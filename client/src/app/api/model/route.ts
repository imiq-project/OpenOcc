import * as fs from "fs";
import {VehicleModel} from "@/model/Configuration";

export async function GET() {
    const vehicleModel = process.env.NEXT_PUBLIC_VEHICLE_MODEL;
    let modelPath = '';

    switch (vehicleModel) {
        case VehicleModel.Shuttle:
            modelPath = './public/golfcart.fbx';
            break;
        case VehicleModel.Husky:
            modelPath = './public/husky.fbx';
            break;
    }

    if (modelPath.length === 0) {
        return new Response(`Configured vehicle model is invalid "${vehicleModel}"`, {
            status: 500,
        });
    }

    const content = fs.readFileSync(modelPath);
    return new Response(content, {
        status: 200,
        headers: {
            "Content-Type": "application/fbx",
        },
    });
}
