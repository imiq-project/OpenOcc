import * as fs from "fs";

const PATH_CUSTOM = "./public/maps/map.xml";
const PATH_DEFAULT = "./public/exer_fallback.xml";

export async function GET() {
    let content;
    if (fs.existsSync(PATH_CUSTOM)) {
        content = fs.readFileSync(PATH_CUSTOM);
    } else {
        content = fs.readFileSync(PATH_DEFAULT);
    }

    return new Response(content, {
        status: 200,
        headers: {
            "Content-Type": "text/xml",
        }
    });
}
