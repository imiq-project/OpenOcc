/** @type {import('next').NextConfig} */
const nextConfig = {
    transpilePackages: ["three"],
    env: {
        occServer: process.env.NEXT_PUBLIC_OCC_SERVER,
        vehicleModel: process.env.NEXT_PUBLIC_VEHICLE_MODEL,
    },
    webpack: (config) => {
        config.externals = [...(config.externals || []), { canvas: 'canvas' }];
        return config;
    },
    output: "standalone",
};

export default nextConfig;
