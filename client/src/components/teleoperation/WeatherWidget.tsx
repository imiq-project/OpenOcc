'use client';

import React, {useEffect, useState} from "react";
import {
    IconSun,
    IconCloud,
    IconCloudRain,
    IconCloudSnow,
    IconCloudFog,
    IconBolt,
    IconWind,
    IconDroplet,
    IconTemperature,
} from "@tabler/icons-react";

const LAT = 52.143;
const LON = 11.650;

interface WeatherData {
    temperature: number;
    windSpeed: number;
    humidity: number;
    weatherCode: number;
    description: string;
}

function getWeatherInfo(code: number): { icon: React.ReactNode; description: string; color: string } {
    if (code === 0) return {icon: <IconSun size={28}/>, description: "Clear sky", color: "text-yellow-400"};
    if (code <= 3) return {icon: <IconCloud size={28}/>, description: "Partly cloudy", color: "text-gray-300"};
    if (code <= 48) return {icon: <IconCloudFog size={28}/>, description: "Fog", color: "text-gray-400"};
    if (code <= 67) return {icon: <IconCloudRain size={28}/>, description: "Rain", color: "text-blue-400"};
    if (code <= 77) return {icon: <IconCloudSnow size={28}/>, description: "Snow", color: "text-blue-200"};
    if (code <= 82) return {icon: <IconCloudRain size={28}/>, description: "Rain showers", color: "text-blue-400"};
    if (code <= 86) return {icon: <IconCloudSnow size={28}/>, description: "Snow showers", color: "text-blue-200"};
    return {icon: <IconBolt size={28}/>, description: "Thunderstorm", color: "text-yellow-300"};
}

const MOCK_WEATHER: WeatherData = {
    temperature: 12,
    windSpeed: 14,
    humidity: 68,
    weatherCode: 2,
    description: "Partly cloudy",
};

const WeatherWidget: React.FC = () => {
    const [weather, setWeather] = useState<WeatherData>(MOCK_WEATHER);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchWeather = async () => {
            try {
                const res = await fetch(
                    `https://api.open-meteo.com/v1/forecast?latitude=${LAT}&longitude=${LON}&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&timezone=Europe/Berlin`
                );
                const data = await res.json();
                const c = data.current;
                setWeather({
                    temperature: Math.round(c.temperature_2m),
                    windSpeed: Math.round(c.wind_speed_10m),
                    humidity: Math.round(c.relative_humidity_2m),
                    weatherCode: c.weather_code,
                    description: getWeatherInfo(c.weather_code).description,
                });
            } catch {
            }
            setLoading(false);
        };

        fetchWeather();
        const interval = setInterval(fetchWeather, 10 * 60 * 1000);
        return () => clearInterval(interval);
    }, []);

    const info = getWeatherInfo(weather.weatherCode);

    return (
        <div className="w-full rounded-lg overflow-hidden border border-white/10">
            <div className="bg-black/30 px-3 py-1.5 text-xs text-white/60 font-medium uppercase tracking-wider">
                Weather — Magdeburg
            </div>
            <div className="p-4 pb-5">
                {loading ? (
                    <div className="text-white/40 text-sm text-center py-2">Loading...</div>
                ) : (
                    <div className="flex items-center gap-4">
                        {/* Main icon + temp */}
                        <div className="flex flex-col items-center gap-1">
                            <span className={info.color}>{info.icon}</span>
                            <span className="text-[10px] text-white/50">{info.description}</span>
                        </div>
                        {/* Stats */}
                        <div className="flex-1 grid grid-cols-3 gap-3">
                            <div className="flex flex-col items-center gap-1">
                                <IconTemperature size={18} className="text-red-400/70" />
                                <span className="text-base font-mono text-white">{weather.temperature}°C</span>
                            </div>
                            <div className="flex flex-col items-center gap-1">
                                <IconWind size={18} className="text-cyan-400/70" />
                                <span className="text-base font-mono text-white">{weather.windSpeed} km/h</span>
                            </div>
                            <div className="flex flex-col items-center gap-1">
                                <IconDroplet size={18} className="text-blue-400/70" />
                                <span className="text-base font-mono text-white">{weather.humidity}%</span>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default WeatherWidget;
