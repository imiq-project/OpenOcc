'use client';

import React, { useState, useEffect } from "react";
import { Slider, Button, Divider } from "@heroui/react";
import { useAlertContext } from "@/context/AlertContext";

const AlertSettings: React.FC = () => {
    const { thresholds, setThresholds } = useAlertContext();

    const [batteryWarning, setBatteryWarning] = useState(thresholds.batteryWarning);
    const [batteryCritical, setBatteryCritical] = useState(thresholds.batteryCritical);
    const [latencyWarning, setLatencyWarning] = useState(thresholds.latencyWarning);
    const [connectionTimeout, setConnectionTimeout] = useState(thresholds.connectionTimeout);
    const [stallTimeout, setStallTimeout] = useState(thresholds.stallTimeout);

    useEffect(() => {
        setBatteryWarning(thresholds.batteryWarning);
        setBatteryCritical(thresholds.batteryCritical);
        setLatencyWarning(thresholds.latencyWarning);
        setConnectionTimeout(thresholds.connectionTimeout);
        setStallTimeout(thresholds.stallTimeout);
    }, [thresholds]);

    const handleSave = () => {
        setThresholds({
            batteryWarning,
            batteryCritical,
            latencyWarning,
            connectionTimeout,
            stallTimeout,
        });
    };

    return (
        <div className="flex flex-col gap-6 max-w-lg">
            <h3 className="text-lg font-semibold">Alert Thresholds</h3>

            <div className="flex flex-col gap-5">
                <Slider
                    label={`Battery Warning — ${batteryWarning}%`}
                    step={5}
                    minValue={10}
                    maxValue={50}
                    value={batteryWarning}
                    onChange={v => setBatteryWarning(v as number)}
                    color="warning"

                    className="max-w-full"
                />

                <Slider
                    label={`Battery Critical — ${batteryCritical}%`}
                    step={5}
                    minValue={5}
                    maxValue={25}
                    value={batteryCritical}
                    onChange={v => setBatteryCritical(v as number)}
                    color="danger"

                    className="max-w-full"
                />

                <Divider />

                <Slider
                    label={`Latency Warning — ${latencyWarning} ms`}
                    step={25}
                    minValue={50}
                    maxValue={500}
                    value={latencyWarning}
                    onChange={v => setLatencyWarning(v as number)}
                    color="warning"
                    className="max-w-full"
                />

                <Slider
                    label={`Connection Timeout — ${connectionTimeout} s`}
                    step={1}
                    minValue={2}
                    maxValue={15}
                    value={connectionTimeout}
                    onChange={v => setConnectionTimeout(v as number)}
                    color="danger"
                    className="max-w-full"
                />

                <Slider
                    label={`Stall Timeout — ${stallTimeout} s`}
                    step={5}
                    minValue={5}
                    maxValue={60}
                    value={stallTimeout}
                    onChange={v => setStallTimeout(v as number)}
                    color="warning"
                    className="max-w-full"
                />
            </div>

            <Button color="primary" className="self-start" onPress={handleSave}>
                Save
            </Button>
        </div>
    );
};

export default AlertSettings;
