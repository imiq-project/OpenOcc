'use client';

import React, {useState, useEffect} from "react";
import {Card, CardBody, CardHeader, Input, Button, Select, SelectItem, Spinner, Chip} from "@heroui/react";
import {IconTruck, IconCircleFilled} from "@tabler/icons-react";
import Image from "next/image";
import {useAuth} from "@/context/AuthContext";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {useRouter} from "next/navigation";

/** Map vehicle IDs to their images. Add more as you get them. */
const VEHICLE_IMAGES: Record<string, string> = {
    husky: "/husky.png",
    delivery_robot: "/robot.jpg",
    cargo_bike: "/cargo.jpg",
    tugger_train: "/train.png",
};

const PLACEHOLDER_IMAGE = "/shuttle_icon.png";

function getVehicleImage(id: string): string {
    return VEHICLE_IMAGES[id] ?? PLACEHOLDER_IMAGE;
}

type Phase = "splash" | "login" | "vehicle" | "connecting";

export default function LoginPage() {
    const {user, login} = useAuth();
    const bridge = useOCCBridge();
    const router = useRouter();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [selectedVehicle, setSelectedVehicle] = useState<string>("");
    const [phase, setPhase] = useState<Phase>("splash");

    // Splash → login after 2.5s
    useEffect(() => {
        const timer = setTimeout(() => setPhase("login"), 2500);
        return () => clearTimeout(timer);
    }, []);

    // When user logs in, move to vehicle phase
    useEffect(() => {
        if (user && phase === "login") {
            setPhase("vehicle");
        }
    }, [user, phase]);

    // Auto-select and auto-connect if only one vehicle
    useEffect(() => {
        if (phase !== "vehicle" || selectedVehicle || bridge.vehicles.length !== 1) return;
        const id = bridge.vehicles[0].Id;
        setSelectedVehicle(id);
        bridge.selectVehicle(id);
        setPhase("connecting");
        const t = setTimeout(() => router.push("/dashboard"), 2000);
        return () => clearTimeout(t);
    }, [phase, bridge.vehicles, selectedVehicle, bridge, router]);

    const handleLogin = () => {
        setError("");
        const success = login(username, password);
        if (!success) {
            setError("Invalid credentials");
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "Enter") {
            if (phase === "login" && !user) handleLogin();
            else if (phase === "vehicle" && selectedVehicle) handleConnect();
        }
    };

    const handleConnect = () => {
        if (selectedVehicle) {
            bridge.selectVehicle(selectedVehicle);
        }
        setPhase("connecting");
        setTimeout(() => router.push("/dashboard"), 2000);
    };

    // ── Splash Screen ──────────────────────────────────────
    if (phase === "splash") {
        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-white gap-6">
                <Image
                    src="/IMIQ_Burgunder.png"
                    alt="IMIQ"
                    width={120}
                    height={120}
                    priority
                />
                <div className="text-center">
                    <h1 className="text-3xl font-bold text-[#7b0038]">OCC</h1>
                    <p className="text-lg text-gray-500 mt-1">Operation Control Center</p>
                </div>
            </div>
        );
    }

    // ── Connecting Screen ──────────────────────────────────
    if (phase === "connecting") {
        const vehicleName = bridge.vehicles.find(v => v.Id === selectedVehicle)?.Name ?? selectedVehicle;

        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-white gap-6">
                <div className="w-64 h-64 rounded-2xl overflow-hidden bg-gray-50 border border-gray-200 shadow-lg">
                    <Image
                        src={getVehicleImage(selectedVehicle)}
                        alt={vehicleName}
                        width={256}
                        height={256}
                        className="w-full h-full object-cover"
                    />
                </div>
                <div className="text-center">
                    <h2 className="text-xl font-bold text-[#7b0038]">{vehicleName}</h2>
                    <p className="text-sm text-gray-500 mt-1">Connecting to vehicle...</p>
                </div>
                <Spinner size="md" color="primary" />
            </div>
        );
    }

    // ── Login / Vehicle Selection ───────────────────────────
    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
            <Card className="w-full max-w-md p-4 shadow-lg">
                <CardHeader className="flex flex-col items-center gap-4 pt-6">
                    <Image src="/IMIQ_Burgunder.png" alt="IMIQ" width={80} height={80} />
                    <div className="text-center">
                        <h1 className="text-2xl font-bold">IMIQ OCC</h1>
                        <p className="text-sm text-default-500">Operation Control Center</p>
                    </div>
                </CardHeader>
                <CardBody className="flex flex-col gap-4">
                    {phase === "login" && !user ? (
                        <>
                            <Input
                                label="Username"
                                labelPlacement="outside"
                                placeholder="Enter username"
                                value={username}
                                onValueChange={setUsername}
                                onKeyDown={handleKeyDown}
                                autoFocus
                            />
                            <Input
                                label="Password"
                                labelPlacement="outside"
                                placeholder="Enter password"
                                type="password"
                                value={password}
                                onValueChange={setPassword}
                                onKeyDown={handleKeyDown}
                            />
                            {error && (
                                <p className="text-danger text-sm">{error}</p>
                            )}
                            <Button color="primary" onPress={handleLogin} className="w-full">
                                Login
                            </Button>
                            <p className="text-xs text-default-400 text-center">
                                Demo: admin/admin or operator01/operator
                            </p>
                        </>
                    ) : (
                        <>
                            <div className="flex items-center gap-2 text-sm text-default-500">
                                <IconTruck size={18} />
                                <span>Select a vehicle to connect</span>
                            </div>

                            {bridge.vehicles.length === 0 ? (
                                <div className="flex flex-col items-center gap-2 py-4">
                                    <Spinner size="sm" />
                                    <p className="text-xs text-default-400">
                                        {bridge.connected
                                            ? "Waiting for vehicles..."
                                            : "Connecting to server..."}
                                    </p>
                                </div>
                            ) : (
                                <div className="flex flex-col gap-3">
                                    {bridge.vehicles.map(v => {
                                        const isSelected = v.Id === selectedVehicle;
                                        return (
                                            <button
                                                key={v.Id}
                                                onClick={() => setSelectedVehicle(v.Id)}
                                                className={`flex items-center gap-3 p-3 rounded-xl border-2 transition-all text-left ${
                                                    isSelected
                                                        ? "border-[#7b0038] bg-[#7b0038]/5"
                                                        : "border-gray-200 hover:border-gray-300 bg-white"
                                                }`}
                                            >
                                                <div className="w-16 h-16 rounded-lg overflow-hidden bg-gray-100 shrink-0">
                                                    <Image
                                                        src={getVehicleImage(v.Id)}
                                                        alt={v.Name}
                                                        width={64}
                                                        height={64}
                                                        className="w-full h-full object-cover"
                                                    />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <span className="font-semibold text-sm">{v.Name}</span>
                                                        <IconCircleFilled
                                                            size={8}
                                                            className={v.Connected ? "text-green-500" : "text-gray-300"}
                                                        />
                                                    </div>
                                                    <span className="text-xs text-gray-400">
                                                        {v.Connected ? "Online" : "Offline"} — {v.Id}
                                                    </span>
                                                </div>
                                                {isSelected && (
                                                    <Chip size="sm" color="primary" variant="flat">Selected</Chip>
                                                )}
                                            </button>
                                        );
                                    })}
                                </div>
                            )}

                            {/* Selected vehicle preview */}
                            {selectedVehicle && VEHICLE_IMAGES[selectedVehicle] && (
                                <div className="flex justify-center">
                                    <div className="w-40 h-40 rounded-xl overflow-hidden bg-gray-50 border border-gray-200 shadow-sm">
                                        <Image
                                            src={getVehicleImage(selectedVehicle)}
                                            alt={selectedVehicle}
                                            width={160}
                                            height={160}
                                            className="w-full h-full object-cover"
                                        />
                                    </div>
                                </div>
                            )}

                            <Button
                                color="primary"
                                onPress={handleConnect}
                                className="w-full"
                                isDisabled={!selectedVehicle}
                            >
                                Connect
                            </Button>
                        </>
                    )}
                </CardBody>
            </Card>
        </div>
    );
}
