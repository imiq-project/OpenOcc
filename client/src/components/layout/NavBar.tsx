'use client';

import React from "react";
import {Navbar, NavbarBrand, NavbarContent, NavbarItem, Button, Chip, Tooltip, Select, SelectItem} from "@heroui/react";
import {
    IconTruck,
    IconSteeringWheel,
    IconList,
    IconSettings,
    IconCircleFilled,
    IconLogout,
} from "@tabler/icons-react";
import {useAuth} from "@/context/AuthContext";
import {useOCCBridge} from "@/context/OCCBridgeContext";
import {usePathname, useRouter} from "next/navigation";
import Image from "next/image";

const NAV_ITEMS = [
    {label: "Operator", href: "/teleoperation", icon: IconSteeringWheel},
    {label: "Mission", href: "/mission", icon: IconTruck},
    {label: "Log", href: "/log", icon: IconList},
    {label: "Settings", href: "/settings", icon: IconSettings},
];

export const NavBar: React.FC = () => {
    const {user, logout} = useAuth();
    const bridge = useOCCBridge();
    const pathname = usePathname();
    const router = useRouter();
    const [clock, setClock] = React.useState(new Date());

    React.useEffect(() => {
        const timer = setInterval(() => setClock(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    if (!user) return null;

    return (
        <Navbar maxWidth="full" className="bg-occ-nav border-b border-occ-nav-border h-12 min-h-[48px] shadow-sm">
            <NavbarBrand className="gap-2 shrink-0">
                <Image src="/IMIQ_Burgunder.png" alt="IMIQ" width={28} height={28} />
                <span className="font-bold text-lg tracking-wide text-primary">IMIQ OCC</span>
            </NavbarBrand>

            <NavbarContent className="gap-1" justify="center">
                {NAV_ITEMS.map(item => {
                    const isActive = pathname.startsWith(item.href);
                    const Icon = item.icon;
                    return (
                        <NavbarItem key={item.href}>
                            <Button
                                variant={isActive ? "flat" : "light"}
                                color={isActive ? "primary" : "default"}
                                onPress={() => router.push(item.href)}
                                size="sm"
                                className="gap-1.5"
                            >
                                <Icon size={18} />
                                <span>{item.label}</span>
                            </Button>
                        </NavbarItem>
                    );
                })}
            </NavbarContent>

            <NavbarContent justify="end" className="gap-3">
                {/* Vehicle selector */}
                <NavbarItem className="flex items-center">
                    {bridge.vehicles.length > 0 ? (
                        <Select
                            size="sm"
                            aria-label="Select vehicle"
                            placeholder="Select vehicle"
                            selectedKeys={bridge.selectedVehicleId ? new Set([bridge.selectedVehicleId]) : new Set()}
                            onSelectionChange={keys => {
                                const selected = Array.from(keys as Set<string>)[0];
                                bridge.selectVehicle(selected ?? null);
                            }}
                            className="w-40"
                            classNames={{
                                trigger: "min-h-unit-8 h-unit-8",
                            }}
                        >
                            {bridge.vehicles.map(v => (
                                <SelectItem key={v.Id} textValue={v.Name}>
                                    {v.Name}
                                </SelectItem>
                            ))}
                        </Select>
                    ) : (
                        <span className="text-xs text-default-400">No vehicles</span>
                    )}
                </NavbarItem>

                <NavbarItem>
                    <span className="text-sm text-default-500 font-mono">
                        {clock.toLocaleTimeString("en-GB")}
                    </span>
                </NavbarItem>
                <NavbarItem>
                    <Tooltip content={bridge.connected ? "Connected to bridge" : "Disconnected from bridge"}>
                        <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-default-100">
                            <IconCircleFilled size={10} className={bridge.connected ? "text-success" : "text-danger"} />
                            <span className={`text-xs font-medium ${bridge.connected ? "text-success" : "text-danger"}`}>
                                {bridge.connected ? "Connected" : "Disconnected"}
                            </span>
                        </div>
                    </Tooltip>
                </NavbarItem>
                <NavbarItem>
                    <Chip variant="flat" size="sm" color="default">
                        {user.username} | {user.role === "admin" ? "Admin" : "Operator"}
                    </Chip>
                </NavbarItem>
                <NavbarItem>
                    <Tooltip content="Logout">
                        <Button isIconOnly variant="light" size="sm" onPress={logout}>
                            <IconLogout size={18} />
                        </Button>
                    </Tooltip>
                </NavbarItem>
            </NavbarContent>
        </Navbar>
    );
};
