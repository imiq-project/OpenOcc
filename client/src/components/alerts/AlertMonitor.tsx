'use client';

import React from "react";
import { useAlerts } from "@/hooks/useAlerts";
import { AlertSound } from "./AlertSound";

export const AlertMonitor: React.FC = () => {
    useAlerts();
    return <AlertSound />;
};
