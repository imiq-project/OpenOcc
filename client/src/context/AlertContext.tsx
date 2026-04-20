'use client';

import React, { createContext, useContext, useState, useCallback, useRef } from "react";
import { Alert, AlertThresholds } from "@/model/OCCMessages";

export interface AlertContextData {
    activeAlerts: Alert[];
    alertHistory: Alert[];
    thresholds: AlertThresholds;
    pushAlert: (alert: Alert) => void;
    dismissAlert: (id: string) => void;
    acknowledgeAlert: (id: string) => void;
    setThresholds: (t: AlertThresholds) => void;
}

const DEFAULT_THRESHOLDS: AlertThresholds = {
    batteryWarning: 25,
    batteryCritical: 10,
    latencyWarning: 150,
    connectionTimeout: 5,
    stallTimeout: 20,
};

const defaultContext: AlertContextData = {
    activeAlerts: [],
    alertHistory: [],
    thresholds: DEFAULT_THRESHOLDS,
    pushAlert: () => {},
    dismissAlert: () => {},
    acknowledgeAlert: () => {},
    setThresholds: () => {},
};

const AlertContext = createContext<AlertContextData>(defaultContext);

export const useAlertContext = () => useContext(AlertContext);

export const AlertProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [activeAlerts, setActiveAlerts] = useState<Alert[]>([]);
    const [alertHistory, setAlertHistory] = useState<Alert[]>([]);
    const [thresholds, setThresholds] = useState<AlertThresholds>(DEFAULT_THRESHOLDS);

    const activeTypesRef = useRef<Set<string>>(new Set());

    const pushAlert = useCallback((alert: Alert) => {
        if (activeTypesRef.current.has(alert.type)) return;

        activeTypesRef.current.add(alert.type);
        setActiveAlerts(prev => [alert, ...prev]);
        setAlertHistory(prev => [alert, ...prev]);
    }, []);

    const dismissAlert = useCallback((id: string) => {
        setActiveAlerts(prev => {
            const alert = prev.find(a => a.id === id);
            if (alert) activeTypesRef.current.delete(alert.type);
            return prev.filter(a => a.id !== id);
        });
        setAlertHistory(prev =>
            prev.map(a => a.id === id ? { ...a, dismissed: true } : a)
        );
    }, []);

    const acknowledgeAlert = useCallback((id: string) => {
        setActiveAlerts(prev =>
            prev.map(a => a.id === id ? { ...a, acknowledged: true } : a)
        );
        setAlertHistory(prev =>
            prev.map(a => a.id === id ? { ...a, acknowledged: true } : a)
        );
    }, []);

    const value: AlertContextData = {
        activeAlerts,
        alertHistory,
        thresholds,
        pushAlert,
        dismissAlert,
        acknowledgeAlert,
        setThresholds,
    };

    return (
        <AlertContext.Provider value={value}>
            {children}
        </AlertContext.Provider>
    );
};

export default AlertContext;
