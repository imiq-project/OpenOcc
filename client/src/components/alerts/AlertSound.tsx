'use client';

import { useEffect, useRef } from "react";
import { useAlertContext } from "@/context/AlertContext";
import { AlertSeverity } from "@/model/OCCMessages";
import { AlertAudio } from "@/bridge/AlertAudio";

export const AlertSound: React.FC = () => {
    const { activeAlerts } = useAlertContext();
    const audioRef = useRef<AlertAudio | null>(null);
    const playedRef = useRef<Set<string>>(new Set());

    useEffect(() => {
        if (!audioRef.current) audioRef.current = new AlertAudio();
        const audio = audioRef.current;

        const hasCritical = activeAlerts.some(
            a => a.severity === AlertSeverity.CRITICAL && !a.acknowledged
        );
        const hasNewWarning = activeAlerts.some(
            a => a.severity === AlertSeverity.WARNING && !playedRef.current.has(a.id)
        );

        if (hasNewWarning) {
            audio.playWarning();
            activeAlerts
                .filter(a => a.severity === AlertSeverity.WARNING)
                .forEach(a => playedRef.current.add(a.id));
        }

        if (hasCritical) {
            audio.playCritical();
        } else {
            audio.stopCritical();
        }

        const activeIds = new Set(activeAlerts.map(a => a.id));
        playedRef.current.forEach(id => {
            if (!activeIds.has(id)) playedRef.current.delete(id);
        });
    }, [activeAlerts]);

    useEffect(() => {
        return () => audioRef.current?.dispose();
    }, []);

    return null;
};
