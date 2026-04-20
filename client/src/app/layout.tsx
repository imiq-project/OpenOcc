'use client';

import {Inter} from "next/font/google";
import React from "react";
import {HeroUIProvider} from "@heroui/react";
import "./globals.css";
import '@mantine/charts/styles.css';
import '@mantine/core/styles.css';
import {MantineProvider} from "@mantine/core";
import {AuthProvider} from "@/context/AuthContext";
import {OCCBridgeProvider} from "@/context/OCCBridgeContext";
import {AlertProvider} from "@/context/AlertContext";
import {AppLayout} from "@/components/layout/AppLayout";

const inter = Inter({subsets: ["latin"]});

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="light">
        <head>
            <title>IMIQ OCC — Operation Control Center</title>
        </head>
        <body className={inter.className}>
        <MantineProvider defaultColorScheme="light">
            <HeroUIProvider>
                <AuthProvider>
                    <OCCBridgeProvider>
                        <AlertProvider>
                            <AppLayout>
                                {children}
                            </AppLayout>
                        </AlertProvider>
                    </OCCBridgeProvider>
                </AuthProvider>
            </HeroUIProvider>
        </MantineProvider>
        </body>
        </html>
    );
}
