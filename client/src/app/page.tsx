'use client';

import {useEffect} from "react";
import {useRouter} from "next/navigation";

export default function RootPage() {
    const router = useRouter();

    useEffect(() => {
        router.push("/teleoperation");
    }, [router]);

    return null;
}
