'use client';

import React, {createContext, useContext, useState, useCallback, useEffect} from "react";
import {OCCUser} from "@/model/OCCMessages";
import {useRouter, usePathname} from "next/navigation";

const HARDCODED_USERS: Array<{ username: string; password: string; user: OCCUser }> = [
    {username: "admin", password: "admin", user: {username: "admin", role: "admin", displayName: "Administrator"}},
    {username: "operator01", password: "operator", user: {username: "operator01", role: "operator", displayName: "Operator"}},
];

interface AuthContextData {
    user: OCCUser | null;
    login: (username: string, password: string) => boolean;
    logout: () => void;
}

const AuthContext = createContext<AuthContextData>({
    user: null,
    login: () => false,
    logout: () => {},
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({children}) => {
    const [user, setUser] = useState<OCCUser | null>(null);
    const router = useRouter();
    const pathname = usePathname();

    const login = useCallback((username: string, password: string): boolean => {
        const match = HARDCODED_USERS.find(u => u.username === username && u.password === password);
        if (match) {
            setUser(match.user);
            return true;
        }
        return false;
    }, []);

    const logout = useCallback(() => {
        setUser(null);
        router.push("/login");
    }, [router]);

    useEffect(() => {
        if (!user && pathname !== "/login") {
            router.push("/login");
        }
    }, [user, pathname, router]);

    return (
        <AuthContext.Provider value={{user, login, logout}}>
            {children}
        </AuthContext.Provider>
    );
};
