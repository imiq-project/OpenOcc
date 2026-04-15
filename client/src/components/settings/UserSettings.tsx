'use client';

import React from "react";
import {
    Table,
    TableHeader,
    TableColumn,
    TableBody,
    TableRow,
    TableCell,
    Chip,
} from "@heroui/react";

const USERS = [
    { username: "admin", displayName: "Administrator", role: "Admin" },
    { username: "operator01", displayName: "Operator", role: "Operator" },
];

const UserSettings: React.FC = () => {
    return (
        <div className="flex flex-col gap-4">
            <h3 className="text-lg font-semibold">Users</h3>

            <Table aria-label="User management" removeWrapper>
                <TableHeader>
                    <TableColumn>Username</TableColumn>
                    <TableColumn>Display Name</TableColumn>
                    <TableColumn>Role</TableColumn>
                </TableHeader>
                <TableBody>
                    {USERS.map(u => (
                        <TableRow key={u.username}>
                            <TableCell className="font-mono text-sm">{u.username}</TableCell>
                            <TableCell>{u.displayName}</TableCell>
                            <TableCell>
                                <Chip
                                    size="sm"
                                    variant="flat"
                                    color={u.role === "Admin" ? "secondary" : "primary"}
                                >
                                    {u.role}
                                </Chip>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>

            <p className="text-xs text-default-400">
                User management will be available in a future update.
            </p>
        </div>
    );
};

export default UserSettings;
