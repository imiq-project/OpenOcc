'use client';

import React, { useState } from "react";
import {
    Table,
    TableHeader,
    TableColumn,
    TableBody,
    TableRow,
    TableCell,
    Chip,
    Button,
    Modal,
    ModalContent,
    ModalHeader,
    ModalBody,
    ModalFooter,
    Input,
    useDisclosure,
} from "@heroui/react";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { useOCCBridge } from "@/context/OCCBridgeContext";
import { api } from "@/lib/api";

const VehicleSettings: React.FC = () => {
    const { vehicles } = useOCCBridge();
    const { isOpen, onOpen, onOpenChange } = useDisclosure();

    const [newId, setNewId] = useState("");
    const [newName, setNewName] = useState("");
    const [newLat, setNewLat] = useState("");
    const [newLon, setNewLon] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleAdd = async (onClose: () => void) => {
        setError(null);
        if (!newId.trim() || !newName.trim()) {
            setError("ID and Name are required");
            return;
        }
        setLoading(true);
        try {
            const res = await api.addVehicle({
                Id: newId.trim(),
                Name: newName.trim(),
                Lat: parseFloat(newLat) || 0,
                Lon: parseFloat(newLon) || 0,
            });
            if (!res.ok) {
                const text = await res.text();
                setError(text || "Failed to add vehicle");
                return;
            }
            setNewId("");
            setNewName("");
            setNewLat("");
            setNewLon("");
            onClose();
        } catch (e) {
            setError(String(e));
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm(`Delete vehicle "${id}"?`)) return;
        try {
            const res = await api.deleteVehicle(id);
            if (!res.ok) {
                alert("Failed to delete vehicle");
            }
        } catch (e) {
            alert(String(e));
        }
    };

    return (
        <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">Vehicles</h3>
                <Button
                    size="sm"
                    variant="flat"
                    color="primary"
                    startContent={<IconPlus size={16} />}
                    onPress={onOpen}
                >
                    Add Vehicle
                </Button>
            </div>

            <Table aria-label="Vehicle configuration" removeWrapper>
                <TableHeader>
                    <TableColumn>ID</TableColumn>
                    <TableColumn>Name</TableColumn>
                    <TableColumn>Latitude</TableColumn>
                    <TableColumn>Longitude</TableColumn>
                    <TableColumn>Status</TableColumn>
                    <TableColumn>{""}</TableColumn>
                </TableHeader>
                <TableBody emptyContent="No vehicles configured.">
                    {vehicles.map((v) => (
                        <TableRow key={v.Id}>
                            <TableCell className="font-mono text-sm">{v.Id}</TableCell>
                            <TableCell>{v.Name}</TableCell>
                            <TableCell className="font-mono text-sm">{v.Lat.toFixed(6)}</TableCell>
                            <TableCell className="font-mono text-sm">{v.Lon.toFixed(6)}</TableCell>
                            <TableCell>
                                <Chip size="sm" variant="dot" color={v.Connected ? "success" : "danger"}>
                                    {v.Connected ? "Online" : "Offline"}
                                </Chip>
                            </TableCell>
                            <TableCell>
                                <Button
                                    size="sm"
                                    variant="light"
                                    color="danger"
                                    isIconOnly
                                    onPress={() => handleDelete(v.Id)}
                                >
                                    <IconTrash size={16} />
                                </Button>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>

            <Modal isOpen={isOpen} onOpenChange={onOpenChange}>
                <ModalContent>
                    {(onClose) => (
                        <>
                            <ModalHeader>Add Vehicle</ModalHeader>
                            <ModalBody>
                                {error && (
                                    <p className="text-sm text-danger">{error}</p>
                                )}
                                <Input
                                    label="Vehicle ID"
                                    placeholder="e.g. husky"
                                    value={newId}
                                    onValueChange={setNewId}
                                    isRequired
                                />
                                <Input
                                    label="Name"
                                    placeholder="e.g. Husky Robot"
                                    value={newName}
                                    onValueChange={setNewName}
                                    isRequired
                                />
                                <Input
                                    label="Latitude"
                                    placeholder="e.g. 52.144"
                                    value={newLat}
                                    onValueChange={setNewLat}
                                    type="number"
                                />
                                <Input
                                    label="Longitude"
                                    placeholder="e.g. 11.654"
                                    value={newLon}
                                    onValueChange={setNewLon}
                                    type="number"
                                />
                            </ModalBody>
                            <ModalFooter>
                                <Button variant="light" onPress={onClose}>
                                    Cancel
                                </Button>
                                <Button
                                    color="primary"
                                    onPress={() => handleAdd(onClose)}
                                    isLoading={loading}
                                >
                                    Add
                                </Button>
                            </ModalFooter>
                        </>
                    )}
                </ModalContent>
            </Modal>
        </div>
    );
};

export default VehicleSettings;
