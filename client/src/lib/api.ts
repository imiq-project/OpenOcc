const BASE = process.env.NEXT_PUBLIC_OCC_SERVER ?? '';

export interface VehiclePayload {
  Id: string;
  Name: string;
  Lat: number;
  Lon: number;
}

export const api = {
  getVehicles: (): Promise<VehiclePayload[]> =>
    fetch(`${BASE}/api/vehicles`).then((r) => {
      if (!r.ok) throw new Error(`Failed to fetch vehicles: ${r.status}`);
      return r.json();
    }),

  addVehicle: (v: VehiclePayload): Promise<Response> =>
    fetch(`${BASE}/api/vehicles`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(v),
    }),

  deleteVehicle: (id: string): Promise<Response> =>
    fetch(`${BASE}/api/vehicles/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
};
