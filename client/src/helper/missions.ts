import { OCCMission } from "@/model/OCCMessages";

export function getActiveMission(missions: OCCMission[]): OCCMission | undefined {
    return missions.find(m => m.status === "EN_ROUTE" || m.status === "DISPATCHED");
}
