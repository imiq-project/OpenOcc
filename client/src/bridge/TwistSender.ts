import type { WebRTCClient } from "./WebRTCClient";
import type { StateMachine } from "./StateMachine";

const MIN_INTERVAL_MS = 100;

export class TwistSender {
  private lastSentAt = 0;
  private readonly rtc: WebRTCClient;
  private readonly sm: StateMachine;

  constructor(rtc: WebRTCClient, sm: StateMachine) {
    this.rtc = rtc;
    this.sm = sm;
  }

  send(linearX: number, angularZ: number): boolean {
    if (this.sm.mode !== "DIRECT") return false;

    const now = Date.now();
    if (now - this.lastSentAt < MIN_INTERVAL_MS) return false;

    this.lastSentAt = now;
    this.rtc.sendTwist(linearX, angularZ);
    return true;
  }
}
