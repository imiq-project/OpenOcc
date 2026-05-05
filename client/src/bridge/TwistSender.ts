import type { WebRTCClient } from "./WebRTCClient";
import type { StateMachine } from "./StateMachine";

export class TwistSender {
  private readonly rtc: WebRTCClient;
  private readonly sm: StateMachine;

  constructor(rtc: WebRTCClient, sm: StateMachine) {
    this.rtc = rtc;
    this.sm = sm;
  }

  send(linearX: number, angularZ: number): boolean {
    if (this.sm.mode !== "DIRECT") return false;
    this.rtc.setTwist(linearX, angularZ);
    return true;
  }
}
