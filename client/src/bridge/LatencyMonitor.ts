import type { WebRTCClient } from "./WebRTCClient";
import type { StateMachine } from "./StateMachine";

const PING_INTERVAL_MS = 100;
const ROLLING_WINDOW = 3;
const RTT_THRESHOLD_MS = 150;

type RttListener = (rttMs: number) => void;

export class LatencyMonitor {
  private samples: number[] = [];
  private _rtt = 0;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private unsubTelemetry: (() => void) | null = null;

  private readonly rtc: WebRTCClient;
  private readonly sm: StateMachine;
  private rttListeners = new Set<RttListener>();
  private rttExceededListeners = new Set<RttListener>();

  constructor(rtc: WebRTCClient, sm: StateMachine) {
    this.rtc = rtc;
    this.sm = sm;
  }

  get rtt(): number {
    return this._rtt;
  }

  onRtt(listener: RttListener): () => void {
    this.rttListeners.add(listener);
    return () => this.rttListeners.delete(listener);
  }

  onRttExceeded(listener: RttListener): () => void {
    this.rttExceededListeners.add(listener);
    return () => this.rttExceededListeners.delete(listener);
  }

  start(): void {
    this.stop();

    this.unsubTelemetry = this.rtc.on("telemetry", (data) => {
      const msg = data as { type?: string; ts?: string };
      if (msg.type !== "pong" || !msg.ts) return;

      const sentMs = Number(msg.ts);
      if (Number.isNaN(sentMs)) return;

      const rtt = Date.now() - sentMs;
      this.samples.push(rtt);
      if (this.samples.length > ROLLING_WINDOW) {
        this.samples.splice(0, this.samples.length - ROLLING_WINDOW);
      }

      const avg = this.samples.reduce((a, b) => a + b, 0) / this.samples.length;
      this._rtt = avg;
      this.rttListeners.forEach((fn) => fn(avg));

      if (avg > RTT_THRESHOLD_MS) {
        if (this.sm.forceStandbyOnHighRtt()) {
          console.warn(
            `[LatencyMonitor] RTT ${avg.toFixed(1)}ms > ${RTT_THRESHOLD_MS}ms — forced Standby`,
          );
          this.rttExceededListeners.forEach((fn) => fn(avg));
        }
      }
    });

    this.pingTimer = setInterval(() => {
      this.rtc.sendPing();
    }, PING_INTERVAL_MS);
  }

  stop(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
    this.unsubTelemetry?.();
    this.unsubTelemetry = null;
    this.samples = [];
    this._rtt = 0;
  }
}
