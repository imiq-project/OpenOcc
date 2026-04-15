import type { WebTransportClient } from "./WebTransportClient";

export type ConnectionState =
  | "new"
  | "connecting"
  | "connected"
  | "disconnected"
  | "failed"
  | "closed";

export type WebRTCEventMap = {
  track: MediaStream;
  telemetry: Record<string, unknown>;
  status: Record<string, unknown>;
  connectionState: ConnectionState;
};

type Listener<T> = (data: T) => void;

export class WebRTCClient {
  private pc: RTCPeerConnection | null = null;
  private commandsChannel: RTCDataChannel | null = null;
  private telemetryChannel: RTCDataChannel | null = null;
  private statusChannel: RTCDataChannel | null = null;

  private wtUnsubscribers: (() => void)[] = [];

  private readonly vehicleId: string;
  private readonly wt: WebTransportClient;

  // eslint-disable-next-line
  private listeners: Record<string, Set<Function>> = {};

  constructor(vehicleId: string, wt: WebTransportClient) {
    this.vehicleId = vehicleId;
    this.wt = wt;
  }

  on<K extends keyof WebRTCEventMap>(
    event: K,
    listener: Listener<WebRTCEventMap[K]>,
  ): () => void {
    if (!this.listeners[event]) {
      this.listeners[event] = new Set();
    }
    this.listeners[event].add(listener);
    return () => this.off(event, listener);
  }

  off<K extends keyof WebRTCEventMap>(
    event: K,
    listener: Listener<WebRTCEventMap[K]>,
  ): void {
    this.listeners[event]?.delete(listener);
  }

  private emit<K extends keyof WebRTCEventMap>(
    event: K,
    data: WebRTCEventMap[K],
  ): void {
    this.listeners[event]?.forEach((fn) => fn(data));
  }

  async connect(): Promise<void> {
    if (this.pc) {
      console.warn("[WebRTC] Already connected or connecting");
      return;
    }

    console.log(`[WebRTC] Starting connection to vehicle ${this.vehicleId}`);

    const servers = await fetch("/iceServers")

    this.pc = new RTCPeerConnection({
      iceServers: (await servers.json()).iceServers,
    });

    this.pc.addTransceiver("video", { direction: "recvonly" }); // camera
    this.pc.addTransceiver("video", { direction: "recvonly" }); // depth

    this.commandsChannel = this.pc.createDataChannel("commands", {
      ordered: false,
      maxRetransmits: 0,
    });

    this.telemetryChannel = this.pc.createDataChannel("telemetry");
    this.statusChannel = this.pc.createDataChannel("status");

    this.bindDataChannelEvents();
    this.bindPeerConnectionEvents();
    this.bindSignalingEvents();

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    this.wt.sendOffer(this.vehicleId, offer.sdp!);
  }

  disconnect(): void {
    console.log(`[WebRTC] Disconnecting from vehicle ${this.vehicleId}`);
    this.cleanup();
    this.emit("connectionState", "closed");
  }

  sendTwist(linearX: number, angularZ: number): void {
    if (!this.commandsChannel || this.commandsChannel.readyState !== "open") {
      return;
    }
    this.commandsChannel.send(
      JSON.stringify({ type: "twist", linear_x: linearX, angular_z: angularZ }),
    );
  }

  sendPing(): void {
    if (!this.commandsChannel || this.commandsChannel.readyState !== "open") {
      return;
    }
    this.commandsChannel.send(`ping:${Date.now()}`);
  }

  private bindDataChannelEvents(): void {
    this.telemetryChannel!.onmessage = (ev) => {
      this.parseAndEmit("telemetry", ev.data);
    };

    this.statusChannel!.onmessage = (ev) => {
      this.parseAndEmit("status", ev.data);
    };

    this.commandsChannel!.onmessage = (ev) => {
      const msg = String(ev.data);
      if (msg.startsWith("pong:")) {
        this.parseAndEmit("telemetry", JSON.stringify({ type: "pong", ts: msg.slice(5) }));
      }
    };

    this.pc!.ondatachannel = (ev) => {
      const ch = ev.channel;
      console.log(`[WebRTC] Remote data channel: ${ch.label}`);
      switch (ch.label) {
        case "telemetry":
          this.telemetryChannel = ch;
          ch.onmessage = (e) => this.parseAndEmit("telemetry", e.data);
          break;
        case "status":
          this.statusChannel = ch;
          ch.onmessage = (e) => this.parseAndEmit("status", e.data);
          break;
        case "commands":
          this.commandsChannel = ch;
          ch.onmessage = (e) => {
            const msg = String(e.data);
            if (msg.startsWith("pong:")) {
              this.parseAndEmit("telemetry", JSON.stringify({ type: "pong", ts: msg.slice(5) }));
            }
          };
          break;
      }
    };
  }

  private bindPeerConnectionEvents(): void {
    const pc = this.pc!;

    pc.ontrack = (ev) => {
      console.log(`[WebRTC] Received media track: ${ev.track.kind}, mid=${ev.transceiver.mid}`);
      const stream = new MediaStream([ev.track]);
      this.emit("track", stream);
    };

    pc.onconnectionstatechange = () => {
      const state = pc.connectionState as ConnectionState;
      console.log(`[WebRTC] Connection state: ${state}`);
      this.emit("connectionState", state);

      if (state === "failed" || state === "closed") {
        this.cleanup();
      }
    };

    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return;
      this.wt.sendIceCandidate(this.vehicleId, ev.candidate.toJSON());
    };
  }

  private bindSignalingEvents(): void {
    const unsubAnswer = this.wt.on("answer", async (msg) => {
      if (!this.pc) return;
      await this.pc.setRemoteDescription({ type: "answer", sdp: msg.Sdp });
      console.log("[WebRTC] Remote description set");
    });
    this.wtUnsubscribers.push(unsubAnswer);

    const unsubIce = this.wt.on("iceCandidate", async (msg) => {
      if (!this.pc) return;
      await this.pc.addIceCandidate(new RTCIceCandidate(msg.Candidate));
    });
    this.wtUnsubscribers.push(unsubIce);
  }

  private parseAndEmit(
    event: "telemetry" | "status",
    raw: unknown,
  ): void {
    try {
      const data =
        typeof raw === "string" ? JSON.parse(raw) : (raw as Record<string, unknown>);
      this.emit(event, data);
    } catch {
      console.warn(`[WebRTC] Invalid JSON on ${event} channel:`, raw);
    }
  }

  private cleanup(): void {
    for (const unsub of this.wtUnsubscribers) {
      unsub();
    }
    this.wtUnsubscribers = [];

    this.commandsChannel?.close();
    this.telemetryChannel?.close();
    this.statusChannel?.close();
    this.commandsChannel = null;
    this.telemetryChannel = null;
    this.statusChannel = null;

    if (this.pc) {
      this.pc.ontrack = null;
      this.pc.onicecandidate = null;
      this.pc.onconnectionstatechange = null;
      this.pc.ondatachannel = null;
      this.pc.close();
      this.pc = null;
    }

    this.listeners = {};
  }
}
