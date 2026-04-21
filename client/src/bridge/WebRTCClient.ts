import type { IoParam, WebTransportClient } from "./WebTransportClient";
import { Vehicle } from "./WebTransportClient";

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
  private datagramsChannel: RTCDataChannel | null = null;
  private messagesChannel: RTCDataChannel | null = null;

  private wtUnsubscribers: (() => void)[] = [];

  private readonly vehicle: Vehicle;
  private readonly wt: WebTransportClient;

  // eslint-disable-next-line
  private listeners: Record<string, Set<Function>> = {};

  constructor(vehicle: Vehicle, wt: WebTransportClient) {
    this.vehicle = vehicle;
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

    console.log(`[WebRTC] Starting connection to vehicle ${this.vehicle.Id}`);

    this.pc = new RTCPeerConnection({
      iceServers: this.wt.getIceServers(),
    });

    // declare transceivers beforehand to get a stable SDP and avoid some python/aiortc bugs
    for (const out of this.vehicle.IoConf.outgoing) {
      for (const i of out.types) {
        if (i == "video") {
          this.pc.addTransceiver("video", { direction: "recvonly" });
        }
      }
    }

    this.datagramsChannel = this.pc.createDataChannel("datagrams", {
      ordered: false,
      maxRetransmits: 0,
    });
    this.messagesChannel = this.pc.createDataChannel("messages");

    this.bindDataChannelEvents();
    this.bindPeerConnectionEvents();
    this.bindSignalingEvents();

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    const sdp = await this.wt.sendRpcRequest(this.vehicle.Id, "_webRtcOffer", [offer.sdp!])
    await this.pc.setRemoteDescription({ type: "answer", sdp: sdp as string });
    console.log("[WebRTC] Remote description set");
  }

  disconnect(): void {
    console.log(`[WebRTC] Disconnecting from vehicle ${this.vehicle.Id}`);
    this.cleanup();
    this.emit("connectionState", "closed");
  }

  private makeIncoming(incoming: Array<IoParam>, values: Record<string, number[]>): Uint8Array {
    // 1) First pass: compute total size
    let totalLength = 0;

    for (const param of incoming) {
      totalLength += param.types.length * 8;
      // worst-case assumption (Int64/UInt64 = 8 bytes)
    }

    const result = new Uint8Array(totalLength);
    const view = new DataView(result.buffer);

    let offset = 0;

    // 2) Second pass: write directly
    for (const param of incoming) {
      const paramValues = values[param.name];

      for (let i = 0; i < param.types.length; i++) {
        const dt = param.types[i];
        const value = paramValues[i];

        switch (dt) {
          case 'int8':
            view.setInt8(offset, value);
            offset += 1;
            break;

          case 'uint8':
            view.setUint8(offset, value);
            offset += 1;
            break;

          case 'int64':
            view.setBigInt64(offset, BigInt(value), false); // big-endian
            offset += 8;
            break;

          case 'uint64':
            view.setBigUint64(offset, BigInt(value), false); // big-endian
            offset += 8;
            break;

          default:
            throw new Error(`Invalid data type ${dt}`);
        }
      }
    }

    // 3) Trim to actual used size (since we overallocated)
    return result.subarray(0, offset);
  }

  sendTwist(linearX: number, angularZ: number): void {
    if (!this.datagramsChannel || this.datagramsChannel.readyState !== "open") {
      return;
    }
    const bytes = this.makeIncoming(this.vehicle.IoConf.incoming, { 'motion': [linearX * 127, angularZ * 127] })
    this.datagramsChannel.send(bytes as any)
  }

  sendPing(): void {
    if (!this.datagramsChannel || this.datagramsChannel.readyState !== "open") {
      return;
    }
    // this.datagramsChannel.send(`ping:${Date.now()}`);
  }

  private bindDataChannelEvents(): void {
    this.messagesChannel!.onmessage = (ev) => {
      this.parseAndEmit("status", ev.data);
    };

    this.datagramsChannel!.onmessage = (ev) => {
      const msg = String(ev.data);
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
      this.wt.sendRpcRequest(this.vehicle.Id, "_iceCandidate", [ev.candidate.toJSON()])
    };
  }

  private bindSignalingEvents(): void {
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

    this.datagramsChannel?.close();
    this.messagesChannel?.close();
    this.datagramsChannel = null;
    this.messagesChannel = null;

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
