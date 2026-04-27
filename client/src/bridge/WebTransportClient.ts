import { Future } from "@/helper/Future";


export interface IoParam {
  name: string
  types: string
}

export interface Command {
  name: string
}
export interface Vehicle {
  Id: string;
  Name: string;
  Lat: number;
  Lon: number;
  Connected: boolean;
  IoConf: {
    incoming: Array<IoParam>,
    outgoing: Array<IoParam>,
    commands: Array<Command>,
  }
}

export interface IceCandidateMessage {
  Type: "ice";
  Candidate: RTCIceCandidateInit;
  Recipient: string;
  [key: string]: unknown;
}

export interface RpcResponse {
  Type: "rpcResponse"
  From: string,
  To: string,
  Payload:  {
    jsonrpc: "2.0"
    id: number,
    result: any
  }
}

export interface AlertMessage {
  Type: "alert";
  VehicleId: string;
  Severity: "critical" | "warning" | "info";
  Code: string;
  Message: string;
  Timestamp: number;
  [key: string]: unknown;
}

export type WebTransportEventMap = {
  vehicleList: Vehicle[];
  iceCandidate: IceCandidateMessage;
  connected: void;
  disconnected: void;
};

type Listener<T> = (data: T) => void;

const HEARTBEAT_INTERVAL_MS = 5_000;
const RECONNECT_DELAY_MS = 3_000;

export class WebTransportClient {
  private transport: WebTransport | null = null;
  private stream: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyed = false;
  private iceServers: RTCIceServer[] = []
  private nextRpcId = 0;
  private rpcWaiters: Map<number, Future<any>> = new Map()

  readonly operatorId: string;
  private readonly serverUrl: string;

  // eslint-disable-next-line
  private listeners: Record<string, Set<Function>> = {};

  constructor(
    host: string,
    operatorId?: string,
  ) {
    this.operatorId = operatorId ?? `occ_${Math.floor(Math.random() * 100_000)}`;
    this.serverUrl = `https://${host}/wt-operator?OperatorId=${this.operatorId}`;
  }

  on<K extends keyof WebTransportEventMap>(
    event: K,
    listener: Listener<WebTransportEventMap[K]>,
  ): () => void {
    if (!this.listeners[event]) {
      this.listeners[event] = new Set();
    }
    this.listeners[event].add(listener);
    return () => this.off(event, listener);
  }

  off<K extends keyof WebTransportEventMap>(
    event: K,
    listener: Listener<WebTransportEventMap[K]>,
  ): void {
    this.listeners[event]?.delete(listener);
  }

  private emit<K extends keyof WebTransportEventMap>(
    event: K,
    data: WebTransportEventMap[K],
  ): void {
    this.listeners[event]?.forEach((fn) => fn(data));
  }

  getIceServers() {
    return this.iceServers
  }

  async connect(): Promise<void> {
    if (this.transport) return;
    this.destroyed = false;

    if (typeof globalThis.WebTransport === "undefined") {
      throw new Error(
        "WebTransport is not supported in this browser. Use Chrome 97+ or Edge 97+.",
      );
    }

    try {
      console.log(`[WT] Connecting as ${this.operatorId}…`);
      this.transport = new WebTransport(this.serverUrl);

      this.transport.closed
        .then(() => this.handleClose("closed normally"))
        .catch((err) => this.handleClose(`closed with error: ${err}`));

      await this.transport.ready;
      console.log("[WT] Connected");
      this.emit("connected", undefined as never);

      this.startHeartbeat();
      await this.readLoop();
    } catch (err) {
      console.error("[WT] Connection failed:", err);
      this.cleanup();
      this.scheduleReconnect();
    }
  }

  disconnect(): void {
    this.destroyed = true;
    this.cleanup();
    console.log("[WT] Disconnected (manual)");
  }

  async sendRpcRequest(vehicleId: string, method: string, params: Array<any>, timeoutMs?: number) {
    this.nextRpcId++
    const future = new Future()
    this.rpcWaiters.set(this.nextRpcId, future)
    console.log(`[RPC] Send request for ${method} with id=${this.nextRpcId}`)
    this.sendJson({
      "Type": "rpcRequest",
      "From": this.operatorId,
      "To": vehicleId,
      "Payload": {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": this.nextRpcId,
      },
    })
    const result = await future.wait(timeoutMs ?? 10_000)
    return result
  }

  private sendJson(obj: Record<string, unknown>): void {
    if (!this.stream) {
      console.warn("[WT] Cannot send — not connected");
      return;
    }
    const encoded = new TextEncoder().encode(JSON.stringify(obj));
    const frame = new Uint8Array(encoded.length + 1);
    frame.set(encoded);
    frame[encoded.length] = 0;
    this.stream.write(frame).catch((err) => {
      console.error("[WT] Stream write error:", err);
    });
  }

  private async readLoop(): Promise<void> {
    if (!this.transport) return;

    const bidiStream = await this.transport.createBidirectionalStream();
    this.stream = bidiStream.writable.getWriter();
    const reader = bidiStream.readable.getReader();
    const decoder = new TextDecoder();

    try {
      let buffer: number[] = [];
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        for (let i = 0; i < value.length; i++) {
          if (value[i] !== 0) {
            buffer.push(value[i]);
          } else {
            if (buffer.length === 0) continue;
            const json = decoder.decode(new Uint8Array(buffer));
            this.handleMessage(json);
            buffer = [];
          }
        }
      }
    } catch (err) {
      console.error("[WT] Read error:", err);
    } finally {
      reader.releaseLock();
      this.stream?.releaseLock();
      this.stream = null;
    }
  }

  private handleMessage(raw: string): void {
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(raw);
    } catch {
      console.error("[WT] Invalid JSON:", raw);
      return;
    }

    switch (data.Type) {
      case "status":
        this.emit("vehicleList", data.Vehicles as Vehicle[]);
        break;
      case "rpcResponse":
        const msg = data as unknown as RpcResponse;
        const future = this.rpcWaiters.get(msg.Payload.id)
        console.log(`[RPC] Received result for ${msg.Payload.id}`)
        if(future) {
          this.rpcWaiters.delete(msg.Payload.id)
          future.resolve(msg.Payload.result)
        } else {
          console.warn("Received unknown rpc response for id", msg.Payload.id)
        }
        break;
      case "iceCandidate":
        this.emit("iceCandidate", data as unknown as IceCandidateMessage);
        break;
      case "iceServers":
        this.iceServers = (data as any).iceServers as RTCIceServer[]
        console.log("[WT] Received a new set of iceServers", this.iceServers)
        break;
      default:
        console.warn("[WT] Unknown message type:", data.Type);
    }
  }

  private startHeartbeat(): void {
    if (!this.transport) return;
    const writer = this.transport.datagrams.writable.getWriter();
    const ping = new Uint8Array([0]);

    writer.write(ping).catch(() => { });

    this.heartbeatTimer = setInterval(() => {
      writer.write(ping).catch(() => { });
    }, HEARTBEAT_INTERVAL_MS);
  }

  private handleClose(reason: string): void {
    console.log(`[WT] ${reason}`);
    this.cleanup();
    this.emit("disconnected", undefined as never);
    this.scheduleReconnect();
  }

  private cleanup(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stream = null;
    if (this.transport) {
      try {
        this.transport.close();
      } catch {
      }
      this.transport = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.destroyed || this.reconnectTimer) return;
    console.log(`[WT] Reconnecting in ${RECONNECT_DELAY_MS / 1000}s…`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, RECONNECT_DELAY_MS);
  }
}
