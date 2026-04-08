import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { Vehicle } from '../model/vehicle';

class WriteQueue {
  private queue: Promise<void>

  constructor(private writer: WritableStreamDefaultWriter) {
    this.queue = Promise.resolve();
  }

  write(chunk: Uint8Array<ArrayBuffer>) {
    this.queue = this.queue.then(() => this.writer.write(chunk));
    return this.queue;
  }

  close() {
    return this.queue.then(() => this.writer.close());
  }
}

@Injectable({
  providedIn: 'root',
})
export class WebTransportService {
  private transport?: WebTransport;
  private writeQueue?: WriteQueue
  private connected$ = new BehaviorSubject<boolean>(false);
  private statusMessages$ = new Subject<Vehicle[]>();
  private answerMessages$ = new Subject<object>();
  private iceServersUpdated$ = new Subject<Array<RTCIceServer>>();
  occId = "occ_" + Math.floor(Math.random() * 100000)

  constructor() {
    this.connect()
  }

  get statusMessages(): Observable<Vehicle[]> {
    return this.statusMessages$.asObservable();
  }

  get answerMessages(): Observable<any> {
    return this.answerMessages$.asObservable();
  }

  get isConnected(): Observable<boolean> {
    return this.connected$.asObservable();
  }

  get iceServersUpdated(): Observable<Array<RTCIceServer>> {
    return this.iceServersUpdated$.asObservable();
  }

  async connect(): Promise<void> {
    if (this.transport) return;

    try {
      console.log("occId=", this.occId)
      const url = `https://${window.location.host}/wt-operator?OccId=${this.occId}`;
      this.transport = new WebTransport(url);

      this.transport.closed
        .then(() => {
          console.log('WebTransport closed normally.');
          this.connected$.next(false);
        })
        .catch((err) => {
          console.error('WebTransport closed with error:', err);
          this.connected$.next(false);
        });

      await this.transport.ready;
      this.connected$.next(true);
      console.log('WebTransport connection ready');

      // TODO: clear timer on connection loss
      const datagramWriter = this.transport.datagrams.writable.getWriter();
      await datagramWriter.write(new Uint8Array([0])); // 1-byte ping
      setInterval(async () => {
        await datagramWriter.write(new Uint8Array([0])); // 1-byte ping
      }, 5000);

      this.readIncoming(); // start reading messages
    } catch (err) {
      console.error('Failed to connect:', err);
      this.connected$.next(false);
      throw err;
    }
  }

  private async readIncoming() {
    if (!this.transport) return;

    const stream = await this.transport.createBidirectionalStream();
    const reader = stream.readable.getReader();
    const writer = stream.writable.getWriter();

    this.writeQueue = new WriteQueue(writer)

    try {
      let buffer = []
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        for (let i = 0; i < value.length; i++) {
          if (value[i] != 0) {
            buffer.push(value[i])
          } else {
            const decoder = new TextDecoder();
            const data = JSON.parse(decoder.decode(new Uint8Array(buffer)))
            const type = data["Type"]
            switch (type) {
              case "status":
                this.statusMessages$.next(data["Vehicles"].map(Vehicle.fromJson));
                break;
              case "answer":
                this.answerMessages$.next(data)
                break
              case "iceServers":
                this.iceServersUpdated$.next(data["iceServers"])
                break;
              default:
                console.error(`Unknown message ${type}`)
                break;
            }
            buffer = []
          }
        }
      }
    } catch (err) {
      console.error('Error reading messages:', err);
    } finally {
      reader.releaseLock();
      this.connected$.next(false);
    }
  }

  async sendDatagram(data: string) {
    if (!this.transport || !this.connected$.value) {
      throw new Error('WebTransport not connected.');
    }

    const writer = this.transport.datagrams.writable.getWriter();
    await writer.write(new TextEncoder().encode(data));
    writer.releaseLock();
  }

  async sendMessage(msg: string) {
    if (!this.transport || !this.connected$.value || !this.writeQueue) {
      throw new Error('WebTransport not connected.');
    }
    const encoder = new TextEncoder();
    await this.writeQueue.write(encoder.encode(msg + "\0"))
  }

  disconnect() {
    this.transport?.close();
    this.transport = undefined;
    this.connected$.next(false);
  }

}
