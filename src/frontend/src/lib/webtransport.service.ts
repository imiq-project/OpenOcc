import { Injectable, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { Vehicle } from '../model/vehicle';
import { WebRtcService } from './webrtc.service';


@Injectable({
  providedIn: 'root',
})
export class WebTransportService implements OnDestroy {
  private transport?: WebTransport;
  private connected$ = new BehaviorSubject<boolean>(false);
  private statusMessages$ = new Subject<Vehicle[]>();
  private answerMessages$ = new Subject<object>();
  occId = "occ_" + Math.floor(Math.random() * 100000)

  constructor(private webRtcService: WebRtcService) {
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
                this.webRtcService.setIceServers(data["iceServers"])
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

  sendData(data: string) {
    if (!this.transport || !this.connected$.value) {
      throw new Error('WebTransport not connected.');
    }

    const writer = this.transport.datagrams.writable.getWriter();
    writer.write(new TextEncoder().encode(data));
    writer.releaseLock();
  }

  disconnect() {
    this.transport?.close();
    this.transport = undefined;
    this.connected$.next(false);
  }

  ngOnDestroy() {
    this.disconnect();
    this.statusMessages$.complete();
    this.answerMessages$.complete();
    this.connected$.complete();
  }
}
