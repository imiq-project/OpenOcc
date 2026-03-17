import { Component, signal, ElementRef, ViewChild } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { AppDrawer } from './drawer/drawer';
import { OnInit, OnDestroy } from '@angular/core';
import { WebTransportService } from '../lib//webtransport.service';
import { State as RtcState, WebRtcService } from '../lib//webrtc.service';
import { Subscription } from 'rxjs';
import { ToastModule } from 'primeng/toast';
import { MessageService } from 'primeng/api';
import { Vehicle } from '../model/vehicle';
import { WebRtcStatus as RtcStatus } from '../lib/webrtc.service'
import { LeafletModule } from '../lib/components/leaflet/leaflet'
import { TagModule } from 'primeng/tag';
import { ButtonModule } from 'primeng/button';
import { DialogModule } from 'primeng/dialog';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { ConfigDialog } from './config-dialog/config-dialog';
import { GamepadService } from '../lib/gamepad.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, AppDrawer, ToastModule, LeafletModule, TagModule, ButtonModule, DialogModule, ProgressSpinnerModule, ConfigDialog],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit, OnDestroy {
  RtcState = RtcState // expose to template
  vehicles = signal<Vehicle[]>([]);
  rtcStatus = signal<RtcStatus>(new RtcStatus(RtcState.Disconnected))
  vehicleToConfigure = signal<Vehicle | null>(null)
  gamepadIndex = signal<number | null>(null)

  subs = new Subscription();

  @ViewChild('remoteVideo', { static: true })
  remoteVideo!: ElementRef<HTMLVideoElement>;

  constructor(
    private webTransport: WebTransportService,
    private webRtc: WebRtcService,
    private gamepadService: GamepadService,
    private toastService: MessageService) {
  }

  ngOnInit() {
    this.subs.add(
      this.webTransport.statusMessages.subscribe((msg) => {
        this.vehicles.set(msg)
      })
    );

    this.subs.add(
      this.webTransport.answerMessages.subscribe((msg) => {
        this.webRtc.answerReceived(msg)
      })
    );

    this.subs.add(
      this.webTransport.isConnected.subscribe((isConnected) => {
        const detail = isConnected ? "Connection Established" : "Connection Lost"
        const severity = isConnected ? "success" : "error"
        const sticky = isConnected ? false : true
        this.toastService.add({ detail: detail, severity: severity, sticky: sticky })
      })
    );

    this.subs.add(
      this.webRtc.status.subscribe((status) => {
        this.rtcStatus.set(status)
      })
    )

    this.subs.add(
      this.gamepadService.connected.subscribe((gamepad) => {
        this.toastService.add({ detail: `Gamepad "${gamepad.id}" connected`, severity: "success" })
        this.gamepadIndex.set(gamepad.index)
      })
    )

    this.subs.add(
      this.gamepadService.disconnected.subscribe((gamepad) => {
        this.toastService.add({ detail: `Gamepad "${gamepad.id}" disconnected`, severity: "error" })
        this.gamepadIndex.set(null)
      })
    )

  }

  ngOnDestroy() {
    this.subs.unsubscribe();
  }

  startTeleop(vehicle: Vehicle) {
    this.webRtc.start(this.webTransport.occId, vehicle, this.remoteVideo.nativeElement, () => this.getPingPayload())
  }

  stopTeleop() {
    this.webRtc.stop()
  }

  getPingPayload() {
    let idx = this.gamepadIndex()
    let speed = 0, angle = 0
    if (idx !== null) {
      const g = navigator.getGamepads()[idx]
      if (g === null) {
        // TODO
        console.error("Gamepad null!")
      } else {
        // console.log(g.axes)
        // 2: rückwärts
        // 0: lenkrad
        // 5: gas
        speed = (g.axes[5] + 1) * -10 * Math.sign(g.axes[2]),
        angle = g.axes[0] * 20
      }
    } else {
      if(this.pressedKeys.has('w')) {
        speed = 20
      }
      if(this.pressedKeys.has('s')) {
        speed = -20
      }
      if(this.pressedKeys.has('a')) {
        angle = -20
      }
      if(this.pressedKeys.has('d')) {
        angle = +20
      }
    }
    return JSON.stringify({
      speed: speed,
      angle: angle,
    })
  }

  private pressedKeys = new Set<string>()
  keydown(event: KeyboardEvent) {
    this.pressedKeys.add(event.key)
  }

  keyup(event: KeyboardEvent) {
    this.pressedKeys.delete(event.key)
  }
}
