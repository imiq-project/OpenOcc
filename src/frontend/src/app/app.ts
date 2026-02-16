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

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, AppDrawer, ToastModule, LeafletModule, TagModule, ButtonModule, DialogModule, ProgressSpinnerModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit, OnDestroy {
  RtcState = RtcState // expose to template
  vehicles = signal<Vehicle[]>([]);
  rtcStatus = signal<RtcStatus>(new RtcStatus(RtcState.Disconnected))

  subs = new Subscription();

  @ViewChild('remoteVideo', { static: true })
  remoteVideo!: ElementRef<HTMLVideoElement>;

  constructor(
    private webTransport: WebTransportService,
    private webRtc: WebRtcService,
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
  }

  ngOnDestroy() {
    this.subs.unsubscribe();
  }

  startTeleop(vehicle: Vehicle) {
    this.webRtc.start(this.webTransport.occId, vehicle, this.remoteVideo.nativeElement, '[]')
  }

  stopTeleop() {
    this.webRtc.stop()
  }

  private pressedKeys = new Set<string>()
  keydown(event: KeyboardEvent) {
    this.pressedKeys.add(event.key)
    if(this.rtcStatus().state == RtcState.Connected) {
      this.webRtc.setPing(JSON.stringify(Array.from(this.pressedKeys.keys())))
    }
  }

  keyup(event: KeyboardEvent) {
    this.pressedKeys.delete(event.key)
    if(this.rtcStatus().state == RtcState.Connected) {
      this.webRtc.setPing(JSON.stringify(Array.from(this.pressedKeys.keys())))
    }
  }
}
