import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { Vehicle } from '../model/vehicle';
import { WebTransportService } from './webtransport.service';
import { Subscription } from 'rxjs';

export enum State {
    Disconnected = "disconnected",
    Connecting = "connecting",
    Connected = "connected",
}


export class WebRtcStatus {
    constructor(
        public state: State,
        public vehicle?: Vehicle, // only set for state != disconnected
    ) { }
}

type PingCallback = () => string;

class Connection {
    constructor(
        public rtc: RTCPeerConnection,
        public pingCallback: PingCallback,
        public pingTimer: number = 0,
    ) { }
}

@Injectable({
    providedIn: 'root',
})
export class WebRtcService {

    private connection?: Connection;
    private status$ = new BehaviorSubject<WebRtcStatus>(new WebRtcStatus(State.Disconnected));
    private iceServers = new Array<RTCIceServer>()
    subs = new Subscription();

    constructor(private webTransport: WebTransportService) {
        this.subs.add(
            this.webTransport.iceServersUpdated.subscribe((servers) => {
                this.iceServers = servers
                console.info(`Received ${servers.length} new ICE servers`)
            })
        );
    }

    get status(): Observable<WebRtcStatus> {
        return this.status$.asObservable();
    }

    setIceServers(servers: Array<RTCIceServer>) {
        this.iceServers = servers
        console.log(`Updated ICE servers, got ${servers.length} servers`)
    }

    async start(occId: string, vehicle: Vehicle, targetEl: HTMLVideoElement, getPingCallback: PingCallback) {
        if (this.connection) {
            console.error("Cannot start WebRTC: connection already exists")
            return
        }
        console.log("Starting WebRTC for", vehicle.id)
        const rtc = new RTCPeerConnection({
            iceServers: this.iceServers
        })
        this.connection = new Connection(rtc, getPingCallback)
        rtc.addTransceiver('video');
        const commandChannel = rtc.createDataChannel('command', {
            ordered: true,
        })
        commandChannel.onmessage = console.log
        const pingChannel = rtc.createDataChannel("ping", {
            ordered: false,
            maxRetransmits: 0,
        })
        pingChannel.onopen = () => {
            this.connection!.pingTimer = setInterval(() => {
                pingChannel.send(this.connection!.pingCallback())
            }, 50)
        }

        rtc.onicecandidate = async (e: RTCPeerConnectionIceEvent) => {
            if (!e.candidate) {
                // end of ice search
                return
            }
            console.log("New ice candidate", e.candidate)
            await this.webTransport.sendMessage(
                JSON.stringify({
                    "Type": "iceCandidate",
                    "To": vehicle.id,
                    "Candidate": e.candidate.toJSON()
                })
            )
        }
        rtc.onicecandidateerror = (event) => {
            console.log("onicecandidateerror", event)
        }
        rtc.ontrack = (event) => {
            targetEl.srcObject = event.streams[0];
        };

        rtc.onconnectionstatechange = () => {
            switch (rtc?.connectionState) {
                case "new":
                case 'connecting':
                    break
                case "connected":
                    this.status$.next(new WebRtcStatus(State.Connected, vehicle))
                    break;
                case "closed":
                case "disconnected":
                case "failed":
                    this.status$.next(new WebRtcStatus(State.Disconnected, vehicle))
                    break;
                default:
                    console.error("Unknown state", rtc?.connectionState)
            }
        }

        this.status$.next(new WebRtcStatus(State.Connecting, vehicle))

        const offer = await rtc.createOffer()
        await rtc.setLocalDescription(offer)
        await this.webTransport.sendMessage(
            JSON.stringify({
                "To": vehicle.id,
                "Type": "offer",
                "OccId": occId,
                "Sdp": offer.sdp
            })
        )
    }

    stop() {
        if (!this.connection) {
            console.error("Cannot stop web rtc: no connection created")
            return
        }
        clearInterval(this.connection.pingTimer)
        this.connection.rtc.onicecandidate = null
        this.connection.rtc.ontrack = null
        this.connection.rtc.onconnectionstatechange = null
        this.connection.rtc?.close()
        this.connection = undefined
        this.status$.next(new WebRtcStatus(State.Disconnected))
    }

    async answerReceived(answer: any) {
        if (!this.connection) {
            console.error("Received answer without active connection")
            return
        }
        await this.connection.rtc.setRemoteDescription({
            sdp: answer["Sdp"],
            type: 'answer',
        })
    }

}