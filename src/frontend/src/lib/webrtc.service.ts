import { Injectable, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { Vehicle } from '../model/vehicle';

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
export class WebRtcService implements OnDestroy {

    private connection?: Connection;
    private status$ = new BehaviorSubject<WebRtcStatus>(new WebRtcStatus(State.Disconnected));

    get status(): Observable<WebRtcStatus> {
        return this.status$.asObservable();
    }

    async start(occId: string, vehicle: Vehicle, targetEl: HTMLVideoElement, getPingCallback: PingCallback) {
        if (this.connection) {
            console.error("Cannot start WebRTC: connection already exists")
            return
        }
        console.log("Starting WebRTC for", vehicle.id)
        const rtc = new RTCPeerConnection({
            iceServers: [
                {
                    urls: "stun:stun.relay.metered.ca:80",
                },
                {
                    urls: "turn:global.relay.metered.ca:80",
                    username: "7e3825a0cbf33ede91e4c977",
                    credential: "1PsnqW7+TZspLryk",
                },
                {
                    urls: "turn:global.relay.metered.ca:80?transport=tcp",
                    username: "7e3825a0cbf33ede91e4c977",
                    credential: "1PsnqW7+TZspLryk",
                },
                {
                    urls: "turn:global.relay.metered.ca:443",
                    username: "7e3825a0cbf33ede91e4c977",
                    credential: "1PsnqW7+TZspLryk",
                },
                {
                    urls: "turns:global.relay.metered.ca:443?transport=tcp",
                    username: "7e3825a0cbf33ede91e4c977",
                    credential: "1PsnqW7+TZspLryk",
                },
            ],
        })
        this.connection = new Connection(rtc, getPingCallback)
        rtc.addTransceiver('video');
        const dc = rtc.createDataChannel("ping", {
            ordered: false,
            maxRetransmits: 0
        })
        dc.onopen = () => {
            this.connection!.pingTimer = setInterval(() => {
                dc.send(this.connection!.pingCallback())
            }, 50)
        }

        rtc.onicecandidate = async (e: RTCPeerConnectionIceEvent) => {
            if (!e.candidate) {
                // end of ice search
                return
            }
            console.log("New ice candidate", e.candidate)
            await fetch(`/send?Recipient=${vehicle.id}`, {
                method: "POST",
                body: JSON.stringify({ "Type": "ice", "Candidate": e.candidate.toJSON() })
            })
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
        await fetch(`/send?Recipient=${vehicle.id}`, {
            method: "POST",
            body: JSON.stringify({ "Type": "offer", "OccId": occId, "Sdp": offer.sdp })
        })
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

    ngOnDestroy(): void {
        this.connection?.rtc.close()
    }

}