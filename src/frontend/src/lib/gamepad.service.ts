import { Injectable, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';


@Injectable({
    providedIn: 'root',
})
export class GamepadService {

    private connected$ = new Subject<Gamepad>()
    private disConnected$ = new Subject<Gamepad>()
    private gamepads = new Array<Gamepad>()

    get connected(): Observable<Gamepad> {
        return this.connected$.asObservable();
    }

    get disconnected(): Observable<Gamepad> {
        return this.disConnected$.asObservable();
    }

    constructor() {
        window.addEventListener("gamepadconnected", (event) => {
            this.connected$.next(event.gamepad)
            this.gamepads.push(event.gamepad)
        })

        window.addEventListener("gamepaddisconnected", (event) => {
            const idx = this.gamepads.findIndex(g => g.id === event.gamepad.id)
            this.gamepads.splice(idx, 1)
            this.disConnected$.next(event.gamepad)
        })
    }
}