import { useEffect, useState } from "react";

enum ConfigState {
    Unknown,
    Axis,
    Button,
}

class GamepadConfig {
    public pedalIdx: number = 0
    public pedalState: ConfigState = ConfigState.Unknown
    public wheelIdx: number = 0
    public wheelState: ConfigState = ConfigState.Unknown
    public invertSpeedIdx: number = 0
    public invertSpeedState: ConfigState = ConfigState.Unknown
    constructor(public index: number) { }
}

class GamepadService {

    private config = new GamepadConfig(0)
    private handler = (e: GamepadEvent) => (this.onGamepadConnected(e))
    public onchange: (speed: number, angle: number) => void = (speed, angle) => {}

    constructor()  {
        if (typeof globalThis.window !== "undefined") {
            window.addEventListener("gamepadconnected", this.handler)
        }
    }

    onGamepadConnected(e: GamepadEvent) {
        console.log(
            "[GP] Gamepad connected at index %d: %s. %d buttons, %d axes.",
            e.gamepad.index,
            e.gamepad.id,
            e.gamepad.buttons.length,
            e.gamepad.axes.length,
        );
        console.log("[GP] To get it configured automatically, first move steering wheel to the left, than pedal, than speed invert")
        this.config = new GamepadConfig(e.gamepad.index)
        this.loop()
    };

    destruct() {
        window.removeEventListener("gamepadconnected", this.handler)
    }

    loop() {
        const gp = globalThis.navigator.getGamepads()[this.config.index]
        if (gp === null) return
        requestAnimationFrame(() => this.loop())

        // find angle first as it can be negative
        let angle = 0
        switch (this.config.wheelState) {
            case ConfigState.Axis:
                angle = gp.axes[this.config.wheelIdx]
                break;
            case ConfigState.Button:
                angle = gp.buttons[this.config.wheelIdx].value
                break;
            case ConfigState.Unknown:
                for (let idx = 0; idx < gp.axes.length; ++idx) {
                    if (gp.axes[idx] < 0) {
                        this.config.wheelState = ConfigState.Axis
                        this.config.wheelIdx = idx;
                        console.log("[GP] Selected %d/%d as steering wheel", this.config.wheelIdx, this.config.wheelState)
                        break;
                    }
                }
                // do not search buttons as they cannot be negative anyway?
                break;
            default:
                break;
        }

        // second search for speed input
        let speed = 0
        switch (this.config.pedalState) {
            case ConfigState.Axis:
                speed = gp.axes[this.config.pedalIdx]
                break;
            case ConfigState.Button:
                speed = gp.buttons[this.config.pedalIdx].value
                break;
            case ConfigState.Unknown:
                if (this.config.wheelState != ConfigState.Unknown) {
                    for (let idx = 0; idx < gp.axes.length; ++idx) {
                        if (gp.axes[idx] != 0) {
                            if (this.config.wheelState == ConfigState.Axis && this.config.wheelIdx == idx) {
                                // already mapped to wheel
                            } else {
                                this.config.pedalState = ConfigState.Axis
                                this.config.pedalIdx = idx;
                                console.log("[GP] Selected %d/%d as pedal", this.config.pedalIdx, this.config.pedalState)
                                break;
                            }
                        }
                    }
                    if (this.config.pedalState == ConfigState.Unknown) {
                        for (let idx = 0; idx < gp.buttons.length; ++idx) {
                            if (gp.buttons[idx].value != 0) {
                                if (this.config.wheelState == ConfigState.Button && this.config.wheelIdx == idx) {
                                    // already mapped to wheel
                                } else {
                                    this.config.pedalState = ConfigState.Button
                                    this.config.pedalIdx = idx;
                                    console.log("[GP] Selected %d/%d as pedal", this.config.pedalIdx, this.config.pedalState)
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            default:
                break;
        }

        // third, assign invert speed
        let invertSpeed = false
        switch (this.config.invertSpeedState) {
            case ConfigState.Axis:
                invertSpeed = gp.axes[this.config.pedalIdx] > 0
                break;
            case ConfigState.Button:
                invertSpeed = gp.buttons[this.config.pedalIdx].pressed
                break;
            case ConfigState.Unknown:
                if (this.config.pedalState != ConfigState.Unknown) {
                    for (let idx = 0; idx < gp.axes.length; ++idx) {
                        if (gp.axes[idx] != 0) {
                            if (this.config.wheelState == ConfigState.Axis && this.config.wheelIdx == idx) {
                                // already mapped to wheel
                            } else if(this.config.pedalState == ConfigState.Axis && this.config.pedalIdx == idx) {
                                // already mapped to pedal
                            } else {
                                this.config.invertSpeedState = ConfigState.Axis
                                this.config.invertSpeedIdx = idx;
                                console.log("[GP] Selected %d/%d as speed invert", this.config.invertSpeedIdx, this.config.invertSpeedState)
                                break;
                            }
                        }
                    }
                    if (this.config.invertSpeedIdx == ConfigState.Unknown) {
                        for (let idx = 0; idx < gp.buttons.length; ++idx) {
                            if (gp.buttons[idx].value != 0) {
                                if (this.config.wheelState == ConfigState.Button && this.config.wheelIdx == idx) {
                                    // already mapped to wheel
                                } else if (this.config.pedalState == ConfigState.Button && this.config.pedalIdx == idx) {
                                    // already mapped to pedal
                                } else {
                                    this.config.invertSpeedState = ConfigState.Button
                                    this.config.invertSpeedIdx = idx;
                                    console.log("[GP] Selected %d/%d as speed invert", this.config.invertSpeedIdx, this.config.invertSpeedState)
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            default:
                break;
        }

        // invert angle as left is negative and right is positive, but for us left should be positive and right negative
        this.onchange(invertSpeed ? -speed : speed, -angle)
    }
}

export function useGamepad() {

    const gamepad = new GamepadService()
    useEffect(() => {
        return () => {
            gamepad.destruct()
        };
    }, []);
    return gamepad;
}
