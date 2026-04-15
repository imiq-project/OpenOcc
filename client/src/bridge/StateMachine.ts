export type Mode = "STANDBY" | "DIRECT" | "TRAJECTORY" | "ESTOP";

type ModeListener = (mode: Mode, prev: Mode) => void;

const VALID_TRANSITIONS: Record<Mode, Mode[]> = {
  STANDBY: ["DIRECT", "TRAJECTORY"],
  DIRECT: ["STANDBY", "TRAJECTORY"],
  TRAJECTORY: ["STANDBY", "DIRECT"],
  ESTOP: [],
};

export class StateMachine {
  private _mode: Mode = "STANDBY";
  private listeners = new Set<ModeListener>();

  get mode(): Mode {
    return this._mode;
  }

  on(listener: ModeListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  requestMode(target: Mode): void {
    if (target === this._mode) return;

    if (target === "ESTOP") {
      throw new Error("Use triggerEStop() to enter ESTOP");
    }

    if (this._mode === "ESTOP") {
      throw new Error("Use clearEStop() to leave ESTOP");
    }

    if (!VALID_TRANSITIONS[this._mode].includes(target)) {
      throw new Error(
        `Invalid transition: ${this._mode} → ${target}`,
      );
    }

    this.transition(target);
  }

  triggerEStop(): void {
    if (this._mode === "ESTOP") return;
    this.transition("ESTOP");
  }

  clearEStop(): void {
    if (this._mode !== "ESTOP") {
      throw new Error(`Not in ESTOP (current: ${this._mode})`);
    }
    this.transition("STANDBY");
  }

  forceStandbyOnHighRtt(): boolean {
    if (this._mode !== "DIRECT") return false;
    this.transition("STANDBY");
    return true;
  }

  private transition(target: Mode): void {
    const prev = this._mode;
    this._mode = target;
    this.listeners.forEach((fn) => fn(target, prev));
  }
}
