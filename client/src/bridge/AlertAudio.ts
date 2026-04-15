export class AlertAudio {
    private ctx: AudioContext | null = null;
    private criticalTimer: ReturnType<typeof setInterval> | null = null;

    private getContext(): AudioContext {
        if (!this.ctx) this.ctx = new AudioContext();
        if (this.ctx.state === "suspended") this.ctx.resume();
        return this.ctx;
    }

    private beep(frequency: number, duration: number, startOffset: number) {
        const ctx = this.getContext();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.type = "square";
        osc.frequency.value = frequency;
        gain.gain.value = 0.15;
        const t = ctx.currentTime + startOffset;
        osc.start(t);
        osc.stop(t + duration);
    }

    playCritical() {
        if (this.criticalTimer) return;
        const burst = () => {
            for (let i = 0; i < 3; i++) this.beep(880, 0.15, i * 0.25);
        };
        burst();
        this.criticalTimer = setInterval(burst, 3000);
    }

    playWarning() {
        this.beep(660, 0.3, 0);
    }

    stopCritical() {
        if (this.criticalTimer) {
            clearInterval(this.criticalTimer);
            this.criticalTimer = null;
        }
    }

    stopAll() {
        this.stopCritical();
    }

    dispose() {
        this.stopAll();
        if (this.ctx) {
            this.ctx.close();
            this.ctx = null;
        }
    }
}
