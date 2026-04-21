export class Future<T> {
    private promise: Promise<T>;
    private resolveFn!: (value: T) => void;
    private rejectFn!: (reason?: any) => void;

    constructor() {
        this.promise = new Promise<T>((resolve, reject) => {
            this.resolveFn = resolve;
            this.rejectFn = reject;
        });
    }

    resolve(value: T) {
        this.resolveFn(value);
    }

    reject(reason?: any) {
        this.rejectFn(reason);
    }

    async wait(timeoutMs?: number): Promise<T> {
        if (timeoutMs == null) {
            return this.promise;
        }

        return Promise.race([
            this.promise,
            new Promise<T>((_, reject) =>
                setTimeout(() => reject(new Error("Timeout")), timeoutMs)
            ),
        ]);
    }
}
