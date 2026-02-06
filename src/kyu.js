// @ts-ignore: Emscripten module has no type definitions
import factory from './libkyu.js';
export class KyuStream {
    constructor(module, key) {
        this.sinkPtr = 0; // FIX: Initialize to 0
        // Internal buffer for framing
        this.stash = null;
        this.module = module;
        const ctxSize = this.module._kyu_get_sizeof_context();
        this.ctx = this.module._malloc(ctxSize);
        this.keyPtr = this.module._malloc(32);
        this.module.HEAPU8.set(key, this.keyPtr);
        this.workBuf = this.module._malloc(65536 + 128);
    }
    static async create(key) {
        const mod = await factory();
        return new KyuStream(mod, key);
    }
    appendToStash(chunk) {
        if (!this.stash)
            return chunk;
        const newBuf = new Uint8Array(this.stash.length + chunk.length);
        newBuf.set(this.stash);
        newBuf.set(chunk, this.stash.length);
        return newBuf;
    }
    get transform() {
        let currentController;
        const sinkCallback = (ctx, bufPtr, len) => {
            const cleartext = new Uint8Array(this.module.HEAPU8.subarray(bufPtr, bufPtr + len));
            currentController.enqueue(new Uint8Array(cleartext));
            return 0;
        };
        this.sinkPtr = this.module.addFunction(sinkCallback, 'iiii');
        return new TransformStream({
            start: () => {
                const res = this.module._kyu_init(this.ctx, this.keyPtr, this.sinkPtr, 0, 0);
                if (res !== 0)
                    throw new Error(`Init Failed: ${res}`);
            },
            transform: (chunk, controller) => {
                currentController = controller;
                let data = this.appendToStash(chunk);
                this.stash = null;
                let offset = 0;
                while (offset < data.length) {
                    const remaining = data.length - offset;
                    // Need at least 16 bytes to read the Header
                    if (remaining < 16) {
                        this.stash = data.slice(offset);
                        break;
                    }
                    // FIX: Header V2 [SeqID:8] [Len:4] [Flags:4]
                    const p = offset;
                    const payloadLen = (data[p + 8]) | (data[p + 9] << 8) | (data[p + 10] << 16) | (data[p + 11] << 24);
                    const packetSize = 16 + 16 + payloadLen;
                    if (remaining < packetSize) {
                        this.stash = data.slice(offset);
                        break;
                    }
                    // Process Packet
                    this.module.HEAPU8.set(data.subarray(offset, offset + packetSize), this.workBuf);
                    const res = this.module._kyu_pull(this.ctx, this.workBuf, packetSize);
                    if (res !== 0) {
                        controller.error(new Error(`Kyu Decrypt Error: ${res}`));
                        return;
                    }
                    offset += packetSize;
                }
            },
            flush: () => {
                this.module._free(this.ctx);
                this.module._free(this.keyPtr);
                this.module._free(this.workBuf);
                this.module.removeFunction(this.sinkPtr);
            }
        });
    }
}
