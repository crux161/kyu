import factory from './libkyu.js';

export class KyuStream {
    private module: any;
    private ctx: number;
    private sinkPtr: number;
    private workBuf: number;
    private keyPtr: number;
    
    // Internal buffer for framing
    private stash: Uint8Array | null = null; 

    private constructor(module: any, key: Uint8Array) {
        this.module = module;
        const ctxSize = this.module._kyu_get_sizeof_context();
        this.ctx = this.module._malloc(ctxSize);
        
        this.keyPtr = this.module._malloc(32);
        this.module.HEAPU8.set(key, this.keyPtr);

        // Allocate a work buffer large enough for the max packet size (64KB + 32 overhead)
        this.workBuf = this.module._malloc(65536 + 128);
    }

    static async create(key: Uint8Array): Promise<KyuStream> {
        const mod = await factory();
        return new KyuStream(mod, key);
    }

    private appendToStash(chunk: Uint8Array): Uint8Array {
        if (!this.stash) return chunk;
        const newBuf = new Uint8Array(this.stash.length + chunk.length);
        newBuf.set(this.stash);
        newBuf.set(chunk, this.stash.length);
        return newBuf;
    }

    get transform(): TransformStream {
        let currentController: TransformStreamDefaultController;

        // Callback: C -> JS
        const sinkCallback = (ctx: number, bufPtr: number, len: number) => {
            const cleartext = new Uint8Array(this.module.HEAPU8.subarray(bufPtr, bufPtr + len));
            currentController.enqueue(new Uint8Array(cleartext)); // Clone memory
            return 0; 
        };

        this.sinkPtr = this.module.addFunction(sinkCallback, 'iiii');

        return new TransformStream({
            start: () => {
                const res = this.module._kyu_init(this.ctx, this.keyPtr, this.sinkPtr, 0, 0);
                if (res !== 0) throw new Error(`Init Failed: ${res}`);
            },

            transform: (chunk: Uint8Array, controller) => {
                currentController = controller;
                
                // 1. Combine previous partial data with new chunk
                let data = this.appendToStash(chunk);
                this.stash = null; // Clear stash, we are consuming 'data'

                let offset = 0;
                while (offset < data.length) {
                    const remaining = data.length - offset;

                    // 2. Need at least 16 bytes to read the Header
                    if (remaining < 16) {
                        this.stash = data.slice(offset);
                        break;
                    }

                    // 3. Parse Header to find Packet Length
                    // Header V2: [SeqID (8)] [Flags (4)] [Len (4)]
                    // We need the Length from bytes 12-15 (Little Endian)
                    const p = offset;
                    const payloadLen = (data[p+8]) | (data[p+9] << 8) | (data[p+10] << 16) | (data[p+11] << 24);
                    
                    const packetSize = 16 + 16 + payloadLen; // Header(16) + MAC(16) + Data

                    // 4. Do we have the full packet?
                    if (remaining < packetSize) {
                        this.stash = data.slice(offset);
                        break;
                    }

                    // 5. Process Packet
                    this.module.HEAPU8.set(
                        data.subarray(offset, offset + packetSize), 
                        this.workBuf
                    );

                    const res = this.module._kyu_pull(
                        this.ctx, 
                        this.workBuf, 
                        packetSize
                    );

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
