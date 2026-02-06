import initLibKyu from './libkyu.js';
import { performance } from 'perf_hooks';

async function runBenchmark() {
    const Kyu = await initLibKyu();
    const CHUNK_SIZE = 65536; 
    const ITERATIONS = 1000;

    // 1. Get exact size required by the C struct
    const ctxSize = Kyu._kyu_get_sizeof_context();
    console.log(`Allocating kyu_context: ${ctxSize} bytes`);

    // 2. Setup Memory
    const ctxPtr = Kyu._malloc(ctxSize); 
    const dataPtr = Kyu._malloc(CHUNK_SIZE);
    const keyPtr = Kyu._malloc(32);
    
    // Sink: Returning 0 tells C "Success"
    const sinkPtr = Kyu.addFunction((ctx, buf, len) => 0, 'iiii');

    // Fill data
    Kyu.HEAPU8.set(new Uint8Array(CHUNK_SIZE).fill(0xAA), dataPtr);
    Kyu.HEAPU8.fill(0x42, keyPtr, keyPtr + 32);

    // 3. Initialize (memset inside here will now be safe)
    const res = Kyu._kyu_init(ctxPtr, keyPtr, sinkPtr, 0, 6);
    if (res !== 0) throw new Error(`Init failed: ${res}`);

    console.log("Benchmark starting...");
    const t0 = performance.now();
    
    for (let i = 0; i < ITERATIONS; i++) {
        const ret = Kyu._kyu_push(ctxPtr, dataPtr, CHUNK_SIZE, 0);
        if (ret !== 0) throw new Error(`Push failed: ${ret}`);
    }
    
    const t1 = performance.now();
    const totalTime = (t1 - t0) / 1000;
    const totalMB = (CHUNK_SIZE * ITERATIONS) / (1024 * 1024);
    
    console.log(`Throughput: ${(totalMB / totalTime).toFixed(2)} MB/s`);

    // 4. Cleanup
    // Free internal C buffers first
    // (We need to export kyu_free if we want to be 100% clean, but calling free() on pointers is minimal)
    // For now, just freeing the main pointers is enough for the benchmark not to crash.
    
    Kyu._free(dataPtr);
    Kyu._free(ctxPtr);
    Kyu._free(keyPtr);
}

runBenchmark().catch(console.error);
