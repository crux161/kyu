import initLibKyu from './libkyu.js';
import { performance } from 'perf_hooks';

async function runBenchmark() {
    const Kyu = await initLibKyu();
    const CHUNK_SIZE = 65536; 
    const ITERATIONS = 1000;

    // Sink: Returning 0 tells C "Success"
    const sinkPtr = Kyu.addFunction((ctx, buf, len) => 0, 'iiii');

    const dataPtr = Kyu._malloc(CHUNK_SIZE);
    const ctxPtr = Kyu._malloc(4096); // Slightly larger for safety
    const keyPtr = Kyu._malloc(32);
    
    // Fill initial data
    Kyu.HEAPU8.set(new Uint8Array(CHUNK_SIZE).fill(0xAA), dataPtr);
    Kyu.HEAPU8.fill(0x42, keyPtr, keyPtr + 32);

    // Init
    const res = Kyu._kyu_init(ctxPtr, keyPtr, sinkPtr, 0, 6);
    if (res !== 0) throw new Error(`Init failed: ${res}`);

    console.log("Benchmark starting...");
    const t0 = performance.now();
    
    for (let i = 0; i < ITERATIONS; i++) {
        // Benchmarking Push (Compress + Encrypt)
        const ret = Kyu._kyu_push(ctxPtr, dataPtr, CHUNK_SIZE, 0);
        if (ret !== 0) throw new Error(`Push failed: ${ret}`);
    }
    
    const t1 = performance.now();
    const totalTime = (t1 - t0) / 1000;
    const totalMB = (CHUNK_SIZE * ITERATIONS) / (1024 * 1024);
    
    console.log(`Throughput: ${(totalMB / totalTime).toFixed(2)} MB/s`);

    // Cleanup
    Kyu._free(dataPtr);
    Kyu._free(ctxPtr);
    Kyu._free(keyPtr);
}

runBenchmark().catch(console.error);
