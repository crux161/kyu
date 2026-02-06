import { KyuStream } from './kyu.js'; // The output from 'tsc kyu.ts'

const fileInput = document.getElementById('fileInput');
const playBtn = document.getElementById('playBtn');
const status = document.getElementById('status');
const video = document.getElementById('videoPlayer');

// Stats Elements
const elMb = document.getElementById('perf-mb');
const elMem = document.getElementById('perf-mem');
const elChunks = document.getElementById('perf-chunks');

let kyu = null;

// Enable button when file is picked
fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        playBtn.disabled = false;
        status.textContent = `Selected: ${fileInput.files[0].name}`;
    }
});

playBtn.addEventListener('click', async () => {
    try {
        playBtn.disabled = true;
        status.textContent = "Initializing WASM...";

        // 1. Initialize Kyu (Hardcoded key for demo: 0x42 repeated)
        const key = new Uint8Array(32).fill(0x42);
        kyu = await KyuStream.create(key);
        
        status.textContent = "Buffering...";
        const file = fileInput.files[0];

        // 2. Create a stream from the file
        const fileStream = file.stream();

        // 3. Pipe through Kyu Decryption
        // File -> Kyu(Decrypt/Decompress) -> Decrypted Stream
        const decryptedStream = fileStream.pipeThrough(kyu.transform);

        // 4. Create a URL for the video element
        const response = new Response(decryptedStream);
        const blob = await response.blob(); // Note: For massive files, use MediaSource API instead of blob()
        const url = URL.createObjectURL(blob);

        video.src = url;
        video.play();
        status.textContent = "Playing Secure Stream";

        // Start perf monitoring
        monitorPerf();

    } catch (e) {
        console.error(e);
        status.textContent = `Error: ${e.message}`;
        status.style.color = "#ff5555";
        playBtn.disabled = false;
    }
});

function monitorPerf() {
    // Simple mock stats - in a real MediaSource implementation 
    // we would measure the throughput of the TransformStream.
    // Since we used .blob() above, the processing happens instantly before playback.
    elChunks.textContent = "Complete"; 
}
