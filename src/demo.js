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

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}


playBtn.addEventListener('click', async () => {
    try {
        playBtn.disabled = true;
        status.textContent = "Initializing WASM...";

        // 1. Initialize Kyu (Hardcoded key 0x42)
        const key = new Uint8Array(32).fill(0x42);
        kyu = await KyuStream.create(key);
        
        status.textContent = "Buffering & Decrypting...";
        const file = fileInput.files[0];

        // 2. Create a stream from the file
        const fileStream = file.stream();

        // 3. Pipe through Kyu Decryption
        const decryptedStream = fileStream.pipeThrough(kyu.transform);

        // 4. Consolidate the stream into a Blob
        // FIX: We must declare 'newResponse' here before using it!
        const newResponse = new Response(decryptedStream);
        const rawBlob = await newResponse.blob();

        // 5. Apply the correct MIME type (Important for the browser player)
        // If your source was .mp4, use 'video/mp4'. If .webm, use 'video/webm'.
        const videoBlob = new Blob([rawBlob], { type: 'video/mp4' });
        let fileSize = formatBytes(videoBlob.size, 2); 
        const url = URL.createObjectURL(videoBlob);

        console.log(`Decrypted Video Size: ${fileSize}`);
        
        video.src = url;
        video.play();
        status.textContent = "Playing Secure Stream";

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
