# Kyu Archiver

**Kyu** is a lightweight, secure, and streaming-capable archiver designed for the modern Unix ecosystem. It combines authenticated encryption (ChaCha20-Poly1305) with adaptive LZ77 compression in a format (QQX5) that is fully pipeline-friendly.

Unlike standard tools, Kyu is designed to be **secure by default**, encrypting all data and metadata with modern cryptography while remaining compatible with standard Unix streams like `tar`.

## Features

* **🔒 Secure:** Authenticated Encryption using ChaCha20-Poly1305 (via Monocypher). Keys derived via Argon2id.
* **📂 Native Directory Support:** Can archive directories directly into USTAR format without external tools.
* **⚡ Adaptive Compression:** Uses a custom LZ77 engine that automatically detects incompressible data (like git objects or images) to prevent file bloating.
* **🌊 Stream Oriented:** Fully supports `stdin` and `stdout` piping. Can be used as a filter in shell scripts.
* **📜 List Mode:** Securely inspect archive contents (filenames and sizes) without extracting or writing data to disk.
* **🚀 Zero Dependencies:** Built with a minimal C99 codebase.

## Building

Kyu has no external dependencies beyond the standard C library.

```bash
# Build using Make
make

# Or manually
./build.sh
```

## Usage

Kyu automatically detects whether it should behave as a file archiver or a stream filter based on your inputs and terminal environment.

### 1. Compressing Files & Directories

**Single File:**
```bash
./kyu -c secret.txt
# Creates: secret.txt.kyu
# Prompts for password securely.
```

**Directory (Native):**
Kyu includes a built-in USTAR writer. It creates standard TAR archives internally.
```bash
./kyu -c MyFolder/
# Creates: MyFolder.tar.kyu
# Contains the full directory tree.
```

**Custom Output:**
```bash
./kyu -c huge_log.log -o archive.kyu
```

### 2. Decompression

**Smart Restore:**
Kyu automatically handles filenames and permissions.
```bash
./kyu -d MyFolder.tar.kyu
# Restores: MyFolder.tar (which can then be extracted via tar)
# Or if it was a single file, restores the original file.
```

**Stream Extraction (Best for Directories):**
You can pipe the decompressed stream directly into `tar` to extract in one step without intermediate files.
```bash
./kyu -d MyFolder.tar.kyu | tar xf -
```

### 3. Unix Streaming (Pipes)

Kyu works seamlessly with Unix pipes. This is ideal for backups or sending data over SSH.

**Backup `/etc` securely:**
```bash
sudo tar cf - /etc | ./kyu -c > etc_backup.kyu
```

**Decrypt and extract on the fly:**
```bash
cat backup.kyu | ./kyu -d | tar xf -
```

### 4. Listing Contents

You can inspect the contents of a `.tar.kyu` archive without extracting it.
```bash
./kyu -l MyFolder.tar.kyu
```
*Note: This decrypts the stream in memory to parse headers but discards the file bodies.*

## Technical Details

### Format (QQX5)
The QQX5 format is chunk-based. Each chunk consists of:
1.  **Length Header (4 bytes):** Encrypted length + "Compressed" flag bit.
2.  **Auth Tag (16 bytes):** Poly1305 MAC.
3.  **Payload (N bytes):** Encrypted data (ChaCha20).

### Compression
Kyu uses a custom **Greedy LZ77** implementation with:
* 32KB Sliding Window.
* Run-Length Encoding (RLE) for literals.
* **Adaptive Mode:** Each 64KB block is compressed independently. If compression does not save space (e.g., on already compressed data), the block is stored raw to avoid expansion overhead.

### Security
* **Cipher:** ChaCha20-Poly1305 (IETF).
* **KDF:** Argon2id (3 passes, 1024KB memory) to resist brute-force attacks.
* **Nonce:** Incremented per chunk to prevent replay/reordering attacks.

## License

MIT License.
Includes Monocypher (CC0/BSD-2-Clause).
