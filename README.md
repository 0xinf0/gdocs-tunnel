# Google Docs Tunnel

Censorship circumvention tool that tunnels traffic through Google Docs Viewer using domain fronting. Designed for users in Iran and other censored networks.

## How It Works

```
[Client in Iran] --> [Google Front] --> [Google Docs Viewer] --> [Your Server] --> [Internet]
```

1. Client connects to `www.google.com` (allowed by censors)
2. Sets `Host: docs.google.com` header (domain fronting)
3. Google Docs Viewer fetches content from your server
4. Traffic is encrypted with X25519 + AES-256-GCM
5. Server IPv6 rotation (2^64 addresses) prevents rate limiting

## Quick Start

### Client (Users in Iran)

Just run the binary - everything is hardcoded:

```bash
./gdocs_tunnel
```

This starts a SOCKS5 proxy on `127.0.0.1:1080`.

**Usage with applications:**
```bash
# curl
curl --socks5 127.0.0.1:1080 https://example.com

# Configure browser/app to use SOCKS5 proxy: 127.0.0.1:1080
```

**Options:**
```
--port <PORT>    Local SOCKS5 port (default: 1080)
--test           Run connection test and exit
--verbose        Enable debug logging
```

### Server (Your Infrastructure)

```bash
# First run generates keypair
./gdocs_server --port 8080

# Show public key (give to client builds)
./gdocs_server --show-key
```

**Options:**
```
--port <PORT>       Listen port (default: 8080)
--key-file <PATH>   Key file path (default: server.key)
--show-key          Print public key and exit
--verbose           Enable debug logging
```

## Server Setup

### Requirements

- Public IPv6 /64 block (for rate limit evasion)
- BGP announcement capability (or provider support)
- Port 8080 open (HTTP)

### IPv6 Configuration

1. **Announce your IPv6 prefix via BGP** (e.g., `2602:f7d0:3::/48`)

2. **Route the /64 to your server**
   ```
   # On router (example for Juniper)
   set routing-options rib inet6.0 static route 2602:f7d0:3:10::/64 next-hop <server-link-local>
   ```

3. **Enable local binding on server**
   ```bash
   ip -6 route add local 2602:f7d0:3:10::/64 dev lo
   ```

4. **Verify from external host**
   ```bash
   curl "http://[2602:f7d0:3:10:abcd:1234:5678:9abc]:8080/health.txt"
   # Should return: OK
   ```

## Building

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add cross-compilation targets
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

### Build Client

```bash
# Native (macOS/Linux)
cargo build --release

# Linux x86_64 (from macOS)
cargo build --release --target x86_64-unknown-linux-gnu

# Linux static binary
cargo build --release --target x86_64-unknown-linux-musl

# Android ARM64
cargo build --release --target aarch64-linux-android

# Android ARM32
cargo build --release --target armv7-linux-androideabi
```

### Build Server

```bash
cargo build --release --target x86_64-unknown-linux-gnu --bin gdocs_server
```

### Updating Hardcoded Config

Edit `src/main.rs`:

```rust
// Server IPv6 prefix - your /64 block
const IPV6_PREFIX: &str = "2602:f7d0:3:10::/64";
const SERVER_PORT: u16 = 8080;

// Server's public key (from: ./gdocs_server --show-key)
const SERVER_PUBLIC_KEY: &str = "nWlaxQRHkjUr5zsZb86oCjifAcsX6mTvhFU0+LchpxM=";
```

Then rebuild the client.

## Android Integration

The client binary can be embedded in an Android app:

### Building for Android

```bash
# ARM64 (most modern devices)
cargo build --release --target aarch64-linux-android

# ARM32 (older devices)
cargo build --release --target armv7-linux-androideabi
```

### Integration Options

1. **As executable**: Extract binary to app's native lib directory, execute via `ProcessBuilder`

2. **As shared library**: Modify to build as `.so`, call via JNI

3. **VpnService**: For system-wide proxying, implement Android VpnService that routes through the SOCKS5 proxy

### Example Android Usage

```kotlin
// Extract and run the binary
val binary = File(context.applicationInfo.nativeLibraryDir, "libgdocs_tunnel.so")
val process = ProcessBuilder(binary.absolutePath, "--port", "1080")
    .redirectErrorStream(true)
    .start()

// Now connect through SOCKS5 at 127.0.0.1:1080
```

## Security

- **X25519 key exchange**: Each session uses ephemeral keys (Noise_N pattern)
- **AES-256-GCM encryption**: All tunnel traffic is authenticated and encrypted
- **No logs**: Server doesn't log destination addresses
- **Domain fronting**: Traffic appears as Google Docs requests
- **Server IPv6 rotation**: Each request uses random IP from 2^64 address space
- **Client IP rotation**: Rotates across 22 Google Anycast frontend IPs to distribute rate limits

## Protocol

```
Client                          Google                         Server
   |                               |                              |
   |-- HTTPS to www.google.com --> |                              |
   |   Host: docs.google.com       |                              |
   |                               |-- HTTP GET ----------------> |
   |                               |   /tunnel/{session}/init.txt |
   |                               |                              |
   |                               | <-- JSON response ---------- |
   |                               |    {"status":"ok",           |
   |                               |     "data":"<encrypted>"}    |
   | <-- viewer response --------- |                              |
```

### URL Endpoints

```
/health.txt                              - Health check
/tunnel/{session_id}/init.txt            - Initialize session
/tunnel/{session_id}/connect/{host}/{port} - Connect to destination
/tunnel/{session_id}/send/{data}.txt     - Send data (encrypted, base64url)
/tunnel/{session_id}/recv.txt            - Receive pending data
/tunnel/{session_id}/close.txt           - Close session
```

### Session ID

Session ID = Base64url(Noise_N handshake message) = 64 characters

Contains the client's ephemeral public key + AEAD tag, allowing the server to derive the same symmetric key.

## Performance

**Measured (real-world testing):**

| Metric | Value | Notes |
|--------|-------|-------|
| Google Docs RTT | ~500ms | Single viewer request |
| Session init | ~500ms | 1 Google roundtrip |
| TCP connect | ~500ms | 1 Google roundtrip |
| Full HTTPS request | 5-7 sec | Init + connect + TLS + data |
| Throughput | 1-5 KB/s | Limited by Google RTT |
| Server IPv6 pool | 2^64 | Avoids server-side rate limits |
| Client Google IPs | 22 | Distributes client-side rate limits |

**Rate Limiting:**
- Google rate limits per client IP and per destination server IP
- Server-side: IPv6 rotation (2^64 addresses) prevents server rate limits
- Client-side: Rotates across 22 Google Anycast IPs to distribute limits
- ~10 requests/minute sustainable per IP pair
- Bursts trigger "No document ID" errors
- 100ms minimum delay between requests helps

**Best for:**
- Telegram, Signal, WhatsApp messaging
- Low-bandwidth web browsing
- Email access
- Text-based applications

**Not suitable for:**
- Video streaming
- Large file downloads
- Real-time gaming

**Optimization (v2 batching):**
- Batch multiple requests → 1 Google roundtrip
- zstd compression → 70-90% smaller payloads
- Can improve effective throughput 5-10x

## Troubleshooting

**"No document ID found"**
- Google rate limiting - wait and retry
- Server not reachable from Google

**"Key derivation failed"**
- Client and server public keys don't match
- Rebuild client with correct `SERVER_PUBLIC_KEY`

**"Connection timeout"**
- IPv6 routing not configured
- Check: `curl "http://[your:ipv6:addr]:8080/health.txt"`

## Files

```
src/main.rs           - Client source
src/bin/server.rs     - Server source
Cargo.toml            - Rust dependencies
server.key            - Server keypair (64 bytes: private + public)
```

## License

MIT
