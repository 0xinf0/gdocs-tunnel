# Android Implementation Guide for LLM

You are implementing an Android app that embeds the `gdocs-tunnel` censorship circumvention tool. This document contains everything you need.

## Overview

`gdocs-tunnel` is a SOCKS5 proxy that tunnels traffic through Google Docs Viewer using domain fronting. It allows users in Iran (and other censored networks) to access the internet by making all traffic appear as legitimate Google Docs requests.

**How it works:**
```
Android App → SOCKS5 (127.0.0.1:1080) → gdocs_tunnel binary → Google Docs Viewer → Server → Internet
```

## Binary Downloads

Get the pre-built binaries from:
https://github.com/0xinf0/gdocs-tunnel/releases/tag/v0.1.0

| Architecture | File | Android ABI |
|--------------|------|-------------|
| ARM64 (modern phones) | `gdocs_tunnel-android-arm64` | `arm64-v8a` |
| ARM32 (older phones) | `gdocs_tunnel-android-arm32` | `armeabi-v7a` |

## Integration Approach

### Option 1: Execute as Binary (Recommended)

The binary is self-contained with all config hardcoded. Just execute it.

**Step 1: Include binary in APK**

Place binaries in:
```
app/src/main/jniLibs/arm64-v8a/libgdocs_tunnel.so
app/src/main/jniLibs/armeabi-v7a/libgdocs_tunnel.so
```

Note: Rename to `.so` extension so Android packages it correctly, even though it's an executable.

**Step 2: Extract and execute**

```kotlin
class TunnelService : Service() {
    private var tunnelProcess: Process? = null

    fun startTunnel(): Boolean {
        val nativeLibDir = applicationInfo.nativeLibraryDir
        val binary = File(nativeLibDir, "libgdocs_tunnel.so")

        if (!binary.exists()) {
            Log.e("Tunnel", "Binary not found: ${binary.absolutePath}")
            return false
        }

        // Make executable (should already be, but ensure)
        binary.setExecutable(true)

        // Start the tunnel process
        val processBuilder = ProcessBuilder(
            binary.absolutePath,
            "--port", "1080"
        )
        processBuilder.redirectErrorStream(true)

        tunnelProcess = processBuilder.start()

        // Read output in background thread
        Thread {
            tunnelProcess?.inputStream?.bufferedReader()?.forEachLine {
                Log.d("Tunnel", it)
            }
        }.start()

        // Wait briefly and check if still running
        Thread.sleep(500)
        return tunnelProcess?.isAlive == true
    }

    fun stopTunnel() {
        tunnelProcess?.destroy()
        tunnelProcess = null
    }
}
```

**Step 3: Configure app to use SOCKS5 proxy**

For HTTP clients:
```kotlin
// OkHttp
val client = OkHttpClient.Builder()
    .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 1080)))
    .build()

// Retrofit with OkHttp
val retrofit = Retrofit.Builder()
    .baseUrl("https://api.example.com/")
    .client(client)
    .build()
```

For WebView (limited support):
```kotlin
// WebView doesn't natively support SOCKS5
// Use a local HTTP proxy that forwards to SOCKS5, or use a WebView alternative
```

### Option 2: VpnService (System-wide proxy)

For system-wide tunneling, implement Android's VpnService:

```kotlin
class TunnelVpnService : VpnService() {
    private var tunnelProcess: Process? = null
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 1. Start the gdocs_tunnel binary
        startTunnelBinary()

        // 2. Create VPN interface
        vpnInterface = Builder()
            .setSession("GDocsTunnel")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .establish()

        // 3. Route traffic through tun2socks or similar
        // You'll need tun2socks to convert TUN traffic to SOCKS5
        startTun2Socks()

        return START_STICKY
    }

    private fun startTunnelBinary() {
        val binary = File(applicationInfo.nativeLibraryDir, "libgdocs_tunnel.so")
        tunnelProcess = ProcessBuilder(binary.absolutePath, "--port", "1080")
            .redirectErrorStream(true)
            .start()
    }

    private fun startTun2Socks() {
        // Use badvpn-tun2socks or similar library
        // to route VPN traffic through SOCKS5 proxy at 127.0.0.1:1080
    }
}
```

## Binary Behavior

**Command line options:**
```
gdocs_tunnel [OPTIONS]

Options:
  --port <PORT>    SOCKS5 listen port (default: 1080)
  --test           Run connection test and exit
  --verbose        Enable debug logging
```

**What's hardcoded in the binary:**
- Server IPv6 prefix: `2602:f7d0:3:10::/64`
- Server port: `8080`
- Server public key: `nWlaxQRHkjUr5zsZb86oCjifAcsX6mTvhFU0+LchpxM=`
- User-Agent rotation (6 common browsers)

**Output:**
```
╔══════════════════════════════════════════════╗
║  Google Docs Tunnel - SOCKS5 Proxy for Iran  ║
╠══════════════════════════════════════════════╣
║  SOCKS5: 127.0.0.1:1080                      ║
║  Server: 2602:f7d0:3:10::/64 (2^64 IPs)      ║
╚══════════════════════════════════════════════╝
```

**Exit codes:**
- 0: Clean shutdown
- 1: Error (check stderr)

## Permissions Required

```xml
<manifest>
    <!-- Required -->
    <uses-permission android:name="android.permission.INTERNET" />

    <!-- For VpnService approach -->
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />

    <application>
        <!-- For VpnService -->
        <service
            android:name=".TunnelVpnService"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

## Testing

**Test binary works:**
```kotlin
fun testTunnel(): Boolean {
    val binary = File(applicationInfo.nativeLibraryDir, "libgdocs_tunnel.so")
    val process = ProcessBuilder(binary.absolutePath, "--test")
        .redirectErrorStream(true)
        .start()

    val output = process.inputStream.bufferedReader().readText()
    val exitCode = process.waitFor()

    Log.d("Tunnel", "Test output: $output")
    return exitCode == 0 && output.contains("All tests passed")
}
```

**Test SOCKS5 proxy:**
```kotlin
fun testProxy(): Boolean {
    val client = OkHttpClient.Builder()
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 1080)))
        .build()

    val request = Request.Builder()
        .url("https://api.ipify.org")
        .build()

    return try {
        val response = client.newCall(request).execute()
        response.isSuccessful
    } catch (e: Exception) {
        false
    }
}
```

## UI Recommendations

1. **Simple toggle**: ON/OFF switch to start/stop tunnel
2. **Status indicator**: Show connection state (Disconnected → Connecting → Connected)
3. **Test button**: Run `--test` to verify tunnel works
4. **Logs view**: Show tunnel output for debugging

## Error Handling

Common issues:

| Error | Cause | Solution |
|-------|-------|----------|
| Binary not found | Wrong path or ABI | Check `nativeLibraryDir` and ABI filters |
| Permission denied | Not executable | Call `binary.setExecutable(true)` |
| Address in use | Port 1080 occupied | Kill existing process or use different port |
| "No document ID" | Google rate limiting | Wait and retry, this is transient |
| Connection timeout | Network issue | Check internet connectivity |

## Performance Notes

- Latency: 200-500ms per request (due to Google Docs Viewer roundtrip)
- Bandwidth: 10-50 KB/s effective throughput
- Best for: Messaging, web browsing, low-bandwidth apps
- Not ideal for: Video streaming, large downloads

## Source Code Reference

Full source code: https://github.com/0xinf0/gdocs-tunnel

Key files:
- `src/main.rs` - Client implementation
- `src/bin/server.rs` - Server implementation
- `README.md` - Full documentation

## Security Notes

- All traffic is encrypted with AES-256-GCM
- Key exchange uses X25519 (Noise_N pattern)
- Each session uses ephemeral keys
- Traffic appears as Google Docs Viewer requests
- No identifying patterns in traffic

---

# Protocol v2: Batched Tunnel (High Performance)

## Overview

Protocol v2 optimizes throughput by batching multiple requests, compressing with zstd, and optionally encoding as video for 25MB capacity.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  v1 Protocol (Current)                                                       │
│  Request 1 → Google → Server → Response 1                                   │
│  Request 2 → Google → Server → Response 2                                   │
│  Request 3 → Google → Server → Response 3                                   │
│  ... 10 round trips for 10 requests                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  v2 Protocol (Batched)                                                       │
│  [Req1, Req2, Req3...] → Compress → Google → Server → [Resp1, Resp2, Resp3] │
│  ... 1 round trip for 10 requests                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Performance Comparison

| Metric | v1 (Current) | v2 (Batched) |
|--------|--------------|--------------|
| Round trips per 10 requests | 10 | 1 |
| Latency | 10 × RTT | 1 × RTT + processing |
| Compression | None | 70-90% smaller (zstd) |
| Max payload | ~8 KB (text) | 25 MB (video) |
| Effective bandwidth | 10-50 KB/s | 100-500 KB/s |

## Data Structures

### Batched Request (Client → Server)

```rust
// Rust
#[derive(Serialize, Deserialize)]
struct BatchedRequest {
    version: u8,                    // Protocol version (2)
    batch_id: u32,                  // For matching responses
    compression: String,            // "zstd" or "none"
    requests: Vec<TunnelRequest>,
}

#[derive(Serialize, Deserialize)]
struct TunnelRequest {
    stream_id: u16,                 // Unique ID to match response
    method: String,                 // "GET", "POST", "CONNECT", etc.
    host: String,                   // Target hostname
    port: u16,                      // Target port
    path: String,                   // URL path
    headers: Vec<(String, String)>, // HTTP headers
    body: Option<Vec<u8>>,          // Request body (POST/PUT)
}
```

```kotlin
// Kotlin (Android)
@Serializable
data class BatchedRequest(
    val version: Int = 2,
    val batchId: Long,
    val compression: String = "zstd",
    val requests: List<TunnelRequest>
)

@Serializable
data class TunnelRequest(
    val streamId: Int,
    val method: String,
    val host: String,
    val port: Int,
    val path: String,
    val headers: List<Pair<String, String>>,
    val body: ByteArray? = null
)
```

### Batched Response (Server → Client)

```rust
#[derive(Serialize, Deserialize)]
struct BatchedResponse {
    version: u8,
    batch_id: u32,
    compression: String,
    responses: Vec<TunnelResponse>,
}

#[derive(Serialize, Deserialize)]
struct TunnelResponse {
    stream_id: u16,                 // Matches request stream_id
    status: u16,                    // HTTP status code
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    error: Option<String>,          // Error message if failed
}
```

## Batching Strategy

### Client-Side Batching

```kotlin
class RequestBatcher {
    private val pendingRequests = mutableListOf<TunnelRequest>()
    private val responseHandlers = mutableMapOf<Int, CompletableDeferred<TunnelResponse>>()
    private var nextStreamId = 0
    private var batchTimer: Job? = null

    // Configuration
    private val BATCH_WINDOW_MS = 50L      // Collect requests for 50ms
    private val MAX_BATCH_SIZE = 10        // Or until 10 requests queued
    private val MAX_BATCH_BYTES = 1_000_000 // Or until 1MB payload

    suspend fun submitRequest(request: TunnelRequest): TunnelResponse {
        val streamId = nextStreamId++
        val requestWithId = request.copy(streamId = streamId)
        val deferred = CompletableDeferred<TunnelResponse>()

        synchronized(this) {
            pendingRequests.add(requestWithId)
            responseHandlers[streamId] = deferred

            // Start batch timer if first request
            if (pendingRequests.size == 1) {
                batchTimer = scope.launch {
                    delay(BATCH_WINDOW_MS)
                    flushBatch()
                }
            }

            // Flush immediately if batch is full
            if (shouldFlush()) {
                batchTimer?.cancel()
                flushBatch()
            }
        }

        return deferred.await()
    }

    private fun shouldFlush(): Boolean {
        return pendingRequests.size >= MAX_BATCH_SIZE ||
               estimateBatchSize() >= MAX_BATCH_BYTES
    }

    private suspend fun flushBatch() {
        val batch: List<TunnelRequest>
        synchronized(this) {
            batch = pendingRequests.toList()
            pendingRequests.clear()
        }

        if (batch.isEmpty()) return

        val batchedRequest = BatchedRequest(
            batchId = System.currentTimeMillis().toInt(),
            requests = batch
        )

        // Serialize, compress, encrypt, send
        val response = sendBatchedRequest(batchedRequest)

        // Dispatch responses to waiting handlers
        response.responses.forEach { resp ->
            responseHandlers[resp.streamId]?.complete(resp)
            responseHandlers.remove(resp.streamId)
        }
    }
}
```

### Server-Side Handling

```python
# Python server pseudocode
async def handle_batched_request(encrypted_payload: bytes) -> bytes:
    # 1. Decrypt
    payload = decrypt(encrypted_payload)

    # 2. Decompress
    if payload.startswith(ZSTD_MAGIC):
        payload = zstd.decompress(payload)

    # 3. Parse batch
    batch = json.loads(payload)

    # 4. Execute all requests in parallel
    tasks = []
    for req in batch['requests']:
        task = asyncio.create_task(execute_request(req))
        tasks.append((req['stream_id'], task))

    # 5. Collect responses
    responses = []
    for stream_id, task in tasks:
        try:
            result = await task
            responses.append({
                'stream_id': stream_id,
                'status': result.status,
                'headers': list(result.headers.items()),
                'body': base64.b64encode(result.body).decode()
            })
        except Exception as e:
            responses.append({
                'stream_id': stream_id,
                'status': 502,
                'error': str(e)
            })

    # 6. Build response batch
    response_batch = {
        'version': 2,
        'batch_id': batch['batch_id'],
        'compression': 'zstd',
        'responses': responses
    }

    # 7. Compress and encrypt
    payload = json.dumps(response_batch).encode()
    compressed = zstd.compress(payload)
    encrypted = encrypt(compressed)

    return encrypted
```

## Wire Format

### Phase 1: Text Encoding (Current Google Docs text endpoint)

```
URL: /tunnel/{session_id}/batch/{base64url_payload}.txt

Payload structure:
┌─────────────────────────────────────────┐
│ Encrypted (AES-256-GCM)                 │
│ ┌─────────────────────────────────────┐ │
│ │ Compressed (zstd)                   │ │
│ │ ┌─────────────────────────────────┐ │ │
│ │ │ JSON BatchedRequest             │ │ │
│ │ │ {                               │ │ │
│ │ │   "version": 2,                 │ │ │
│ │ │   "batch_id": 12345,            │ │ │
│ │ │   "requests": [...]             │ │ │
│ │ │ }                               │ │ │
│ │ └─────────────────────────────────┘ │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Phase 2: Video Encoding (Future - 25MB capacity)

```
URL: Google Docs Viewer video endpoint

Payload embedded in:
- MP4 metadata (moov atom)
- WebM metadata
- Or raw frames (steganography)

Benefits:
- 25MB max file size vs ~8KB text
- Suitable for bulk transfers
- Video is common Google Docs content
```

## Server Endpoints

Add to existing server:

```
# Existing v1 endpoints (keep for compatibility)
/tunnel/{session_id}/init.txt
/tunnel/{session_id}/connect/{host}/{port}
/tunnel/{session_id}/send/{data}.txt
/tunnel/{session_id}/recv.txt

# New v2 batched endpoint
/tunnel/{session_id}/batch/{payload}.txt    # Text-encoded batch
/tunnel/{session_id}/batch/video            # Video-encoded batch (Phase 2)
```

## Implementation Checklist

### Client (Rust/Android)

- [ ] Add `zstd` crate dependency
- [ ] Implement `BatchedRequest` / `BatchedResponse` structs
- [ ] Create `RequestBatcher` with timer-based flushing
- [ ] Add batch endpoint to `GoogleDocsTunnel`
- [ ] Multiplex responses back to correct streams
- [ ] Fallback to v1 for single low-latency requests

### Server (Rust)

- [ ] Add `zstd` decompression
- [ ] Parse `BatchedRequest` JSON
- [ ] Execute requests in parallel with `tokio::spawn`
- [ ] Aggregate responses into `BatchedResponse`
- [ ] Compress and encrypt response
- [ ] Add `/batch/` route

## Migration Strategy

1. **Server**: Deploy with both v1 and v2 endpoints
2. **Client**: Use v2 for bulk requests, v1 for single requests
3. **Detection**: Check `version` field in response

```rust
// Client can choose protocol based on request pattern
fn choose_protocol(pending_requests: &[Request]) -> Protocol {
    if pending_requests.len() == 1 && is_low_latency_request(&pending_requests[0]) {
        Protocol::V1  // Single request, use direct path
    } else {
        Protocol::V2  // Multiple requests, use batching
    }
}
```

## Example: Batched Web Page Load

Loading a web page typically requires 20-50 requests (HTML, CSS, JS, images).

**v1 Protocol:**
```
50 requests × 300ms RTT = 15 seconds
```

**v2 Protocol:**
```
1 batch × 300ms RTT + 100ms processing = 400ms
```

**37x faster for web browsing!**
