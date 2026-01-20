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
