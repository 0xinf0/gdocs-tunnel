//! Google Docs Viewer Tunnel - Censorship Circumvention Tool
//!
//! Tunnels traffic through Google Docs Viewer using domain fronting.
//! For users in Iran and other censored networks.
//!
//! Usage: gdocs_tunnel --key <server_public_key>
//!
//! Uses X25519 key exchange - client only needs server's public key.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, HOST, USER_AGENT};
use serde::Deserialize;
use snow::Builder;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::{debug, error, info, warn};

// ============= HARD-CODED CONFIGURATION =============
// Server IPv6 prefix - each request uses a random IP from this range
// to distribute load across Google's rate limiting
const IPV6_PREFIX: &str = "2602:f7d0:3:10::/64";
const SERVER_PORT: u16 = 8080;

// Server's public key (X25519) - for encrypting tunnel traffic
const SERVER_PUBLIC_KEY: &str = "nWlaxQRHkjUr5zsZb86oCjifAcsX6mTvhFU0+LchpxM=";

const GOOGLE_VIEWER_URL: &str = "https://www.google.com/viewer";
const GOOGLE_VIEWERNG_URL: &str = "https://www.google.com/viewerng/text";
const DEFAULT_SOCKS_PORT: u16 = 1080;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_UPLOAD_CHUNK: usize = 1100;
const MIN_REQUEST_DELAY: Duration = Duration::from_millis(100);

// Random User-Agents to avoid fingerprinting
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

// ============= GOOGLE FRONTEND IP ROTATION =============
// Verified working Google frontend IPs (Anycast - work globally)
// These are actual IPs returned by DNS for www.google.com
// Rotate to distribute rate limiting across Google's infrastructure
const GOOGLE_FRONTEND_IPS: &[u32] = &[
    // 142.250.x.x range
    0x8EFA_B004,  // 142.250.176.4
    0x8EFA_BCE4,  // 142.250.188.228
    0x8EFA_4424,  // 142.250.68.36
    0x8EFA_4444,  // 142.250.68.68
    0x8EFA_48A4,  // 142.250.72.164
    0x8EFA_4884,  // 142.250.72.132
    0x8EFA_C464,  // 142.250.196.100
    // 142.251.x.x range
    0x8EFB_2864,  // 142.251.40.100
    0x8EFB_2244,  // 142.251.34.68
    // 172.217.x.x range
    0xACD9_0C84,  // 172.217.12.132
    0xACD9_0E64,  // 172.217.14.100
    // 173.194.x.x range (frequently returned by DNS)
    0xADC2_DB68,  // 173.194.219.104
    0xADC2_DB67,  // 173.194.219.103
    0xADC2_DB69,  // 173.194.219.105
    0xADC2_DB93,  // 173.194.219.147
    0xADC2_DB63,  // 173.194.219.99
    0xADC2_DB6A,  // 173.194.219.106
    // 216.58.x.x range
    0xD83A_D2CE,  // 216.58.210.206
    // 74.125.x.x range
    0x4A7D_8A64,  // 74.125.138.100
    0x4A7D_8A65,  // 74.125.138.101
    // 64.233.x.x range
    0x40E9_B963,  // 64.233.185.99
    0x40E9_B964,  // 64.233.185.100
];

fn random_google_ip() -> std::net::Ipv4Addr {
    use rand::seq::SliceRandom;
    let ip = GOOGLE_FRONTEND_IPS
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap_or(GOOGLE_FRONTEND_IPS[0]);
    std::net::Ipv4Addr::from(ip)
}

// ============= IPv6 ROTATION =============
#[derive(Clone)]
struct Ipv6Prefix {
    base: u128,
    mask_bits: u8,
}

impl Ipv6Prefix {
    fn parse(prefix_str: &str) -> Result<Self> {
        let parts: Vec<&str> = prefix_str.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid prefix format, expected addr/bits"));
        }

        let addr: Ipv6Addr = parts[0].parse()
            .map_err(|_| anyhow!("Invalid IPv6 address"))?;
        let mask_bits: u8 = parts[1].parse()
            .map_err(|_| anyhow!("Invalid prefix length"))?;

        if mask_bits > 128 {
            return Err(anyhow!("Prefix length must be <= 128"));
        }

        let base = u128::from(addr);
        // Zero out the host bits
        let mask = if mask_bits == 0 { 0 } else { !0u128 << (128 - mask_bits) };
        let base = base & mask;

        Ok(Self { base, mask_bits })
    }

    fn random_addr(&self) -> Ipv6Addr {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        // Generate random host bits
        let host_bits = 128 - self.mask_bits;
        let random_part: u128 = if host_bits >= 64 {
            ((rng.next_u64() as u128) << 64) | (rng.next_u64() as u128)
        } else {
            rng.next_u64() as u128
        };

        // Mask to only use host bits
        let host_mask = if host_bits == 128 { !0u128 } else { (1u128 << host_bits) - 1 };
        let addr = self.base | (random_part & host_mask);

        Ipv6Addr::from(addr)
    }
}

// ============= CLI =============
#[derive(Parser, Debug)]
#[command(name = "gdocs_tunnel")]
#[command(about = "SOCKS5 proxy through Google Docs - for Iran")]
struct Args {
    /// Local SOCKS5 port
    #[arg(short, long, default_value_t = DEFAULT_SOCKS_PORT)]
    port: u16,

    /// Run connection test and exit
    #[arg(long)]
    test: bool,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

// ============= CRYPTO (X25519 ECDH + AES-GCM) =============
// Session-based encryption using X25519 key exchange:
// 1. Client generates ephemeral X25519 keypair per session
// 2. Client does DH with server's static public key
// 3. Both sides derive symmetric key from shared secret
// 4. All messages use AES-256-GCM with derived key
//
// Format: ephemeral_public (32) + nonce (12) + ciphertext (includes 16-byte tag)

use snow::params::NoiseParams;

struct Crypto {
    server_public_key: [u8; 32],
}

/// Per-session crypto state with derived symmetric key
struct SessionCrypto {
    cipher: Aes256Gcm,
    handshake_message: [u8; 48],  // Full Noise_N handshake message (e + AEAD tag)
}

impl Crypto {
    fn new(key_base64: &str) -> Result<Self> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_base64.trim())
            .context("Invalid base64 key")?;

        if key_bytes.len() != 32 {
            return Err(anyhow!("Key must be 32 bytes (got {})", key_bytes.len()));
        }

        let mut server_public_key = [0u8; 32];
        server_public_key.copy_from_slice(&key_bytes);

        Ok(Self { server_public_key })
    }

    /// Create session crypto with X25519 key exchange
    fn new_session(&self) -> Result<SessionCrypto> {
        // Generate ephemeral keypair using snow's DH
        let params: NoiseParams = "Noise_N_25519_AESGCM_SHA256".parse()?;
        let builder = Builder::new(params);
        let keypair = builder.generate_keypair()?;

        // X25519 DH to get shared secret
        let mut noise = Builder::new("Noise_N_25519_AESGCM_SHA256".parse()?)
            .local_private_key(&keypair.private)
            .remote_public_key(&self.server_public_key)
            .build_initiator()?;

        // Perform handshake to establish shared secret
        // This writes: ephemeral_public (32) + encrypted empty payload with AEAD tag (16)
        let mut handshake_message = [0u8; 48];
        let _ = noise.write_message(&[], &mut handshake_message)?;

        // Get handshake hash as symmetric key BEFORE converting to transport
        let key_material = noise.get_handshake_hash();

        let cipher = Aes256Gcm::new_from_slice(key_material)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

        Ok(SessionCrypto {
            cipher,
            handshake_message,
        })
    }
}

impl SessionCrypto {
    /// Encrypt with session key (ephemeral public key is in session_id, not here)
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Format: nonce (12) + ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt server response
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Format: nonce (12) + ciphertext
        if data.len() < 12 + 16 {
            return Err(anyhow!("Ciphertext too short"));
        }

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }
}

// ============= SERVER RESPONSE =============
#[derive(Debug, Deserialize)]
struct ServerResponse {
    status: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct ViewerContent {
    #[serde(default)]
    #[allow(dead_code)]
    mimetype: String,
    data: String,
}

// ============= GOOGLE DOCS TUNNEL =============
struct GoogleDocsTunnel {
    session_id: String,  // Base64 of ephemeral public key (so server can derive same key)
    session_crypto: SessionCrypto,
    ipv6_prefix: Ipv6Prefix,
    connected: Arc<Mutex<bool>>,
    last_request: Arc<Mutex<std::time::Instant>>,
}

impl GoogleDocsTunnel {
    fn new(crypto: &Crypto) -> Result<Self> {
        let ipv6_prefix = Ipv6Prefix::parse(IPV6_PREFIX)?;
        let session_crypto = crypto.new_session()?;

        // Use full handshake message as session ID (URL-safe base64)
        // Server will derive the same symmetric key from this 48-byte message
        let session_id = URL_SAFE_NO_PAD.encode(&session_crypto.handshake_message);

        Ok(Self {
            session_id,
            session_crypto,
            ipv6_prefix,
            connected: Arc::new(Mutex::new(false)),
            last_request: Arc::new(Mutex::new(std::time::Instant::now())),
        })
    }

    /// Build HTTP client for domain fronting with random User-Agent and random Google IP
    fn build_client(&self) -> Result<reqwest::Client> {
        use rand::seq::SliceRandom;

        let ua = USER_AGENTS.choose(&mut rand::thread_rng())
            .unwrap_or(&USER_AGENTS[0]);

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("docs.google.com"));
        headers.insert(USER_AGENT, HeaderValue::from_str(ua).unwrap());

        // Pick random Google frontend IP to distribute rate limiting
        let google_ip = random_google_ip();
        let socket_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(google_ip),
            443,
        );

        debug!("Using Google frontend IP: {}", google_ip);

        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(REQUEST_TIMEOUT)
            .http1_only()
            // Override DNS: connect to random Google IP instead of resolving
            .resolve("www.google.com", socket_addr)
            .resolve("docs.google.com", socket_addr)
            .build()
            .context("Failed to build HTTP client")
    }

    /// Get random server IPv6 address for this request
    fn random_server_ip(&self) -> Ipv6Addr {
        self.ipv6_prefix.random_addr()
    }

    /// Fetch URL through Google Docs Viewer with domain fronting
    async fn fetch_via_viewer(&self, path: &str) -> Result<ServerResponse> {
        // Rate limiting: ensure minimum delay between requests
        {
            let mut last = self.last_request.lock().await;
            let elapsed = last.elapsed();
            if elapsed < MIN_REQUEST_DELAY {
                tokio::time::sleep(MIN_REQUEST_DELAY - elapsed).await;
            }
            *last = std::time::Instant::now();
        }

        // Build client for domain fronting
        let client = self.build_client()?;

        // Use random IPv6 from our range - distributes across Google's rate limits
        let server_ip = self.random_server_ip();
        let target_url = format!("http://[{}]:{}{}", server_ip, SERVER_PORT, path);
        let viewer_url = format!("{}?url={}&embedded=true", GOOGLE_VIEWER_URL, target_url);

        debug!("Using server IP: {}", server_ip);

        debug!("Fetching via viewer: {}", path);

        // Step 1: Get viewer page
        let resp = client
            .get(&viewer_url)
            .send()
            .await
            .context("Viewer request failed")?;

        if !resp.status().is_success() {
            return Err(anyhow!("Viewer returned status: {}", resp.status()));
        }

        let body = resp.text().await.context("Failed to read viewer response")?;

        // Step 2: Extract document ID
        let re = Regex::new(r"text\?id\\u003d([A-Za-z0-9_-]+)").unwrap();
        let doc_id = re
            .captures(&body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| anyhow!("No document ID found in viewer response"))?;

        // Step 3: Fetch actual content
        let content_url = format!("{}?id={}", GOOGLE_VIEWERNG_URL, doc_id);
        let content_resp = client
            .get(&content_url)
            .send()
            .await
            .context("Content fetch failed")?;

        let content_text = content_resp
            .text()
            .await
            .context("Failed to read content")?;

        // Step 4: Parse response
        // Format: )]}'\n{"mimetype":"text/plain","data":"..."}
        let json_str = content_text
            .strip_prefix(")]}'")
            .map(|s| s.trim())
            .unwrap_or(&content_text);

        let outer: ViewerContent =
            serde_json::from_str(json_str).context("Failed to parse outer JSON")?;

        let inner: ServerResponse =
            serde_json::from_str(&outer.data).context("Failed to parse inner JSON")?;

        Ok(inner)
    }

    /// Initialize tunnel session
    async fn init_session(&self) -> Result<()> {
        info!("Initializing session: {}", &self.session_id[..8]);

        let resp = self
            .fetch_via_viewer(&format!("/tunnel/{}/init.txt", self.session_id))
            .await?;

        let decrypted = self.session_crypto.decrypt(
            &base64::engine::general_purpose::STANDARD
                .decode(&resp.data)
                .context("Base64 decode failed")?,
        )?;

        if decrypted.starts_with(b"SESSION_OK") {
            info!("Session initialized");
            Ok(())
        } else {
            Err(anyhow!(
                "Session init failed: {}",
                String::from_utf8_lossy(&decrypted)
            ))
        }
    }

    /// Connect to destination through tunnel
    async fn connect(&self, host: &str, port: u16) -> Result<()> {
        info!("Connecting to {}:{}", host, port);

        let resp = self
            .fetch_via_viewer(&format!(
                "/tunnel/{}/connect/{}/{}.txt",
                self.session_id, host, port
            ))
            .await?;

        let decrypted = self.session_crypto.decrypt(
            &base64::engine::general_purpose::STANDARD
                .decode(&resp.data)
                .context("Base64 decode failed")?,
        )?;

        if decrypted.starts_with(b"CONNECTED") {
            *self.connected.lock().await = true;
            info!("Connected to {}:{}", host, port);
            Ok(())
        } else {
            Err(anyhow!(
                "Connect failed: {}",
                String::from_utf8_lossy(&decrypted)
            ))
        }
    }

    /// Send data through tunnel with automatic chunking for large payloads
    async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !*self.connected.lock().await {
            return Err(anyhow!("Not connected"));
        }

        let mut all_response = Vec::new();

        // Chunk large data to fit in URL path
        for chunk in data.chunks(MAX_UPLOAD_CHUNK) {
            // Encrypt and encode for URL
            let encrypted = self.session_crypto.encrypt(chunk)?;
            let encoded = URL_SAFE_NO_PAD.encode(&encrypted);

            let resp = self
                .fetch_via_viewer(&format!(
                    "/tunnel/{}/send/{}.txt",
                    self.session_id, encoded
                ))
                .await?;

            if resp.status == "closed" {
                *self.connected.lock().await = false;
            }

            let decrypted = self.session_crypto.decrypt(
                &base64::engine::general_purpose::STANDARD
                    .decode(&resp.data)
                    .context("Base64 decode failed")?,
            )?;

            // Skip sequence number (4 bytes) and collect response data
            if decrypted.len() > 4 {
                all_response.extend_from_slice(&decrypted[4..]);
            }
        }

        Ok(all_response)
    }

    /// Receive data from tunnel
    async fn recv(&self) -> Result<Vec<u8>> {
        if !*self.connected.lock().await {
            return Err(anyhow!("Not connected"));
        }

        let resp = self
            .fetch_via_viewer(&format!("/tunnel/{}/recv.txt", self.session_id))
            .await?;

        if resp.status == "closed" {
            *self.connected.lock().await = false;
        }

        let decrypted = self.session_crypto.decrypt(
            &base64::engine::general_purpose::STANDARD
                .decode(&resp.data)
                .context("Base64 decode failed")?,
        )?;

        // Skip sequence number (4 bytes)
        if decrypted.len() > 4 {
            Ok(decrypted[4..].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Close tunnel
    async fn close(&self) {
        let _ = self
            .fetch_via_viewer(&format!("/tunnel/{}/close.txt", self.session_id))
            .await;
        *self.connected.lock().await = false;
    }
}

// ============= SOCKS5 PROXY =============
async fn handle_socks5(mut stream: TcpStream, crypto: Arc<Crypto>) -> Result<()> {
    let peer = stream.peer_addr().ok();

    // SOCKS5 greeting
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS5 greeting"));
    }

    // No auth response
    stream.write_all(&[0x05, 0x00]).await?;

    // SOCKS5 request
    let n = stream.read(&mut buf).await?;
    if n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
        // Only CONNECT supported
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(anyhow!("Only CONNECT command supported"));
    }

    // Parse destination
    let (host, port) = match buf[3] {
        0x01 => {
            // IPv4
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port)
        }
        0x03 => {
            // Domain
            let len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            (domain, port)
        }
        0x04 => {
            // IPv6
            let ip = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
                u16::from_be_bytes([buf[16], buf[17]]),
                u16::from_be_bytes([buf[18], buf[19]])
            );
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (ip, port)
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Address type not supported: {}", buf[3]));
        }
    };

    info!("[{:?}] CONNECT {}:{}", peer, host, port);

    // Create tunnel with new session keys
    let tunnel = GoogleDocsTunnel::new(&crypto)?;

    // Initialize and connect
    if let Err(e) = tunnel.init_session().await {
        error!("Session init failed: {}", e);
        stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(e);
    }

    if let Err(e) = tunnel.connect(&host, port).await {
        error!("Connect failed: {}", e);
        stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(e);
    }

    // Success response
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // Relay data
    relay_data(&mut stream, tunnel).await?;

    Ok(())
}

async fn relay_data(stream: &mut TcpStream, tunnel: GoogleDocsTunnel) -> Result<()> {
    // Use upload chunk size for reading since that's what we can send per request
    let mut buf = vec![0u8; MAX_UPLOAD_CHUNK];

    loop {
        tokio::select! {
            // Local -> Tunnel
            result = timeout(POLL_INTERVAL, stream.read(&mut buf)) => {
                match result {
                    Ok(Ok(0)) => {
                        // Connection closed
                        break;
                    }
                    Ok(Ok(n)) => {
                        match tunnel.send(&buf[..n]).await {
                            Ok(response) if !response.is_empty() => {
                                stream.write_all(&response).await?;
                            }
                            Err(e) => {
                                warn!("Send error: {}", e);
                                break;
                            }
                            _ => {}
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Read error: {}", e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - poll for incoming data
                        match tunnel.recv().await {
                            Ok(data) if !data.is_empty() => {
                                stream.write_all(&data).await?;
                            }
                            Err(e) => {
                                warn!("Recv error: {}", e);
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if !*tunnel.connected.lock().await {
            break;
        }
    }

    tunnel.close().await;
    Ok(())
}

// ============= TEST =============
async fn run_test(crypto: &Crypto) -> Result<()> {
    println!("Testing Google Docs Viewer tunnel...");
    println!("Server IPv6 range: {} (2^64 addresses)", IPV6_PREFIX);
    println!();

    let tunnel = GoogleDocsTunnel::new(crypto)?;

    print!("1. Testing domain fronting... ");
    tunnel.init_session().await?;
    println!("OK");

    print!("2. Testing connection... ");
    tunnel.connect("httpbin.org", 80).await?;
    println!("OK");

    print!("3. Testing data transfer... ");
    let request = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
    let mut response = tunnel.send(request).await?;

    // Wait for response
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let more = tunnel.recv().await?;
        if !more.is_empty() {
            response.extend(more);
        }
        if response.windows(4).any(|w| w == b"HTTP") {
            break;
        }
    }

    if response.windows(4).any(|w| w == b"HTTP") {
        println!("OK");
        println!("   Response preview: {}", String::from_utf8_lossy(&response[..100.min(response.len())]));
    } else {
        println!("FAILED - no HTTP response");
        return Err(anyhow!("Test failed"));
    }

    tunnel.close().await;
    println!();
    println!("All tests passed! Tunnel is working.");
    Ok(())
}

// ============= MAIN =============
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // Initialize crypto with hard-coded server public key
    let crypto = Arc::new(Crypto::new(SERVER_PUBLIC_KEY)?);

    // Run test if requested
    if args.test {
        return run_test(&crypto).await;
    }

    // Start SOCKS5 server
    println!("╔══════════════════════════════════════════════╗");
    println!("║  Google Docs Tunnel - SOCKS5 Proxy for Iran  ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  SOCKS5: 127.0.0.1:{:<25}║", args.port);
    println!("║  Server: {} (2^64 IPs)     ║", IPV6_PREFIX);
    println!("╠══════════════════════════════════════════════╣");
    println!("║  curl --socks5 127.0.0.1:{} URL              ║", args.port);
    println!("╚══════════════════════════════════════════════╝");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port)).await?;
    info!("Listening on 127.0.0.1:{}", args.port);

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("New connection from {:?}", addr);

        let crypto = crypto.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5(stream, crypto).await {
                error!("Handler error: {}", e);
            }
        });
    }
}
