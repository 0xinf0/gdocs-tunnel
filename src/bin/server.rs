//! Google Docs Viewer Tunnel - Server Component
//!
//! Deploy this on your server. Clients will access via domain fronting through Google.
//! Uses X25519 key exchange - share public key with clients.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use serde::Serialize;
use snow::Builder;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
    time::timeout,
};
use tracing::{debug, error, info, warn};

// ============= CONFIGURATION =============
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BUFFER_SIZE: usize = 65536;
const POLL_WAIT: Duration = Duration::from_secs(3);

// Download chunk size: 24KB leaves room for encryption overhead + JSON
// This is the max that reliably works through Google Docs Viewer text?id= endpoint
const MAX_DOWNLOAD_CHUNK: usize = 24000;

// ============= CLI =============
#[derive(Parser, Debug)]
#[command(name = "gdocs_tunnel_server")]
#[command(about = "Google Docs Viewer Tunnel Server")]
struct Args {
    /// Path to private key file (generates if missing)
    #[arg(short, long, default_value = "server.key")]
    key_file: PathBuf,

    /// Show public key and exit (give this to clients)
    #[arg(long)]
    show_key: bool,

    /// Port to listen on
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

// ============= CRYPTO (X25519 + AES-GCM) =============
// Server has static keypair. Client sends ephemeral public key with each session.
// Derive symmetric key via X25519 DH for encryption/decryption.

#[derive(Clone)]
struct ServerKeys {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl ServerKeys {
    fn generate() -> Result<Self> {
        let params: snow::params::NoiseParams = "Noise_N_25519_AESGCM_SHA256".parse()?;
        let keypair = Builder::new(params).generate_keypair()?;

        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_key.copy_from_slice(&keypair.private);
        public_key.copy_from_slice(&keypair.public);

        Ok(Self { private_key, public_key })
    }

    fn load(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read key file")?;
        if data.len() != 64 {
            return Err(anyhow!("Invalid key file (expected 64 bytes: private + public)"));
        }

        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_key.copy_from_slice(&data[..32]);
        public_key.copy_from_slice(&data[32..]);

        Ok(Self { private_key, public_key })
    }

    fn save(&self, path: &std::path::Path) -> Result<()> {
        // Store both private and public key (64 bytes total)
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.private_key);
        data.extend_from_slice(&self.public_key);
        std::fs::write(path, &data).context("Failed to write key file")?;
        Ok(())
    }

    fn public_key_base64(&self) -> String {
        STANDARD.encode(&self.public_key)
    }

    /// Derive session cipher from client's full Noise handshake message
    fn derive_session_cipher(&self, handshake_message: &[u8]) -> Result<Aes256Gcm> {
        if handshake_message.len() != 48 {
            return Err(anyhow!("Invalid handshake message length (expected 48, got {})", handshake_message.len()));
        }

        // Use Noise_N as responder to derive the same key as client
        let mut noise = Builder::new("Noise_N_25519_AESGCM_SHA256".parse()?)
            .local_private_key(&self.private_key)
            .build_responder()?;

        // Read the full handshake message: ephemeral_public (32) + AEAD tag (16)
        noise.read_message(handshake_message, &mut [])?;

        // Get the same handshake hash as symmetric key
        let key_material = noise.get_handshake_hash();

        Aes256Gcm::new_from_slice(key_material)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))
    }
}

/// Per-request crypto using derived session key
struct SessionCrypto {
    cipher: Aes256Gcm,
}

impl SessionCrypto {
    fn encrypt(&self, plaintext: &[u8]) -> Result<String> {
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Response format: nonce (12) + ciphertext (no ephemeral - client knows the key)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(&result))
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Input format: nonce (12) + ciphertext
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

// ============= SESSION =============
struct Session {
    #[allow(dead_code)]
    created: Instant,
    last_activity: Instant,
    socket: Option<TcpStream>,
    out_buffer: Vec<u8>,
    seq_out: u32,
    connected: bool,
    crypto: Option<SessionCrypto>,  // Derived from client's ephemeral key
}

impl Session {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            created: now,
            last_activity: now,
            socket: None,
            out_buffer: Vec::new(),
            seq_out: 0,
            connected: false,
            crypto: None,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }
}

// ============= APP STATE =============
struct AppState {
    keys: ServerKeys,
    sessions: RwLock<HashMap<String, Arc<RwLock<Session>>>>,
}

impl AppState {
    fn new(keys: ServerKeys) -> Self {
        Self {
            keys,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    async fn get_session(&self, session_id: &str) -> Option<Arc<RwLock<Session>>> {
        self.sessions.read().await.get(session_id).cloned()
    }

    async fn create_session(&self, session_id: &str) -> Arc<RwLock<Session>> {
        let mut sessions = self.sessions.write().await;
        let session = Arc::new(RwLock::new(Session::new()));
        sessions.insert(session_id.to_string(), session.clone());
        session
    }

    async fn remove_session(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    /// Get session crypto from session_id (which is the full Noise handshake message)
    fn get_session_crypto(&self, session_id: &str) -> Result<SessionCrypto> {
        let handshake_message = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(session_id)
            .context("Invalid session ID")?;
        let cipher = self.keys.derive_session_cipher(&handshake_message)?;
        Ok(SessionCrypto { cipher })
    }
}

// ============= RESPONSE TYPES =============
#[derive(Serialize)]
struct TunnelResponse {
    status: String,
    ts: u64,
    data: String,
}

impl TunnelResponse {
    fn ok(crypto: &SessionCrypto, data: &[u8]) -> Self {
        Self {
            status: "ok".to_string(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data: crypto.encrypt(data).unwrap_or_default(),
        }
    }

    fn error(crypto: &SessionCrypto, msg: &str) -> Self {
        Self {
            status: "error".to_string(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data: crypto.encrypt(msg.as_bytes()).unwrap_or_default(),
        }
    }

    fn closed(crypto: &SessionCrypto, data: &[u8]) -> Self {
        Self {
            status: "closed".to_string(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data: crypto.encrypt(data).unwrap_or_default(),
        }
    }

    // For errors when we don't have session crypto yet
    fn plain_error(msg: &str) -> Self {
        Self {
            status: "error".to_string(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data: msg.to_string(),  // Unencrypted error
        }
    }
}

// Text response for Google Docs Viewer
fn text_response(resp: TunnelResponse) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Cache-Control", "no-cache, no-store, must-revalidate"),
        ],
        serde_json::to_string(&resp).unwrap_or_default(),
    )
}

// ============= HANDLERS =============

async fn health() -> impl IntoResponse {
    "OK"
}

async fn init_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    info!("[{}] Session init", &session_id[..8.min(session_id.len())]);

    // Session ID is base64-encoded full Noise handshake message (48 bytes)
    let handshake_message = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&session_id)
    {
        Ok(k) if k.len() == 48 => k,
        Ok(k) => {
            warn!("[{}] Invalid session ID length (got {} bytes, expected 48)", &session_id[..8.min(session_id.len())], k.len());
            return text_response(TunnelResponse::plain_error("INVALID_SESSION_ID"));
        }
        _ => {
            warn!("[{}] Invalid session ID (base64 decode failed)", &session_id[..8.min(session_id.len())]);
            return text_response(TunnelResponse::plain_error("INVALID_SESSION_ID"));
        }
    };

    // Derive session crypto from full handshake message
    let cipher = match state.keys.derive_session_cipher(&handshake_message) {
        Ok(c) => c,
        Err(e) => {
            error!("[{}] Key derivation failed: {}", &session_id[..8.min(session_id.len())], e);
            return text_response(TunnelResponse::plain_error("KEY_DERIVATION_FAILED"));
        }
    };

    let session_crypto = SessionCrypto { cipher };

    // Create session with crypto
    let session = state.create_session(&session_id).await;
    {
        let mut sess = session.write().await;
        sess.crypto = Some(SessionCrypto {
            cipher: state.keys.derive_session_cipher(&handshake_message).unwrap(),
        });
    }

    let msg = format!("SESSION_OK:{}", &session_id[..8.min(session_id.len())]);
    text_response(TunnelResponse::ok(&session_crypto, msg.as_bytes()))
}

async fn connect(
    State(state): State<Arc<AppState>>,
    Path((session_id, host, port_txt)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let port: u16 = port_txt.trim_end_matches(".txt").parse().unwrap_or(0);

    let crypto = match state.get_session_crypto(&session_id) {
        Ok(c) => c,
        Err(_) => return text_response(TunnelResponse::plain_error("INVALID_SESSION")),
    };

    let session = match state.get_session(&session_id).await {
        Some(s) => s,
        None => return text_response(TunnelResponse::error(&crypto, "NO_SESSION")),
    };

    if port == 0 {
        return text_response(TunnelResponse::error(&crypto, "INVALID_PORT"));
    }
    info!("[{}] Connect to {}:{}", &session_id[..8.min(session_id.len())], host, port);

    let addr = format!("{}:{}", host, port);
    let socket = match timeout(SOCKET_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            error!("[{}] Connect failed: {}", &session_id[..8.min(session_id.len())], e);
            return text_response(TunnelResponse::error(&crypto, &format!("CONNECT_FAILED:{}", e)));
        }
        Err(_) => return text_response(TunnelResponse::error(&crypto, "CONNECT_TIMEOUT")),
    };

    {
        let mut sess = session.write().await;
        sess.socket = Some(socket);
        sess.connected = true;
        sess.touch();
    }

    info!("[{}] Connected to {}:{}", &session_id[..8.min(session_id.len())], host, port);
    text_response(TunnelResponse::ok(&crypto, format!("CONNECTED:{}:{}", host, port).as_bytes()))
}

async fn send_data(
    State(state): State<Arc<AppState>>,
    Path((session_id, data)): Path<(String, String)>,
) -> impl IntoResponse {
    debug!("[{}] Send data", &session_id[..8.min(session_id.len())]);

    let crypto = match state.get_session_crypto(&session_id) {
        Ok(c) => c,
        Err(_) => return text_response(TunnelResponse::plain_error("INVALID_SESSION")),
    };

    let session = match state.get_session(&session_id).await {
        Some(s) => s,
        None => return text_response(TunnelResponse::error(&crypto, "NO_SESSION")),
    };

    // Decode and decrypt incoming data
    let decrypted = match decode_url_data(&crypto, &data) {
        Ok(d) => d,
        Err(e) => {
            warn!("[{}] Decrypt failed: {}", &session_id[..8.min(session_id.len())], e);
            return text_response(TunnelResponse::error(&crypto, "DECRYPT_FAILED"));
        }
    };

    let out_data;
    let seq_out;
    let connected;

    {
        let mut sess = session.write().await;
        sess.touch();

        let mut write_failed = false;
        let mut conn_closed = false;

        if let Some(ref mut socket) = sess.socket {
            if let Err(e) = socket.write_all(&decrypted).await {
                warn!("[{}] Socket write failed: {}", &session_id[..8.min(session_id.len())], e);
                write_failed = true;
            } else {
                let mut buf = vec![0u8; MAX_BUFFER_SIZE];
                match timeout(Duration::from_millis(100), socket.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => sess.out_buffer.extend_from_slice(&buf[..n]),
                    Ok(Ok(0)) => conn_closed = true,
                    _ => {}
                }
            }
        }

        if write_failed || conn_closed {
            sess.connected = false;
        }

        connected = sess.connected;
        let chunk_size = MAX_DOWNLOAD_CHUNK.min(sess.out_buffer.len());
        out_data = sess.out_buffer.drain(..chunk_size).collect::<Vec<_>>();
        sess.seq_out += 1;
        seq_out = sess.seq_out;
    }

    let mut response = Vec::with_capacity(4 + out_data.len());
    response.extend_from_slice(&seq_out.to_be_bytes());
    response.extend_from_slice(&out_data);

    if connected {
        text_response(TunnelResponse::ok(&crypto, &response))
    } else {
        text_response(TunnelResponse::closed(&crypto, &response))
    }
}

async fn recv_data(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    debug!("[{}] Recv poll", &session_id[..8.min(session_id.len())]);

    let crypto = match state.get_session_crypto(&session_id) {
        Ok(c) => c,
        Err(_) => return text_response(TunnelResponse::plain_error("INVALID_SESSION")),
    };

    let session = match state.get_session(&session_id).await {
        Some(s) => s,
        None => return text_response(TunnelResponse::error(&crypto, "NO_SESSION")),
    };

    // Wait for data - aggressively fill buffer up to MAX_DOWNLOAD_CHUNK
    let start = Instant::now();
    while start.elapsed() < POLL_WAIT {
        let current_size = {
            let sess = session.read().await;
            if !sess.connected { break; }
            sess.out_buffer.len()
        };

        if current_size >= MAX_DOWNLOAD_CHUNK { break; }

        {
            let mut sess = session.write().await;
            let mut got_data = false;
            let mut conn_closed = false;

            if let Some(ref mut socket) = sess.socket {
                let mut buf = vec![0u8; MAX_BUFFER_SIZE];
                match timeout(Duration::from_millis(100), socket.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        sess.out_buffer.extend_from_slice(&buf[..n]);
                        got_data = true;
                    }
                    Ok(Ok(0)) => conn_closed = true,
                    _ => {}
                }
            }

            if got_data {
                sess.touch();
                if sess.out_buffer.len() < MAX_DOWNLOAD_CHUNK { continue; }
                break;
            }
            if conn_closed {
                sess.connected = false;
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut out_data;
    let seq_out;
    let connected;

    {
        let mut sess = session.write().await;
        sess.touch();
        let chunk_size = MAX_DOWNLOAD_CHUNK.min(sess.out_buffer.len());
        out_data = sess.out_buffer.drain(..chunk_size).collect::<Vec<_>>();
        sess.seq_out += 1;
        seq_out = sess.seq_out;
        connected = sess.connected;
    }

    let mut response = Vec::with_capacity(4 + out_data.len());
    response.extend_from_slice(&seq_out.to_be_bytes());
    response.append(&mut out_data);

    if connected {
        text_response(TunnelResponse::ok(&crypto, &response))
    } else {
        text_response(TunnelResponse::closed(&crypto, &response))
    }
}

async fn close_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    info!("[{}] Close", &session_id[..8.min(session_id.len())]);

    let crypto = match state.get_session_crypto(&session_id) {
        Ok(c) => c,
        Err(_) => return text_response(TunnelResponse::plain_error("INVALID_SESSION")),
    };

    if let Some(session) = state.get_session(&session_id).await {
        let mut sess = session.write().await;
        sess.connected = false;
        if let Some(mut socket) = sess.socket.take() {
            let _ = socket.shutdown().await;
        }
    }

    state.remove_session(&session_id).await;
    text_response(TunnelResponse::ok(&crypto, b"CLOSED"))
}

// ============= HELPERS =============

fn decode_url_data(crypto: &SessionCrypto, data: &str) -> Result<Vec<u8>> {
    // Strip .txt suffix if present
    let clean_data = data.trim_end_matches(".txt");

    // Add padding if needed for base64url
    let padded = match clean_data.len() % 4 {
        2 => format!("{}==", clean_data),
        3 => format!("{}=", clean_data),
        _ => clean_data.to_string(),
    };

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(clean_data)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded))
        .context("URL base64 decode failed")?;

    // Decrypt: format is nonce (12) + ciphertext
    crypto.decrypt(&decoded)
}

// Session cleanup task
async fn cleanup_sessions(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        let mut to_remove = Vec::new();

        {
            let sessions = state.sessions.read().await;
            for (id, session) in sessions.iter() {
                let sess = session.read().await;
                if sess.is_expired() {
                    to_remove.push(id.clone());
                }
            }
        }

        for id in to_remove {
            info!("[{}] Cleaning up expired session", &id[..8.min(id.len())]);
            state.remove_session(&id).await;
        }
    }
}

// ============= MAIN =============
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load or generate keypair
    let keys = if args.key_file.exists() {
        ServerKeys::load(&args.key_file)?
    } else {
        let keys = ServerKeys::generate()?;
        keys.save(&args.key_file)?;
        eprintln!("Generated new keypair: {}", args.key_file.display());
        keys
    };

    // Show key and exit if requested
    if args.show_key {
        println!("{}", keys.public_key_base64());
        return Ok(());
    }

    // Setup logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let state = Arc::new(AppState::new(keys.clone()));

    // Start cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        cleanup_sessions(cleanup_state).await;
    });

    // Build router
    let app = Router::new()
        .route("/health.txt", get(health))
        .route("/tunnel/:session_id/init.txt", get(init_session))
        .route("/tunnel/:session_id/connect/:host/:port", get(connect))
        .route("/tunnel/:session_id/send/:data.txt", get(send_data))
        .route("/tunnel/:session_id/recv.txt", get(recv_data))
        .route("/tunnel/:session_id/close.txt", get(close_session))
        .with_state(state);

    // Listen on all IPv6 (also accepts IPv4 on most systems via dual-stack)
    let addr: SocketAddr = format!("[::]:{}", args.port).parse()?;

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Google Docs Tunnel Server                   ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Port: {:<37}║", args.port);
    println!("║  Key file: {:<33}║", args.key_file.display());
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Public key (give to clients):               ║");
    println!("║  {}  ║", keys.public_key_base64());
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Client usage:                               ║");
    println!("║  gdocs_tunnel --key <public_key>             ║");
    println!("╚══════════════════════════════════════════════╝");

    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
