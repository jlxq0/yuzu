use crate::{protocol, tunnel};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info};

/// Maximum concurrent connections
const MAX_CONNECTIONS: usize = 64;
/// Maximum failed auth attempts per IP before ban
const MAX_FAILURES_PER_IP: usize = 5;
/// Ban duration after too many failures
const BAN_DURATION: std::time::Duration = std::time::Duration::from_secs(300);

/// Per-IP rate limiter
struct RateLimiter {
    failures: HashMap<IpAddr, (usize, Instant)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            failures: HashMap::new(),
        }
    }

    fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some((count, last)) = self.failures.get(ip) {
            *count >= MAX_FAILURES_PER_IP && last.elapsed() < BAN_DURATION
        } else {
            false
        }
    }

    fn record_failure(&mut self, ip: IpAddr) {
        let entry = self.failures.entry(ip).or_insert((0, Instant::now()));
        // Reset if ban has expired
        if entry.1.elapsed() >= BAN_DURATION {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
            entry.1 = Instant::now();
        }
    }

    fn record_success(&mut self, ip: &IpAddr) {
        self.failures.remove(ip);
    }

    /// Clean up old entries periodically
    fn cleanup(&mut self) {
        self.failures
            .retain(|_, (_, last)| last.elapsed() < BAN_DURATION * 2);
    }
}

pub struct ServerConfig {
    pub listen: String,
    pub domain: String,
    pub secret_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

fn cover_page(domain: &str) -> String {
    let body = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>{domain}</title>\
         <style>*{{margin:0;padding:0}}body{{font-family:system-ui;background:#fafafa;\
         color:#333;display:flex;justify-content:center;align-items:center;\
         min-height:100vh}}h1{{font-size:2rem;font-weight:300}}</style>\
         </head><body><h1>{domain}</h1></body></html>"
    );
    format!(
        "HTTP/1.1 200 OK\r\n\
         Server: nginx\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: strict-origin-when-cross-origin\r\n\
         \r\n\
         {}",
        body.len(),
        body
    )
}

pub async fn run(config: ServerConfig) -> Result<()> {
    let secret = protocol::load_secret(&config.secret_path)?;
    let acceptor = crate::transport::tls_acceptor(&config.cert_path, &config.key_path)?;
    let listener = TcpListener::bind(&config.listen).await?;
    let cover = cover_page(&config.domain);
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    // Create server TUN device
    let tun_cfg = tunnel::TunConfig::default();
    let tun_dev = tunnel::create_device(&tun_cfg.server_ip, tun_cfg.prefix_len, tun_cfg.mtu)?;
    let tun_name = tun_dev.name().unwrap_or_else(|_| "tun?".into());

    // Set up NAT
    let subnet = format!(
        "{}/{}",
        tun_cfg
            .server_ip
            .rsplit_once('.')
            .map(|(base, _)| format!("{base}.0"))
            .unwrap_or("10.66.0.0".into()),
        tun_cfg.prefix_len
    );
    tunnel::setup_server_nat(&tun_name, &subnet)?;

    let tun_dev = Arc::new(tun_dev);
    let ip_alloc = Arc::new(tunnel::IpAllocator::new());

    info!("yuzu server listening on {}", config.listen);
    info!("  domain: {}", config.domain);
    info!("  tun: {tun_name} ({})", tun_cfg.server_ip);
    info!("  max connections: {MAX_CONNECTIONS}");

    // Handle cleanup on shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tunnel::teardown_server_nat();
        info!("server shutting down");
        std::process::exit(0);
    });

    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    // Periodic cleanup of rate limiter
    let rl_cleanup = rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            rl_cleanup.lock().await.cleanup();
        }
    });

    loop {
        let (stream, addr) = listener.accept().await?;
        let ip = addr.ip();

        // Check rate limit
        if rate_limiter.lock().await.is_banned(&ip) {
            debug!("{addr}: rate limited, dropping");
            drop(stream);
            continue;
        }

        // Connection limit
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("{addr}: connection limit reached, dropping");
                drop(stream);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let secret = secret.clone();
        let cover = cover.clone();
        let tun = tun_dev.clone();
        let rl = rate_limiter.clone();
        let alloc = ip_alloc.clone();

        tokio::spawn(async move {
            let authenticated = handle_connection(stream, &acceptor, &secret, &cover, tun, &alloc).await;
            match authenticated {
                Ok(true) => rl.lock().await.record_success(&ip),
                Ok(false) => rl.lock().await.record_failure(ip),
                Err(e) => {
                    debug!("{addr}: {e}");
                    rl.lock().await.record_failure(ip);
                }
            }
            drop(permit);
        });
    }
}

/// Returns Ok(true) if client authenticated, Ok(false) if auth failed
async fn handle_connection(
    stream: TcpStream,
    acceptor: &tokio_rustls::TlsAcceptor,
    secret: &[u8],
    cover: &str,
    tun_dev: Arc<tun_rs::AsyncDevice>,
    ip_alloc: &tunnel::IpAllocator,
) -> Result<bool> {
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        acceptor.accept(stream),
    )
    .await
    .context("TLS handshake timeout")?
    .context("TLS handshake")?;

    // Read secret with timeout
    let mut buf = vec![0u8; protocol::SECRET_LEN];
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tls.read_exact(&mut buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        _ => {
            serve_cover(&mut tls, cover).await?;
            return Ok(false);
        }
    }

    if !bool::from(buf.ct_eq(secret)) {
        serve_cover(&mut tls, cover).await?;
        return Ok(false);
    }

    // Read mode byte
    let mut mode = [0u8; 1];
    if tls.read_exact(&mut mode).await.is_err() {
        return Ok(false);
    }

    if mode[0] != tunnel::TUN_MARKER {
        serve_cover(&mut tls, cover).await?;
        return Ok(false);
    }

    debug!("client authenticated, entering TUN mode");

    // Allocate client IP
    let client_ip = ip_alloc
        .allocate()
        .context("IP pool exhausted")?;
    debug!("assigned client IP: {client_ip}");

    let cfg = tunnel::TunConfig::default();
    let mut config_buf = [0u8; 32];
    let client_bytes = client_ip.as_bytes();
    let server_bytes = cfg.server_ip.as_bytes();
    config_buf[..client_bytes.len()].copy_from_slice(client_bytes);
    config_buf[16..16 + server_bytes.len()].copy_from_slice(server_bytes);
    tls.write_all(&config_buf).await?;
    tls.flush().await?;

    // Ensure route to client IP
    let tun_name = tun_dev.name().unwrap_or_else(|_| "tun0".into());
    tunnel::setup_server_tun_route(&tun_name, &client_ip)?;

    // Relay packets
    tunnel::relay(tun_dev, tls).await?;

    Ok(true)
}

async fn serve_cover<S: AsyncWriteExt + Unpin>(stream: &mut S, cover: &str) -> Result<()> {
    stream.write_all(cover.as_bytes()).await.ok();
    stream.shutdown().await.ok();
    Ok(())
}
