use crate::{protocol, transport, tunnel};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

pub struct ServerConfig {
    pub listen: String,
    pub domain: String,
    pub secret_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ssh_backend: Option<String>,
    pub et_backend: Option<String>,
    pub camouflage: bool,
}

fn cover_page(domain: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         Server: nginx\r\n\
         Content-Type: text/html\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\r\n\
         <!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>{domain}</title>\
         <style>*{{margin:0;padding:0}}body{{font-family:system-ui;background:#fafafa;\
         color:#333;display:flex;justify-content:center;align-items:center;\
         min-height:100vh}}h1{{font-size:2rem;font-weight:300}}</style>\
         </head><body><h1>{domain}</h1></body></html>"
    )
}

pub async fn run(config: ServerConfig) -> Result<()> {
    let secret = protocol::load_secret(&config.secret_path)?;
    let acceptor = transport::tls_acceptor(&config.cert_path, &config.key_path)?;
    let listener = TcpListener::bind(&config.listen).await?;
    let cover = cover_page(&config.domain);

    // Create server TUN device
    let tun_cfg = tunnel::TunConfig::default();
    let tun_dev = tunnel::create_device(&tun_cfg.server_ip, tun_cfg.prefix_len, tun_cfg.mtu)?;
    let tun_name = tun_dev.name().unwrap_or_else(|_| "utun?".into());

    // Set up NAT
    let subnet = format!("{}/{}", tun_cfg.server_ip.rsplit_once('.').map(|(base, _)| format!("{base}.0")).unwrap_or("10.66.0.0".into()), tun_cfg.prefix_len);
    tunnel::setup_server_nat(&tun_name, &subnet)?;

    let tun_dev = Arc::new(tun_dev);

    info!("yuzu server listening on {}", config.listen);
    info!("  domain: {}", config.domain);
    info!("  tun: {tun_name} ({})", tun_cfg.server_ip);

    // Handle cleanup on shutdown
    let subnet_cleanup = subnet.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tunnel::teardown_server_nat();
        info!("server shutting down");
        std::process::exit(0);
    });

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let secret = secret.clone();
        let cover = cover.clone();
        let tun = tun_dev.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &acceptor, &secret, &cover, tun).await {
                debug!("connection from {addr}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: &tokio_rustls::TlsAcceptor,
    secret: &[u8],
    cover: &str,
    tun_dev: Arc<tun_rs::AsyncDevice>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await.context("TLS handshake")?;

    // Read secret
    let mut buf = vec![0u8; protocol::SECRET_LEN];
    if tls.read_exact(&mut buf).await.is_err() {
        return serve_cover(&mut tls, cover).await;
    }

    if !bool::from(buf.ct_eq(secret)) {
        return serve_cover(&mut tls, cover).await;
    }

    debug!("client authenticated");

    // Read mode byte
    let mut mode = [0u8; 1];
    if tls.read_exact(&mut mode).await.is_err() {
        return Ok(());
    }

    match mode[0] {
        // TUN mode
        tunnel::TUN_MARKER => {
            info!("client entering TUN mode");
            // Send server TUN IP config to client
            let cfg = tunnel::TunConfig::default();
            let config_msg = format!("{}\n{}\n{}\n", cfg.client_ip, cfg.server_ip, cfg.prefix_len);
            tls.write_all(config_msg.as_bytes()).await?;
            tls.flush().await?;

            // Relay packets
            tunnel::relay(tun_dev, tls).await?;
        }
        // SSH
        b'S' => {
            debug!("detected SSH");
            let mut target = TcpStream::connect("127.0.0.1:22").await?;
            target.write_all(&mode).await?;
            transport::relay(tls, target).await?;
        }
        // ET
        0x0a => {
            debug!("detected ET");
            let mut target = TcpStream::connect("127.0.0.1:2022").await?;
            target.write_all(&mode).await?;
            transport::relay(tls, target).await?;
        }
        other => {
            warn!("unknown mode byte: {other:#04x}");
        }
    }

    Ok(())
}

async fn serve_cover<S: AsyncWriteExt + Unpin>(stream: &mut S, cover: &str) -> Result<()> {
    debug!("serving cover page");
    stream.write_all(cover.as_bytes()).await.ok();
    stream.shutdown().await.ok();
    Ok(())
}
