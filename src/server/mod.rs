use crate::{protocol, transport};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
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

/// Cover page HTML
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

    info!("yuzu server listening on {}", config.listen);
    info!("  domain: {}", config.domain);
    if let Some(ref ssh) = config.ssh_backend {
        info!("  ssh: {ssh}");
    }
    if let Some(ref et) = config.et_backend {
        info!("  et: {et}");
    }

    let ssh_backend = config.ssh_backend.clone();
    let et_backend = config.et_backend.clone();

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let secret = secret.clone();
        let cover = cover.clone();
        let ssh = ssh_backend.clone();
        let et = et_backend.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &acceptor, &secret, &cover, &ssh, &et).await
            {
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
    ssh_backend: &Option<String>,
    et_backend: &Option<String>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await.context("TLS handshake")?;

    // Read secret (64 bytes)
    let mut buf = vec![0u8; protocol::SECRET_LEN];
    match tokio::io::AsyncReadExt::read_exact(&mut tls, &mut buf).await {
        Ok(_) => {}
        Err(_) => {
            return serve_cover(&mut tls, cover).await;
        }
    }

    if !bool::from(buf.ct_eq(secret)) {
        return serve_cover(&mut tls, cover).await;
    }

    debug!("client authenticated");

    // Read first byte to detect protocol
    let mut peek = [0u8; 1];
    match tls.read_exact(&mut peek).await {
        Ok(_) => {}
        Err(_) => return Ok(()),
    }

    match peek[0] {
        // SSH: starts with 'S' (SSH-2.0-...)
        b'S' if ssh_backend.is_some() => {
            let backend = ssh_backend.as_ref().unwrap();
            debug!("detected SSH, proxying to {backend}");
            let mut target = TcpStream::connect(backend).await?;
            // Replay the 'S' byte
            target.write_all(&peek).await?;
            transport::relay(tls, target).await?;
        }

        // ET: protobuf starts with 0x0a (field 1, wire type 2 = length-delimited string)
        0x0a if et_backend.is_some() => {
            let backend = et_backend.as_ref().unwrap();
            debug!("detected ET, proxying to {backend}");
            let mut target = TcpStream::connect(backend).await?;
            target.write_all(&peek).await?;
            transport::relay(tls, target).await?;
        }

        // TUN packet: our protocol — first byte is IP version (0x45 = IPv4, 0x60 = IPv6)
        0x45 | 0x60 => {
            debug!("TUN mode");
            handle_tun(tls, peek[0]).await?;
        }

        // Framed TUN: length-prefixed packets (0x00 = our framing marker)
        0x00 => {
            debug!("framed TUN mode");
            handle_framed_tun(tls).await?;
        }

        other => {
            warn!("unknown protocol byte after auth: {other:#04x}");
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

/// Handle framed TUN packets: [len: u16be, packet: bytes]
async fn handle_framed_tun<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S) -> Result<()> {
    // TODO: create TUN device, forward packets
    // For now, just read and discard
    info!("TUN mode connected (not yet implemented)");
    let mut buf = vec![0u8; 65536];
    loop {
        let len = match stream.read_u16().await {
            Ok(l) => l as usize,
            Err(_) => break,
        };
        if len == 0 || len > 65535 {
            break;
        }
        stream.read_exact(&mut buf[..len]).await?;
        // TODO: write to TUN device
    }
    Ok(())
}

/// Handle raw TUN packet (first byte already read)
async fn handle_tun<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut _stream: S, _first: u8) -> Result<()> {
    info!("raw TUN mode (not yet implemented)");
    Ok(())
}
