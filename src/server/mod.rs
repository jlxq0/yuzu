use crate::{protocol, transport};
use anyhow::{Context, Result};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

/// Cover page HTML
fn cover_page(domain: &str) -> String {
    format!(
        r#"HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html
Connection: close
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{domain}</title>
<style>*{{margin:0;padding:0}}body{{font-family:system-ui;background:#fafafa;color:#333;display:flex;justify-content:center;align-items:center;min-height:100vh}}h1{{font-size:2rem;font-weight:300}}</style>
</head><body><h1>{domain}</h1></body></html>"#
    )
}

/// Run the server
pub async fn run(
    listen: &str,
    domain: &str,
    secret_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    let secret = protocol::load_secret(secret_path)?;
    let acceptor = transport::tls_acceptor(cert_path, key_path)?;
    let listener = TcpListener::bind(listen).await?;
    let cover = cover_page(domain);

    info!("yuzu server listening on {listen} (domain: {domain})");

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let secret = secret.clone();
        let cover = cover.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &acceptor, &secret, &cover).await {
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
) -> Result<()> {
    // TLS handshake
    let mut tls = acceptor.accept(stream).await.context("TLS handshake")?;

    // Read secret (64 bytes)
    let mut buf = vec![0u8; protocol::SECRET_LEN];
    match tokio::io::AsyncReadExt::read_exact(&mut tls, &mut buf).await {
        Ok(_) => {}
        Err(_) => {
            // Couldn't read enough bytes — serve cover page
            tls.write_all(cover.as_bytes()).await.ok();
            tls.shutdown().await.ok();
            return Ok(());
        }
    }

    // Constant-time compare
    if buf.ct_eq(secret).into() {
        // Authenticated — enter tunnel mode
        debug!("client authenticated");
        handle_tunnel(tls).await
    } else {
        // Wrong secret — serve cover page
        debug!("wrong secret, serving cover page");
        tls.write_all(cover.as_bytes()).await.ok();
        tls.shutdown().await.ok();
        Ok(())
    }
}

async fn handle_tunnel<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S) -> Result<()> {
    // Read SOCKS5-style connect request from the tunnel
    // Frame: [type: u8, addr_len: u8, addr: bytes, port: u16be]
    let frame_type = stream.read_u8().await?;

    match frame_type {
        0x01 => {
            // TCP connect
            let addr_len = stream.read_u8().await? as usize;
            let mut addr_buf = vec![0u8; addr_len];
            stream.read_exact(&mut addr_buf).await?;
            let addr = String::from_utf8(addr_buf)?;
            let port = stream.read_u16().await?;

            let target = format!("{addr}:{port}");
            debug!("connecting to {target}");

            match TcpStream::connect(&target).await {
                Ok(target_stream) => {
                    // Send success
                    stream.write_u8(0x00).await?;
                    // Relay
                    transport::relay(stream, target_stream).await?;
                }
                Err(e) => {
                    // Send failure
                    stream.write_u8(0x01).await?;
                    warn!("connect to {target} failed: {e}");
                }
            }
        }
        _ => {
            warn!("unknown frame type: {frame_type:#x}");
        }
    }

    Ok(())
}
