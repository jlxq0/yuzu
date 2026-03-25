use crate::{camouflage, protocol, transport};
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Run the client: create TUN, route all traffic through TLS tunnel
pub async fn run(
    server: &str,
    secret_path: &Path,
    enable_camouflage: bool,
) -> Result<()> {
    let secret = protocol::load_secret(secret_path)?;
    let connector = transport::tls_connector()?;
    let (host, port) = parse_server(server)?;

    info!("connecting to {host}:{port}");

    // Connect to server via TLS
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .context("connecting to server")?;

    let server_name = ServerName::try_from(host.clone())?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;

    // Send secret
    tls.write_all(&secret).await?;

    // Send framing marker (0x00 = framed TUN mode)
    tls.write_u8(0x00).await?;
    tls.flush().await?;

    info!("authenticated, entering TUN mode");

    if enable_camouflage {
        let h = host.clone();
        tokio::spawn(async move {
            camouflage::run_decoy_traffic(&h).await;
        });
    }

    // TODO: create TUN device, set up routes, relay packets
    // For now, demonstrate the connection works
    info!("TUN mode connected (not yet implemented)");
    info!("press Ctrl+C to exit");

    // Keep connection alive
    tokio::signal::ctrl_c().await?;

    Ok(())
}

fn parse_server(server: &str) -> Result<(String, u16)> {
    if let Some(pos) = server.rfind(':') {
        let host = server[..pos].to_string();
        let port: u16 = server[pos + 1..].parse()?;
        Ok((host, port))
    } else {
        Ok((server.to_string(), 443))
    }
}
