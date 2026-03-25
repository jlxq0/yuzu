use crate::{camouflage, protocol, transport, tunnel};
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Run the client: create TUN, route all traffic through TLS tunnel
pub async fn run(server: &str, secret_path: &Path, enable_camouflage: bool, insecure: bool) -> Result<()> {
    let secret = protocol::load_secret(secret_path)?;
    let connector = transport::tls_connector(insecure)?;
    let (host, port) = parse_server(server)?;

    info!("connecting to {host}:{port}");

    // Connect via TLS
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .context("connecting to server")?;

    let server_name = ServerName::try_from(host.clone())?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;

    // Authenticate
    tls.write_all(&secret).await?;

    // Request TUN mode
    tls.write_u8(tunnel::TUN_MARKER).await?;
    tls.flush().await?;

    // Read TUN config from server
    let mut reader = BufReader::new(tls);
    let mut client_ip = String::new();
    let mut server_ip = String::new();
    let mut prefix_str = String::new();
    reader.read_line(&mut client_ip).await?;
    reader.read_line(&mut server_ip).await?;
    reader.read_line(&mut prefix_str).await?;
    let client_ip = client_ip.trim().to_string();
    let server_ip = server_ip.trim().to_string();
    let prefix_len: u8 = prefix_str.trim().parse().unwrap_or(24);

    info!("TUN config: client={client_ip}, server={server_ip}/{prefix_len}");

    // Unwrap the BufReader to get the stream back
    let tls = reader.into_inner();

    // Create TUN device
    let dev = tunnel::create_device(&client_ip, prefix_len, 1400)?;
    let tun_name = dev.name().unwrap_or_else(|_| "utun?".into());
    let dev = Arc::new(dev);

    // Resolve server IP for route exclusion
    let server_addr = dns_resolve(&host).await?;
    info!("server resolved to {server_addr}");

    // Set up routes
    tunnel::setup_client_routes(&tun_name, &server_addr)?;

    // Handle cleanup on shutdown
    let server_addr_cleanup = server_addr.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tunnel::teardown_client_routes(&server_addr_cleanup);
        info!("client shutting down");
        std::process::exit(0);
    });

    if enable_camouflage {
        let h = host.clone();
        tokio::spawn(async move {
            camouflage::run_decoy_traffic(&h).await;
        });
    }

    info!("tunnel active — all traffic routed through {tun_name}");

    // Relay packets between TUN and TLS
    tunnel::relay(dev, tls).await?;

    // If relay ends, clean up
    tunnel::teardown_client_routes(&server_addr);

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

/// Resolve hostname to IP (needed for route exclusion)
async fn dns_resolve(host: &str) -> Result<String> {
    use tokio::net::lookup_host;
    let addr = lookup_host(format!("{host}:0"))
        .await?
        .next()
        .context("DNS resolution failed")?;
    Ok(addr.ip().to_string())
}
