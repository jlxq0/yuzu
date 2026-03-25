use crate::{camouflage, protocol, transport, tunnel};
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Run the client: create TUN, route all traffic, auto-reconnect on drop
pub async fn run(
    server: &str,
    secret_path: &Path,
    enable_camouflage: bool,
    insecure: bool,
) -> Result<()> {
    let secret = protocol::load_secret(secret_path)?;
    let connector = transport::tls_connector(insecure)?;
    let (host, port) = parse_server(server)?;

    if insecure {
        warn!("WARNING: --insecure disables ALL TLS certificate verification. Vulnerable to MITM.");
    }

    // Resolve server IP before creating TUN (DNS won't work after route change)
    let server_addr = dns_resolve(&host).await?;
    info!("server resolved to {server_addr}");

    // First connection to get TUN config
    info!("connecting to {host}:{port}");
    let mut tls = connect_and_auth(&host, port, &connector, &secret).await?;

    // Read TUN config
    let mut config_buf = [0u8; 32];
    tls.read_exact(&mut config_buf)
        .await
        .context("reading TUN config")?;
    let client_ip = std::str::from_utf8(&config_buf[..16])?
        .trim_end_matches('\0')
        .trim()
        .to_string();
    let server_ip = std::str::from_utf8(&config_buf[16..32])?
        .trim_end_matches('\0')
        .trim()
        .to_string();
    let prefix_len: u8 = 24;

    info!("TUN config: client={client_ip}, server={server_ip}/{prefix_len}");

    // Create TUN device (once — persists across reconnects)
    let dev = tunnel::create_device(&client_ip, prefix_len, 1400)?;
    let tun_name = dev.name().unwrap_or_else(|_| "tun?".into());
    let dev = Arc::new(dev);

    // Set up routes (once)
    tunnel::setup_client_routes(&tun_name, &server_addr)?;
    tunnel::setup_client_dns()?;

    // Handle cleanup on shutdown
    let server_addr_cleanup = server_addr.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await.ok();

        tunnel::teardown_client_dns();
        tunnel::teardown_client_routes(&server_addr_cleanup);
        info!("shutting down");
        std::process::exit(0);
    });

    if enable_camouflage {
        let h = host.clone();
        tokio::spawn(async move {
            camouflage::run_decoy_traffic(&h).await;
        });
    }

    info!("tunnel active — all traffic routed through {tun_name}");

    // Main loop: relay packets, reconnect on failure
    let mut backoff = 1u64;
    loop {
        // Relay packets until connection drops
        let result = tunnel::relay(dev.clone(), tls).await;
        match &result {
            Ok(_) => info!("tunnel closed cleanly"),
            Err(e) => warn!("tunnel disconnected: {e}"),
        }

        // Reconnect loop
        loop {
            info!("reconnecting in {backoff}s...");
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;

            match connect_and_auth(&host, port, &connector, &secret).await {
                Ok(mut new_tls) => {
                    // Read TUN config (we ignore it — TUN already exists)
                    let mut buf = [0u8; 32];
                    if let Err(e) = new_tls.read_exact(&mut buf).await {
                        warn!("reconnect config read failed: {e}");
                        backoff = (backoff * 2).min(60);
                        continue;
                    }
                    tls = new_tls;
                    backoff = 1;
                    info!("reconnected");
                    break;
                }
                Err(e) => {
                    warn!("reconnect failed: {e}");
                    backoff = (backoff * 2).min(60);
                }
            }
        }
    }
}

/// Connect to server, TLS handshake, send secret + TUN marker
async fn connect_and_auth(
    host: &str,
    port: u16,
    connector: &tokio_rustls::TlsConnector,
    secret: &[u8],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .context("TCP connect")?;

    let server_name = ServerName::try_from(host.to_string())?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;

    tls.write_all(secret).await?;
    tls.write_u8(tunnel::TUN_MARKER).await?;
    tls.flush().await?;

    Ok(tls)
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

async fn dns_resolve(host: &str) -> Result<String> {
    use tokio::net::lookup_host;
    let addr = lookup_host(format!("{host}:0"))
        .await?
        .next()
        .context("DNS resolution failed")?;
    Ok(addr.ip().to_string())
}
