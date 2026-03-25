use crate::{camouflage, protocol, transport};
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

/// Run the client
pub async fn run(
    server: &str,
    secret_path: &Path,
    socks_port: u16,
    enable_camouflage: bool,
    _tunnel_dns: bool,
) -> Result<()> {
    let secret = protocol::load_secret(secret_path)?;
    let connector = transport::tls_connector()?;

    // Parse server address
    let (host, port) = parse_server(server)?;

    // Start SOCKS5 proxy
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let listener = TcpListener::bind(&socks_addr).await?;
    info!("SOCKS5 proxy listening on {socks_addr}");
    info!("server: {host}:{port}");

    if enable_camouflage {
        let host = host.clone();
        tokio::spawn(async move {
            camouflage::run_decoy_traffic(&host).await;
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        let connector = connector.clone();
        let secret = secret.clone();
        let host = host.clone();
        let port = port;

        tokio::spawn(async move {
            if let Err(e) =
                handle_socks5(stream, &connector, &secret, &host, port).await
            {
                debug!("socks5 from {addr}: {e}");
            }
        });
    }
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

async fn handle_socks5(
    mut client: TcpStream,
    connector: &tokio_rustls::TlsConnector,
    secret: &[u8],
    server_host: &str,
    server_port: u16,
) -> Result<()> {
    // SOCKS5 handshake
    // Read version + methods
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        anyhow::bail!("not SOCKS5");
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // No auth required
    client.write_all(&[0x05, 0x00]).await?;

    // Read connect request
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        anyhow::bail!("only CONNECT supported");
    }

    // Parse destination address
    let (dest_addr, dest_port) = match req[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            (format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]), port)
        }
        0x03 => {
            // Domain
            let len = client.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            client.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            (String::from_utf8(domain)?, port)
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let a = std::net::Ipv6Addr::from(addr);
            (a.to_string(), port)
        }
        _ => anyhow::bail!("unsupported address type"),
    };

    debug!("SOCKS5 CONNECT {dest_addr}:{dest_port}");

    // Connect to yuzu server via TLS
    let tcp = TcpStream::connect(format!("{server_host}:{server_port}"))
        .await
        .context("connecting to yuzu server")?;

    let server_name = ServerName::try_from(server_host.to_string())?;
    let mut tls = connector.connect(server_name, tcp).await.context("TLS")?;

    // Send secret
    tls.write_all(secret).await?;

    // Send connect request through tunnel
    // Frame: [type: 0x01, addr_len: u8, addr: bytes, port: u16be]
    tls.write_u8(0x01).await?;
    let addr_bytes = dest_addr.as_bytes();
    tls.write_u8(addr_bytes.len() as u8).await?;
    tls.write_all(addr_bytes).await?;
    tls.write_u16(dest_port).await?;
    tls.flush().await?;

    // Read response
    let status = tls.read_u8().await?;
    if status != 0x00 {
        // SOCKS5 failure response
        client
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("server connect failed");
    }

    // SOCKS5 success response
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Relay traffic
    transport::relay(client, tls).await?;

    Ok(())
}
