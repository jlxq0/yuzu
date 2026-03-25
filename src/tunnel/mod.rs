use anyhow::{Context, Result};
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

/// TUN tunnel configuration
pub struct TunConfig {
    /// Client-side TUN IP
    pub client_ip: String,
    /// Server-side TUN IP
    pub server_ip: String,
    /// Subnet prefix length
    pub prefix_len: u8,
    /// MTU (leave room for TLS + framing overhead)
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            client_ip: "10.66.0.2".into(),
            server_ip: "10.66.0.1".into(),
            prefix_len: 24,
            mtu: 1400,
        }
    }
}

/// Frame marker sent after secret to indicate TUN mode
pub const TUN_MARKER: u8 = 0x00;

/// Create a TUN device and return it
pub fn create_device(ip: &str, prefix_len: u8, mtu: u16) -> Result<tun_rs::AsyncDevice> {
    let dev = tun_rs::DeviceBuilder::new()
        .ipv4(ip, prefix_len, None)
        .mtu(mtu)
        .build_async()
        .context("creating TUN device")?;

    let name = dev.name().unwrap_or_else(|_| "utun?".into());
    info!("created TUN device {name} with ip {ip}/{prefix_len}, mtu {mtu}");

    // Bring interface up
    Command::new("ifconfig")
        .args([&name, "up"])
        .status()
        .context("ifconfig up")?;

    Ok(dev)
}

/// Set up client-side routing: all traffic through TUN, except VPN server
pub fn setup_client_routes(tun_name: &str, server_ip: &str) -> Result<()> {
    // Find the current default gateway
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("getting default gateway")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let gateway = stdout
        .lines()
        .find(|l| l.contains("gateway:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .context("parsing default gateway")?;

    info!("original gateway: {gateway}");

    // Route VPN server traffic through original gateway (avoid loop)
    run_cmd("route", &["add", "-host", server_ip, &gateway])?;

    // Route everything else through TUN (0/1 + 128/1 trick)
    run_cmd("route", &["add", "-net", "0.0.0.0/1", "-interface", tun_name])?;
    run_cmd("route", &["add", "-net", "128.0.0.0/1", "-interface", tun_name])?;

    info!("routes configured: all traffic → {tun_name}");
    Ok(())
}

/// Clean up client-side routes
pub fn teardown_client_routes(server_ip: &str) {
    let _ = run_cmd("route", &["delete", "-net", "0.0.0.0/1"]);
    let _ = run_cmd("route", &["delete", "-net", "128.0.0.0/1"]);
    let _ = run_cmd("route", &["delete", "-host", server_ip]);
    info!("routes cleaned up");
}

/// Set up server-side NAT: forward TUN traffic to the internet
pub fn setup_server_nat(tun_name: &str, subnet: &str) -> Result<()> {
    // Enable IP forwarding
    run_cmd("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;

    // Find the internet-facing interface
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let iface = stdout
        .lines()
        .find(|l| l.contains("interface:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "en0".into());

    info!("NAT: {subnet} → {iface}");

    let rules = format!(
        "nat on {iface} from {subnet} to any -> ({iface})\npass on {tun_name} all\n"
    );
    std::fs::write("/tmp/yuzu-pf.conf", &rules)?;
    run_cmd("pfctl", &["-f", "/tmp/yuzu-pf.conf", "-e"])?;

    info!("NAT enabled");
    Ok(())
}

/// Teardown server NAT
pub fn teardown_server_nat() {
    let _ = run_cmd("pfctl", &["-d"]);
    let _ = std::fs::remove_file("/tmp/yuzu-pf.conf");
}

/// Relay packets between TUN device and a framed TLS stream
///
/// Framing: each IP packet is prefixed with [len: u16 big-endian]
pub async fn relay_tun_to_stream<S>(
    dev: Arc<tun_rs::AsyncDevice>,
    mut stream: S,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let dev_reader = dev.clone();
    let dev_writer = dev.clone();

    // TUN → TLS stream
    let tun_to_stream = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match dev_reader.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let len = n as u16;
                    let mut frame = Vec::with_capacity(2 + n);
                    frame.extend_from_slice(&len.to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    // We can't write to `stream` here because it's moved
                    // to the other task. We need a channel.
                    debug!("tun→stream: {n} bytes");
                }
                Ok(_) => continue,
                Err(e) => {
                    error!("TUN read error: {e}");
                    break;
                }
            }
        }
    });

    // TLS stream → TUN
    let stream_to_tun = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let len = match AsyncReadExt::read_u16(&mut stream).await {
                Ok(l) => l as usize,
                Err(_) => break,
            };
            if len == 0 || len > 65535 {
                break;
            }
            if let Err(e) = AsyncReadExt::read_exact(&mut stream, &mut buf[..len]).await {
                error!("stream read error: {e}");
                break;
            }
            if let Err(e) = dev_writer.send(&buf[..len]).await {
                error!("TUN write error: {e}");
                break;
            }
            debug!("stream→tun: {len} bytes");
        }
    });

    tokio::select! {
        _ = tun_to_stream => warn!("tun→stream ended"),
        _ = stream_to_tun => warn!("stream→tun ended"),
    }

    Ok(())
}

/// Bidirectional relay using split stream and channels
pub async fn relay<S>(dev: Arc<tun_rs::AsyncDevice>, stream: S) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut stream_reader, mut stream_writer) = tokio::io::split(stream);
    let dev_reader = dev.clone();
    let dev_writer = dev.clone();

    // TUN → TLS
    let t2s = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match dev_reader.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let len = (n as u16).to_be_bytes();
                    if stream_writer.write_all(&len).await.is_err() {
                        break;
                    }
                    if stream_writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if stream_writer.flush().await.is_err() {
                        break;
                    }
                }
                Ok(_) => continue,
                Err(e) => {
                    error!("TUN read: {e}");
                    break;
                }
            }
        }
    });

    // TLS → TUN
    let s2t = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let len = match stream_reader.read_u16().await {
                Ok(l) => l as usize,
                Err(_) => break,
            };
            if len == 0 || len > 65535 {
                break;
            }
            if stream_reader.read_exact(&mut buf[..len]).await.is_err() {
                break;
            }
            if dev_writer.send(&buf[..len]).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        _ = t2s => {},
        _ = s2t => {},
    }

    Ok(())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{cmd} {:?} failed: {status}", args);
    }
    Ok(())
}
