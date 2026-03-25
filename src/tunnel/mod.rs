use anyhow::{Context, Result};
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};

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

    let name = dev.name().unwrap_or_else(|_| "tun?".into());
    info!("created TUN device {name} with ip {ip}/{prefix_len}, mtu {mtu}");

    // Bring interface up
    if cfg!(target_os = "linux") {
        run_cmd("ip", &["link", "set", &name, "up"])?;
    } else {
        Command::new("ifconfig")
            .args([&name, "up"])
            .status()
            .context("ifconfig up")?;
    }

    Ok(dev)
}

/// Set up point-to-point addressing on the TUN (server side)
/// This ensures the kernel knows to route packets for the client IP through the TUN
pub fn setup_server_tun_route(tun_name: &str, client_ip: &str) -> Result<()> {
    if cfg!(target_os = "linux") {
        // On Linux, the /24 subnet route from device creation is sufficient,
        // but explicitly add a route for the client IP to be sure
        let _ = run_cmd("ip", &["route", "add", &format!("{client_ip}/32"), "dev", tun_name]);
    }
    Ok(())
}

/// Set up client-side routing: all traffic through TUN, except VPN server
pub fn setup_client_routes(tun_name: &str, server_ip: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        setup_routes_macos(tun_name, server_ip)
    } else {
        setup_routes_linux(tun_name, server_ip)
    }
}

fn setup_routes_macos(tun_name: &str, server_ip: &str) -> Result<()> {
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
    run_cmd("route", &["add", "-host", server_ip, &gateway])?;
    run_cmd("route", &["add", "-net", "0.0.0.0/1", "-interface", tun_name])?;
    run_cmd("route", &["add", "-net", "128.0.0.0/1", "-interface", tun_name])?;
    info!("routes configured: all traffic → {tun_name}");
    Ok(())
}

fn setup_routes_linux(tun_name: &str, server_ip: &str) -> Result<()> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("getting default gateway")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // "default via 172.31.1.1 dev eth0"
    let gateway = stdout
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .context("parsing default gateway")?
        .to_string();

    info!("original gateway: {gateway}");
    run_cmd("ip", &["route", "add", server_ip, "via", &gateway])?;
    run_cmd("ip", &["route", "add", "0.0.0.0/1", "dev", tun_name])?;
    run_cmd("ip", &["route", "add", "128.0.0.0/1", "dev", tun_name])?;
    info!("routes configured: all traffic → {tun_name}");
    Ok(())
}

/// Clean up client-side routes
pub fn teardown_client_routes(server_ip: &str) {
    if cfg!(target_os = "macos") {
        let _ = run_cmd("route", &["delete", "-net", "0.0.0.0/1"]);
        let _ = run_cmd("route", &["delete", "-net", "128.0.0.0/1"]);
        let _ = run_cmd("route", &["delete", "-host", server_ip]);
    } else {
        let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1"]);
        let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1"]);
        let _ = run_cmd("ip", &["route", "del", server_ip]);
    }
    info!("routes cleaned up");
}

/// Set up server-side NAT: forward TUN traffic to the internet
pub fn setup_server_nat(tun_name: &str, subnet: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        setup_nat_macos(tun_name, subnet)
    } else {
        setup_nat_linux(tun_name, subnet)
    }
}

fn setup_nat_linux(tun_name: &str, subnet: &str) -> Result<()> {
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;

    // Find default interface
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let iface = stdout
        .split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .unwrap_or("eth0")
        .to_string();

    info!("NAT: {subnet} → {iface}");

    // NAT all traffic from TUN interface (not just subnet — client may send with original source IP)
    run_cmd("iptables", &["-t", "nat", "-A", "POSTROUTING", "-o", &iface, "-j", "MASQUERADE"])?;
    run_cmd("iptables", &["-A", "FORWARD", "-i", tun_name, "-o", &iface, "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "FORWARD", "-i", &iface, "-o", tun_name, "-j", "ACCEPT"])?;

    info!("NAT enabled (iptables)");
    Ok(())
}

fn setup_nat_macos(tun_name: &str, subnet: &str) -> Result<()> {
    run_cmd("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;

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
        "nat on {iface} from any to any -> ({iface})\npass on {tun_name} all\n"
    );
    std::fs::write("/tmp/yuzu-pf.conf", &rules)?;
    run_cmd("pfctl", &["-f", "/tmp/yuzu-pf.conf", "-e"])?;

    info!("NAT enabled (pf)");
    Ok(())
}

/// Teardown server NAT
pub fn teardown_server_nat() {
    if cfg!(target_os = "macos") {
        let _ = run_cmd("pfctl", &["-d"]);
        let _ = std::fs::remove_file("/tmp/yuzu-pf.conf");
    } else {
        // Linux: flush iptables rules (simple cleanup)
        let _ = run_cmd("iptables", &["-t", "nat", "-F"]);
        let _ = run_cmd("iptables", &["-F", "FORWARD"]);
    }
}

/// Override DNS to use public resolvers (traffic goes through tunnel)
pub fn setup_client_dns() -> Result<()> {
    if cfg!(target_os = "linux") {
        // Back up existing resolv.conf
        let _ = std::fs::copy("/etc/resolv.conf", "/tmp/yuzu-resolv.conf.bak");
        std::fs::write("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")?;
        info!("DNS set to 8.8.8.8 / 1.1.1.1 (through tunnel)");
    }
    // macOS: DNS is handled by scutil, more complex — skip for now
    Ok(())
}

/// Restore original DNS
pub fn teardown_client_dns() {
    if cfg!(target_os = "linux") {
        if let Ok(_) = std::fs::copy("/tmp/yuzu-resolv.conf.bak", "/etc/resolv.conf") {
            info!("DNS restored");
        }
    }
}

/// Bidirectional relay: TUN device <-> framed TLS stream
/// Framing: each IP packet is prefixed with [len: u16 big-endian]
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
        let mut count: u64 = 0;
        loop {
            match dev_reader.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    // Only forward IPv4/IPv6 packets
                    let version = buf[0] >> 4;
                    if version != 4 && version != 6 {
                        debug!("tun→tls: skipping non-IP packet (version byte: {:#04x})", buf[0]);
                        continue;
                    }
                    count += 1;
                    if count <= 3 || count % 1000 == 0 {
                        debug!("tun→tls: {n} bytes (pkt #{count})");
                    }
                    let len = (n as u16).to_be_bytes();
                    if let Err(e) = stream_writer.write_all(&len).await {
                        error!("tun→tls: write len failed: {e}");
                        break;
                    }
                    if let Err(e) = stream_writer.write_all(&buf[..n]).await {
                        error!("tun→tls: write data failed: {e}");
                        break;
                    }
                    if let Err(e) = stream_writer.flush().await {
                        error!("tun→tls: flush failed: {e}");
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
        let mut count: u64 = 0;
        loop {
            let len = match stream_reader.read_u16().await {
                Ok(l) => l as usize,
                Err(e) => {
                    error!("tls→tun: read len failed: {e}");
                    break;
                }
            };
            if len == 0 || len > 65535 {
                error!("tls→tun: invalid len {len}");
                break;
            }
            if let Err(e) = stream_reader.read_exact(&mut buf[..len]).await {
                error!("tls→tun: read data failed: {e}");
                break;
            }
            count += 1;
            if count <= 3 || count % 1000 == 0 {
                debug!("tls→tun: {len} bytes (pkt #{count})");
            }
            if let Err(e) = dev_writer.send(&buf[..len]).await {
                error!("tls→tun: TUN write failed: {e}");
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
