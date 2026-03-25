use anyhow::{bail, Context, Result};
use std::path::Path;

/// Secret is always 64 hex chars (32 bytes = 256 bits)
pub const SECRET_LEN: usize = 64;

/// Generate a new random secret (64 hex chars)
pub fn generate_secret() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(&bytes)
}

/// Load and validate secret from file
pub fn load_secret(path: &Path) -> Result<Vec<u8>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading secret from {}", path.display()))?;
    let secret = content.trim();
    if secret.len() != SECRET_LEN {
        bail!(
            "secret must be {} hex chars, got {}",
            SECRET_LEN,
            secret.len()
        );
    }
    Ok(secret.as_bytes().to_vec())
}

/// Frame types for the tunnel protocol
#[repr(u8)]
pub enum FrameType {
    /// TCP connect request: [domain_len: u8, domain: bytes, port: u16be]
    Connect = 0x01,
    /// TCP data
    Data = 0x02,
    /// Connection close
    Close = 0x03,
    /// UDP packet: [addr_len: u8, addr: bytes, port: u16be, data]
    UdpPacket = 0x04,
    /// DNS query (tunneled)
    DnsQuery = 0x05,
    /// DNS response
    DnsResponse = 0x06,
    /// Keepalive / padding
    Ping = 0x07,
}

fn hex_encode(_bytes: &[u8]) -> String {
    _bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// We'll add hex as a dependency, but for now inline it
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
