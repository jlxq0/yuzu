use anyhow::{bail, Context, Result};
use std::path::Path;

/// Secret is always 64 hex chars (32 bytes = 256 bits)
pub const SECRET_LEN: usize = 64;

/// Generate a new random secret (64 hex chars)
pub fn generate_secret() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
