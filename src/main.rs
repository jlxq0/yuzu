use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod acme;
mod camouflage;
mod client;
mod protocol;
mod server;
mod transport;

#[derive(Parser)]
#[command(name = "yuzu", version, about = "Anti-censorship tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose logging (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Clone, ValueEnum)]
enum DnsProviderType {
    Bunny,
    Cloudflare,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as tunnel server
    Server {
        /// Listen address
        #[arg(short, long, default_value = "0.0.0.0:443")]
        listen: String,

        /// Domain name (for TLS cert and cover site)
        #[arg(short, long)]
        domain: String,

        /// Path to shared secret file (64 hex chars)
        #[arg(short, long)]
        secret: PathBuf,

        /// TLS certificate file (PEM). If omitted, uses ACME (Let's Encrypt).
        #[arg(long)]
        cert: Option<PathBuf>,

        /// TLS private key file (PEM). If omitted, uses ACME (Let's Encrypt).
        #[arg(long)]
        key: Option<PathBuf>,

        /// DNS provider for ACME challenges
        #[arg(long, value_enum)]
        acme_dns: Option<DnsProviderType>,

        /// DNS provider API token (or set BUNNY_API_KEY / CLOUDFLARE_API_TOKEN)
        #[arg(long)]
        acme_dns_token: Option<String>,

        /// Use Let's Encrypt staging (for testing)
        #[arg(long)]
        acme_staging: bool,

        /// Directory to store ACME state (account, certs)
        #[arg(long, default_value = "~/.yuzu")]
        acme_dir: String,
    },

    /// Run as tunnel client
    Client {
        /// Server address (domain:port)
        #[arg(long)]
        server: String,

        /// Path to shared secret file (64 hex chars)
        #[arg(long)]
        secret: PathBuf,

        /// Local SOCKS5 proxy port
        #[arg(long, default_value = "1080")]
        socks_port: u16,

        /// Enable traffic camouflage (decoy HTTPS requests)
        #[arg(long)]
        camouflage: bool,

        /// Tunnel DNS through the connection
        #[arg(long)]
        tunnel_dns: bool,
    },

    /// Generate a new shared secret
    Secret,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "yuzu=info",
        1 => "yuzu=debug",
        _ => "yuzu=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    match cli.command {
        Commands::Server {
            listen,
            domain,
            secret,
            cert,
            key,
            acme_dns,
            acme_dns_token,
            acme_staging,
            acme_dir,
        } => {
            // Resolve cert + key: either provided or via ACME
            let (cert_path, key_path) = match (cert, key) {
                (Some(c), Some(k)) => (c, k),
                (None, None) => {
                    // ACME mode
                    let dir = acme_dir.replace('~', &std::env::var("HOME")?);
                    let state = acme::AcmeState::new(std::path::Path::new(&dir));

                    if state.has_valid_cert(&domain) {
                        tracing::info!("using existing certificate");
                        (state.cert_path(&domain), state.key_path(&domain))
                    } else {
                        let dns_type = acme_dns.unwrap_or_else(|| {
                            // Try to auto-detect from env vars
                            if std::env::var("BUNNY_API_KEY").is_ok() {
                                DnsProviderType::Bunny
                            } else {
                                DnsProviderType::Cloudflare
                            }
                        });

                        match dns_type {
                            DnsProviderType::Bunny => {
                                let token = acme_dns_token
                                    .or_else(|| std::env::var("BUNNY_API_KEY").ok())
                                    .expect("BUNNY_API_KEY or --acme-dns-token required");
                                let zone_id =
                                    acme::dns::BunnyDns::find_zone_id(&token, &domain).await?;
                                let dns = acme::dns::BunnyDns::new(token, zone_id);
                                acme::provision(&domain, &state, &dns, acme_staging).await?
                            }
                            DnsProviderType::Cloudflare => {
                                let token = acme_dns_token
                                    .or_else(|| std::env::var("CLOUDFLARE_API_TOKEN").ok())
                                    .expect(
                                        "CLOUDFLARE_API_TOKEN or --acme-dns-token required",
                                    );
                                let zone_id =
                                    acme::dns::CloudflareDns::find_zone_id(&token, &domain)
                                        .await?;
                                let dns = acme::dns::CloudflareDns::new(token, zone_id);
                                acme::provision(&domain, &state, &dns, acme_staging).await?
                            }
                        }
                    }
                }
                _ => bail!("provide both --cert and --key, or neither (for ACME)"),
            };

            server::run(&listen, &domain, &secret, &cert_path, &key_path).await?;
        }
        Commands::Client {
            server,
            secret,
            socks_port,
            camouflage,
            tunnel_dns,
        } => {
            client::run(&server, &secret, socks_port, camouflage, tunnel_dns).await?;
        }
        Commands::Secret => {
            let secret = protocol::generate_secret();
            println!("{secret}");
        }
    }

    Ok(())
}
