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
mod tunnel;

#[derive(Parser)]
#[command(name = "yuzu", version, about = "Anti-censorship tunnel. All traffic over TLS on 443.")]
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

    /// Run as tunnel client (creates TUN interface, routes all traffic)
    Client {
        /// Server address (domain:port)
        #[arg(long)]
        server: String,

        /// Path to shared secret file (64 hex chars)
        #[arg(long)]
        secret: PathBuf,

        /// Enable traffic camouflage (decoy HTTPS requests)
        #[arg(long)]
        camouflage: bool,

        /// Skip TLS certificate verification (for self-signed certs)
        #[arg(long)]
        insecure: bool,
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
            let (cert_path, key_path) = resolve_certs(
                cert,
                key,
                &domain,
                acme_dns,
                acme_dns_token,
                acme_staging,
                &acme_dir,
            )
            .await?;

            let config = server::ServerConfig {
                listen,
                domain,
                secret_path: secret,
                cert_path,
                key_path,
            };
            server::run(config).await?;
        }
        Commands::Client {
            server,
            secret,
            camouflage,
            insecure,
        } => {
            client::run(&server, &secret, camouflage, insecure).await?;
        }
        Commands::Secret => {
            let secret = protocol::generate_secret();
            println!("{secret}");
        }
    }

    Ok(())
}

async fn resolve_certs(
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    domain: &str,
    acme_dns: Option<DnsProviderType>,
    acme_dns_token: Option<String>,
    acme_staging: bool,
    acme_dir: &str,
) -> Result<(PathBuf, PathBuf)> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok((c, k)),
        (None, None) => {
            let dir = acme_dir.replace('~', &std::env::var("HOME")?);
            let state = acme::AcmeState::new(std::path::Path::new(&dir));

            if state.has_valid_cert(domain) {
                tracing::info!("using existing certificate");
                Ok((state.cert_path(domain), state.key_path(domain)))
            } else {
                let dns_type = acme_dns.unwrap_or_else(|| {
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
                            acme::dns::BunnyDns::find_zone_id(&token, domain).await?;
                        let dns = acme::dns::BunnyDns::new(token, zone_id);
                        acme::provision(domain, &state, &dns, acme_staging).await
                    }
                    DnsProviderType::Cloudflare => {
                        let token = acme_dns_token
                            .or_else(|| std::env::var("CLOUDFLARE_API_TOKEN").ok())
                            .expect("CLOUDFLARE_API_TOKEN or --acme-dns-token required");
                        let zone_id =
                            acme::dns::CloudflareDns::find_zone_id(&token, domain).await?;
                        let dns = acme::dns::CloudflareDns::new(token, zone_id);
                        acme::provision(domain, &state, &dns, acme_staging).await
                    }
                }
            }
        }
        _ => bail!("provide both --cert and --key, or neither (for ACME)"),
    }
}
