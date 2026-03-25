use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

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

        /// TLS certificate file (PEM)
        #[arg(long)]
        cert: PathBuf,

        /// TLS private key file (PEM)
        #[arg(long)]
        key: PathBuf,
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
        } => {
            server::run(&listen, &domain, &secret, &cert, &key).await?;
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
