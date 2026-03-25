use rand::Rng;
use tracing::{debug, warn};

/// URLs that generate realistic-looking HTTPS traffic
const DECOY_URLS: &[&str] = &[
    "https://www.google.com/generate_204",
    "https://www.wikipedia.org/",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
    "https://www.amazon.com/",
    "https://news.ycombinator.com/",
    "https://www.bbc.com/",
    "https://www.reuters.com/",
    "https://www.github.com/",
    "https://stackoverflow.com/",
    "https://weather.com/",
    "https://www.nytimes.com/",
    "https://www.reddit.com/",
    "https://www.cloudflare.com/",
    "https://www.youtube.com/",
];

/// Run background decoy HTTPS traffic to blend in
pub async fn run_decoy_traffic(_server_host: &str) {
    debug!("camouflage: starting decoy traffic");

    let client = match reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("camouflage: failed to create HTTP client: {e}");
            return;
        }
    };

    loop {
        // Random interval between 5-30 seconds
        let delay = rand::rng().random_range(5..30);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

        // Pick a random URL
        let url = DECOY_URLS[rand::rng().random_range(0..DECOY_URLS.len())];

        // Make a real HTTPS request (generates real TLS traffic on the wire)
        match client.get(url).send().await {
            Ok(resp) => {
                // Read some of the body to generate realistic traffic
                let _ = resp.bytes().await;
                debug!("camouflage: fetched {url}");
            }
            Err(e) => {
                debug!("camouflage: {url} failed: {e}");
            }
        }
    }
}
