use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tracing::debug;

/// DNS provider trait for ACME DNS-01 challenges
pub trait DnsProvider: Send + Sync {
    /// Create a TXT record, return an opaque record ID for cleanup
    fn create_txt(
        &self,
        name: &str,
        value: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;

    /// Delete a previously created record by ID
    fn delete_record(
        &self,
        record_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

// ─── Bunny.net ─────────────────────────────────────────────────

pub struct BunnyDns {
    client: Client,
    api_key: String,
    zone_id: u64,
}

impl BunnyDns {
    pub fn new(api_key: String, zone_id: u64) -> Self {
        Self {
            client: Client::new(),
            api_key,
            zone_id,
        }
    }

    /// Look up the zone ID by domain name
    pub async fn find_zone_id(api_key: &str, domain: &str) -> Result<u64> {
        #[derive(Deserialize)]
        struct Zone {
            #[serde(rename = "Id")]
            id: u64,
            #[serde(rename = "Domain")]
            domain: String,
        }
        #[derive(Deserialize)]
        struct ZoneList {
            #[serde(rename = "Items")]
            items: Vec<Zone>,
        }

        let client = Client::new();
        let resp: ZoneList = client
            .get("https://api.bunny.net/dnszone")
            .header("AccessKey", api_key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        resp.items
            .iter()
            .find(|z| domain == z.domain || domain.ends_with(&format!(".{}", z.domain)))
            .map(|z| z.id)
            .context(format!("no Bunny DNS zone found for {domain}"))
    }
}

impl DnsProvider for BunnyDns {
    async fn create_txt(&self, name: &str, value: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Record {
            #[serde(rename = "Id")]
            id: u64,
        }

        debug!("bunny: creating TXT {name} = {value}");
        let resp: Record = self
            .client
            .put(format!(
                "https://api.bunny.net/dnszone/{}/records",
                self.zone_id
            ))
            .header("AccessKey", &self.api_key)
            .json(&serde_json::json!({
                "Type": 3,
                "Name": name,
                "Value": value,
                "Ttl": 300
            }))
            .send()
            .await?
            .error_for_status()
            .context("bunny: create TXT record")?
            .json()
            .await?;

        Ok(resp.id.to_string())
    }

    async fn delete_record(&self, record_id: &str) -> Result<()> {
        let id: u64 = record_id.parse()?;
        debug!("bunny: deleting record {id}");
        self.client
            .delete(format!(
                "https://api.bunny.net/dnszone/{}/records/{id}",
                self.zone_id
            ))
            .header("AccessKey", &self.api_key)
            .send()
            .await?
            .error_for_status()
            .context("bunny: delete record")?;
        Ok(())
    }
}

// ─── Cloudflare ────────────────────────────────────────────────

pub struct CloudflareDns {
    client: Client,
    api_token: String,
    zone_id: String,
}

impl CloudflareDns {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
        }
    }

    /// Look up the zone ID by domain name
    pub async fn find_zone_id(api_token: &str, domain: &str) -> Result<String> {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Zone {
            id: String,
            name: String,
        }
        #[derive(Deserialize)]
        struct CfResp {
            result: Vec<Zone>,
        }

        let client = Client::new();
        let resp: CfResp = client
            .get("https://api.cloudflare.com/client/v4/zones")
            .bearer_auth(api_token)
            .query(&[("name", domain)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        resp.result
            .into_iter()
            .next()
            .map(|z| z.id)
            .context(format!("no Cloudflare zone found for {domain}"))
    }
}

impl DnsProvider for CloudflareDns {
    async fn create_txt(&self, name: &str, value: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct CfResp {
            result: CfRecord,
        }
        #[derive(Deserialize)]
        struct CfRecord {
            id: String,
        }

        debug!("cloudflare: creating TXT {name} = {value}");
        let resp: CfResp = self
            .client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": 120
            }))
            .send()
            .await?
            .error_for_status()
            .context("cloudflare: create TXT record")?
            .json()
            .await?;

        Ok(resp.result.id)
    }

    async fn delete_record(&self, record_id: &str) -> Result<()> {
        debug!("cloudflare: deleting record {record_id}");
        self.client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{record_id}",
                self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()
            .context("cloudflare: delete record")?;
        Ok(())
    }
}
