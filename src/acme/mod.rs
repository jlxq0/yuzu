pub mod dns;

use anyhow::{bail, Context, Result};
use dns::DnsProvider;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Where to store ACME state (account credentials, certs)
pub struct AcmeState {
    pub dir: PathBuf,
}

impl AcmeState {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
        }
    }

    fn credentials_path(&self) -> PathBuf {
        self.dir.join("acme-account.json")
    }

    pub fn cert_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.pem"))
    }

    pub fn key_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}-key.pem"))
    }

    /// Check if valid cert exists and is not expiring within 30 days
    pub fn has_valid_cert(&self, domain: &str) -> bool {
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);
        if !cert_path.exists() || !key_path.exists() {
            return false;
        }
        // TODO: check expiry with x509-parser
        true
    }
}

/// Provision a TLS certificate via ACME DNS-01 challenge
pub async fn provision<D: DnsProvider>(
    domain: &str,
    state: &AcmeState,
    dns: &D,
    staging: bool,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(&state.dir)?;

    // Get or create ACME account
    let account = get_or_create_account(state, staging).await?;

    info!("requesting certificate for {domain}");

    // Create order
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("creating ACME order")?;

    // Process DNS challenges
    let mut cleanup: Vec<String> = Vec::new();

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("getting authorization")?;
        match authz.status {
            AuthorizationStatus::Valid => {
                debug!("authorization already valid");
                continue;
            }
            AuthorizationStatus::Pending => {}
            other => bail!("unexpected authorization status: {other:?}"),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .context("no DNS-01 challenge offered")?;

        let identifier = challenge.identifier().to_string();
        let txt_name = format!("_acme-challenge.{identifier}");
        let txt_value = challenge.key_authorization().dns_value();

        info!("setting DNS TXT: {txt_name} = {txt_value}");
        let record_id = dns
            .create_txt(&txt_name, &txt_value)
            .await
            .context("creating DNS TXT record")?;
        cleanup.push(record_id);

        // Wait for DNS propagation
        info!("waiting 30s for DNS propagation...");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        // Mark challenge ready
        challenge
            .set_ready()
            .await
            .context("setting challenge ready")?;
        debug!("challenge submitted");
    }

    // Poll until ready
    info!("waiting for ACME validation...");
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("polling order")?;
    if status != OrderStatus::Ready {
        // Clean up DNS records before erroring
        cleanup_dns(&cleanup, dns).await;
        bail!("unexpected order status: {status:?}");
    }

    // Finalize — generates key + CSR
    info!("finalizing order...");
    let private_key_pem = order.finalize().await.context("finalizing order")?;

    // Get certificate
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("getting certificate")?;

    // Clean up DNS records
    cleanup_dns(&cleanup, dns).await;

    // Save cert and key
    let cert_path = state.cert_path(domain);
    let key_path = state.key_path(domain);
    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &private_key_pem)?;

    info!("certificate saved to {}", cert_path.display());
    info!("private key saved to {}", key_path.display());

    Ok((cert_path, key_path))
}

async fn get_or_create_account(state: &AcmeState, staging: bool) -> Result<Account> {
    let creds_path = state.credentials_path();
    let url = if staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    if creds_path.exists() {
        debug!("loading existing ACME account from {}", creds_path.display());
        let json = std::fs::read_to_string(&creds_path)?;
        let credentials: AccountCredentials = serde_json::from_str(&json)?;
        let account = Account::builder()?.from_credentials(credentials).await?;
        return Ok(account);
    }

    info!("creating new ACME account");
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url.to_owned(),
            None,
        )
        .await
        .context("creating ACME account")?;

    let json = serde_json::to_string_pretty(&credentials)?;
    std::fs::write(&creds_path, &json)?;
    debug!("saved ACME credentials to {}", creds_path.display());

    Ok(account)
}

async fn cleanup_dns<D: DnsProvider>(record_ids: &[String], dns: &D) {
    for id in record_ids {
        if let Err(e) = dns.delete_record(id).await {
            warn!("failed to clean up DNS record {id}: {e}");
        }
    }
}

/// Background task: check cert expiry and renew if needed
#[allow(dead_code)]
pub async fn renewal_loop<D: DnsProvider>(
    domain: String,
    _state: AcmeState,
    _dns: D,
    _staging: bool,
) {
    loop {
        // Check every 12 hours
        tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;

        // TODO: actually parse cert and check expiry
        // For now, just log
        debug!("renewal check for {domain}");
    }
}
