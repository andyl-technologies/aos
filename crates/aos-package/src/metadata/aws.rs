//! The AWS IMDSv2 [`PlatformFetcher`] — the cloud exemplar.
//!
//! GCP, Azure, DigitalOcean, and OpenStack IMDS fetchers follow the same shape
//! with provider-specific endpoints, headers, and encodings in
//! [`crate::metadata::cloud`].
//!
//! # IMDSv2 token dance (mandatory)
//!
//! ```text
//! PUT  http://169.254.169.254/latest/api/token
//!        X-aws-ec2-metadata-token-ttl-seconds: 21600
//!   -> <token>
//! GET  http://169.254.169.254/latest/<path>
//!        X-aws-ec2-metadata-token: <token>
//! ```
//!
//! `fetch_user_data` GETs `/latest/user-data`: HTTP 200 is the literal
//! complete provisioning input (or a pointer JSON, resolved with a
//! content-pin); HTTP 404 means
//! no user-data attached (`Ok(None)`, *not* an error). `fetch_facts` reads
//! `instance-id`, `placement/{region,availability-zone}`, `local-hostname`,
//! the `public-keys/<i>/openssh-key` list, and the `network/interfaces/macs/`
//! tree.

use anyhow::{Context, Result};

use super::fetcher::{Facts, MacIface, PlatformFetcher, PointerDoc, UserData};
use super::http::MetadataHttp;

/// IMDS link-local base URL (plain HTTP).
pub const IMDS_BASE: &str = "http://169.254.169.254";
/// IMDSv2 token TTL, in seconds (6h).
pub const TOKEN_TTL_SECS: &str = "21600";
/// Header carrying the token TTL on the PUT request.
pub const TOKEN_TTL_HEADER: &str = "X-aws-ec2-metadata-token-ttl-seconds";
/// Header carrying the session token on every GET.
pub const TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";

/// The AWS IMDSv2 fetcher.
pub struct AwsImdsFetcher {
    base: String,
}

impl Default for AwsImdsFetcher {
    fn default() -> Self {
        Self {
            base: IMDS_BASE.to_string(),
        }
    }
}

impl AwsImdsFetcher {
    /// Use a custom base URL (tests point this at a recorded fixture origin).
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into() }
    }

    /// Run the mandatory IMDSv2 token PUT and return the session token.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the PUT fails or returns an empty body.
    async fn token(&self, http: &dyn MetadataHttp) -> Result<String> {
        let url = format!("{}/latest/api/token", self.base);
        let resp = http
            .put(&url, Vec::new(), &[(TOKEN_TTL_HEADER, TOKEN_TTL_SECS)])
            .await
            .context("IMDSv2 token PUT")?;
        resp.into_ok_string()
            .filter(|s| !s.is_empty())
            .context("IMDSv2 token: empty body")
    }

    /// GET a metadata path under `/latest/`, returning `None` on 404.
    async fn get_meta(
        &self,
        http: &dyn MetadataHttp,
        token: &str,
        path: &str,
    ) -> Result<Option<String>> {
        let url = format!("{}/latest/{path}", self.base);
        let resp = http
            .get(&url, &[(TOKEN_HEADER, token)])
            .await
            .with_context(|| format!("IMDS GET {path}"))?;
        if resp.status == 404 {
            return Ok(None);
        }
        Ok(resp.into_ok_string())
    }
}

#[async_trait::async_trait]
impl PlatformFetcher for AwsImdsFetcher {
    fn platform_id(&self) -> &'static str {
        "aws"
    }

    async fn fetch_user_data(&self, http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        let token = self.token(http).await?;
        let url = format!("{}/latest/user-data", self.base);
        let resp = http
            .get(&url, &[(TOKEN_HEADER, &token)])
            .await
            .context("IMDS GET /latest/user-data")?;
        if resp.status == 404 {
            // No user-data attached — a valid, non-error state.
            return Ok(None);
        }
        let Some(body) = resp.into_ok_body() else {
            return Ok(None);
        };
        // A pointer doc (the 16 KB cap escape hatch) parses as JSON; anything
        // else is the literal host.nix.
        if let Ok(ptr) = serde_json::from_slice::<PointerDoc>(&body) {
            return Ok(Some(UserData::Pointer(ptr)));
        }
        Ok(Some(UserData::Inline {
            payload: body,
            sig: None,
        }))
    }

    async fn fetch_facts(&self, http: &dyn MetadataHttp) -> Result<Facts> {
        let token = self.token(http).await?;
        let mut facts = Facts {
            instance_id: self.get_meta(http, &token, "meta-data/instance-id").await?,
            region: self
                .get_meta(http, &token, "meta-data/placement/region")
                .await?,
            availability_zone: self
                .get_meta(http, &token, "meta-data/placement/availability-zone")
                .await?,
            hostname: self
                .get_meta(http, &token, "meta-data/local-hostname")
                .await?,
            ..Default::default()
        };

        // public-keys/<i>/openssh-key — the listing is `<i>=<name>` lines;
        // iterate indices found in the listing.
        if let Some(listing) = self
            .get_meta(http, &token, "meta-data/public-keys/")
            .await?
        {
            for line in listing.lines() {
                let idx = line.split('=').next().unwrap_or(line).trim();
                if idx.is_empty() {
                    continue;
                }
                let path = format!("meta-data/public-keys/{idx}/openssh-key");
                if let Some(key) = self.get_meta(http, &token, &path).await? {
                    facts.ssh_authorized_keys.push(key.trim().to_string());
                }
            }
        }

        // network/interfaces/macs/<mac>/ listing → mac map. AWS provides DHCP,
        // so the interface name is the platform's; we record the MAC and leave
        // iface as the device-index hint the renderer can Match on.
        if let Some(listing) = self
            .get_meta(http, &token, "meta-data/network/interfaces/macs/")
            .await?
        {
            for line in listing.lines() {
                let mac = line.trim().trim_end_matches('/').to_lowercase();
                if mac.is_empty() {
                    continue;
                }
                let idx_path = format!("meta-data/network/interfaces/macs/{mac}/device-number");
                let iface = self
                    .get_meta(http, &token, &idx_path)
                    .await?
                    .map(|n| format!("eth{}", n.trim()))
                    .unwrap_or_default();
                facts.mac_to_iface.push(MacIface { mac, iface });
            }
        }

        Ok(facts)
    }
}
