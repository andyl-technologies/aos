//! Native cloud metadata fetchers.
//!
//! Each implementation owns only its provider's endpoint, required headers,
//! and payload encoding. Returned bytes remain uninterpreted until the common
//! initrd authorization phase.

use anyhow::{Context, Result};
use base64::Engine;

use super::fetcher::{Facts, PlatformFetcher, StaticNetwork, UserData};
use super::http::MetadataHttp;

const LINK_LOCAL_BASE: &str = "http://169.254.169.254";

/// A local platform with no standardized metadata channel.
pub struct NoMetadataFetcher {
    platform_id: &'static str,
}

impl NoMetadataFetcher {
    /// Create a fetcher that explicitly reports no attached user-data.
    pub fn new(platform_id: &'static str) -> Self {
        Self { platform_id }
    }
}

#[async_trait::async_trait]
impl PlatformFetcher for NoMetadataFetcher {
    fn platform_id(&self) -> &'static str {
        self.platform_id
    }

    async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        Ok(None)
    }

    async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
        Ok(Facts::default())
    }
}

async fn plain_user_data(
    http: &dyn MetadataHttp,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Option<UserData>> {
    let response = http
        .get(url, headers)
        .await
        .with_context(|| format!("fetching user-data from {url}"))?;
    if response.status == 404 {
        return Ok(None);
    }
    Ok(response
        .into_ok_body()
        .map(|payload| UserData::Inline { payload, sig: None }))
}

async fn optional_text(
    http: &dyn MetadataHttp,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Option<String>> {
    let response = http
        .get(url, headers)
        .await
        .with_context(|| format!("fetching metadata from {url}"))?;
    if response.status == 404 {
        return Ok(None);
    }
    Ok(response.into_ok_string())
}

async fn optional_lines(
    http: &dyn MetadataHttp,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<Vec<String>> {
    Ok(optional_text(http, url, headers)
        .await?
        .map(|body| {
            body.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default())
}

/// Google Compute Engine metadata fetcher.
#[derive(Default)]
pub struct GcpFetcher;

#[async_trait::async_trait]
impl PlatformFetcher for GcpFetcher {
    fn platform_id(&self) -> &'static str {
        "gcp"
    }

    async fn fetch_user_data(&self, http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        plain_user_data(
            http,
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/user-data",
            &[("Metadata-Flavor", "Google")],
        )
        .await
    }

    async fn fetch_facts(&self, http: &dyn MetadataHttp) -> Result<Facts> {
        let headers = [("Metadata-Flavor", "Google")];
        let base = "http://metadata.google.internal/computeMetadata/v1/instance";
        let zone = optional_text(http, &format!("{base}/zone"), &headers).await?;
        Ok(Facts {
            hostname: optional_text(http, &format!("{base}/hostname"), &headers).await?,
            instance_id: optional_text(http, &format!("{base}/id"), &headers).await?,
            availability_zone: zone
                .as_deref()
                .and_then(|value| value.rsplit('/').next())
                .map(str::to_string),
            region: zone
                .as_deref()
                .and_then(|value| value.rsplit('/').next())
                .and_then(|value| value.rsplit_once('-').map(|(region, _)| region.to_string())),
            ..Default::default()
        })
    }
}

/// Microsoft Azure IMDS fetcher.
#[derive(Default)]
pub struct AzureFetcher;

#[async_trait::async_trait]
impl PlatformFetcher for AzureFetcher {
    fn platform_id(&self) -> &'static str {
        "azure"
    }

    async fn fetch_user_data(&self, http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        let url = format!(
            "{LINK_LOCAL_BASE}/metadata/instance/compute/userData?api-version=2021-02-01&format=text"
        );
        let response = http
            .get(&url, &[("Metadata", "true")])
            .await
            .context("fetching Azure user-data")?;
        if response.status == 404 {
            return Ok(None);
        }
        let Some(encoded) = response.into_ok_body() else {
            return Ok(None);
        };
        let payload = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("decoding Azure base64 user-data")?;
        Ok(Some(UserData::Inline { payload, sig: None }))
    }

    async fn fetch_facts(&self, http: &dyn MetadataHttp) -> Result<Facts> {
        let base = format!(
            "{LINK_LOCAL_BASE}/metadata/instance/compute?api-version=2021-02-01&format=text"
        );
        Ok(Facts {
            hostname: optional_text(
                http,
                &base.replace("/compute?", "/compute/name?"),
                &[("Metadata", "true")],
            )
            .await?,
            ..Default::default()
        })
    }
}

/// DigitalOcean metadata fetcher.
#[derive(Default)]
pub struct DigitalOceanFetcher;

#[async_trait::async_trait]
impl PlatformFetcher for DigitalOceanFetcher {
    fn platform_id(&self) -> &'static str {
        "digitalocean"
    }

    async fn fetch_user_data(&self, http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        plain_user_data(
            http,
            &format!("{LINK_LOCAL_BASE}/metadata/v1/user-data"),
            &[],
        )
        .await
    }

    async fn fetch_facts(&self, http: &dyn MetadataHttp) -> Result<Facts> {
        let base = format!("{LINK_LOCAL_BASE}/metadata/v1");
        let interface = format!("{base}/interfaces/public/0");
        let address = optional_text(http, &format!("{interface}/ipv4/address"), &[]).await?;
        let netmask = optional_text(http, &format!("{interface}/ipv4/netmask"), &[]).await?;
        let gateway = optional_text(http, &format!("{interface}/ipv4/gateway"), &[]).await?;
        let anchor_address =
            optional_text(http, &format!("{interface}/anchor_ipv4/address"), &[]).await?;
        let anchor_netmask =
            optional_text(http, &format!("{interface}/anchor_ipv4/netmask"), &[]).await?;
        let mac = optional_text(http, &format!("{interface}/mac"), &[]).await?;
        let dns = optional_lines(http, &format!("{base}/dns/nameservers"), &[]).await?;

        let mut network = StaticNetwork {
            mac: mac.map(|value| value.to_lowercase()),
            gateway,
            dns,
            ..StaticNetwork::default()
        };
        if let Some(address) = address {
            network
                .addresses
                .push(with_netmask(&address, netmask.as_deref()));
        }
        if let Some(address) = anchor_address {
            network
                .addresses
                .push(with_netmask(&address, anchor_netmask.as_deref()));
        }

        Ok(Facts {
            hostname: optional_text(http, &format!("{base}/hostname"), &[]).await?,
            instance_id: optional_text(http, &format!("{base}/id"), &[]).await?,
            region: optional_text(http, &format!("{base}/region"), &[]).await?,
            network: network.is_seedable().then_some(network),
            ..Default::default()
        })
    }
}

/// OpenStack link-local metadata fetcher.
#[derive(Default)]
pub struct OpenStackImdsFetcher;

#[async_trait::async_trait]
impl PlatformFetcher for OpenStackImdsFetcher {
    fn platform_id(&self) -> &'static str {
        "openstack"
    }

    async fn fetch_user_data(&self, http: &dyn MetadataHttp) -> Result<Option<UserData>> {
        plain_user_data(
            http,
            &format!("{LINK_LOCAL_BASE}/openstack/latest/user_data"),
            &[],
        )
        .await
    }

    async fn fetch_facts(&self, http: &dyn MetadataHttp) -> Result<Facts> {
        let url = format!("{LINK_LOCAL_BASE}/openstack/latest/meta_data.json");
        let Some(body) = http
            .get(&url, &[])
            .await
            .context("fetching OpenStack metadata")?
            .into_ok_body()
        else {
            return Ok(Facts::default());
        };
        #[derive(serde::Deserialize)]
        struct Meta {
            hostname: Option<String>,
            uuid: Option<String>,
        }
        let meta: Meta = serde_json::from_slice(&body).context("parsing OpenStack metadata")?;
        let network = http
            .get(
                &format!("{LINK_LOCAL_BASE}/openstack/latest/network_data.json"),
                &[],
            )
            .await
            .context("fetching OpenStack network data")?
            .into_ok_body()
            .map(|body| super::staticnet::parse_openstack_network_data(&body))
            .transpose()?;
        Ok(Facts {
            hostname: meta.hostname,
            instance_id: meta.uuid,
            network: network.filter(StaticNetwork::is_seedable),
            ..Default::default()
        })
    }
}

fn with_netmask(address: &str, netmask: Option<&str>) -> String {
    match netmask {
        Some(netmask) if !address.contains('/') => {
            format!("{address}/{}", super::staticnet::netmask_to_prefix(netmask))
        }
        _ => address.to_string(),
    }
}
