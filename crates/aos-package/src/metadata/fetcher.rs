//! The [`PlatformFetcher`] trait and the normalized data it produces.
//!
//! A fetcher encodes one platform's documented user-data + instance-metadata
//! contract (endpoint paths, required headers, payload encoding, facts
//! locations) over the shared HTTP surface ([`crate::metadata::http`]). It is
//! the only seam the dispatcher knows about; selection is by `PLATFORM_ID`
//! from `detect`.
//!
//! # Trust boundary
//!
//! Everything a fetcher returns is untrusted. [`UserData`] bytes are stashed
//! verbatim; the following initrd authorization phase owns the trust decision.
//! A fetcher must never promote a [`Facts`] field into a security decision.
//!
//! # Data shapes
//!
//! - [`UserData`] — literal `host.nix`, or a size-cap transport pointer to the
//!   exact `host.nix` bytes.
//! - [`Facts`] — normalized, unauthenticated instance facts rendered to
//!   `host-facts.nix` as `host.facts.*` ([`crate::metadata::facts_render`]).
//! - [`StaticNetwork`] — the parsed DHCP-less network config seeded into
//!   networkd ([`crate::metadata::staticnet`]).

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use super::http::MetadataHttp;

/// A cross-cloud user-data + instance-metadata acquisition strategy.
///
/// Implementors encode one platform's documented contract over the shared
/// [`MetadataHttp`] surface (or, for offline channels, a mounted directory).
/// The dispatcher selects one by `PLATFORM_ID` and calls
/// [`fetch_user_data`](PlatformFetcher::fetch_user_data) then
/// [`fetch_facts`](PlatformFetcher::fetch_facts).
///
/// The trait takes `&dyn MetadataHttp` rather than the concrete
/// `aos_net::TransferEngine` named in the build spec so the cloud fetchers are
/// unit-testable against recorded fixtures with no live network; the
/// production adapter ([`super::http::EngineHttp`]) wraps a real
/// `TransferEngine` plus the `tokio::time::timeout` shim.
#[async_trait::async_trait]
pub trait PlatformFetcher: Send + Sync {
    /// Stable platform identifier, matching `PLATFORM_ID` in `platform.env`
    /// (e.g. `"aws"`, `"nocloud"`, `"config-drive"`, `"qemu"`,
    /// `"aos-metadata"`).
    fn platform_id(&self) -> &'static str;

    /// Acquire the operator user-data payload, if present.
    ///
    /// Returns `Ok(None)` when the platform has no user-data attached — a
    /// valid, non-error state that resolves to gen-0-only config.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on transport failure after retries are exhausted, or
    /// when a required local file is unreadable. Acquisition never authorizes
    /// the returned bytes.
    async fn fetch_user_data(&self, http: &dyn MetadataHttp) -> Result<Option<UserData>>;

    /// Acquire normalized instance facts.
    ///
    /// Facts are recorded-but-unauthenticated (`facts_hash` in the manifest);
    /// a fetcher must not promote any fact into a security decision. Returns
    /// `Ok(Facts::default())` when the platform exposes no metadata document.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on transport failure after retries are exhausted, or
    /// when a present-but-malformed metadata document cannot be parsed.
    async fn fetch_facts(&self, http: &dyn MetadataHttp) -> Result<Facts>;
}

/// Operator user-data: exact inline `host.nix` bytes or a size-cap pointer.
///
/// The `Pointer` form is the escape hatch for platforms with a small user-data
/// cap (AWS 16 KB): a tiny JSON document naming a `host.nix` URL, its `sha256`
/// content-pin, and an optional detached-signature URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserData {
    /// Exact literal `host.nix` bytes.
    Inline {
        /// Verbatim user-data.
        payload: Vec<u8>,
        /// Detached SSHSIG over the complete payload, if carried separately.
        sig: Option<String>,
    },
    /// A pointer used when user-data exceeds the platform cap. The agent
    /// resolves it: GET `host_nix_url` with `sha256` as a content-pin
    /// (integrity before authenticity), then GET `sig_url` if present.
    Pointer(PointerDoc),
}

/// The JSON transport pointer used when `host.nix` exceeds a platform cap.
///
/// ```json
/// { "host_nix_url": "https://…/host.nix", "sha256": "…", "sig_url": "https://…/host.nix.sig" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerDoc {
    /// URL of the complete literal `host.nix`.
    pub host_nix_url: String,
    /// Lowercase-hex SHA-256 content-pin enforced on the fetch.
    pub sha256: String,
    /// Optional URL of the detached SSHSIG.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_url: Option<String>,
}

/// The concrete operator bytes after a [`UserData`] is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUserData {
    /// Exact user-data bytes.
    pub payload: Vec<u8>,
    /// Detached SSHSIG over `payload`, if present.
    pub sig: Option<String>,
}

impl UserData {
    /// Resolve to concrete bytes, fetching the pointer target if necessary.
    ///
    /// `Inline` is returned as-is. `Pointer` triggers a content-pinned GET of
    /// `host_nix_url` (the pin is enforced by the HTTP surface) and, if
    /// present, a GET of `sig_url`.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the pointer target is unreachable, the content-pin
    /// fails, or the signature URL is set but unreachable.
    pub async fn resolve(self, http: &dyn MetadataHttp) -> Result<ResolvedUserData> {
        match self {
            Self::Inline { payload, sig } => Ok(ResolvedUserData { payload, sig }),
            Self::Pointer(p) => {
                let body = http
                    .get_pinned(&p.host_nix_url, &p.sha256, &[])
                    .await
                    .with_context(|| format!("fetching host.nix pointer {}", p.host_nix_url))?
                    .into_ok_body()
                    .ok_or_else(|| {
                        anyhow!("host.nix pointer {} returned no body", p.host_nix_url)
                    })?;
                let sig = match &p.sig_url {
                    Some(url) => http
                        .get(url, &[])
                        .await
                        .with_context(|| format!("fetching signature pointer {url}"))?
                        .into_ok_body()
                        .and_then(|b| String::from_utf8(b).ok()),
                    None => None,
                };
                Ok(ResolvedUserData { payload: body, sig })
            }
        }
    }
}

/// Normalized, unauthenticated instance facts.
///
/// Rendered to `host-facts.nix` as `host.facts.*`
/// ([`crate::metadata::facts_render`]) and recorded under `facts_hash`. Every
/// field is data the operator's modules may *read*, never an authorization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Facts {
    /// Instance hostname (`local-hostname` / `.hostname`).
    pub hostname: Option<String>,
    /// SSH public keys advertised by the platform. Unauthenticated: never
    /// seeded for gen-0 login (review M-gen0key).
    pub ssh_authorized_keys: Vec<String>,
    /// Opaque platform instance id.
    pub instance_id: Option<String>,
    /// Cloud region, when exposed.
    pub region: Option<String>,
    /// Availability zone, when exposed.
    pub availability_zone: Option<String>,
    /// Stable MAC → kernel interface name pairs, for networkd `Match=`.
    pub mac_to_iface: Vec<MacIface>,
    /// Disk serial / wwn identifiers, for repart device matching.
    pub disk_ids: Vec<String>,
    /// Parsed static network config for DHCP-less clouds. `None` ⇒ the gen-0
    /// DHCP seed suffices.
    pub network: Option<StaticNetwork>,
}

/// One MAC-address-to-interface-name binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacIface {
    /// Lowercase MAC address (`0a:1b:2c:3d:4e:5f`).
    pub mac: String,
    /// Kernel network interface name (`ens5`).
    pub iface: String,
}

/// A parsed DHCP-less network configuration.
///
/// Normalized from OpenStack `network_data.json`, NoCloud netplan
/// `network-config`, or a DigitalOcean IMDS interface document, and rendered
/// to a single `10-aos-seed.network` ([`crate::metadata::staticnet`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticNetwork {
    /// MAC address used in the networkd `[Match]` section. Empty ⇒ match the
    /// first managed link.
    pub mac: Option<String>,
    /// `Address=` entries in CIDR form (`203.0.113.10/24`).
    pub addresses: Vec<String>,
    /// Default gateway, rendered as `Gateway=`.
    pub gateway: Option<String>,
    /// DNS servers, rendered as repeated `DNS=`.
    pub dns: Vec<String>,
}

impl StaticNetwork {
    /// Whether this config carries enough to seed a route (at least one
    /// address).
    pub fn is_seedable(&self) -> bool {
        !self.addresses.is_empty()
    }
}
