//! The `aos metadata` agent for fetching host configuration and instance facts.
//!
//! Package-owned provider methods own cross-cloud acquisition and the narrow
//! first-boot trust boundary. They keep untrusted acquisition bytes in private
//! transaction scratch, publish authorized values through typed operation
//! results, and retain recovery input through content-addressed resources.
//!
//! # Module map
//!
//! - [`detect`] — the DMI decision table and config-drive probe.
//! - [`fetcher`] — the [`PlatformFetcher`] trait and the normalized
//!   [`UserData`] / [`Facts`] / [`StaticNetwork`] it produces.
//! - [`http`] — the [`MetadataHttp`] surface: the `TransferEngine`-backed
//!   adapter (with the `tokio::time::timeout` shim) and the recorded mock.
//! - [`mount`] — the config-drive mount helper (`blkid -L` + `mount -o ro`),
//!   behind a mockable trait.
//! - [`offline`] — the offline fetchers (aos-metadata ISO, NoCloud,
//!   config-drive, qemu fw_cfg).
//! - [`aws`] — AWS IMDSv2; [`cloud`] — the other native cloud fetchers.
//! - [`staticnet`] — DHCP-less network parsing + networkd render.
//! - [`facts_render`] — `facts.json` → `host-facts.nix`.
//! - [`policy`] — whole-input authorization and typed handoff to configuration
//!   evaluation.
//! - [`trust`] — configuration signature authentication.
//!
//! # Testability
//!
//! Every system surface — DMI sysfs, `blkid`/`mount`, the HTTP/IMDS client — is
//! behind a trait or a path parameter, so the whole agent is unit-tested with
//! fixtures. Real block-device probing and live metadata services remain
//! integration-tested by the selected provider package.

pub mod aws;
pub mod cloud;
pub mod detect;
pub mod executable;
pub mod facts_render;
pub mod fetcher;
pub mod http;
pub mod mount;
pub mod offline;
pub mod policy;
pub mod provider;
pub mod staticnet;
pub mod trust;
mod yaml;

#[cfg(test)]
mod tests;

use anyhow::{Context, Result};

pub use detect::{
    AcquisitionContext, PlatformCapability, PlatformId, classify_dmi, needs_network,
    platform_capability,
};
pub use facts_render::render_host_facts_nix;
pub use facts_render::{canonicalize_host_facts, normalize_host_facts};
pub use fetcher::{Facts, PlatformFetcher, StaticNetwork, UserData};
pub use http::{EngineHttp, MetadataHttp};
pub use mount::{BlkidProbe, ConfigDriveProbe};

use aos_net::transfer::{TransferEngine, TransferEngineConfig};
use serde::{Deserialize, Serialize};

/// The platform result published by the selected detector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectedPlatform {
    /// The stable result schema.
    pub schema: String,
    /// The package-owned platform identifier.
    pub platform_id: String,
    /// Whether acquisition requires early network readiness.
    pub need_network: bool,
}

/// Untrusted metadata bytes and normalized facts returned by acquisition.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquiredMetadata {
    /// The stable result schema.
    pub schema: String,
    /// The platform that supplied the data.
    pub platform_id: String,
    /// Exact operator module bytes, when supplied by the platform.
    pub host_module: Option<String>,
    /// Detached signature over the exact module bytes, when supplied.
    pub host_module_signature: Option<String>,
    /// Normalized observational instance facts.
    pub facts: Facts,
}

/// Exact metadata payloads returned by one platform acquisition.
#[derive(Clone, Debug, PartialEq)]
pub struct FetchedMetadata {
    /// Exact operator module text, when supplied by the platform.
    pub host_module: Option<String>,
    /// Detached signature over the exact module text, when supplied.
    pub host_module_signature: Option<String>,
    /// Canonical observational instance facts.
    pub facts: Facts,
}

/// Selects the [`PlatformFetcher`] for a typed detection result.
///
/// Offline channels use the private mounted directory carried by the result;
/// cloud channels ignore it.
/// Detection emits only identifiers with an explicit capability. A manually
/// supplied or stale unknown identifier fails closed instead of silently
/// discarding possible control-plane provisioning data.
///
/// # Errors
///
/// Returns an error when `platform_id` is not part of the supported capability
/// model.
pub fn select_fetcher(context: &AcquisitionContext) -> Result<Box<dyn PlatformFetcher>> {
    let platform_id = context.platform.as_str();
    let offline_directory = || {
        context
            .metadata_dir
            .as_deref()
            .with_context(|| format!("metadata platform {platform_id:?} has no detected media"))
    };
    let fetcher: Box<dyn PlatformFetcher> = match context.platform {
        PlatformId::AosMetadata => Box::new(offline::AosMetadataFetcher::new(offline_directory()?)),
        PlatformId::Nocloud => Box::new(offline::NoCloudFetcher::new(offline_directory()?)),
        PlatformId::ConfigDrive => Box::new(offline::ConfigDriveFetcher::new(offline_directory()?)),
        PlatformId::Qemu => Box::new(offline::QemuFwCfgFetcher::default()),
        PlatformId::Aws => Box::new(aws::AwsImdsFetcher::default()),
        PlatformId::Gcp => Box::new(cloud::GcpFetcher),
        PlatformId::Azure => Box::new(cloud::AzureFetcher),
        PlatformId::Digitalocean => Box::new(cloud::DigitalOceanFetcher),
        PlatformId::Openstack => Box::new(cloud::OpenStackImdsFetcher),
        PlatformId::Metal | PlatformId::Hyperv | PlatformId::Vmware | PlatformId::Virtualbox => {
            Box::new(cloud::NoMetadataFetcher::new(platform_id))
        }
    };
    Ok(fetcher)
}

/// Selects the platform fetcher and returns its exact typed result.
///
/// # Errors
///
/// Returns an error on transport failure, invalid UTF-8 operator input, or
/// facts that cannot be represented in canonical form.
pub async fn fetch_metadata(context: &AcquisitionContext) -> Result<FetchedMetadata> {
    let fetcher = select_fetcher(context)?;

    let engine = TransferEngine::new(TransferEngineConfig::default());
    let http = EngineHttp::new(engine);

    fetch_metadata_with(&*fetcher, &http).await
}

/// Drives one fetcher against an injected HTTP surface.
///
/// # Errors
///
/// As [`fetch_metadata`].
pub(crate) async fn fetch_metadata_with(
    fetcher: &dyn PlatformFetcher,
    http: &dyn MetadataHttp,
) -> Result<FetchedMetadata> {
    let user_data = fetcher
        .fetch_user_data(http)
        .await
        .context("fetching user-data")?;
    let (host_module, host_module_signature) = match user_data {
        Some(ud) => {
            let resolved = ud.resolve(http).await.context("resolving user-data")?;
            let module = String::from_utf8(resolved.payload)
                .context("operator module is not valid UTF-8")?;
            (Some(module), resolved.sig)
        }
        None => (None, None),
    };

    let facts = fetcher.fetch_facts(http).await.context("fetching facts")?;
    let facts = canonicalize_host_facts(&facts)?;

    Ok(FetchedMetadata {
        host_module,
        host_module_signature,
        facts,
    })
}

/// A best-effort RFC 3339 UTC timestamp.
///
/// Uses the system clock; the value is recorded, never used in a security
/// decision, so a coarse seconds-resolution stamp is sufficient. Falls back to
/// the Unix epoch when the clock is before it.
pub fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal civil-time conversion (UTC) without a date crate.
    civil_from_unix(secs)
}

/// Convert Unix seconds to an `YYYY-MM-DDThh:mm:ssZ` string (UTC).
fn civil_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}
