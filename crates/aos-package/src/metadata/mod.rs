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
//! - [`stash`] — private transaction-local acquisition state.
//! - [`provisioning`] — whole-input authorization and host extraction.
//! - [`repart`] — shared typed storage validation.
//!
//! # Testability
//!
//! Every system surface — DMI sysfs, `blkid`/`mount`, the HTTP/IMDS client — is
//! behind a trait or a path parameter, so the whole agent is unit-tested off-box
//! with fixtures. Genuinely builder-gated: real `blkid`/`mount` (root), live
//! IMDS, and the initrd systemd services.

pub mod aws;
pub mod cloud;
pub mod detect;
pub mod facts_render;
pub mod fetcher;
pub mod http;
pub mod mount;
pub mod offline;
pub mod provider;
pub mod provisioning;
pub mod repart;
pub mod stash;
pub mod staticnet;
mod yaml;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use anyhow::{Context, Result};

pub use detect::{PlatformCapability, classify_dmi, needs_network, platform_capability};
pub use facts_render::render_host_facts_nix;
pub use fetcher::{Facts, PlatformFetcher, StaticNetwork, UserData};
pub use http::{EngineHttp, MetadataHttp};
pub use mount::{BlkidProbe, ConfigDriveProbe};
pub use provisioning::{AuthorizeOptions, EvalProvisioningOptions, ProvisioningTrust};
pub use stash::{MetadataResult, PlatformEnv, Stash};

use aos_net::transfer::{TransferEngine, TransferEngineConfig};

/// Select the [`PlatformFetcher`] for a `PLATFORM_ID`, given the resolved
/// offline `metadata_dir` (when one was mounted by `detect`).
///
/// Offline channels need their mounted directory; cloud channels ignore it.
/// Detection emits only identifiers with an explicit capability. A manually
/// supplied or stale unknown identifier fails closed instead of silently
/// discarding possible control-plane provisioning data.
///
/// # Errors
///
/// Returns an error when `platform_id` is not part of the supported capability
/// model.
pub fn select_fetcher(
    platform_id: &str,
    metadata_dir: Option<&str>,
) -> Result<Box<dyn PlatformFetcher>> {
    let offline_directory = || {
        metadata_dir.with_context(|| {
            format!("metadata platform {platform_id:?} has no detected offline directory")
        })
    };
    let fetcher: Box<dyn PlatformFetcher> = match platform_id {
        "aos-metadata" => Box::new(offline::AosMetadataFetcher::new(offline_directory()?)),
        "nocloud" => Box::new(offline::NoCloudFetcher::new(offline_directory()?)),
        "config-drive" => Box::new(offline::ConfigDriveFetcher::new(offline_directory()?)),
        "qemu" => Box::new(offline::QemuFwCfgFetcher::default()),
        "aws" => Box::new(aws::AwsImdsFetcher::default()),
        "gcp" => Box::new(cloud::GcpFetcher),
        "azure" => Box::new(cloud::AzureFetcher),
        "digitalocean" => Box::new(cloud::DigitalOceanFetcher),
        "openstack" => Box::new(cloud::OpenStackImdsFetcher),
        "metal" => Box::new(cloud::NoMetadataFetcher::new("metal")),
        "hyperv" => Box::new(cloud::NoMetadataFetcher::new("hyperv")),
        "vmware" => Box::new(cloud::NoMetadataFetcher::new("vmware")),
        "virtualbox" => Box::new(cloud::NoMetadataFetcher::new("virtualbox")),
        _ => anyhow::bail!("unsupported metadata platform id {platform_id:?}"),
    };
    Ok(fetcher)
}

/// Options for [`run_fetch`].
pub struct FetchOptions {
    /// The stash directory holding `platform.env` and receiving outputs.
    pub stash_dir: PathBuf,
}

/// Selects the fetcher and acquires exact payload bytes and instance facts.
///
/// Reads `PLATFORM_ID`/`METADATA_DIR` from the stash's `platform.env`. Writes
/// `user-data` (+ `user-data.sig`), `facts.json`, and the
/// `.metadata-result.json` acquisition record. Network facts remain typed
/// provider output and are never rendered into an ambient configuration file.
///
/// # Errors
///
/// Returns `Err` on transport failure after retries, an unreadable
/// `platform.env`, or a stash write failure. A platform with no user-data
/// attached is *not* an error: the run record records `fetched_user_data:
/// false` and no `host.nix` is written.
pub async fn run_fetch(opts: &FetchOptions) -> Result<()> {
    let stash = Stash::open(&opts.stash_dir)?;
    let env = stash.read_platform_env()?;
    let fetcher = select_fetcher(&env.platform_id, env.metadata_dir.as_deref())?;

    let engine = TransferEngine::new(TransferEngineConfig::default());
    let http = EngineHttp::new(engine);

    run_fetch_with(&stash, &*fetcher, &http, &env.platform_id).await
}

/// The testable core of [`run_fetch`]: drive a given fetcher + HTTP surface and
/// write the stash. Exposed within the crate for unit tests against recorded
/// fixtures.
///
/// # Errors
///
/// As [`run_fetch`].
pub(crate) async fn run_fetch_with(
    stash: &Stash,
    fetcher: &dyn PlatformFetcher,
    http: &dyn MetadataHttp,
    platform_id: &str,
) -> Result<()> {
    stash.clear_fetch_outputs()?;

    // 1. Exact user-data, resolving the top-level pointer form if present.
    let user_data = fetcher
        .fetch_user_data(http)
        .await
        .context("fetching user-data")?;
    let (fetched, user_data_sha256, sig_present) = match user_data {
        Some(ud) => {
            let resolved = ud.resolve(http).await.context("resolving user-data")?;
            let sha = stash.write_user_data(&resolved.payload, resolved.sig.as_deref())?;
            (true, Some(sha), resolved.sig.is_some())
        }
        None => (false, None, false),
    };

    // 2. Facts (recorded, unauthenticated).
    let facts = fetcher.fetch_facts(http).await.context("fetching facts")?;
    let facts_hash = stash.write_facts(&facts)?;

    // 3. Run record.
    let result = MetadataResult {
        platform_id: platform_id.to_string(),
        fetched_user_data: fetched,
        user_data_source: user_data_source(platform_id).to_string(),
        user_data_sha256,
        sig_present,
        facts_hash,
        timestamp: now_rfc3339(),
    };
    stash.write_result(&result)?;
    Ok(())
}

/// The `user_data_source` tag recorded for a platform.
fn user_data_source(platform_id: &str) -> &'static str {
    match platform_id {
        "aos-metadata" | "nocloud" | "config-drive" => "config-drive",
        "qemu" => "fw_cfg",
        _ => "imds",
    }
}

/// A best-effort RFC 3339 UTC timestamp.
///
/// Uses the system clock; the value is recorded, never used in a security
/// decision, so a coarse seconds-resolution stamp is sufficient. Falls back to
/// the Unix epoch when the clock is before it.
pub(crate) fn now_rfc3339() -> String {
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
