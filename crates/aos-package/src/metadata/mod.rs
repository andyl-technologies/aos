//! The `aos metadata` agent for fetching host configuration and instance facts.
//!
//! Initrd phases own cross-cloud acquisition and the narrow first-boot trust
//! boundary. Fetch stores exact bytes. Authorization applies the measured
//! `platform` or `signed` policy and is the only phase allowed to produce exact
//! `host.nix`. Restricted evaluation then projects one-time provisioning and
//! renders transient repart definitions. Full evaluation remains in stage 2.
//!
//! ```text
//! aos metadata detect   # DMI/SMBIOS/ISO → /run/aos-metadata/platform.env
//! aos metadata fetch    # platform → exact user-data + facts
//! aos metadata authorize # trust policy → exact host.nix
//! aos metadata eval-provisioning # restricted projection → repart.d
//! ```
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
//! - [`stash`] — the `/run/aos-metadata` stash format.
//! - [`provisioning`] — whole-input authorization and host extraction.
//! - [`repart`] — typed storage validation and transient repart rendering.
//! - [`state`] — durable provisioning evidence and last-known-good input.
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
pub mod provisioning;
pub mod repart;
pub mod stash;
pub mod state;
pub mod staticnet;
mod yaml;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use anyhow::{Context, Result};

pub use detect::{
    DetectOptions, PlatformCapability, classify_dmi, needs_network, platform_capability, run_detect,
};
pub use facts_render::render_host_facts_nix;
pub use fetcher::{Facts, PlatformFetcher, StaticNetwork, UserData};
pub use http::{EngineHttp, MetadataHttp};
pub use mount::{BlkidProbe, ConfigDriveProbe};
pub use provisioning::{
    AuthorizeOptions, EvalProvisioningOptions, ProvisioningSource, ProvisioningTrust,
};
pub use stash::{MetadataResult, PlatformEnv, Stash};
pub use state::{PersistProvisioningOptions, ProvisioningAudit};

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
    let fetcher: Box<dyn PlatformFetcher> = match platform_id {
        "aos-metadata" => Box::new(offline::AosMetadataFetcher::new(
            metadata_dir.unwrap_or(stash::DEFAULT_MEDIA_DIR),
        )),
        "nocloud" => Box::new(offline::NoCloudFetcher::new(
            metadata_dir.unwrap_or(stash::DEFAULT_MEDIA_DIR),
        )),
        "config-drive" => Box::new(offline::ConfigDriveFetcher::new(
            metadata_dir.unwrap_or(stash::DEFAULT_MEDIA_DIR),
        )),
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
    /// Optional gen-0 `/var/etc` root to additionally seed the static-network
    /// config into (the documented DHCP-less seam). `None` ⇒ stash-only.
    pub var_etc_root: Option<PathBuf>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            stash_dir: PathBuf::from(stash::DEFAULT_STASH_DIR),
            var_etc_root: None,
        }
    }
}

/// Run `aos metadata fetch`: select the fetcher, acquire and stash the
/// exact payload + facts, and seed DHCP-less networking.
///
/// Reads `PLATFORM_ID`/`METADATA_DIR` from the stash's `platform.env`. Writes
/// `user-data` (+ `user-data.sig`), `facts.json`, the optional network seed,
/// and the `.metadata-result.json` acquisition record. Never authorizes input.
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

    run_fetch_with(
        &stash,
        &*fetcher,
        &http,
        opts.var_etc_root.as_deref(),
        &env.platform_id,
    )
    .await
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
    var_etc_root: Option<&std::path::Path>,
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

    // 3. DHCP-less static-network seed.
    let mut network_seed_written = false;
    if let Some(net) = &facts.network {
        if net.is_seedable() {
            let rendered = staticnet::render_networkd(net)?;
            stash.write_network_seed(&rendered)?;
            // Documented seam: also place into the gen-0 /var/etc lower so stage-2
            // networkd has a route before any config-gen.
            if let Some(root) = var_etc_root {
                let dir = root.join("systemd/network");
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
                std::fs::write(dir.join(staticnet::SEED_FILENAME), &rendered)
                    .context("seeding /var/etc network")?;
            }
            network_seed_written = true;
        }
    }

    // 4. Run record.
    let result = MetadataResult {
        platform_id: platform_id.to_string(),
        fetched_user_data: fetched,
        user_data_source: user_data_source(platform_id).to_string(),
        user_data_sha256,
        sig_present,
        facts_hash,
        network_seed_written,
        timestamp: now_rfc3339(),
    };
    stash.write_result(&result)?;
    Ok(())
}

/// Run provisioning authorization with the production HTTP adapter.
///
/// # Errors
///
/// Returns an error for trust, schema, content-pin, validation, or stash
/// failures. Errors are intentionally fatal to the initrd ordering chain.
pub async fn authorize_main(opts: &AuthorizeOptions) -> Result<()> {
    provisioning::run_authorize(opts)?;
    Ok(())
}

/// Runs the restricted initrd provisioning projection and renderer.
///
/// # Errors
///
/// Returns an error when Nix evaluation, strict validation, or rendering
/// fails. The caller must treat this as fatal before disk mutation.
pub fn eval_provisioning_main(opts: &EvalProvisioningOptions) -> Result<()> {
    provisioning::run_eval_provisioning(opts)?;
    Ok(())
}

/// Verify the initrd-to-stage-2 host content binding.
///
/// # Errors
///
/// Returns an error when the accepted host or authorization record is missing
/// or the content hash differs.
pub fn verify_binding_main(stash_dir: &std::path::Path) -> Result<()> {
    provisioning::verify_host_binding(stash_dir)
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

/// Entry point for `aos metadata detect` with production defaults (real
/// `blkid`/`mount` probe over the live `/sys`).
///
/// # Errors
///
/// Returns `Err` on probe/mount or write failure.
pub fn detect_main() -> Result<()> {
    let opts = DetectOptions::default();
    let probe = BlkidProbe::default();
    run_detect(&opts, &probe)
}

/// Entry point for `aos metadata fetch` with production defaults.
///
/// # Errors
///
/// As [`run_fetch`].
pub async fn fetch_main() -> Result<()> {
    run_fetch(&FetchOptions::default()).await
}
