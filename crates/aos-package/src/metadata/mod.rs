//! The `aos metadata` agent for fetching host configuration and instance facts.
//!
//! Two initrd phases own cross-cloud user-data + instance-metadata acquisition,
//! replacing Ignition's fetch layer. The agent is **transport-only**: it
//! fetches and stashes *untrusted* bytes; signature verification is deferred to
//! the stage-2 `aos-eval.service`. A failed or missing fetch leaves no
//! `host.nix` in the stash, so eval falls through to gen-0-only config — the
//! failure-safe path.
//!
//! ```text
//! aos metadata detect   # DMI/SMBIOS/ISO → /run/aos-metadata/platform.env
//! aos metadata fetch    # platform → /run/aos-metadata/{host.nix, host.nix.sig, facts.json, …}
//! ```
//!
//! # Module map
//!
//! - [`detect`] — the DMI decision table (ported from
//!   `pkgs/boot/aos-platform-detect.nix`) + the config-drive probe.
//! - [`fetcher`] — the [`PlatformFetcher`] trait and the normalized
//!   [`UserData`] / [`Facts`] / [`StaticNetwork`] it produces.
//! - [`http`] — the [`MetadataHttp`] surface: the `TransferEngine`-backed
//!   adapter (with the `tokio::time::timeout` shim) and the recorded mock.
//! - [`mount`] — the config-drive mount helper (`blkid -L` + `mount -o ro`),
//!   behind a mockable trait.
//! - [`offline`] — the offline fetchers (aos-metadata ISO, NoCloud,
//!   config-drive, qemu fw_cfg).
//! - [`aws`] — the AWS IMDSv2 cloud exemplar; [`cloud`] — the other cloud
//!   vendors as `TODO` stubs.
//! - [`staticnet`] — DHCP-less network parsing + networkd render.
//! - [`facts_render`] — `facts.json` → `host-facts.nix`.
//! - [`stash`] — the `/run/aos-metadata` stash format.
//! - [`repart`] — the two-boot custom-repart persist seam.
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
pub mod repart;
pub mod staticnet;
pub mod stash;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use anyhow::{Context, Result};

pub use detect::{DetectOptions, classify_dmi, needs_network, run_detect};
pub use facts_render::render_host_facts_nix;
pub use fetcher::{Facts, PlatformFetcher, StaticNetwork, UserData};
pub use http::{EngineHttp, MetadataHttp};
pub use mount::{BlkidProbe, ConfigDriveProbe};
pub use stash::{MetadataResult, PlatformEnv, Stash};

use aos_net::transfer::{TransferEngine, TransferEngineConfig};

/// Select the [`PlatformFetcher`] for a `PLATFORM_ID`, given the resolved
/// offline `metadata_dir` (when one was mounted by `detect`).
///
/// Offline channels need their mounted directory; cloud channels ignore it.
/// An unknown platform maps to the AWS exemplar only when it is `aws`;
/// otherwise it falls back to a cloud stub or, lacking a directory, the qemu
/// reader, so an un-ported platform is failure-safe.
pub fn select_fetcher(platform_id: &str, metadata_dir: Option<&str>) -> Box<dyn PlatformFetcher> {
    match platform_id {
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
        // metal / vultr / hetzner / scaleway / oraclecloud and the unknown
        // tail: no native fetcher yet ⇒ qemu fw_cfg reader is the only offline
        // probe, else gen-0-only via the empty result.
        _ => Box::new(offline::QemuFwCfgFetcher::default()),
    }
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
/// untrusted payload + facts, and seed DHCP-less networking.
///
/// Reads `PLATFORM_ID`/`METADATA_DIR` from the stash's `platform.env`. Writes
/// `host.nix` (+ `host.nix.sig`), `facts.json`, the optional network seed, and
/// the `.metadata-result.json` run record. Never verifies a signature.
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
    let fetcher = select_fetcher(&env.platform_id, env.metadata_dir.as_deref());

    let engine = TransferEngine::new(TransferEngineConfig::default());
    let http = EngineHttp::new(engine);

    run_fetch_with(&stash, &*fetcher, &http, opts.var_etc_root.as_deref(), &env.platform_id).await
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
    // 1. User-data (untrusted), resolving the pointer form if present.
    let user_data = fetcher
        .fetch_user_data(http)
        .await
        .context("fetching user-data")?;
    let (fetched, host_nix_sha256, sig_present) = match user_data {
        Some(ud) => {
            let resolved = ud.resolve(http).await.context("resolving user-data")?;
            let sha = stash.write_host_nix(&resolved.host_nix, resolved.sig.as_deref())?;
            (true, Some(sha), resolved.sig.is_some())
        }
        None => (false, None, false),
    };

    // 2. Facts (recorded, unauthenticated).
    let facts = fetcher.fetch_facts(http).await.context("fetching facts")?;
    let facts_hash = stash.write_facts(&facts)?;

    // 3. DHCP-less static-network seed.
    let mut network_seed_written = false;
    if let Some(net) = &facts.network
        && net.is_seedable()
    {
        let rendered = staticnet::render_networkd(net);
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

    // 4. Run record.
    let result = MetadataResult {
        platform_id: platform_id.to_string(),
        fetched_user_data: fetched,
        user_data_source: user_data_source(platform_id).to_string(),
        host_nix_sha256,
        sig_present,
        facts_hash,
        network_seed_written,
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
fn now_rfc3339() -> String {
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
