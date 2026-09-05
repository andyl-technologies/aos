//! Signed system-image discovery through configured Git and HTTP registries.
//!
//! Discovery reuses the package registry synchronizer and its signature,
//! roster-continuity, and channel-rollback checks. Image queries keep a separate
//! cache so selecting a historical release never changes package tracking.
//! Trust continuity and rollout floors are shared across all image selectors
//! for the registry and checked against the configured package-sync state.
//!
//! The private `image-catalog-v1/<registry>/state.json` file has this shape:
//!
//! ```json
//! {"schema":1,"trust":{},"selections":{}}
//! ```

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_core::output::Printer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::ApmConfig;
use crate::download::resolve_mirror_chain;
use crate::registry::{git, parse::parse_registry_all_platforms};
use crate::types::{RegistryState, SysrootImageEntry, TrackingMode};

/// Selects a signed image catalog without changing package registry tracking.
#[derive(Debug, Clone, Default)]
pub struct ImageSelection {
    /// Configured APM registry name.
    pub registry: String,
    /// Exact signed release tag, mutually exclusive with `channel`.
    pub release: Option<String>,
    /// Signed rollout channel, using the client's persisted partition and floor.
    pub channel: Option<String>,
    /// Optional sysroot package name.
    pub package: Option<String>,
    /// Optional architecture such as `x86_64` or `aarch64`.
    pub architecture: Option<String>,
    /// Optional disk encoding such as `raw` or `qcow2`.
    pub format: Option<String>,
    /// Optional end-user target such as `qemu-kvm`.
    pub target: Option<String>,
}

/// An image authenticated by the selected registry's signed metadata.
#[derive(Debug, Clone)]
pub struct VerifiedRegistryImage {
    /// Package that publishes this image.
    pub package: String,
    /// Exact commit whose signature and roster policy authenticated the image.
    pub registry_commit: String,
    /// Complete validated image and delivery identity from the signed catalog.
    pub image: SysrootImageEntry,
    /// Selected registry's committed and client-configured cache chain.
    pub cache_urls: Vec<String>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogState {
    schema: u32,
    trust: RegistryState,
    #[serde(default)]
    tuf_commit: Option<String>,
    selections: BTreeMap<String, RegistryState>,
}

/// Lists authenticated image entries from a configured registry.
///
/// Uses the existing APM trust anchors, Git/HTTP synchronizer, and binary-cache
/// resolution. A failed refresh never falls back to stale extracted metadata.
/// Neither a Hub connection nor a Nix store import is required.
///
/// # Errors
///
/// Returns an error for unknown or disabled registries, unsigned configuration,
/// conflicting selectors, concurrent discovery, signature or rollback failures,
/// malformed catalogs, and cache/state I/O failures.
pub async fn list(
    config: &ApmConfig,
    selection: &ImageSelection,
    printer: &Printer,
) -> Result<Vec<VerifiedRegistryImage>> {
    ensure!(
        selection.release.is_none() || selection.channel.is_none(),
        "release and channel are mutually exclusive"
    );
    let target = selection
        .target
        .as_ref()
        .map(|target| {
            serde_json::from_value::<crate::types::ImageTarget>(serde_json::Value::String(
                target.clone(),
            ))
        })
        .transpose()
        .context("unsupported image --target")?;
    let (registry, configured_state) =
        config.find_registry(&selection.registry).with_context(|| {
            format!(
                "registry '{}' is not configured; add it with `apm registry add`",
                selection.registry
            )
        })?;
    ensure!(registry.enabled, "registry '{}' is disabled", registry.name);
    ensure!(
        registry
            .signing
            .as_ref()
            .is_none_or(|signing| signing.required),
        "image discovery requires signed metadata; enable registry.signing.required for '{}'",
        registry.name
    );
    let configured_tracking = registry.tracking_mode()?;
    let tracking = if let Some(release) = &selection.release {
        semver::Version::parse(release)
            .context("--release must name a semantic-version release tag")?;
        TrackingMode::Tag(release.clone())
    } else if let Some(channel) = &selection.channel {
        crate::types::validate_channel_name(channel)?;
        TrackingMode::Channel(channel.clone())
    } else {
        configured_tracking.clone()
    };
    let selector = selector_key(&tracking);
    let root = config
        .cache_path()
        .join("image-catalog-v1")
        .join(&registry.name);
    fs::create_dir_all(&root).context("creating image catalog cache")?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("lock"))
        .context("opening image catalog lock")?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("image catalog is busy; retry when the other registry query finishes")?;
    let state_path = root.join("state.json");
    let mut saved = read_state(&state_path)?;
    if let Some(configured) = configured_state.as_ref()
        && configured.tuf_root_version.is_some()
        && (saved.tuf_commit.is_none()
            || configured.tuf_root_version > saved.trust.tuf_root_version)
    {
        saved.tuf_commit = configured.last_commit.clone();
    }
    merge_configured_state(&mut saved.trust, configured_state.as_ref())?;
    let previous = saved
        .selections
        .get(&selector)
        .cloned()
        .or_else(|| {
            (tracking == configured_tracking)
                .then(|| configured_state.clone())
                .flatten()
        })
        .unwrap_or_default();
    let immutable = git::tracking_mode_is_immutable_pin(&tracking);
    let mut state = saved.trust.clone();
    state.last_commit = previous.last_commit.clone();
    if immutable {
        // A deliberately selected archive has its own frozen TUF envelope.
        // Registry-wide roster checks still authorize its signers today; an
        // archive cannot lower live/channel TUF floors or renew freshness.
        copy_tuf_versions(&mut state, &previous);
    }
    let cache_dir = root.join(&selector).join("cache");
    let registry_dir = root.join(&selector).join("registries");
    let configured_roster = configured_state.as_ref().and_then(|state| {
        state
            .last_roster_commit
            .as_deref()
            .or(state.last_commit.as_deref())
    });
    let configured_selected = if tracking == configured_tracking {
        configured_state
            .as_ref()
            .and_then(|state| state.last_commit.as_deref())
    } else {
        None
    };
    let result = git::sync_git_with_continuity(
        registry,
        &tracking,
        &cache_dir,
        &registry_dir,
        &config.scope.trusted_keys_dirs(),
        &mut state,
        printer,
        git::SyncContinuity {
            roster: configured_roster,
            selected: configured_selected,
            exact_selected: immutable
                .then_some(previous.last_commit.as_deref())
                .flatten(),
            tuf_previous: if immutable {
                None
            } else {
                saved.tuf_commit.as_deref()
            },
        },
    )
    .await?;

    saved.selections.insert(selector, state.clone());
    let previous_trust = saved.trust.clone();
    saved.trust = state.clone();
    saved.trust.last_commit = None;
    if immutable {
        copy_tuf_versions(&mut saved.trust, &previous_trust);
    } else if state.tuf_root_version.is_some() {
        saved.tuf_commit = Some(result.new_commit.clone());
    }
    if !matches!(tracking, TrackingMode::Channel(_)) {
        saved.trust.last_update = previous_trust.last_update;
    }
    write_state(&state_path, &saved)?;

    let receipt = crate::registry::load_release_trust_receipt(
        &cache_dir.join(&registry.name),
        &registry.name,
    )?;
    let selected_release = receipt.as_ref().map(|receipt| receipt.release_tag.as_str());
    let cache_urls = resolve_mirror_chain(&registry_dir, registry);
    let mut images = Vec::new();
    for package in parse_registry_all_platforms(&cache_dir.join(&registry.name))? {
        if !package.sysroot
            || selection
                .package
                .as_ref()
                .is_some_and(|name| name != &package.name)
        {
            continue;
        }
        for image in package.images {
            if image.delivery.is_store_only() {
                continue;
            }
            if selected_release.is_some_and(|release| release != image.delivery.release)
                || selection
                    .architecture
                    .as_ref()
                    .is_some_and(|architecture| architecture != &image.delivery.architecture)
                || selection
                    .format
                    .as_ref()
                    .is_some_and(|format| format != &image.format)
                || target.is_some_and(|target| !image.delivery.compatible_targets.contains(&target))
            {
                continue;
            }
            images.push(VerifiedRegistryImage {
                package: package.name.clone(),
                registry_commit: result.new_commit.clone(),
                image,
                cache_urls: cache_urls.clone(),
            });
        }
    }
    images.sort_by(|left, right| {
        (
            &left.package,
            &left.image.delivery.release,
            &left.image.delivery.platform,
            &left.image.format,
        )
            .cmp(&(
                &right.package,
                &right.image.delivery.release,
                &right.image.delivery.platform,
                &right.image.format,
            ))
    });
    Ok(images)
}

fn read_state(path: &Path) -> Result<CatalogState> {
    match fs::read(path) {
        Ok(bytes) => {
            let state: CatalogState =
                serde_json::from_slice(&bytes).context("reading image trust state")?;
            ensure!(state.schema == 1, "unsupported image trust state schema");
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CatalogState {
            schema: 1,
            ..Default::default()
        }),
        Err(error) => Err(error).context("reading image trust state"),
    }
}

fn write_state(path: &Path, state: &CatalogState) -> Result<()> {
    let parent = path
        .parent()
        .context("image trust state has no directory")?;
    let mut output =
        tempfile::NamedTempFile::new_in(parent).context("creating image trust state")?;
    output.write_all(&serde_json::to_vec(state)?)?;
    output.as_file().sync_all()?;
    output
        .persist(path)
        .context("persisting image trust state")?;
    Ok(())
}

/// Preserves the stricter counters while leaving exact release selection local.
fn merge_configured_state(
    state: &mut RegistryState,
    configured: Option<&RegistryState>,
) -> Result<()> {
    let Some(configured) = configured else {
        return Ok(());
    };
    if state.last_roster_commit.is_none() {
        state.last_roster_commit = configured
            .last_roster_commit
            .clone()
            .or_else(|| configured.last_commit.clone());
    }
    if let Some(floor) = &configured.floor {
        let configured_floor =
            semver::Version::parse(floor).context("configured registry floor is invalid")?;
        let current_floor = state
            .floor
            .as_deref()
            .map(semver::Version::parse)
            .transpose()
            .context("image registry floor is invalid")?;
        match current_floor {
            None => {
                state.floor = Some(floor.clone());
                state.last_update = configured.last_update.clone();
            }
            Some(current) if configured_floor > current => {
                state.floor = Some(floor.clone());
                state.last_update = configured.last_update.clone();
            }
            Some(current) if configured_floor == current => {
                // The first accepted observation starts the freeze window;
                // another consumer must not renew it for an unchanged floor.
                state.last_update = match (&state.last_update, &configured.last_update) {
                    (Some(left), Some(right)) => Some(left.min(right).clone()),
                    (Some(value), None) | (None, Some(value)) => Some(value.clone()),
                    (None, None) => None,
                };
            }
            Some(_) => {}
        }
    }
    state.bucket = configured.bucket.or(state.bucket);
    state.retained.extend(configured.retained.iter().cloned());
    state.retained.sort();
    state.retained.dedup();
    state.tuf_root_version = state.tuf_root_version.max(configured.tuf_root_version);
    state.tuf_targets_version = state
        .tuf_targets_version
        .max(configured.tuf_targets_version);
    state.tuf_snapshot_version = state
        .tuf_snapshot_version
        .max(configured.tuf_snapshot_version);
    state.tuf_timestamp_version = state
        .tuf_timestamp_version
        .max(configured.tuf_timestamp_version);
    Ok(())
}

/// Copies counters without changing roster, release, or rollout state.
fn copy_tuf_versions(state: &mut RegistryState, source: &RegistryState) {
    state.tuf_root_version = source.tuf_root_version;
    state.tuf_targets_version = source.tuf_targets_version;
    state.tuf_snapshot_version = source.tuf_snapshot_version;
    state.tuf_timestamp_version = source.tuf_timestamp_version;
}

/// Uses the full selector identity; Display intentionally abbreviates commits.
fn selector_key(tracking: &TrackingMode) -> String {
    let (kind, value) = match tracking {
        TrackingMode::Commit(value) => ("commit", value.clone()),
        TrackingMode::Branch(value) => ("branch", value.clone()),
        TrackingMode::Channel(value) => ("channel", value.clone()),
        TrackingMode::Tag(value) => ("tag", value.clone()),
        TrackingMode::Version(value) => ("version", value.to_string()),
        TrackingMode::Default => ("default", String::new()),
    };
    let mut digest = Sha256::new();
    digest.update(kind.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_commit_identity_and_tracking_kind_partition_selection_state() {
        let prefix = "a".repeat(12);
        let first = TrackingMode::Commit(format!("{prefix}{}", "1".repeat(52)));
        let second = TrackingMode::Commit(format!("{prefix}{}", "2".repeat(52)));
        assert_eq!(first.to_string(), second.to_string());
        assert_ne!(selector_key(&first), selector_key(&second));
        assert_ne!(
            selector_key(&TrackingMode::Tag("stable".into())),
            selector_key(&TrackingMode::Channel("stable".into()))
        );
    }

    #[test]
    fn configured_channel_floor_retains_its_original_freshness_observation() {
        let configured = RegistryState {
            floor: Some("2.0.0".into()),
            last_update: Some("2026-09-01T00:00:00Z".into()),
            bucket: Some(17),
            tuf_targets_version: Some(2),
            ..Default::default()
        };
        let mut image = RegistryState::default();
        merge_configured_state(&mut image, Some(&configured)).expect("initial consumer state");
        assert_eq!(image.floor, configured.floor);
        assert_eq!(image.last_update, configured.last_update);
        assert_eq!(image.bucket, Some(17));
        image.last_update = Some("2026-09-02T00:00:00Z".into());
        image.tuf_targets_version = Some(3);
        merge_configured_state(&mut image, Some(&configured)).expect("merge existing consumer");
        assert_eq!(
            image.last_update, configured.last_update,
            "unchanged floor cannot renew freshness"
        );
        assert_eq!(image.tuf_targets_version, Some(3));
    }
}
