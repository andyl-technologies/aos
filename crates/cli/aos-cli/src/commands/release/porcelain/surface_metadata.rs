//! TUF metadata, release record, and timestamp of a destination's publication.
//!
//! The first destination published on a surface carries that surface's TUF
//! metadata for the release: an immutable metadata set at the surface's next
//! versions, a timestamp pointing at its snapshot, and, on the production
//! surface, the public release record. A later destination on the same
//! surface reuses the publication and carries none of these.
//!
//! The driver runs, in order:
//!
//! ```text
//! [production] step record          publish/<slug>/release-record.json
//! step tuf                          publish/<slug>/tuf/metadata/
//! step timestamp refresh            publish/<slug>/timestamp/timestamp.json
//! step compose-surface              publish/<slug>/timestamp/{surface,overlay}/
//! step publish --surface overlay    (immutable metadata, manifest, record)
//! step timestamp publish            publish/<slug>/timestamp/published/
//! ```
//!
//! `step publish` uploads everything but `tuf/timestamp.json`; `step timestamp
//! publish` then replaces the surface's timestamp over exactly its previous
//! version, so readers move to the new snapshot only once every file it names
//! is served.
//!
//! Versions come from the surface's anonymous read-back, never from local
//! counters. With `tuf/timestamp.json` at version `N` naming snapshot `S`, the
//! new targets, delegated, and snapshot metadata all take version `M + 1`,
//! where `M` is the highest non-root version `S` describes (at least `S`
//! itself), and the new timestamp takes version `N + 1` in the new-snapshot
//! continuity mode. A surface without TUF metadata starts at version 1.
//! Versions past `M` that a surface already serves as immutable targets or
//! snapshot metadata belong to a release whose publication committed but
//! whose timestamp never moved; the new set skips past them, because an
//! immutable path can never take different bytes.
//! Using one version for every role keeps each role strictly increasing
//! across releases whatever their release classes.
//!
//! ```json
//! {"destination":"production/candidate","metadata_version":44,
//!  "schema_version":"aos.release.surface-tuf-state/v1",
//!  "snapshot_version":44,"surface_identity":"cdn-2026-09","timestamp_version":86}
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::plan::{
    PlannedDestination, PlannedSurface, ReleaseClass, ReleasePlan, SurfaceKind, SurfaceRole,
};
use aos_release_format::signing::SignerRole;
use aos_release_format::tuf::{SnapshotMetadataV1, TimestampMetadataV1, TufEnvelopeV1, TufRole};
use serde::{Deserialize, Serialize};

use super::super::access::{self, SignerNeed};
use super::super::config::{MaintainerConfig, TufConfig};
use super::super::{compose_surface, record, timestamp, tuf, verify};
use super::Session;
use super::keys;
use super::observe::Observation;
use super::planner::{SurfaceMetadataFacts, format_time};
use super::steps::Driver;
use super::workdir::{self, WorkDir};
use crate::cli::{
    ReleaseComposeSurfaceArgs, ReleaseRecordArgs, ReleaseTimestampCommand,
    ReleaseTimestampPublishArgs, ReleaseTimestampRefreshArgs, ReleaseTufArgs,
};
use aos_release_coordinator::{projection as project, readback};

/// Exact schema identifier of the recorded surface TUF state.
const SURFACE_TUF_STATE: &str = "aos.release.surface-tuf-state/v1";

/// Path of the surface's mutable timestamp pointer.
const TIMESTAMP_PATH: &str = "tuf/timestamp.json";

/// Largest TUF pointer or snapshot read back from a surface.
const MAX_METADATA_BYTES: usize = 1024 * 1024;

/// Most consecutive abandoned metadata versions skipped before failing.
const MAX_ABANDONED_VERSIONS: u64 = 64;

/// Validity of the top-level and delegated targets metadata.
const TARGETS_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Validity of the snapshot; timestamp renewals can extend freshness only
/// until the snapshot they point at expires.
const SNAPSHOT_VALIDITY: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Validity of a signed timestamp: the 48-hour maximum the TUF policy allows.
const TIMESTAMP_VALIDITY: Duration = Duration::from_secs(48 * 60 * 60);

/// TUF state a surface served when its next metadata versions were chosen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SurfaceTufState {
    /// Exact schema identifier.
    pub(super) schema_version: String,
    /// Destination that publishes the surface's metadata.
    pub(super) destination: String,
    /// Planned surface identity.
    pub(super) surface_identity: String,
    /// Version of the served timestamp, or zero when the surface serves none.
    pub(super) timestamp_version: u64,
    /// Version of the snapshot the served timestamp names, or zero.
    pub(super) snapshot_version: u64,
    /// Highest non-root metadata version the served snapshot describes, or
    /// zero, raised past any abandoned versions the surface already serves.
    pub(super) metadata_version: u64,
}

impl SurfaceTufState {
    /// Derives the state from a surface's served timestamp and snapshot bytes.
    ///
    /// Only versions are taken from the served bytes; the snapshot must be
    /// exactly the one the timestamp describes. `step timestamp refresh`
    /// verifies the served timestamp's signatures before it is continued.
    ///
    /// # Errors
    /// Returns an error for noncanonical or malformed metadata, a foreign
    /// registry, or a snapshot that is missing or differs from the
    /// timestamp's description.
    pub(super) fn from_served(
        registry: &str,
        destination: &str,
        surface_identity: &str,
        timestamp: Option<&[u8]>,
        snapshot: Option<&[u8]>,
    ) -> Result<Self> {
        let mut state = Self {
            schema_version: SURFACE_TUF_STATE.to_owned(),
            destination: destination.to_owned(),
            surface_identity: surface_identity.to_owned(),
            timestamp_version: 0,
            snapshot_version: 0,
            metadata_version: 0,
        };
        let Some(timestamp) = timestamp else {
            return Ok(state);
        };

        let timestamp = parse_timestamp(timestamp, "served TUF timestamp")?;
        let snapshot = snapshot.context("surface serves a timestamp without its snapshot")?;
        let description = &timestamp.signed.snapshot;
        if Sha256Digest::of_bytes(snapshot) != description.sha256
            || u64::try_from(snapshot.len())? != description.length
        {
            bail!("served TUF snapshot differs from the served timestamp's description");
        }
        canonical::require_canonical(snapshot, "served TUF snapshot")?;
        let snapshot: TufEnvelopeV1<SnapshotMetadataV1> =
            canonical::from_slice(snapshot, "served TUF snapshot")?;
        if timestamp.signed.registry != registry || snapshot.signed.registry != registry {
            bail!("surface serves TUF metadata for a different registry");
        }
        if snapshot.signed.version != description.version {
            bail!("served TUF snapshot version differs from the timestamp's description");
        }

        state.timestamp_version = timestamp.signed.version;
        state.snapshot_version = snapshot.signed.version;
        // Root versions follow root rotation, not releases; every other role
        // must advance past what the surface already serves.
        state.metadata_version = snapshot
            .signed
            .metadata
            .iter()
            .filter(|described| !described.path.ends_with(".root.json"))
            .map(|described| described.version)
            .chain([snapshot.signed.version])
            .max()
            .unwrap_or(snapshot.signed.version);
        Ok(state)
    }

    /// Returns the version of the release's targets, delegated, and snapshot metadata.
    ///
    /// # Errors
    /// Returns an error when the version would overflow.
    pub(super) fn next_metadata_version(&self) -> Result<u64> {
        self.metadata_version
            .checked_add(1)
            .context("surface TUF metadata version overflowed")
    }
}

/// Returns the version the next timestamp takes after `previous`, or 1 for none.
///
/// # Errors
/// Returns an error for a malformed previous timestamp or version overflow.
pub(super) fn next_timestamp_version(previous: Option<&[u8]>) -> Result<u64> {
    let Some(previous) = previous else {
        return Ok(1);
    };
    parse_timestamp(previous, "served TUF timestamp")?
        .signed
        .version
        .checked_add(1)
        .context("TUF timestamp version overflowed")
}

/// Observes the surface-metadata facts of one destination.
///
/// An unpublished destination publishes its surface's metadata unless the
/// surface already holds this release (another destination published it
/// there). A published destination owns metadata exactly when its TUF set
/// exists.
///
/// # Errors
/// Returns an error for an unreadable refreshed timestamp.
pub(super) fn facts(
    session: &Session,
    observation: &Observation,
    destination: &PlannedDestination,
) -> Result<Option<SurfaceMetadataFacts>> {
    let work = &session.work;
    let name = destination.name.as_str();
    let owns = match observation.state_of(name) {
        None => !observation.journal.as_ref().is_some_and(|(_, journal)| {
            journal
                .summary
                .surface_holds_publication(destination.surface)
        }),
        Some(_) => work.tuf_metadata(name).is_dir(),
    };
    if !owns {
        return Ok(None);
    }

    let refreshed = work.refreshed_timestamp(name);
    let timestamp_expires = if refreshed.is_file() {
        let bytes = super::super::capture::control_file(&refreshed, "refreshed TUF timestamp")?;
        let timestamp = parse_timestamp(&bytes, "refreshed TUF timestamp")?;
        Some(super::observe::parse_time(&timestamp.signed.expires)?)
    } else {
        None
    };
    Ok(Some(SurfaceMetadataFacts {
        record_required: destination.surface == SurfaceRole::Production,
        record: work.release_record(name).is_file(),
        tuf: work.tuf_metadata(name).is_dir(),
        timestamp_expires,
        composed: work.composed_surface(name).is_dir() && work.surface_overlay(name).is_dir(),
        timestamp_published: work
            .timestamp_publication(name)
            .join("publication-evidence.json")
            .is_file(),
        missing_config: missing_config(&session.config, session.plan.release_class),
    }))
}

/// Names the first maintainer-configuration key the TUF steps need but lack.
///
/// The steps need `[tuf]` for the root and its independent trust, and the
/// targets, release-class, snapshot, and timestamp signer roles.
pub(super) fn missing_config(config: &MaintainerConfig, class: ReleaseClass) -> Option<String> {
    if config.tuf.is_none() {
        return Some("[tuf] (root, trusted_root_keys, trusted_root_threshold)".to_owned());
    }
    [
        SignerRole::TufTargets,
        TufRole::for_release(class).signer_role(),
        SignerRole::TufSnapshot,
        SignerRole::TufTimestamp,
    ]
    .into_iter()
    .find(|role| config.role_keys(*role).is_err())
    .map(|role| format!("[signer.roles.{}]", role_name(role)))
}

/// Returns a signer role's public spelling, such as `tuf-snapshot`.
fn role_name(role: SignerRole) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{role:?}"))
}

impl Driver<'_> {
    /// Composes the public release record from the signed staging qualification.
    pub(super) fn record(
        &self,
        destination: &PlannedDestination,
        observation: &Observation,
    ) -> Result<()> {
        let config = &self.session.config;
        let work = &self.session.work;
        let name = destination.name.as_str();
        let signed = work
            .phase(name, super::workdir::Phase::Staging)
            .join("signed");
        let output = work.release_record(name);
        create_parent(&output)?;
        record::run(
            &ReleaseRecordArgs {
                to: name.to_owned(),
                bundle: work.bundle(),
                signed_qualification: signed.join("signed-qualification.json"),
                qualification_report: signed.join("qualification-report.json"),
                staging_receipt: self.staging_receipt(observation)?,
                trusted_keys: keys::trusted(config)?,
                qualification_keys: keys::role_specs(config, SignerRole::Qualification)?,
                output,
            },
            self.printer,
        )
    }

    /// Signs the release's immutable TUF set at the surface's next versions.
    pub(super) async fn tuf(&self, destination: &PlannedDestination) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let trust = require_tuf(config)?;

        let served = self.served_tuf(destination, true).await?;
        let planned = session.plan.surface(destination.surface)?;
        let mut state = SurfaceTufState::from_served(
            &session.plan.registry,
            name,
            &planned.identity,
            served.timestamp.as_deref(),
            served.snapshot.as_deref(),
        )?;
        state.metadata_version = self
            .last_occupied_version(destination, state.metadata_version)
            .await?;
        let version = state.next_metadata_version()?;
        let now = SystemTime::now();
        let delegated_role = TufRole::for_release(session.plan.release_class).signer_role();

        let output = work.tuf_metadata(name);
        create_parent(&output)?;
        tuf::run(
            &ReleaseTufArgs {
                release_record: (destination.surface == SurfaceRole::Production)
                    .then(|| work.release_record(name)),
                plan: work.plan(),
                bundle: work.bundle(),
                manifest_keys: keys::trusted(config)?,
                root: trust.root.clone(),
                previous_root: None,
                trusted_root_keys: trust.trusted_root_keys.clone(),
                trusted_root_threshold: trust.trusted_root_threshold,
                targets_keys: threshold_specs(config, SignerRole::TufTargets)?,
                delegated_keys: threshold_specs(config, delegated_role)?,
                snapshot_keys: threshold_specs(config, SignerRole::TufSnapshot)?,
                signer_executable: config.signer.executable.clone(),
                signer_config: config.signer.config.clone(),
                signer_timeout_seconds: config.signer.timeout_seconds,
                targets_version: version,
                delegated_version: version,
                snapshot_version: version,
                targets_expires: format_time(later(now, TARGETS_VALIDITY)?),
                delegated_expires: format_time(later(now, TARGETS_VALIDITY)?),
                snapshot_expires: format_time(later(now, SNAPSHOT_VALIDITY)?),
                now: format_time(now),
                output,
            },
            self.printer,
        )
        .await?;

        // Recorded after the set exists: it documents where the versions came
        // from, and a failed attempt observes the surface afresh.
        workdir::write_new_json(&work.surface_tuf_state(name), &state)
    }

    /// Signs the timestamp that moves the surface to the release's snapshot.
    ///
    /// The previous timestamp is read back from the surface now, not when the
    /// metadata was signed, so a routine renewal in between is continued
    /// rather than overwritten.
    pub(super) async fn refresh_timestamp(&self, destination: &PlannedDestination) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let trust = require_tuf(config)?;

        let attempt = work.timestamp_attempt(name);
        if attempt.exists() {
            // A previous refresh failed before signing; keep it for audit.
            retire(work, &attempt, self.printer)?;
        }
        fs::create_dir_all(&attempt)?;
        let served = self.served_tuf(destination, false).await?;
        let previous = match &served.timestamp {
            Some(bytes) => {
                let path = work.previous_timestamp(name);
                workdir::write_new_file(&path, bytes)?;
                Some(path)
            }
            None => None,
        };
        let metadata = MetadataFiles::find(&work.tuf_metadata(name), &session.plan)?;
        let now = SystemTime::now();

        timestamp::run(
            &ReleaseTimestampCommand::Refresh(ReleaseTimestampRefreshArgs {
                to: name.to_owned(),
                plan: work.plan(),
                root: metadata.root,
                snapshot: metadata.snapshot,
                previous_timestamp: previous,
                trusted_root_keys: trust.trusted_root_keys.clone(),
                trusted_root_threshold: trust.trusted_root_threshold,
                signing_keys: threshold_specs(config, SignerRole::TufTimestamp)?,
                signer_executable: config.signer.executable.clone(),
                signer_config: config.signer.config.clone(),
                signer_timeout_seconds: config.signer.timeout_seconds,
                version: next_timestamp_version(served.timestamp.as_deref())?,
                issued_at: format_time(now),
                expires: format_time(later(now, TIMESTAMP_VALIDITY)?),
                output: work.refreshed_timestamp(name),
            }),
            self.printer,
        )
        .await
    }

    /// Moves an expiring timestamp attempt aside so it is signed again.
    pub(super) fn retire_timestamp(&self, destination: &PlannedDestination) -> Result<()> {
        let work = &self.session.work;
        retire(
            work,
            &work.timestamp_attempt(&destination.name),
            self.printer,
        )
    }

    /// Composes the complete surface and the immutable overlay `step publish` uploads.
    pub(super) fn compose_surface(&self, destination: &PlannedDestination) -> Result<()> {
        let session = self.session;
        let config = &session.config;
        let work = &session.work;
        let name = destination.name.as_str();
        let trust = require_tuf(config)?;
        let composed = work.composed_surface(name);

        if !composed.exists() {
            let refreshed = work.refreshed_timestamp(name);
            let previous_version = previous_version(&refreshed)?;
            let metadata = MetadataFiles::find(&work.tuf_metadata(name), &session.plan)?;

            // The composed surface is the complete registry surface `step
            // timestamp publish` needs: the projected bundle plus metadata.
            let trusted_keys = keys::trusted(config)?;
            let bundle = verify::verified_bundle(&work.bundle(), &trusted_keys)?;
            let projection = project::plan_projection(&work.bundle(), &bundle.manifest.payload)?;
            let projected = project::materialize(
                &work.bundle(),
                &bundle.captured.files,
                &projection,
                &bundle.captured.manifest_bytes,
                None,
            )?;
            compose_surface::run(
                &ReleaseComposeSurfaceArgs {
                    to: name.to_owned(),
                    release_record: (destination.surface == SurfaceRole::Production)
                        .then(|| work.release_record(name)),
                    plan: work.plan(),
                    bundle: work.bundle(),
                    manifest_keys: trusted_keys,
                    base_surface: projected.root().to_path_buf(),
                    root: metadata.root,
                    previous_root: None,
                    targets: metadata.targets,
                    delegated: metadata.delegated,
                    snapshot: metadata.snapshot,
                    timestamp: refreshed,
                    trusted_root_keys: trust.trusted_root_keys.clone(),
                    trusted_root_threshold: trust.trusted_root_threshold,
                    previous_timestamp_version: previous_version,
                    now: format_time(SystemTime::now()),
                    output: composed.clone(),
                },
                self.printer,
            )?;
        }

        let overlay = work.surface_overlay(name);
        if !overlay.exists() {
            write_overlay(&composed, &overlay, &session.plan)?;
        }
        Ok(())
    }

    /// Replaces the surface's timestamp with the attempt's signed timestamp.
    pub(super) async fn publish_timestamp(&self, destination: &PlannedDestination) -> Result<()> {
        let session = self.session;
        let work = &session.work;
        let name = destination.name.as_str();
        let trust = require_tuf(&session.config)?;
        let refreshed = work.refreshed_timestamp(name);
        let metadata = MetadataFiles::find(&work.tuf_metadata(name), &session.plan)?;
        timestamp::run(
            &ReleaseTimestampCommand::Publish(ReleaseTimestampPublishArgs {
                to: name.to_owned(),
                plan: work.plan(),
                root: metadata.root,
                snapshot: metadata.snapshot,
                previous_version: previous_version(&refreshed)?,
                timestamp: refreshed,
                trusted_root_keys: trust.trusted_root_keys.clone(),
                trusted_root_threshold: trust.trusted_root_threshold,
                registry_surface: work.composed_surface(name),
                token: None,
                config: Some(session.config_path.clone()),
                output: work.timestamp_publication(name),
            }),
            self.printer,
        )
        .await
    }

    /// Reads the surface's served timestamp (and its snapshot) anonymously.
    async fn served_tuf(
        &self,
        destination: &PlannedDestination,
        with_snapshot: bool,
    ) -> Result<ServedTuf> {
        let session = self.session;
        let planned = session.plan.surface(destination.surface)?;
        let client = access::connect(
            &session.plan,
            destination.surface,
            None,
            Some(&session.config_path),
            SignerNeed::None,
        )
        .await?;
        client.verify_identity().await?;

        let public = readback::public_client()?;
        let base = public_base(planned, &session.plan.registry)?;
        let timestamp =
            readback::fetch_small(&public, &base, TIMESTAMP_PATH, MAX_METADATA_BYTES).await?;
        let snapshot = match (&timestamp, with_snapshot) {
            (Some(bytes), true) => {
                let described = parse_timestamp(bytes, "served TUF timestamp")?;
                let path = format!("tuf/{}", described.signed.snapshot.path);
                Some(
                    readback::fetch_small(&public, &base, &path, MAX_METADATA_BYTES)
                        .await?
                        .with_context(|| format!("surface serves no {path}"))?,
                )
            }
            _ => None,
        };
        client.verify_identity().await?;
        Ok(ServedTuf {
            timestamp,
            snapshot,
        })
    }

    /// Returns the highest metadata version at or after `served` that the
    /// surface already occupies.
    ///
    /// The timestamp names only the snapshot readers trust. A release whose
    /// publication committed before its timestamp moved leaves later targets
    /// and snapshot files behind, and those immutable paths cannot be reused.
    async fn last_occupied_version(
        &self,
        destination: &PlannedDestination,
        served: u64,
    ) -> Result<u64> {
        let session = self.session;
        let planned = session.plan.surface(destination.surface)?;
        let public = readback::public_client()?;
        let base = public_base(planned, &session.plan.registry)?;

        let mut occupied = served;
        for _ in 0..MAX_ABANDONED_VERSIONS {
            let next = occupied
                .checked_add(1)
                .context("surface TUF metadata version overflowed")?;
            if !version_is_occupied(&public, &base, next).await? {
                return Ok(occupied);
            }
            self.printer.info(&format!(
                "Skipping TUF metadata version {next}, which an unfinished release already occupies"
            ));
            occupied = next;
        }
        bail!("surface holds more than {MAX_ABANDONED_VERSIONS} abandoned TUF metadata versions")
    }
}

/// Reports whether the surface serves targets or snapshot metadata at `version`.
async fn version_is_occupied(
    public: &reqwest::Client,
    base: &url::Url,
    version: u64,
) -> Result<bool> {
    for role in ["targets", "snapshot"] {
        let path = format!("tuf/{version}.{role}.json");
        if readback::fetch_small(public, base, &path, MAX_METADATA_BYTES)
            .await?
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// TUF bytes a surface serves anonymously.
struct ServedTuf {
    /// `tuf/timestamp.json`, when served.
    timestamp: Option<Vec<u8>>,
    /// The snapshot the timestamp names, when requested.
    snapshot: Option<Vec<u8>>,
}

/// Paths of one immutable TUF metadata set written by `step tuf`.
struct MetadataFiles {
    root: PathBuf,
    targets: PathBuf,
    delegated: PathBuf,
    snapshot: PathBuf,
}

impl MetadataFiles {
    /// Finds the single `<version>.<role>.json` file of each role in `directory`.
    fn find(directory: &Path, plan: &ReleasePlan) -> Result<Self> {
        let delegated_role = TufRole::for_release(plan.release_class).as_str();
        let mut found: [Option<PathBuf>; 4] = Default::default();
        for entry in fs::read_dir(directory)
            .with_context(|| format!("reading TUF metadata {}", directory.display()))?
        {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some((version, role)) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .and_then(|name| name.split_once('.'))
            else {
                bail!("unexpected TUF metadata file {}", entry.path().display());
            };
            if version.parse::<u64>().is_err() {
                bail!("unexpected TUF metadata file {}", entry.path().display());
            }
            let slot = match role {
                "root" => 0,
                "targets" => 1,
                role if role == delegated_role => 2,
                "snapshot" => 3,
                _ => bail!("unexpected TUF metadata file {}", entry.path().display()),
            };
            if found[slot].replace(entry.path()).is_some() {
                bail!("{} holds more than one {role} file", directory.display());
            }
        }
        let [Some(root), Some(targets), Some(delegated), Some(snapshot)] = found else {
            bail!("{} is not a complete TUF metadata set", directory.display());
        };
        Ok(Self {
            root,
            targets,
            delegated,
            snapshot,
        })
    }
}

/// Returns the anonymous read-back root of a surface's registry objects.
///
/// Hub objects live below `<hub>/<registry>/`; a static surface's read-back
/// origin is the registry root itself.
fn public_base(planned: &PlannedSurface, registry: &str) -> Result<url::Url> {
    match planned.kind {
        SurfaceKind::Hub => readback::base_url(&format!(
            "{}/{registry}",
            planned.origin.trim_end_matches('/')
        )),
        SurfaceKind::Static => readback::base_url(planned.readback()),
    }
}

/// Returns the `[tuf]` trust inputs the TUF steps need.
fn require_tuf(config: &MaintainerConfig) -> Result<&TufConfig> {
    config
        .tuf
        .as_ref()
        .context("maintainer configuration has no [tuf] section")
}

/// Returns `KEY_ID=PATH` for exactly a role's threshold of configured keys.
fn threshold_specs(config: &MaintainerConfig, role: SignerRole) -> Result<Vec<String>> {
    Ok(keys::threshold(config, role)?
        .iter()
        .map(keys::spec)
        .collect())
}

/// Returns the version the attempt's timestamp replaces on the surface.
fn previous_version(refreshed: &Path) -> Result<u64> {
    let bytes = super::super::capture::control_file(refreshed, "refreshed TUF timestamp")?;
    parse_timestamp(&bytes, "refreshed TUF timestamp")?
        .signed
        .version
        .checked_sub(1)
        .context("refreshed TUF timestamp has version zero")
}

/// Parses a canonical signed timestamp envelope.
fn parse_timestamp(bytes: &[u8], label: &str) -> Result<TufEnvelopeV1<TimestampMetadataV1>> {
    canonical::require_canonical(bytes, label)?;
    canonical::from_slice(bytes, label)
}

/// Returns `now + validity`.
fn later(now: SystemTime, validity: Duration) -> Result<SystemTime> {
    now.checked_add(validity)
        .context("metadata expiry overflowed the clock")
}

/// Creates the parent directory of a leaf output.
fn create_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Moves `path` to the first free `<name>.retired-<n>` beside it.
fn retire(work: &WorkDir, path: &Path, printer: &aos_cli_ui::output::Printer) -> Result<()> {
    let parent = path.parent().context("retired path has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("retired path has no UTF-8 name")?;
    let target = (1..=u32::MAX)
        .map(|attempt| parent.join(format!("{name}.retired-{attempt}")))
        .find(|candidate| !candidate.exists())
        .context("no free retired-attempt name")?;
    workdir::rename_noreplace(path, &target)?;
    printer.info(&format!(
        "Retired {} to {}; it will be signed again",
        work.relative(path),
        work.relative(&target)
    ));
    Ok(())
}

/// Copies the immutable publication files of a composed surface into `overlay`.
///
/// The overlay holds the TUF metadata except the mutable timestamp, the
/// release manifest at its delegated path, and the release record when one
/// was composed. It is built privately and exposed with a no-replace rename.
fn write_overlay(composed: &Path, overlay: &Path, plan: &ReleasePlan) -> Result<()> {
    let parent = overlay.parent().context("overlay path has no parent")?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-overlay-")
        .tempdir_in(parent)?;
    let staged = temporary.path().join("overlay");

    let tuf = composed.join("tuf");
    for entry in fs::read_dir(&tuf).with_context(|| format!("reading {}", tuf.display()))? {
        let entry = entry?;
        let relative = Path::new("tuf").join(entry.file_name());
        if relative == Path::new(TIMESTAMP_PATH) {
            continue;
        }
        copy_regular(composed, &staged, &relative)?;
    }
    let prefix = format!(
        "releases/{}/{}",
        TufRole::for_release(plan.release_class).as_str(),
        plan.version
    );
    copy_regular(
        composed,
        &staged,
        Path::new(&format!("{prefix}/release-manifest.json")),
    )?;
    let record = aos_release_format::record::record_path(plan.release_class, &plan.version);
    if composed.join(&record).exists() {
        copy_regular(composed, &staged, Path::new(&record))?;
    }

    workdir::rename_noreplace(&staged, overlay)
}

/// Copies one regular file at `relative` from `source` to `destination`.
fn copy_regular(source: &Path, destination: &Path, relative: &Path) -> Result<()> {
    let from = source.join(relative);
    if !fs::symlink_metadata(&from)
        .with_context(|| format!("reading {}", from.display()))?
        .is_file()
    {
        bail!(
            "composed surface object {} is not a regular file",
            relative.display()
        );
    }
    let to = destination.join(relative);
    create_parent(&to)?;
    fs::copy(&from, &to).with_context(|| format!("copying {}", relative.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_release_format::registry::EXPERIMENTAL_REGISTRY;
    use aos_release_format::tuf::{
        RootMetadataV1, TUF_ROOT_V1, TUF_SPEC_VERSION, canonical_targets_metadata,
        immutable_snapshot_metadata, timestamp_metadata,
    };

    use super::*;

    /// Returns canonical bytes of a served timestamp at `version` and its snapshot.
    fn served(
        version: u64,
        snapshot_version: u64,
        targets_version: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let root = TufEnvelopeV1 {
            signed: RootMetadataV1 {
                schema_version: TUF_ROOT_V1.to_owned(),
                spec_version: TUF_SPEC_VERSION.to_owned(),
                registry: EXPERIMENTAL_REGISTRY.to_owned(),
                version: 3,
                expires: "2030-01-01T00:00:00Z".to_owned(),
                consistent_snapshot: true,
                keys: Vec::new(),
                roles: Vec::new(),
            },
            signatures: Vec::new(),
        };
        let targets = TufEnvelopeV1 {
            signed: canonical_targets_metadata(
                EXPERIMENTAL_REGISTRY,
                targets_version,
                "2030-01-01T00:00:00Z".to_owned(),
            )?,
            signatures: Vec::new(),
        };
        let delegated = TufEnvelopeV1 {
            signed: aos_release_format::tuf::delegated_release_metadata(
                EXPERIMENTAL_REGISTRY,
                snapshot_version,
                "2030-01-01T00:00:00Z".to_owned(),
                aos_release_format::tuf::TufReleaseTargetV1 {
                    path: "releases/edge/2026.9.0/release-manifest.json".to_owned(),
                    release_id: "release-2026.9.0".to_owned(),
                    release_class: aos_release_format::plan::ReleaseClass::Edge,
                    manifest_digest: Sha256Digest::of_bytes("manifest"),
                    length: 10,
                    record: None,
                },
            )?,
            signatures: Vec::new(),
        };
        let snapshot = TufEnvelopeV1 {
            signed: immutable_snapshot_metadata(
                EXPERIMENTAL_REGISTRY,
                snapshot_version,
                "2030-01-01T00:00:00Z".to_owned(),
                &root,
                &targets,
                &delegated,
            )?,
            signatures: Vec::new(),
        };
        let timestamp = TufEnvelopeV1 {
            signed: timestamp_metadata(
                EXPERIMENTAL_REGISTRY,
                version,
                "2029-12-30T00:00:00Z".to_owned(),
                "2029-12-31T00:00:00Z".to_owned(),
                &snapshot,
            )?,
            signatures: Vec::new(),
        };
        Ok((
            canonical::to_vec(&timestamp)?,
            canonical::to_vec(&snapshot)?,
        ))
    }

    fn state(timestamp: Option<&[u8]>, snapshot: Option<&[u8]>) -> Result<SurfaceTufState> {
        SurfaceTufState::from_served(
            EXPERIMENTAL_REGISTRY,
            "production/edge",
            "cdn-2026-09",
            timestamp,
            snapshot,
        )
    }

    #[tokio::test]
    async fn abandoned_targets_or_snapshot_metadata_occupies_its_version() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::create_dir_all(root.path().join("tuf"))?;
        std::fs::write(root.path().join("tuf/1.root.json"), b"root")?;
        std::fs::write(root.path().join("tuf/1.targets.json"), b"targets")?;
        std::fs::write(root.path().join("tuf/2.snapshot.json"), b"snapshot")?;
        let base = readback::base_url(&format!("file://{}", root.path().display()))?;
        let public = readback::public_client()?;

        assert!(version_is_occupied(&public, &base, 1).await?);
        assert!(version_is_occupied(&public, &base, 2).await?);
        // A root file alone never claims a release version.
        assert!(!version_is_occupied(&public, &base, 3).await?);
        Ok(())
    }

    #[test]
    fn a_surface_without_tuf_metadata_starts_at_version_one() -> Result<()> {
        let empty = state(None, None)?;
        assert_eq!(empty.timestamp_version, 0);
        assert_eq!(empty.next_metadata_version()?, 1);
        assert_eq!(next_timestamp_version(None)?, 1);
        Ok(())
    }

    #[test]
    fn a_surface_at_timestamp_version_n_produces_n_plus_one() -> Result<()> {
        let (timestamp, snapshot) = served(86, 44, 43)?;
        let observed = state(Some(&timestamp), Some(&snapshot))?;
        assert_eq!(observed.timestamp_version, 86);
        assert_eq!(observed.snapshot_version, 44);
        assert_eq!(observed.next_metadata_version()?, 45);
        assert_eq!(next_timestamp_version(Some(&timestamp))?, 87);
        Ok(())
    }

    #[test]
    fn metadata_versions_advance_past_every_served_non_root_role() -> Result<()> {
        // A targets version above the snapshot's still bounds the next version;
        // the root's version (3) never does.
        let (timestamp, snapshot) = served(2, 1, 9)?;
        assert_eq!(
            state(Some(&timestamp), Some(&snapshot))?.next_metadata_version()?,
            10
        );
        Ok(())
    }

    #[test]
    fn served_snapshots_must_match_the_timestamp_description() -> Result<()> {
        let (timestamp, _) = served(86, 44, 43)?;
        let (_, other) = served(86, 45, 43)?;
        assert!(state(Some(&timestamp), Some(&other)).is_err());
        assert!(state(Some(&timestamp), None).is_err());
        assert!(
            SurfaceTufState::from_served(
                "andyl/main",
                "production/edge",
                "cdn-2026-09",
                Some(&timestamp),
                Some(&served(86, 44, 43)?.1),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn missing_tuf_configuration_is_named() -> Result<()> {
        let fixture = super::super::testing::config_fixture()?;
        let mut config = fixture.config.clone();
        assert!(
            missing_config(&config, ReleaseClass::Edge).is_some_and(|key| key.starts_with("[tuf]"))
        );

        config.tuf = Some(TufConfig {
            root: fixture.directory.path().join("root.json"),
            trusted_root_keys: vec!["root-v1=/keys/root-v1.pub".to_owned()],
            trusted_root_threshold: 1,
        });
        assert_eq!(missing_config(&config, ReleaseClass::Edge), None);
        assert_eq!(
            missing_config(&config, ReleaseClass::Stable).as_deref(),
            Some("[signer.roles.tuf-stable]")
        );

        config.signer.roles.remove("tuf-snapshot");
        assert_eq!(
            missing_config(&config, ReleaseClass::Edge).as_deref(),
            Some("[signer.roles.tuf-snapshot]")
        );
        Ok(())
    }
}
