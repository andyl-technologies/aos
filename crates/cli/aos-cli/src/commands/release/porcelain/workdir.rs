//! The per-release work directory driven by the porcelain.
//!
//! `aos maintain release new` creates `<work_root>/<release_id>/`; every later
//! porcelain command selects it with `--work DIR`, or else the newest release
//! under the configuration's `work_root`. Leaf commands write their outputs
//! into this tree without replacing an existing path; the only file the
//! driver rewrites is the `release.toml` index (and the `journal.jsonl`
//! convenience link beside it).
//!
//! ```text
//! release.toml                     index: registry, version, release_id,
//!                                  config digest, created_at, latest_journal
//! request.json, plan.json          derived request and frozen plan
//! plan.superseded-<n>.json         plans replaced by an accepted override
//! contract.json                    exported contract the request binds
//! contributor-authorization.json   public summary bound by the plan
//! inputs/source-registry/          operator: clean authoring registry at the base
//! inputs/container/                operator: signed OCI release bundle
//! inputs/advisory-disposition.json operator: reviewed advisory disposition
//! bootstrap/<role>/                operator: step bootstrap output of a first
//!                                  release (signed-intents/, bootstrap-evidence.json)
//! build/                           build report, SBOM, build journal
//! images/<platform>/<variant>/     finalize-image work, finalized/ output
//! registry/prepared/               isolated registry (finalized in place)
//! registry/transaction.json        transaction for operator review
//! registry/transaction-accepted.json
//! registry/result.json             finalize-registry result
//! cache/                           signed static cache
//! assembled/                       payload and unsigned manifest payload
//! finalized/{bundle,release-journal.jsonl}
//! verification.json                offline verification record
//! publish/<slug>/release-record.json
//!                                  step record (first production destination)
//! publish/<slug>/tuf/metadata/     step tuf at the surface's next versions
//! publish/<slug>/tuf/surface-state.json
//!                                  surface TUF state the versions came from
//! publish/<slug>/timestamp/        one timestamp attempt, retired as a unit:
//!                                  previous-timestamp.json (served), timestamp.json
//!                                  (step timestamp refresh), surface/ (step
//!                                  compose-surface), overlay/ (immutable subset
//!                                  step publish uploads), published/ (step
//!                                  timestamp publish)
//! publish/<slug>/timestamp.retired-<n>/
//! publish/<slug>/published/        receipt.json, release-journal.jsonl
//! qualification/<slug>/<phase>/    prepared/, review-<key>.json, signed/
//! qualification/<slug>/<phase>.retired-<n>/
//! channels/<slug>/ring-<n>/        channel-receipt.json, release-journal.jsonl
//! channels/<slug>/completion-<key>.json
//! channels/<slug>/complete/        completion evidence and journal
//! journal.jsonl                    link to the latest journal
//! ```
//!
//! `<slug>` is the destination name with `/` replaced by `-`, for example
//! `production-stable`; `<phase>` is `staging`, `rollout-<ring>`, or
//! `complete`.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::plan::{ReleasePlan, SurfaceRole};
use aos_release_format::platform::Platform;
use serde::{Deserialize, Serialize};

use super::super::capture;
use super::super::config::MaintainerConfig;
use super::super::journal::Journal;

/// Exact schema identifier of the work-directory index.
pub(super) const WORK_INDEX: &str = "aos.release.work-index/v1";

/// Name of the index file at the root of every work directory.
const INDEX_FILE: &str = "release.toml";

/// Name of the convenience link to the latest journal.
const JOURNAL_LINK: &str = "journal.jsonl";

/// Contents of `release.toml`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseIndex {
    /// Exact index schema identifier.
    pub(super) schema_version: String,
    /// Registry the release publishes.
    pub(super) registry: String,
    /// Calendar release version.
    pub(super) version: String,
    /// Immutable release identity.
    pub(super) release_id: String,
    /// SHA-256 of the maintainer configuration bytes `new` read.
    pub(super) config_digest: String,
    /// RFC 3339 UTC creation time.
    pub(super) created_at: String,
    /// Work-relative path of the newest verified journal, once one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_journal: Option<String>,
}

/// A qualification hold point of one destination.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Phase {
    /// Observations over the staging surface before production publication.
    Staging,
    /// Fresh health observations before one rollout ring.
    Rollout(u16),
    /// Observations after the soak, before completion.
    Complete,
}

impl Phase {
    /// Returns the directory name of the phase below `qualification/<slug>/`.
    pub(super) fn directory_name(self) -> String {
        match self {
            Self::Staging => "staging".to_owned(),
            Self::Rollout(ring) => format!("rollout-{ring}"),
            Self::Complete => "complete".to_owned(),
        }
    }

    /// Returns the leaf command's `--phase` spelling.
    pub(super) const fn leaf_phase(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Rollout(_) => "rollout",
            Self::Complete => "complete",
        }
    }

    /// Returns the library hold point.
    pub(super) const fn qualification_phase(
        self,
    ) -> aos_release_format::qualification::QualificationPhase {
        match self {
            Self::Staging => aos_release_format::qualification::QualificationPhase::Staging,
            Self::Rollout(_) => aos_release_format::qualification::QualificationPhase::Rollout,
            Self::Complete => aos_release_format::qualification::QualificationPhase::Complete,
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Staging => formatter.write_str("staging"),
            Self::Rollout(ring) => write!(formatter, "rollout ring {ring}"),
            Self::Complete => formatter.write_str("complete"),
        }
    }
}

/// Returns the directory-safe spelling of a destination name.
///
/// `production/stable` becomes `production-stable`. Destination names are
/// `<role>/<channel>` and channels contain no `/`, so the mapping is
/// injective over planned destinations.
pub(super) fn destination_slug(destination: &str) -> String {
    destination.replace('/', "-")
}

/// One release work directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WorkDir {
    root: PathBuf,
}

impl WorkDir {
    /// Wraps a work directory path, made absolute against the current directory.
    ///
    /// # Errors
    /// Returns an error when the current directory cannot be determined.
    pub(super) fn new(root: &Path) -> Result<Self> {
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()
                .context("resolving the work directory")?
                .join(root)
        };
        Ok(Self { root })
    }

    /// Selects `explicit`, or the newest release directory under `work_root`.
    ///
    /// # Errors
    /// Returns an error when no release exists under `work_root` or an
    /// explicit directory has no index.
    pub(super) fn select(config: &MaintainerConfig, explicit: Option<&Path>) -> Result<Self> {
        let work = match explicit {
            Some(path) => Self::new(path)?,
            None => newest_release(&config.work_root)?,
        };
        if !work.index_path().exists() {
            bail!(
                "{} is not a release work directory (no {INDEX_FILE}); run aos maintain release new",
                work.root.display()
            );
        }
        Ok(work)
    }

    /// Returns the work directory root.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// Returns a work-relative path joined onto the root.
    pub(super) fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.join(relative)
    }

    /// Returns the path of `release.toml`.
    pub(super) fn index_path(&self) -> PathBuf {
        self.join(INDEX_FILE)
    }

    /// Returns the derived plan request path.
    pub(super) fn request(&self) -> PathBuf {
        self.join("request.json")
    }

    /// Returns the frozen plan path.
    pub(super) fn plan(&self) -> PathBuf {
        self.join("plan.json")
    }

    /// Returns the exported contract path.
    pub(super) fn contract(&self) -> PathBuf {
        self.join("contract.json")
    }

    /// Returns the contributor-authorization copy bound by the plan.
    pub(super) fn contributor_authorization(&self) -> PathBuf {
        self.join("contributor-authorization.json")
    }

    /// Returns the operator-supplied clean authoring registry.
    pub(super) fn source_registry(&self) -> PathBuf {
        self.join("inputs/source-registry")
    }

    /// Returns the `step bootstrap` output of a first release on one surface.
    pub(super) fn bootstrap(&self, role: SurfaceRole) -> PathBuf {
        self.join(format!("bootstrap/{role}"))
    }

    /// Returns the operator-supplied signed OCI release bundle.
    pub(super) fn container(&self) -> PathBuf {
        self.join("inputs/container")
    }

    /// Returns the operator-supplied reviewed advisory disposition.
    pub(super) fn advisory_disposition(&self) -> PathBuf {
        self.join("inputs/advisory-disposition.json")
    }

    /// Returns the build evidence directory.
    pub(super) fn build(&self) -> PathBuf {
        self.join("build")
    }

    /// Returns the build report path.
    pub(super) fn build_report(&self) -> PathBuf {
        self.join("build/evidence/build-report.json")
    }

    /// Returns the SPDX document path.
    pub(super) fn sbom(&self) -> PathBuf {
        self.join("build/evidence/sbom.spdx.json")
    }

    /// Returns the build journal path.
    pub(super) fn build_journal(&self) -> PathBuf {
        self.join("build/release-journal.jsonl")
    }

    /// Returns the private finalize-image work directory of one image cell.
    pub(super) fn image_work(&self, platform: Platform, system_variant: &str) -> PathBuf {
        self.join("images")
            .join(platform.as_str())
            .join(system_variant)
    }

    /// Returns the prepared (and later finalized) isolated registry.
    pub(super) fn registry(&self) -> PathBuf {
        self.join("registry/prepared")
    }

    /// Returns the generated registry transaction.
    pub(super) fn transaction(&self) -> PathBuf {
        self.join("registry/transaction.json")
    }

    /// Returns the operator's recorded transaction acceptance.
    pub(super) fn transaction_acceptance(&self) -> PathBuf {
        self.join("registry/transaction-accepted.json")
    }

    /// Returns the registry finalization result.
    pub(super) fn registry_result(&self) -> PathBuf {
        self.join("registry/result.json")
    }

    /// Returns the signed static cache.
    pub(super) fn cache(&self) -> PathBuf {
        self.join("cache")
    }

    /// Returns the assembled payload directory.
    pub(super) fn assembled(&self) -> PathBuf {
        self.join("assembled")
    }

    /// Returns the finalized output directory.
    pub(super) fn finalized(&self) -> PathBuf {
        self.join("finalized")
    }

    /// Returns the closed signed bundle.
    pub(super) fn bundle(&self) -> PathBuf {
        self.join("finalized/bundle")
    }

    /// Returns the finalized journal.
    pub(super) fn finalized_journal(&self) -> PathBuf {
        self.join("finalized/release-journal.jsonl")
    }

    /// Returns the offline verification record.
    pub(super) fn verification(&self) -> PathBuf {
        self.join("verification.json")
    }

    /// Returns immutable upload evidence retained before a destination is published.
    pub(super) fn staged_upload(&self, destination: &str) -> PathBuf {
        self.join("publish")
            .join(destination_slug(destination))
            .join("uploaded")
    }

    /// Returns the durable evidence for an uploaded unpublished candidate.
    pub(super) fn staged_upload_record(&self, destination: &str) -> PathBuf {
        self.staged_upload(destination).join("staged-upload.json")
    }

    /// Returns the publication output of one destination.
    pub(super) fn published(&self, destination: &str) -> PathBuf {
        self.join("publish")
            .join(destination_slug(destination))
            .join("published")
    }

    /// Returns the publication directory of one destination.
    fn publication_root(&self, destination: &str) -> PathBuf {
        self.join("publish").join(destination_slug(destination))
    }

    /// Returns the public release record written by `step record`.
    pub(super) fn release_record(&self, destination: &str) -> PathBuf {
        self.publication_root(destination)
            .join("release-record.json")
    }

    /// Returns the immutable TUF metadata set written by `step tuf`.
    pub(super) fn tuf_metadata(&self, destination: &str) -> PathBuf {
        self.publication_root(destination).join("tuf/metadata")
    }

    /// Returns the surface TUF state the metadata versions were derived from.
    pub(super) fn surface_tuf_state(&self, destination: &str) -> PathBuf {
        self.publication_root(destination)
            .join("tuf/surface-state.json")
    }

    /// Returns the current timestamp attempt of a destination.
    ///
    /// Everything derived from one signed timestamp lives here, so an expired
    /// or superseded attempt is retired with a single rename.
    pub(super) fn timestamp_attempt(&self, destination: &str) -> PathBuf {
        self.publication_root(destination).join("timestamp")
    }

    /// Returns the timestamp the surface served when the attempt was signed.
    pub(super) fn previous_timestamp(&self, destination: &str) -> PathBuf {
        self.timestamp_attempt(destination)
            .join("previous-timestamp.json")
    }

    /// Returns the timestamp signed by `step timestamp refresh`.
    pub(super) fn refreshed_timestamp(&self, destination: &str) -> PathBuf {
        self.timestamp_attempt(destination).join("timestamp.json")
    }

    /// Returns the complete surface written by `step compose-surface`.
    pub(super) fn composed_surface(&self, destination: &str) -> PathBuf {
        self.timestamp_attempt(destination).join("surface")
    }

    /// Returns the immutable overlay `step publish --surface` uploads.
    pub(super) fn surface_overlay(&self, destination: &str) -> PathBuf {
        self.timestamp_attempt(destination).join("overlay")
    }

    /// Returns the output of `step timestamp publish`.
    pub(super) fn timestamp_publication(&self, destination: &str) -> PathBuf {
        self.timestamp_attempt(destination).join("published")
    }

    /// Returns one destination's publication receipt.
    pub(super) fn publication_receipt(&self, destination: &str) -> PathBuf {
        self.published(destination).join("receipt.json")
    }

    /// Returns one destination's qualification directory for a phase.
    pub(super) fn phase(&self, destination: &str, phase: Phase) -> PathBuf {
        self.join("qualification")
            .join(destination_slug(destination))
            .join(phase.directory_name())
    }

    /// Returns one destination's channel evidence directory.
    pub(super) fn channels(&self, destination: &str) -> PathBuf {
        self.join("channels").join(destination_slug(destination))
    }

    /// Returns the channel-advance output of one ring.
    pub(super) fn ring(&self, destination: &str, ring: u16) -> PathBuf {
        self.channels(destination).join(format!("ring-{ring}"))
    }

    /// Returns the channel receipt of one ring.
    pub(super) fn ring_receipt(&self, destination: &str, ring: u16) -> PathBuf {
        self.ring(destination, ring).join("channel-receipt.json")
    }

    /// Returns the completion output of one destination.
    pub(super) fn completion(&self, destination: &str) -> PathBuf {
        self.channels(destination).join("complete")
    }

    /// Returns one reviewer's completion approval of a destination.
    pub(super) fn completion_approval(&self, destination: &str, key_id: &str) -> PathBuf {
        self.channels(destination)
            .join(format!("completion-{key_id}.json"))
    }

    /// Returns a work-relative display string for `path`.
    pub(super) fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .display()
            .to_string()
    }

    /// Reads and validates `release.toml`.
    ///
    /// # Errors
    /// Returns an error for an unreadable, malformed, or foreign index.
    pub(super) fn read_index(&self) -> Result<ReleaseIndex> {
        let bytes = capture::control_file(&self.index_path(), "release index")?;
        let text = std::str::from_utf8(&bytes).context("release index is not UTF-8")?;
        let index: ReleaseIndex = toml::from_str(text).context("parsing release index")?;
        if index.schema_version != WORK_INDEX {
            bail!("unsupported release index schema: {}", index.schema_version);
        }
        Ok(index)
    }

    /// Creates `release.toml`; the index must not exist yet.
    ///
    /// # Errors
    /// Returns an error when the index exists or cannot be written.
    pub(super) fn create_index(&self, index: &ReleaseIndex) -> Result<()> {
        write_new_file(&self.index_path(), toml::to_string(index)?.as_bytes())
    }

    /// Records `journal` as the latest journal in the index and the link.
    ///
    /// The index is the only file the driver replaces; it is rewritten
    /// through a synced temporary file and an atomic rename.
    ///
    /// # Errors
    /// Returns an error when the index cannot be read or rewritten.
    pub(super) fn record_latest_journal(&self, journal: &Path) -> Result<()> {
        let mut index = self.read_index()?;
        let relative = self.relative(journal);
        if index.latest_journal.as_deref() == Some(relative.as_str()) {
            return Ok(());
        }
        index.latest_journal = Some(relative.clone());
        replace_file(&self.index_path(), toml::to_string(&index)?.as_bytes())?;
        self.refresh_journal_link(&relative)
    }

    /// Points `journal.jsonl` at the latest journal.
    fn refresh_journal_link(&self, relative: &str) -> Result<()> {
        let link = self.join(JOURNAL_LINK);
        let temporary = self.join(format!(".{JOURNAL_LINK}.tmp"));
        if temporary.symlink_metadata().is_ok() {
            fs::remove_file(&temporary)?;
        }
        std::os::unix::fs::symlink(relative, &temporary)
            .with_context(|| format!("linking {JOURNAL_LINK} to {relative}"))?;
        fs::rename(&temporary, &link).with_context(|| format!("installing {}", link.display()))?;
        Ok(())
    }

    /// Returns every journal a leaf command may have written, in step order.
    ///
    /// The list covers the build and finalize journals, every destination's
    /// publication, ring, and completion journals of `plan`.
    pub(super) fn journal_candidates(&self, plan: &ReleasePlan) -> Vec<PathBuf> {
        let mut candidates = vec![self.build_journal(), self.finalized_journal()];
        for destination in &plan.destinations {
            candidates.push(
                self.published(&destination.name)
                    .join("release-journal.jsonl"),
            );
            for ring in 1..=destination.rings.len() {
                if let Ok(ring) = u16::try_from(ring) {
                    candidates.push(
                        self.ring(&destination.name, ring)
                            .join("release-journal.jsonl"),
                    );
                }
            }
            candidates.push(
                self.completion(&destination.name)
                    .join("release-journal.jsonl"),
            );
        }
        candidates
    }

    /// Finds the newest journal of the release without writing anything.
    ///
    /// Every successor journal extends its input by exactly one or two
    /// entries, so the newest journal is the verified candidate with the
    /// most entries; every other candidate must be a prefix of it. A
    /// candidate that fails verification or diverges fails closed.
    /// [`WorkDir::record_latest_journal`] records the result in the index.
    ///
    /// # Errors
    /// Returns an error for an unreadable, invalid, diverging, or foreign
    /// journal.
    pub(super) fn latest_journal(&self, plan: &ReleasePlan) -> Result<Option<(PathBuf, Journal)>> {
        let mut journals = Vec::new();
        for path in self.journal_candidates(plan) {
            if !path.exists() {
                continue;
            }
            let journal = Journal::read(&path, "release journal")
                .with_context(|| format!("reading {}", self.relative(&path)))?;
            aos_release_format::verify::verify_journal_for_plan(plan, &journal.entries)
                .with_context(|| format!("verifying {}", self.relative(&path)))?;
            journals.push((path, journal));
        }
        let Some(newest) = journals
            .iter()
            .map(|(_, journal)| journal.entries.len())
            .max()
        else {
            return Ok(None);
        };
        let position = journals
            .iter()
            .position(|(_, journal)| journal.entries.len() == newest)
            .context("journal selection lost its newest candidate")?;
        let (path, journal) = journals.swap_remove(position);
        for (other, candidate) in &journals {
            if !journal.bytes.starts_with(&candidate.bytes) {
                bail!(
                    "{} diverges from the newest journal {}",
                    self.relative(other),
                    self.relative(&path)
                );
            }
        }
        Ok(Some((path, journal)))
    }
}

/// Returns the most recently created release directory under `work_root`.
fn newest_release(work_root: &Path) -> Result<WorkDir> {
    let mut newest: Option<(String, PathBuf)> = None;
    let entries = fs::read_dir(work_root)
        .with_context(|| format!("reading work root {}", work_root.display()))?;
    for entry in entries {
        let path = entry?.path();
        let work = WorkDir::new(&path)?;
        if !work.index_path().is_file() {
            continue;
        }
        let index = work
            .read_index()
            .with_context(|| format!("reading {}", work.index_path().display()))?;
        let key = format!("{}\u{0}{}", index.created_at, path.display());
        if newest.as_ref().is_none_or(|(best, _)| key > *best) {
            newest = Some((key, path));
        }
    }
    let (_, path) = newest.with_context(|| {
        format!(
            "no release under {}; run aos maintain release new or pass --work",
            work_root.display()
        )
    })?;
    WorkDir::new(&path)
}

/// Returns the SHA-256 identity of exact bytes, as `sha256:<hex>`.
pub(super) fn digest_string(bytes: &[u8]) -> String {
    Sha256Digest::of_bytes(bytes).to_string()
}

/// Writes canonical JSON to a new file.
///
/// # Errors
/// Returns an error when encoding fails or the file exists.
pub(super) fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_new_file(path, &canonical::to_vec(value)?)
}

/// Writes a new file through a synced temporary and a no-clobber rename.
///
/// # Errors
/// Returns an error when `path` exists or any write, sync, or rename fails.
pub(super) fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = parent_of(path);
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a temporary file beside {}", path.display()))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("installing new file {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Replaces a file through a synced temporary and an atomic rename.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = parent_of(path);
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Moves `from` to `to` without replacing an existing path.
///
/// # Errors
/// Returns an error when `to` exists or the rename fails.
pub(super) fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .with_context(|| format!("moving {} to {}", from.display(), to.display()))?;
    File::open(parent_of(to))?.sync_all()?;
    Ok(())
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(created_at: &str) -> ReleaseIndex {
        ReleaseIndex {
            schema_version: WORK_INDEX.to_owned(),
            registry: "andyl/experimental".to_owned(),
            version: "2026.9.0-dev.20260929.1".to_owned(),
            release_id: "release-2026.9.0-dev.20260929.1".to_owned(),
            config_digest: digest_string(b"config"),
            created_at: created_at.to_owned(),
            latest_journal: None,
        }
    }

    #[test]
    fn destination_slugs_replace_the_role_separator() {
        assert_eq!(destination_slug("production/stable"), "production-stable");
        assert_eq!(destination_slug("staging/edge"), "staging-edge");
        assert_eq!(
            destination_slug("production/stable-2026.3"),
            "production-stable-2026.3"
        );
    }

    #[test]
    fn layout_paths_follow_the_documented_tree() -> Result<()> {
        let work = WorkDir::new(Path::new("/work/release-1"))?;
        assert_eq!(
            work.publication_receipt("production/stable"),
            PathBuf::from("/work/release-1/publish/production-stable/published/receipt.json")
        );
        assert_eq!(
            work.phase("production/stable", Phase::Rollout(2)),
            PathBuf::from("/work/release-1/qualification/production-stable/rollout-2")
        );
        assert_eq!(
            work.ring_receipt("staging/edge", 1),
            PathBuf::from("/work/release-1/channels/staging-edge/ring-1/channel-receipt.json")
        );
        assert_eq!(
            work.completion_approval("production/stable", "evidence-1"),
            PathBuf::from("/work/release-1/channels/production-stable/completion-evidence-1.json")
        );
        assert_eq!(
            work.relative(&work.finalized_journal()),
            "finalized/release-journal.jsonl"
        );
        assert_eq!(
            work.relative(&work.tuf_metadata("production/candidate")),
            "publish/production-candidate/tuf/metadata"
        );
        assert_eq!(
            work.relative(&work.surface_overlay("staging/edge")),
            "publish/staging-edge/timestamp/overlay"
        );
        Ok(())
    }

    #[test]
    fn index_round_trips_and_selects_the_newest_release() -> Result<()> {
        let root = tempfile::tempdir()?;
        let older = WorkDir::new(&root.path().join("older"))?;
        let newer = WorkDir::new(&root.path().join("newer"))?;
        fs::create_dir_all(older.root())?;
        fs::create_dir_all(newer.root())?;
        older.create_index(&index("2026-09-01T00:00:00Z"))?;
        newer.create_index(&index("2026-09-02T00:00:00Z"))?;
        assert!(newer.create_index(&index("2026-09-03T00:00:00Z")).is_err());
        assert_eq!(newer.read_index()?, index("2026-09-02T00:00:00Z"));
        assert_eq!(newest_release(root.path())?, newer);

        let journal = newer.build_journal();
        newer.record_latest_journal(&journal)?;
        assert_eq!(
            newer.read_index()?.latest_journal.as_deref(),
            Some("build/release-journal.jsonl")
        );
        assert!(newer.join(JOURNAL_LINK).symlink_metadata().is_ok());
        Ok(())
    }

    #[test]
    fn new_files_and_renames_never_replace() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("nested/file.json");
        write_new_file(&path, b"first")?;
        assert!(write_new_file(&path, b"second").is_err());
        let moved = root.path().join("moved.json");
        rename_noreplace(&path, &moved)?;
        write_new_file(&path, b"third")?;
        assert!(rename_noreplace(&path, &moved).is_err());
        assert_eq!(fs::read(&moved)?, b"first");
        Ok(())
    }
}
