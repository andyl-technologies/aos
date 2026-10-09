//! Successor journals and no-replace evidence directories.
//!
//! Every effectful step appends exactly one entry to the verified input
//! journal and writes its outputs as a new directory. The directory is built
//! privately, synced, and exposed with a `RENAME_NOREPLACE` rename, so an
//! existing path is never replaced and a crash leaves either no output or a
//! complete one.

use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::state::{JournalEntry, JournalSummary, ReleaseState, parse_journal};

use super::capture;

/// A verified input journal with its exact bytes.
pub struct Journal {
    /// Exact canonical JSONL bytes.
    pub bytes: Vec<u8>,
    /// Parsed entries.
    pub entries: Vec<JournalEntry>,
    /// Replayed state.
    pub summary: JournalSummary,
}

impl Journal {
    /// Reads, parses, and replays a journal file.
    ///
    /// # Errors
    /// Returns an error for an unreadable, malformed, or inconsistent journal.
    pub fn read(path: &Path, label: &str) -> Result<Self> {
        let bytes = capture::control_file(path, label)?;
        let entries = parse_journal(&bytes)?;
        let summary = aos_release_format::verify::verify_journal(&entries)?;
        Ok(Self {
            bytes,
            entries,
            summary,
        })
    }

    /// Requires the journal to belong to `plan` and bind `manifest_digest`.
    ///
    /// # Errors
    /// Returns an error for another plan, destination entries outside the
    /// plan, or a missing or different manifest.
    pub fn require_release(
        &self,
        plan: &aos_release_format::plan::ReleasePlan,
        manifest_digest: Sha256Digest,
    ) -> Result<()> {
        aos_release_format::verify::verify_journal_for_plan(plan, &self.entries)?;
        let latest = self.entries.last().context("release journal is empty")?;
        if latest.manifest_digest != Some(manifest_digest) {
            bail!("release journal does not bind the exact release bundle");
        }
        Ok(())
    }

    /// Returns whether any entry already records `evidence`.
    pub fn contains_evidence(&self, evidence: Sha256Digest) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.evidence.contains(&evidence))
    }
}

/// One transition appended to a journal.
pub struct Transition<'a> {
    /// State committed by the transition.
    pub new_state: ReleaseState,
    /// Destination for published, rolling, and complete transitions.
    pub destination: Option<&'a str>,
    /// Stable operation identifiers.
    pub operation_ids: Vec<String>,
    /// Evidence digests accepted by the transition.
    pub evidence: Vec<Sha256Digest>,
    /// RFC 3339 UTC time of the transition.
    pub recorded_at: String,
}

/// Appends one entry and returns the verified successor bytes.
///
/// The prior state is the destination's current state, or the global state
/// for a first publication and for global transitions.
///
/// # Errors
/// Returns an error for an empty journal, sequence overflow,
/// duplicate evidence, or an illegal transition.
pub fn append(entries: &[JournalEntry], transition: Transition<'_>) -> Result<Vec<u8>> {
    let summary = aos_release_format::verify::verify_journal(entries)?;
    let previous = entries.last().context("release journal is empty")?;
    let prior_state = transition
        .destination
        .and_then(|destination| summary.state_of(destination))
        .unwrap_or(summary.global);
    let mut evidence = transition.evidence;
    evidence.sort();
    evidence.dedup();
    let entry = JournalEntry {
        schema_version: aos_release_format::RELEASE_JOURNAL_ENTRY.to_owned(),
        sequence: previous
            .sequence
            .checked_add(1)
            .context("journal sequence overflowed")?,
        previous_entry_digest: Some(previous.digest()?),
        plan_digest: previous.plan_digest,
        manifest_digest: previous.manifest_digest,
        prior_state: Some(prior_state),
        new_state: transition.new_state,
        destination: transition.destination.map(str::to_owned),
        operation_ids: transition.operation_ids,
        evidence,
        recorded_at: transition.recorded_at,
    };
    let mut complete = entries.to_vec();
    complete.push(entry);
    aos_release_format::verify::verify_journal(&complete)?;
    encode(&complete)
}

/// Returns the current time as RFC 3339 UTC with second precision.
pub fn now_utc() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}

/// Encodes entries as canonical, newline-terminated JSONL.
///
/// # Errors
/// Returns an error if an entry cannot be canonically encoded.
pub fn encode(entries: &[JournalEntry]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(canonical::to_vec(entry)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// Writes a new evidence directory containing exactly `files`.
///
/// Names may contain `/` for nested files. The directory appears atomically
/// and never replaces an existing path.
///
/// # Errors
/// Returns an error when `output` exists, a name is not a normalized relative
/// path, or any write, sync, or rename fails.
pub fn persist_tree(output: &Path, files: &[(&str, &[u8])], label: &str) -> Result<()> {
    if output.exists() {
        bail!("{label} output already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".aos-release-evidence-")
        .tempdir_in(parent)?;
    let root = temporary.path().join("tree");
    fs::create_dir(&root)?;
    for (name, bytes) in files {
        aos_release_format::artifact::BundlePath::parse(*name)
            .with_context(|| format!("invalid evidence file name {name}"))?;
        let path = root.join(name);
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("evidence output repeats {name}"))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    sync_directories(&root)?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &root,
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .with_context(|| format!("installing {label} output {}", output.display()))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sync_directories(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned() -> JournalEntry {
        JournalEntry {
            schema_version: aos_release_format::RELEASE_JOURNAL_ENTRY.to_owned(),
            sequence: 1,
            previous_entry_digest: None,
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: None,
            prior_state: None,
            new_state: ReleaseState::Planned,
            destination: None,
            operation_ids: Vec::new(),
            evidence: Vec::new(),
            recorded_at: "2026-09-03T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn append_derives_prior_state_and_rejects_illegal_transitions() -> Result<()> {
        let built = append(
            &[planned()],
            Transition {
                new_state: ReleaseState::Built,
                destination: None,
                operation_ids: vec!["build".into()],
                evidence: Vec::new(),
                recorded_at: "2026-09-03T01:00:00Z".into(),
            },
        )?;
        let entries = parse_journal(&built)?;
        assert_eq!(entries[1].prior_state, Some(ReleaseState::Planned));

        let published = append(
            &entries,
            Transition {
                new_state: ReleaseState::Published,
                destination: Some("staging/edge"),
                operation_ids: vec!["publish".into()],
                evidence: Vec::new(),
                recorded_at: "2026-09-03T02:00:00Z".into(),
            },
        );
        assert!(
            published.is_err(),
            "publication requires a finalized journal"
        );
        Ok(())
    }

    #[test]
    fn evidence_output_never_replaces_existing_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("evidence");
        persist_tree(
            &output,
            &[("receipt.json", b"receipt"), ("reports/a.json", b"a")],
            "test",
        )?;
        assert!(persist_tree(&output, &[("receipt.json", b"other")], "test").is_err());
        assert_eq!(fs::read(output.join("receipt.json"))?, b"receipt");
        assert_eq!(fs::read(output.join("reports/a.json"))?, b"a");
        assert!(persist_tree(&temp.path().join("bad"), &[("../escape", b"x")], "test").is_err());
        Ok(())
    }
}
