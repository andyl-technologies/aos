//! Retains journal-owned store objects across immutable initrd replacements.
//!
//! A compressed Nix export lives beside the durable paired journals. Its
//! manifest is published last, so interrupted staging leaves the previous
//! snapshot readable. The export restores transport bytes and registration;
//! the normal journal admission and NAR checks remain authoritative.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::store_closure::closure_paths;

const MANIFEST_BYTES: u64 = 1024 * 1024;
// The ESP and initrd are bounded environments. Refuse an oversized retained
// delta before selection rather than silently consuming their boot budgets.
const COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const EXPORT_BYTES: u64 = 256 * 1024 * 1024;
const DIRECTORY: &str = "retained-store";
const MANIFEST: &str = "manifest.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    roots: BTreeSet<PathBuf>,
    payload: Option<Payload>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    sha256: String,
    compressed_bytes: u64,
    export_bytes: u64,
}

/// Resolves the sealed journal through its validated writable ESP mount.
///
/// # Errors
/// Returns an error for noncanonical paths, unrelated mounts, or aliased state.
pub(crate) fn writable_journal(state: &Path, storage: &Path, boot: &Path) -> Result<PathBuf> {
    for path in [state, storage, boot] {
        ensure!(
            path.is_absolute()
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
                && fs::canonicalize(path)? == path,
            "initrd journal storage path is not canonical"
        );
    }
    let relative = state
        .strip_prefix(storage)
        .context("initrd journal is outside its storage mount")?;
    ensure!(
        relative.components().count() > 0,
        "initrd journal cannot own the mount root"
    );
    let destination = boot.join(relative);
    ensure!(
        fs::canonicalize(&destination)? == destination,
        "writable initrd journal traverses an alias"
    );
    let selected = fs::metadata(state)?;
    let writable = fs::metadata(&destination)?;
    ensure!(
        selected.is_dir()
            && writable.is_dir()
            && selected.dev() == writable.dev()
            && selected.ino() == writable.ino()
            && fs::metadata(storage)?.dev() == fs::metadata(boot)?.dev(),
        "writable ESP path differs from the selected initrd journal"
    );
    Ok(destination)
}

/// Preserves retained inputs and both directions of the bootable-image delta.
///
/// # Errors
/// Returns an error for invalid roots, unavailable closures, conflicting files,
/// exceeded transport bounds, or failed export and durable publication.
pub(crate) fn preserve(
    nix_store: &Path,
    journal: &Path,
    retained: &[String],
    running: &BTreeSet<PathBuf>,
    candidate: &BTreeSet<PathBuf>,
) -> Result<()> {
    let mut command = Command::new(nix_store);
    preserve_with(&mut command, journal, retained, running, candidate)
}

fn preserve_with(
    command: &mut Command,
    journal: &Path,
    retained: &[String],
    running: &BTreeSet<PathBuf>,
    candidate: &BTreeSet<PathBuf>,
) -> Result<()> {
    let mut roots = BTreeSet::new();
    for root in retained {
        aos_release::artifact::require_store_path(root, false)?;
        roots.insert(PathBuf::from(root));
    }
    roots.extend(running.symmetric_difference(candidate).cloned());
    for root in running.union(candidate) {
        aos_release::artifact::require_store_path(
            root.to_str().context("store root is not UTF-8")?,
            false,
        )?;
    }
    let common = running
        .intersection(candidate)
        .cloned()
        .collect::<BTreeSet<_>>();
    // Query even shared retained roots: a root's references must be preserved
    // too, not just its pathname or the original admission document.
    let closure = if roots.is_empty() {
        BTreeSet::new()
    } else {
        closure_paths(&mut base_command(command), &roots)?
    };
    let delta = closure
        .difference(&common)
        .cloned()
        .collect::<BTreeSet<_>>();
    let directory = owned_directory(journal)?;
    let previous = read_manifest(&directory)?;
    if let Some(previous) = &previous {
        verify_payload(&directory, previous)?;
    }

    // Build off the ESP first; publication never replaces its live payload.
    let mut temporary = tempfile::tempfile()?;
    let payload = if delta.is_empty() {
        None
    } else {
        // Command is a reusable base (tests select a private local store).
        let mut export = base_command(command);
        let mut child = export
            .args(["--export"])
            .args(&delta)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let transfer = (|| -> Result<Payload> {
            let input = child.stdout.take().context("store export has no stdout")?;
            let mut encoder = zstd::stream::write::Encoder::new(
                LimitedWriter {
                    output: &mut temporary,
                    remaining: COMPRESSED_BYTES,
                },
                9,
            )?;
            let bytes = io::copy(&mut input.take(EXPORT_BYTES + 1), &mut encoder)?;
            ensure!(
                bytes <= EXPORT_BYTES,
                "retained initrd export exceeds its expansion bound"
            );
            encoder.finish()?;
            let compressed_bytes = temporary.metadata()?.len();
            temporary.sync_all()?;
            temporary.seek(SeekFrom::Start(0))?;
            Ok(Payload {
                sha256: hash_reader(&mut temporary)?,
                compressed_bytes,
                export_bytes: bytes,
            })
        })();
        if transfer.is_err() {
            let _ = child.kill();
        }
        let status = child.wait()?;
        let payload = transfer?;
        ensure!(status.success(), "retained initrd store export failed");
        publish_payload(&directory, &payload, &mut temporary)?;
        Some(payload)
    };
    let manifest = Manifest {
        schema: "aos.initrd-retained-store".into(),
        roots: delta,
        payload,
    };
    let bytes = serde_json::to_vec(&manifest)?;
    ensure!(
        bytes.len() as u64 <= MANIFEST_BYTES,
        "retained initrd manifest exceeds its bound"
    );
    let mut publication = tempfile::Builder::new()
        .prefix(".manifest-")
        .tempfile_in(&directory)?;
    publication.write_all(&bytes)?;
    publication.as_file().sync_all()?;
    publication.persist(directory.join(MANIFEST))?;
    File::open(&directory)?.sync_all()?;
    if let Some(payload) = previous.and_then(|value| value.payload) {
        if manifest
            .payload
            .as_ref()
            .is_none_or(|current| current.sha256 != payload.sha256)
        {
            fs::remove_file(payload_path(&directory, &payload)?)?;
            File::open(&directory)?.sync_all()?;
        }
    }
    Ok(())
}

/// Restores a published snapshot before the initrd journal opens.
///
/// # Errors
/// Returns an error for malformed or changed snapshots, unavailable references,
/// exceeded bounds, or a failed Nix import or registration check.
pub(crate) fn restore(nix_store: &Path, journal: &Path) -> Result<()> {
    restore_with(&mut Command::new(nix_store), journal)
}

fn restore_with(command: &mut Command, journal: &Path) -> Result<()> {
    let directory = journal.join(DIRECTORY);
    let Some(manifest) = read_manifest(&directory)? else {
        return Ok(());
    };
    verify_payload(&directory, &manifest)?;
    let Some(payload) = &manifest.payload else {
        return Ok(());
    };
    let file = regular_file(&payload_path(&directory, payload)?)?;
    let mut decoder = zstd::stream::read::Decoder::new(file)?;
    // Import's root listing goes to a private file, preventing a pipe deadlock
    // while the bounded export is streamed into the child.
    let output = tempfile::tempfile()?;
    let mut child = base_command(command)
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::inherit())
        .spawn()?;
    let transfer = (|| -> Result<()> {
        let mut input = child.stdin.take().context("store import has no stdin")?;
        let bytes = io::copy(
            &mut decoder.by_ref().take(payload.export_bytes + 1),
            &mut input,
        )?;
        ensure!(
            bytes == payload.export_bytes,
            "retained initrd export length changed"
        );
        Ok(())
    })();
    if transfer.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    transfer?;
    ensure!(status.success(), "retained initrd store import failed");
    ensure!(
        output.metadata()?.len() <= MANIFEST_BYTES,
        "store import returned an oversized inventory"
    );
    let mut output = output;
    output.seek(SeekFrom::Start(0))?;
    let mut listing = String::new();
    output.read_to_string(&mut listing)?;
    let imported = listing.lines().map(PathBuf::from).collect::<BTreeSet<_>>();
    ensure!(
        imported == manifest.roots,
        "store import differs from retained snapshot inventory"
    );
    let status = base_command(command)
        .arg("--check-validity")
        .args(&manifest.roots)
        .status()?;
    ensure!(
        status.success(),
        "retained initrd roots are not registered after import"
    );
    Ok(())
}

fn base_command(command: &Command) -> Command {
    let mut cloned = Command::new(command.get_program());
    cloned.args(command.get_args());
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            cloned.env(key, value);
        } else {
            cloned.env_remove(key);
        }
    }
    cloned
}

fn owned_directory(journal: &Path) -> Result<PathBuf> {
    ensure!(
        fs::canonicalize(journal)? == journal,
        "initrd journal traverses an alias"
    );
    let directory = journal.join(DIRECTORY);
    match fs::create_dir(&directory) {
        Ok(()) => {
            File::open(journal)?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure!(
        fs::symlink_metadata(&directory)?.is_dir(),
        "retained store directory is not a real directory"
    );
    Ok(directory)
}

fn read_manifest(directory: &Path) -> Result<Option<Manifest>> {
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) => ensure!(
            metadata.is_dir() && fs::canonicalize(directory)? == directory,
            "retained store directory traverses an alias"
        ),
    }
    let path = directory.join(MANIFEST);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "retained store manifest is not a regular file"
        ),
    }
    let mut bytes = Vec::new();
    regular_file(&path)?
        .take(MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MANIFEST_BYTES,
        "retained store manifest exceeds its bound"
    );
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.schema == "aos.initrd-retained-store",
        "unknown retained store manifest"
    );
    ensure!(
        manifest.payload.is_some() != manifest.roots.is_empty(),
        "retained store manifest inventory is inconsistent"
    );
    for root in &manifest.roots {
        aos_release::artifact::require_store_path(
            root.to_str().context("retained root is not UTF-8")?,
            false,
        )?;
    }
    Ok(Some(manifest))
}

fn regular_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "retained store object is not a regular file"
    );
    Ok(file)
}

fn payload_path(directory: &Path, payload: &Payload) -> Result<PathBuf> {
    ensure!(
        payload.sha256.len() == 64
            && payload
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid retained store digest"
    );
    ensure!(
        (1..=COMPRESSED_BYTES).contains(&payload.compressed_bytes)
            && (1..=EXPORT_BYTES).contains(&payload.export_bytes),
        "retained store payload exceeds its bounds"
    );
    Ok(directory.join(format!("{}.export.zst", payload.sha256)))
}

fn verify_payload(directory: &Path, manifest: &Manifest) -> Result<()> {
    if let Some(payload) = &manifest.payload {
        let mut file = regular_file(&payload_path(directory, payload)?)?;
        ensure!(
            file.metadata()?.len() == payload.compressed_bytes,
            "retained store compressed length changed"
        );
        ensure!(
            hash_reader(&mut file)? == payload.sha256,
            "retained store compressed digest changed"
        );
    }
    Ok(())
}

fn publish_payload(directory: &Path, payload: &Payload, source: &mut File) -> Result<()> {
    let destination = payload_path(directory, payload)?;
    if destination.try_exists()? {
        let mut existing = regular_file(&destination)?;
        ensure!(
            existing.metadata()?.len() == payload.compressed_bytes
                && hash_reader(&mut existing)? == payload.sha256,
            "existing retained store object conflicts with snapshot"
        );
        return Ok(());
    }
    let mut staging = tempfile::Builder::new()
        .prefix(".payload-")
        .tempfile_in(directory)?;
    source.seek(SeekFrom::Start(0))?;
    ensure!(
        io::copy(source, &mut staging)? == payload.compressed_bytes,
        "retained store publication length changed"
    );
    staging.as_file().sync_all()?;
    // FAT32 cannot hard-link a tempfile. Publish without replacement using
    // the filesystem's rename primitive instead.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging.path(),
        rustix::fs::CWD,
        &destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn hash_reader(input: &mut impl Read) -> Result<String> {
    let mut hash = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

struct LimitedWriter<W> {
    output: W,
    remaining: u64,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::other(
                "retained initrd transport exceeds its compressed bound",
            ));
        }
        let count = self.output.write(bytes)?;
        self.remaining -= count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
#[path = "initrd_store_tests.rs"]
mod tests;
