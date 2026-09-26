//! Concurrent Bazel-layout disk storage, with side metadata outside its root.
//!
//! ```text
//! cache/ac/ab/abcdef...       ActionResult protobuf
//! cache/cas/ab/abcdef...      SHA-256 addressed bytes
//! state/locks/<action>       advisory lock, never unlinked
//! state/events/<unique>.json immutable provenance event
//! ```
//! Blobs are committed before action results. Readers verify every digest and
//! stage every output before replacing any destination. Eviction or damage is
//! a recoverable miss. No writable build output is hardlinked into the CAS.

use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use prost::Message;

use crate::{
    model::hash,
    proto::{ActionResult, Digest, OutputFile},
};

/// Owns the separate Bazel-format cache and invocation metadata roots.
pub struct Backend {
    /// Canonical directory containing action results and CAS blobs.
    pub root: PathBuf,
    /// Canonical directory containing locks and provenance, outside the CAS.
    pub state: PathBuf,
}

impl Backend {
    /// Creates storage directories and rejects overlapping data/state roots.
    ///
    /// # Errors
    /// Returns an error for filesystem failures or nested roots.
    pub fn new(root: PathBuf, state: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&state)?;
        let root = root.canonicalize()?;
        let state = state.canonicalize()?;
        ensure!(
            !state.starts_with(&root) && !root.starts_with(&state),
            "cache and state directories must be separate, non-nested roots"
        );
        for directory in [
            root.join("cas"),
            root.join("ac"),
            state.join("locks"),
            state.join("events"),
            state.join("latest"),
        ] {
            fs::create_dir_all(directory)?;
        }
        Ok(Self { root, state })
    }

    /// Resolves a validated lowercase SHA-256 key in a cache namespace.
    ///
    /// # Errors
    /// Returns an error when the key is not a canonical SHA-256 digest.
    pub fn path(&self, kind: &str, key: &str) -> Result<PathBuf> {
        ensure!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid SHA-256 key"
        );
        Ok(self.root.join(kind).join(&key[..2]).join(key))
    }

    /// Publishes immutable bytes in the CAS and returns their digest.
    ///
    /// # Errors
    /// Returns an error if the blob cannot be written or its size represented.
    pub fn put(&self, bytes: &[u8]) -> Result<Digest> {
        let digest = Digest {
            hash: hash(bytes),
            size_bytes: bytes.len().try_into()?,
        };
        atomic(&self.path("cas", &digest.hash)?, bytes)?;
        Ok(digest)
    }

    fn get(&self, digest: &Digest) -> Result<Vec<u8>> {
        let path = self.path("cas", &digest.hash)?;
        let bytes = fs::read(&path)?;
        ensure!(
            bytes.len() as i64 == digest.size_bytes && hash(&bytes) == digest.hash,
            "missing or corrupt CAS blob {}",
            digest.hash
        );
        // Bazel's collector uses access mtimes rather than maintaining a DB.
        touch(&path)?;
        Ok(bytes)
    }

    /// Acquires the per-action OS lock, released when its descriptor closes.
    ///
    /// # Errors
    /// Returns an error for invalid action keys or filesystem locking failures.
    pub fn lock(&self, action: &str) -> Result<File> {
        self.path("ac", action)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.state.join("locks").join(action))?;
        lock.lock()?;
        Ok(lock)
    }

    /// Validates a cached result and restores its exact invocation output set.
    ///
    /// # Errors
    /// Returns an error for missing/corrupt entries, output mismatches, or failed
    /// writes; callers treat these failures as misses and compile normally.
    pub fn restore(
        &self,
        action: &str,
        outputs: &[String],
        optional: &BTreeSet<String>,
    ) -> Result<ActionResult> {
        let path = self.path("ac", action)?;
        let bytes = fs::read(&path)?;
        let result = ActionResult::decode(bytes.as_slice())?;
        ensure!(
            result.encode_to_vec() == bytes && result.exit_code == 0,
            "unsupported or unsuccessful action result"
        );
        let destinations: std::collections::BTreeMap<_, _> = outputs
            .iter()
            .map(|path| Ok((wire_output(path)?, path)))
            .collect::<Result<_>>()?;
        let actual: BTreeSet<_> = result
            .output_files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        ensure!(
            actual.len() == result.output_files.len()
                && actual.iter().all(|path| destinations.contains_key(*path))
                && destinations
                    .iter()
                    .all(|(wire, path)| actual.contains(wire.as_str()) || optional.contains(*path)),
            "cached output set differs from invocation"
        );
        let mut staged = Vec::new();
        for output in &result.output_files {
            let destination = safe_output(
                destinations
                    .get(&output.path)
                    .ok_or_else(|| anyhow::anyhow!("unexpected cached output"))?,
            )?;
            let data = self.get(
                output
                    .digest
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no output digest"))?,
            )?;
            let parent = destination.parent().unwrap_or(Path::new("."));
            fs::create_dir_all(parent)?;
            // Set the creation mode before opening the file: the kernel then
            // applies the caller's umask or inherited ACL. A later chmod(0644)
            // would remove the write permission shared Cargo targets need.
            let mut temporary = tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(if output.is_executable {
                    0o777
                } else {
                    0o666
                }))
                .tempfile_in(parent)?;
            temporary.write_all(&data)?;
            staged.push((temporary, destination));
        }
        // Absence is part of an optional output's cached result; do not leave
        // a stale .dwo from an earlier invocation next to a restored object.
        for missing in optional
            .iter()
            .filter(|path| wire_output(path).is_ok_and(|wire| !actual.contains(wire.as_str())))
        {
            match fs::remove_file(safe_output(missing)?) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        for (temporary, destination) in staged {
            temporary.persist(destination)?;
        }
        touch(&path)?;
        Ok(result)
    }

    /// Stores successful compiler outputs before publishing their action result.
    ///
    /// # Errors
    /// Returns an error for missing required outputs, non-regular artifacts, or
    /// filesystem failures. A partial publication cannot produce a valid hit.
    pub fn publish(
        &self,
        action: &str,
        outputs: &[String],
        optional: &BTreeSet<String>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<()> {
        let mut files = Vec::new();
        for output in outputs {
            let path = safe_output(output)?;
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && optional.contains(output) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            ensure!(metadata.is_file(), "compiler output is not a regular file");
            files.push(OutputFile {
                path: wire_output(output)?,
                digest: Some(self.put(&fs::read(path)?)?),
                is_executable: metadata.permissions().mode() & 0o111 != 0,
            });
        }
        atomic(
            &self.path("ac", action)?,
            &ActionResult {
                output_files: files,
                exit_code: 0,
                stdout_raw: stdout,
                stderr_raw: stderr,
            }
            .encode_to_vec(),
        )
    }
}

/// Refreshes access age using the kernel's current time. Explicit timestamps
/// require ownership even on a writable file; UTIME_NOW for both timestamps
/// permits the different Nix build users authorized by the cache's default ACL.
fn touch(path: &Path) -> Result<()> {
    let now = rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: rustix::fs::UTIME_NOW,
    };
    rustix::fs::futimens(
        File::open(path)?,
        &rustix::fs::Timestamps {
            last_access: now,
            last_modification: now,
        },
    )?;
    Ok(())
}

/// Validates a caller-supplied output destination, never an untrusted cache path.
///
/// Absolute paths are necessary for Cargo's persistent target directory. The
/// backend maps wire names back through this invocation's exact destination set.
///
/// # Errors
/// Returns an error for an empty, stream, or directory destination.
pub fn safe_output(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    ensure!(
        !value.is_empty() && value != "-" && path.file_name().is_some(),
        "output is not a file destination: {value}"
    );
    Ok(path.to_owned())
}

/// Encodes a destination as a legal REAPI output path without exposing it as
/// filesystem authority. The action inventory retains the original mapping.
///
/// # Errors
/// Returns an error for an invalid destination or unavailable working directory.
pub fn wire_output(value: &str) -> Result<String> {
    let path = std::env::current_dir()?.join(safe_output(value)?);
    Ok(format!(
        "outputs/{}",
        hash(path.as_os_str().as_encoded_bytes())
    ))
}

/// Publishes a complete file with an atomic rename in the destination filesystem.
///
/// # Errors
/// Returns an error if the parent, staging file, or rename cannot be completed.
pub fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o666))
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.persist(path)?;
    Ok(())
}
