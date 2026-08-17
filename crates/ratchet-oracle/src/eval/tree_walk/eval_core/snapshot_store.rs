//! The on-disk prelude-snapshot tier (RFC-0007 doc 31 §1 step-4 W3/W4).
//!
//! Stores one snapshot file per `(eval system, carrier)` under the
//! `AOS_NIX_CACHE` root the parse cache already derives its location from:
//!
//! ```text
//! $AOS_NIX_CACHE/snapshots/v<IMAGE_VERSION>-prelude-<system>-candidate-c.aosnap
//! ```
//!
//! The file wraps the [`HeapSnapshotManifest`] around the heap image bytes.
//! The path is a *locator only*: staleness and validity are enforced entirely
//! by the restore pipeline (wrapper digest, image digest and version, code
//! fingerprint refuse-on-drift, identity re-interning) — a stale or foreign
//! file is a refusal that falls back to the cold path, never trusted.
//!
//! The tier is opt-in (the doc-14 pattern): `AOS_NIX_SNAPSHOT=1` enables the
//! adopt-at-init attempt, and `AOS_NIX_SNAPSHOT_WARM=1` additionally makes
//! the evaluation write a snapshot post-eval (the prelude-warmer flow — run
//! it on a dedicated prelude-forcing expression, since the capture-time
//! collapse leaves the source heap capture-only).
//!
//! # Wrapper wire format (little-endian)
//!
//! ```text
//! snapshot-file v1:
//!   magic:        8 bytes = "AOSNIXS1"
//!   version:      u32     = 1
//!   module_count: u64
//!   modules:      per module: name(len u32 | bytes)
//!                 | base_flag u8 [ base(len u32 | bytes) ]
//!                 | source(len u32 | bytes)
//!   seed_count:   u64
//!   seeds:        per seed: path(len u32 | bytes) | value_word u64
//!   image_len:    u64
//!   image:        image_len bytes (a self-integrity-checked HeapImage)
//!   digest:       u64 = xxh3-64 of every preceding byte
//! ```

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

use ratchet_value::heap::{HeapImage, IMAGE_VERSION, SnapshotError};

use super::super::TreeWalk;
use super::heap_image::{HeapSnapshotManifest, SnapshotManifestModule};

/// Magic tag of a snapshot wrapper file.
const SNAPSHOT_MAGIC: [u8; 8] = *b"AOSNIXS1";

/// The wrapper format version (independent of the image version, which is
/// embedded in the file name and in the image bytes themselves).
const SNAPSHOT_WRAPPER_VERSION: u32 = 1;

/// Returns whether the snapshot tier is enabled (`AOS_NIX_SNAPSHOT=1`).
pub(crate) fn snapshot_tier_enabled() -> bool {
    std::env::var("AOS_NIX_SNAPSHOT").is_ok_and(|value| value == "1")
}

/// Returns whether this evaluation should write a snapshot post-eval
/// (`AOS_NIX_SNAPSHOT_WARM=1`, the prelude-warmer flow).
pub(crate) fn snapshot_warm_requested() -> bool {
    std::env::var("AOS_NIX_SNAPSHOT_WARM").is_ok_and(|value| value == "1")
}

/// Returns the snapshot file path for one cache root and eval system.
///
/// The image version is part of the file name, so a build with a newer wire
/// format simply misses old files instead of parsing and refusing them.
pub(crate) fn snapshot_file_path(cache_root: &Path, system: &[u8]) -> PathBuf {
    let system = String::from_utf8_lossy(system);
    let system: String = system
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cache_root.join("snapshots").join(format!(
        "v{IMAGE_VERSION}-prelude-{system}-candidate-c.aosnap"
    ))
}

/// A snapshot wrapper file failed to read, parse, or write.
#[derive(Debug, Error)]
pub(crate) enum SnapshotStoreError {
    /// The file could not be read or written.
    #[error("snapshot file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The wrapper bytes are truncated, mis-tagged, or digest-mismatched.
    #[error("snapshot file is malformed")]
    Malformed,
    /// The embedded heap image failed its own parse or integrity check.
    #[error(transparent)]
    Image(#[from] SnapshotError),
}

/// Serializes and atomically writes one snapshot file (temp + rename).
///
/// # Errors
///
/// Returns [`SnapshotStoreError::Io`] when the directory, temp file, or
/// rename fails.
pub(crate) fn write_snapshot_file(
    path: &Path,
    manifest: &HeapSnapshotManifest,
    image_bytes: &[u8],
) -> Result<(), SnapshotStoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&SNAPSHOT_MAGIC);
    out.extend_from_slice(&SNAPSHOT_WRAPPER_VERSION.to_le_bytes());
    out.extend_from_slice(&(manifest.modules.len() as u64).to_le_bytes());
    for module in &manifest.modules {
        write_len_prefixed(&mut out, &module.name);
        match &module.path_literal_base {
            Some(base) => {
                out.push(1);
                write_len_prefixed(&mut out, base);
            }
            None => out.push(0),
        }
        write_len_prefixed(&mut out, &module.source);
    }
    out.extend_from_slice(&(manifest.import_seeds.len() as u64).to_le_bytes());
    for (seed_path, word) in &manifest.import_seeds {
        write_len_prefixed(&mut out, seed_path.to_string_lossy().as_bytes());
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&(image_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(image_bytes);
    let digest = xxh3_64(&out);
    out.extend_from_slice(&digest.to_le_bytes());

    let parent = path.parent().ok_or(SnapshotStoreError::Malformed)?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "snapshot".to_owned()),
        std::process::id()
    ));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&out)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Reads and validates one snapshot file back into its manifest and image.
///
/// # Errors
///
/// Returns [`SnapshotStoreError::Io`] when the file cannot be read,
/// [`SnapshotStoreError::Malformed`] for truncated, mis-tagged, or
/// digest-mismatched wrapper bytes, and [`SnapshotStoreError::Image`] when
/// the embedded image fails its own parse.
pub(crate) fn read_snapshot_file(
    path: &Path,
) -> Result<(HeapSnapshotManifest, HeapImage), SnapshotStoreError> {
    let bytes = fs::read(path)?;
    if bytes.len() < 8 + 4 + 8 + 8 {
        return Err(SnapshotStoreError::Malformed);
    }
    let digest_start = bytes.len() - 8;
    let expected = xxh3_64(&bytes[..digest_start]);
    let actual = u64::from_le_bytes(
        bytes[digest_start..]
            .try_into()
            .map_err(|_| SnapshotStoreError::Malformed)?,
    );
    if expected != actual {
        return Err(SnapshotStoreError::Malformed);
    }
    let bytes = &bytes[..digest_start];
    if bytes[0..8] != SNAPSHOT_MAGIC {
        return Err(SnapshotStoreError::Malformed);
    }
    let mut cursor = 8usize;
    let version = read_u32(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)?;
    if version != SNAPSHOT_WRAPPER_VERSION {
        return Err(SnapshotStoreError::Malformed);
    }
    let module_count = read_u64(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)? as usize;
    let mut modules = Vec::new();
    for _ in 0..module_count {
        let name = read_len_prefixed(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)?;
        let path_literal_base = match bytes.get(cursor).copied() {
            Some(0) => {
                cursor += 1;
                None
            }
            Some(1) => {
                cursor += 1;
                Some(read_len_prefixed(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)?)
            }
            _ => return Err(SnapshotStoreError::Malformed),
        };
        let source = read_len_prefixed(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)?;
        modules.push(SnapshotManifestModule {
            name,
            path_literal_base,
            source,
        });
    }
    let seed_count = read_u64(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)? as usize;
    let mut import_seeds = Vec::new();
    for _ in 0..seed_count {
        let path_bytes =
            read_len_prefixed(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)?;
        let path = PathBuf::from(
            String::from_utf8(path_bytes).map_err(|_| SnapshotStoreError::Malformed)?,
        );
        let mut word = [0u8; 8];
        let end = cursor.checked_add(8).ok_or(SnapshotStoreError::Malformed)?;
        word.copy_from_slice(
            bytes
                .get(cursor..end)
                .ok_or(SnapshotStoreError::Malformed)?,
        );
        cursor = end;
        import_seeds.push((path, u64::from_le_bytes(word)));
    }
    let image_len = read_u64(bytes, &mut cursor).ok_or(SnapshotStoreError::Malformed)? as usize;
    let end = cursor
        .checked_add(image_len)
        .ok_or(SnapshotStoreError::Malformed)?;
    let image_bytes = bytes
        .get(cursor..end)
        .ok_or(SnapshotStoreError::Malformed)?;
    if end != bytes.len() {
        return Err(SnapshotStoreError::Malformed);
    }
    let image = HeapImage::from_bytes(image_bytes)?;
    Ok((
        HeapSnapshotManifest {
            modules,
            import_seeds,
        },
        image,
    ))
}

/// The outcome of a flag-gated snapshot-adoption attempt (step-4 W4).
#[derive(Debug)]
pub(crate) enum SnapshotAdoptAttempt {
    /// The snapshot was adopted; the evaluator starts over the restored heap.
    Adopted,
    /// The tier is enabled but adoption fell back to the cold path.
    Refused(String),
    /// The tier is disabled or the evaluator/options cannot use it.
    Disabled,
}

/// Writing a prelude snapshot post-eval failed.
#[derive(Debug, Error)]
pub(crate) enum SnapshotWriteError {
    /// The pre-capture forced-thunk collapse or the capture itself refused.
    #[error("prelude snapshot capture failed: {0}")]
    Capture(#[from] crate::eval::heap::EvalHeapSnapshotError),
    /// The wrapper file failed to serialize or write.
    #[error(transparent)]
    Store(#[from] SnapshotStoreError),
}

impl TreeWalk {
    /// Returns the configured snapshot file location, when the tier can run:
    /// serial evaluator, `AOS_NIX_SNAPSHOT=1`, and a parse-cache root to
    /// anchor the `snapshots/` sibling under the shared cache root.
    fn snapshot_file_location(&self) -> Option<PathBuf> {
        if self.shared.is_some() || !snapshot_tier_enabled() {
            return None;
        }
        let parse_root = self.options.parse_cache_root()?;
        let cache_root = parse_root.parent()?;
        let system = self.options.current_system().unwrap_or(b"any");
        Some(snapshot_file_path(cache_root, system))
    }

    /// Attempts flag-gated snapshot adoption at evaluator init (step-4 W4).
    ///
    /// Any failure — missing file, malformed wrapper, image refusal, code
    /// drift — falls back to the cold path and reports the reason in the
    /// returned attempt; it is never an evaluation error.
    pub(crate) fn maybe_adopt_prelude_snapshot(&mut self) -> SnapshotAdoptAttempt {
        let Some(path) = self.snapshot_file_location() else {
            return SnapshotAdoptAttempt::Disabled;
        };
        self.try_adopt_snapshot_file(&path)
    }

    /// Writes the post-eval prelude snapshot when the warmer flags are set
    /// (step-4 W3). Runs the mutating forced-thunk collapse first, so the
    /// heap is capture-only afterwards — call at the end of a dedicated
    /// warmer evaluation, never mid-eval.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotWriteError`] when the collapse, capture, or file
    /// write refuses; callers on the production path log and continue (the
    /// tier is advisory).
    pub(crate) fn write_prelude_snapshot(&mut self) -> Result<PathBuf, SnapshotWriteError> {
        let path = self
            .snapshot_file_location()
            .ok_or(SnapshotStoreError::Malformed)
            .map_err(SnapshotWriteError::Store)?;
        self.write_prelude_snapshot_to(&path)?;
        Ok(path)
    }

    /// Writes the post-eval prelude snapshot to an explicit path (the
    /// flag-independent core of [`TreeWalk::write_prelude_snapshot`], and the
    /// hermetic-test entry). Same collapse/capture-only contract.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotWriteError`] when the collapse, capture, or file
    /// write refuses.
    pub(crate) fn write_prelude_snapshot_to(
        &mut self,
        path: &Path,
    ) -> Result<(), SnapshotWriteError> {
        self.heap.collapse_forced_thunks()?;
        let identity = self.snapshot_code_identity();
        let image = self
            .heap
            .capture_heap_image_with_code_identity(&identity, &self.symbols)?;
        let manifest = self.snapshot_manifest();
        write_snapshot_file(path, &manifest, &image.to_bytes())?;
        Ok(())
    }

    /// Attempts adoption from an explicit snapshot file path (the
    /// flag-independent core of [`TreeWalk::maybe_adopt_prelude_snapshot`],
    /// and the hermetic-test entry).
    pub(crate) fn try_adopt_snapshot_file(&mut self, path: &Path) -> SnapshotAdoptAttempt {
        let (manifest, image) = match read_snapshot_file(path) {
            Ok(parts) => parts,
            Err(SnapshotStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return SnapshotAdoptAttempt::Refused("no snapshot file".to_owned());
            }
            Err(error) => return SnapshotAdoptAttempt::Refused(error.to_string()),
        };
        match self.adopt_heap_snapshot(&manifest, &image) {
            Ok(()) => SnapshotAdoptAttempt::Adopted,
            Err(error) => SnapshotAdoptAttempt::Refused(error.to_string()),
        }
    }
}

/// Appends one `u32`-length-prefixed byte run.
fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Reads a little-endian `u32` at `*cursor`, advancing it.
fn read_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let field: [u8; 4] = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(u32::from_le_bytes(field))
}

/// Reads a little-endian `u64` at `*cursor`, advancing it.
fn read_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let end = cursor.checked_add(8)?;
    let field: [u8; 8] = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(u64::from_le_bytes(field))
}

/// Reads a `u32`-length-prefixed byte run at `*cursor`, advancing past it.
fn read_len_prefixed(bytes: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    let len = read_u32(bytes, cursor)? as usize;
    let end = cursor.checked_add(len)?;
    let run = bytes.get(*cursor..end)?.to_vec();
    *cursor = end;
    Some(run)
}
