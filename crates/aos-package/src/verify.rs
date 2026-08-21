//! Content-hash verification for downloads, NARs, and installed packages.
//!
//! apm verifies package integrity at several layers of the install pipeline,
//! each catching a different failure mode:
//!
//! - **Layer 4a** ([`verify_download_hash`]): SHA-256 of the compressed
//!   `.nar.zst` as downloaded — catches corrupted or tampered transfers.
//! - **Layer 4b** ([`verify_nar_hash`]): SHA-256 of the *decompressed* NAR
//!   stream — catches a valid-zstd-but-wrong-content substitution.
//! - **Image extraction** ([`extract_regular_file_nar`]): accepts only one
//!   canonical, non-executable regular-file root and writes its bytes without
//!   importing the object into a Nix store.
//! - **Layer 4c** ([`verify_nar_blessed`]): the decompressed NAR's SHA-256
//!   and size must match a *blessed* NAR in the signed `store/` realisation
//!   graph (RFC-0005) - unlike 4a/4b, whose expected values come from the
//!   unauthenticated narinfo, this roots the bytes at the registry
//!   signature. Decompression is capped at the largest blessed size so
//!   untrusted compressed input cannot expand unboundedly.
//! - **Layer 5** ([`verify_store_path`]): the path reported by
//!   `nix-store --import` must equal the path the registry promised.
//! - **Post-install** ([`verify_installed`]): re-dump an installed store
//!   path with `nix-store --dump` and compare its NAR hash against the
//!   registry — catches on-disk modification after install (`apm verify`).
//!
//! Hashes are canonically `sha256:<hex>`, but comparison helpers also accept
//! the Nix SRI form `sha256-<base64>` (see [`sha256_digest_hex`]). All
//! hashing is streaming, so arbitrarily large NARs never reside in memory.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
#[cfg(test)]
use base64::Engine as _;
use sha2::{Digest, Sha256};

use aos_core::error::AosError;
use aos_core::nix::aos_nix_env;
use aos_core::output::Printer;

use crate::download::DownloadResult;
use crate::registry::store::{NarBytes, TrustContext};
use crate::registry::store_path_hash;

// ---------------------------------------------------------------------------
// SHA-256 computation
// ---------------------------------------------------------------------------

/// Buffer size for streaming hash computation (64 KiB).
const HASH_BUF_SIZE: usize = 64 * 1024;

/// Compute SHA-256 of a file, returning `"sha256:<hex>"` format.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file =
        File::open(path).with_context(|| format!("opening {} for hashing", path.display()))?;
    let reader = BufReader::new(file);
    sha256_stream(reader)
}

/// Compute SHA-256 of a `Read` stream, returning `"sha256:<hex>"` format.
///
/// Reads in 64 KiB chunks to avoid loading the full content into memory.
///
/// # Errors
///
/// Returns an error if reading from the stream fails.
pub fn sha256_stream(mut reader: impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    loop {
        let n = reader
            .read(&mut buf)
            .context("reading stream for hashing")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    Ok(format!("sha256:{hex}"))
}

/// Convert a SHA-256 hash into a lowercase hex digest.
///
/// Accepts the AOS internal `sha256:<hex>` form, Nix's base32
/// `sha256:<52-char-nix32>` form (used by the `store/` graph and Nix
/// signing fingerprints), and the Nix SRI `sha256-<base64>` form emitted
/// by `nix path-info --json`.
///
/// # Errors
///
/// Returns an error if the value is not a supported, well-formed SHA-256 hash.
pub fn sha256_digest_hex(hash: &str) -> Result<String> {
    aos_core::nar::cache::canonical_sha256_hex(hash)
}

/// Return whether two SHA-256 hashes identify the same digest.
///
/// Both sides are normalized with [`sha256_digest_hex`], so the `sha256:`
/// hex and `sha256-` SRI forms compare equal when they name the same digest.
///
/// # Errors
///
/// Returns an error if either hash is a malformed SRI value.
pub fn sha256_hashes_equal(left: &str, right: &str) -> Result<bool> {
    Ok(sha256_digest_hex(left)? == sha256_digest_hex(right)?)
}

// ---------------------------------------------------------------------------
// Layer 4a: download hash verification
// ---------------------------------------------------------------------------

/// Verify the compressed NAR download hash (Layer 4a).
///
/// Computes SHA-256 of the file at `path` and compares against `expected`.
/// The expected hash may be `sha256:<hex>` or Nix SRI `sha256-<base64>`.
///
/// # Errors
///
/// Returns [`AosError::HashMismatch`] if the digests differ, or an error if
/// the file cannot be read or `expected` is a malformed SRI hash.
pub fn verify_download_hash(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if !sha256_hashes_equal(&actual, expected)? {
        return Err(AosError::HashMismatch {
            expected: expected.to_string(),
            actual,
        }
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer 4b: NAR hash verification (streaming decompression)
// ---------------------------------------------------------------------------

/// Verify the decompressed NAR hash (Layer 4b).
///
/// Decompresses the `.nar.zst` file at `path` using streaming zstd
/// decompression and computes SHA-256 of the raw NAR content.  Compares
/// against `expected`.
///
/// Uses `zstd::stream::read::Decoder` so the full decompressed NAR is never
/// loaded into memory.
///
/// # Errors
///
/// Returns [`AosError::HashMismatch`] if the digests differ, or an error if
/// the file cannot be opened, is not valid zstd, or `expected` is a
/// malformed SRI hash.
pub fn verify_nar_hash(path: &Path, expected: &str) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for NAR hash verification", path.display()))?;
    let reader = BufReader::new(file);
    let decoder = zstd::stream::read::Decoder::new(reader)
        .with_context(|| format!("creating zstd decoder for {}", path.display()))?;

    let actual = sha256_stream(decoder)?;
    if !sha256_hashes_equal(&actual, expected)? {
        return Err(AosError::HashMismatch {
            expected: expected.to_string(),
            actual,
        }
        .into());
    }
    Ok(())
}

/// Extracts a verified regular-file NAR into `output` without using the Nix store.
///
/// The decoder accepts only the canonical NAR shape for one non-executable root
/// regular file. Directories, symlinks, executable files, non-zero padding,
/// trailing archive data, and sizes that disagree with signed metadata are
/// rejected. Callers must authenticate and verify the compressed download and
/// NAR hash before invoking this function.
///
/// # Errors
///
/// Returns an error when decompression fails, the NAR is malformed or has an
/// unsupported root type, either signed size disagrees, or writing fails.
pub fn extract_regular_file_nar(
    path: &Path,
    mut output: impl Write,
    expected_file_size: u64,
    expected_nar_size: u64,
) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for NAR extraction", path.display()))?;
    let reader = BufReader::new(file);
    let decoder = zstd::stream::read::Decoder::new(reader)
        .with_context(|| format!("creating zstd decoder for {}", path.display()))?;
    let mut reader = CountingReader::new(decoder);

    expect_nix_string(&mut reader, b"nix-archive-1", "archive magic")?;
    expect_nix_string(&mut reader, b"(", "root opening marker")?;
    expect_nix_string(&mut reader, b"type", "root type attribute")?;
    expect_nix_string(&mut reader, b"regular", "regular-file root type")?;
    expect_nix_string(&mut reader, b"contents", "non-executable file contents")?;

    let content_size = read_u64(&mut reader, "file content size")?;
    if content_size != expected_file_size {
        bail!(
            "NAR regular-file size {content_size} does not match signed image size {expected_file_size}"
        );
    }
    copy_exact(&mut reader, &mut output, content_size)?;
    read_zero_padding(&mut reader, content_size, "file contents")?;
    expect_nix_string(&mut reader, b")", "root closing marker")?;

    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        bail!("NAR contains trailing archive data");
    }
    if reader.bytes_read() != expected_nar_size {
        bail!(
            "decompressed NAR size {} does not match signed NAR size {expected_nar_size}",
            reader.bytes_read()
        );
    }
    output.flush().context("flushing extracted NAR file")?;
    Ok(())
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("NAR byte count overflow"))?;
        Ok(count)
    }
}

fn read_u64(reader: &mut impl Read, label: &str) -> Result<u64> {
    let mut encoded = [0_u8; 8];
    reader
        .read_exact(&mut encoded)
        .with_context(|| format!("reading NAR {label}"))?;
    Ok(u64::from_le_bytes(encoded))
}

fn expect_nix_string(reader: &mut impl Read, expected: &[u8], label: &str) -> Result<()> {
    let size = read_u64(reader, label)?;
    if size != expected.len() as u64 {
        bail!("NAR {label} has an unexpected length");
    }
    let mut actual = vec![0_u8; expected.len()];
    reader
        .read_exact(&mut actual)
        .with_context(|| format!("reading NAR {label}"))?;
    if actual != expected {
        bail!("NAR {label} is not the required regular-file encoding");
    }
    read_zero_padding(reader, size, label)
}

fn read_zero_padding(reader: &mut impl Read, size: u64, label: &str) -> Result<()> {
    let padding = (8 - size % 8) % 8;
    let mut bytes = [0_u8; 7];
    reader
        .read_exact(&mut bytes[..padding as usize])
        .with_context(|| format!("reading NAR {label} padding"))?;
    if bytes[..padding as usize].iter().any(|byte| *byte != 0) {
        bail!("NAR {label} has non-zero padding");
    }
    Ok(())
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, size: u64) -> Result<()> {
    let mut remaining = size;
    let mut buffer = [0_u8; 1024 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .context("converting NAR read size")?;
        let count = reader
            .read(&mut buffer[..wanted])
            .context("reading NAR regular-file contents")?;
        if count == 0 {
            bail!("NAR ended before its declared regular-file contents");
        }
        writer
            .write_all(&buffer[..count])
            .context("writing extracted NAR regular file")?;
        remaining -= count as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer 4c: blessed-content verification against the store/ graph
// ---------------------------------------------------------------------------

/// Format a blessed NAR set for diagnostics.
fn describe_blessed(blessed: &[NarBytes]) -> String {
    blessed
        .iter()
        .map(|n| format!("{}:{}", n.nar_hash(), n.size))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Verify a downloaded `.nar.zst` against a path's blessed NAR set (Layer 4c).
///
/// Streams zstd decompression of the file at `path`, counting bytes and
/// computing SHA-256, and accepts iff some blessed NAR in `blessed` matches
/// both the digest and the exact size. Decompression aborts as soon as the
/// stream exceeds the largest blessed size, bounding the output produced from
/// not-yet-verified input.
///
/// On success, returns the verified NAR hash as `"sha256:<hex>"`.
///
/// # Errors
///
/// Returns an error when `blessed` is empty, when the file cannot be opened
/// or is not valid zstd, when the decompressed stream exceeds every blessed
/// size, or - as [`AosError::HashMismatch`] - when the digest/size pair
/// matches no blessed NAR.
pub fn verify_nar_blessed(path: &Path, blessed: &[NarBytes]) -> Result<String> {
    let cap =
        blessed.iter().map(|n| n.size).max().ok_or_else(|| {
            anyhow::anyhow!("no blessed NAR to verify {} against", path.display())
        })?;

    let file = File::open(path)
        .with_context(|| format!("opening {} for blessed NAR verification", path.display()))?;
    let reader = BufReader::new(file);
    let mut decoder = zstd::stream::read::Decoder::new(reader)
        .with_context(|| format!("creating zstd decoder for {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = decoder
            .read(&mut buf)
            .with_context(|| format!("decompressing {}", path.display()))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > cap {
            bail!(
                "decompressed NAR from {} exceeds the largest blessed size ({cap} bytes); \
                 refusing to continue decompressing untrusted input",
                path.display(),
            );
        }
        hasher.update(&buf[..n]);
    }

    let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
    if blessed.iter().any(|nar| nar.matches(&actual, total)) {
        return Ok(actual);
    }

    Err(AosError::HashMismatch {
        expected: describe_blessed(blessed),
        actual: format!("{actual} ({total} bytes)"),
    }
    .into())
}

/// Verify a batch of downloaded NARs before import (Layers 4a + 4c/4b).
///
/// Every result gets the compressed-file check (Layer 4a) against the
/// narinfo `FileHash` it was downloaded under - an integrity precheck, not
/// a trust decision. The trust decision is per path, judged against the
/// path's *own* source registry via `ctx`:
///
/// - The path's registry publishes a `store/` graph → Layer 4c, the signed
///   graph is authoritative ([`verify_nar_blessed`]). A missing record is a
///   hard failure (also caught up front by [`TrustContext::enforce_totality`]).
/// - The path's registry has no graph (legacy) → Layer 4b against the
///   unauthenticated narinfo `NarHash`, with a one-time warning.
///
/// Callers should run [`TrustContext::enforce_totality`] over the full
/// closure *before* this, so a stripped graph fails even for members already
/// present locally (which never reach this download-only path).
///
/// # Errors
///
/// Returns an error on the first result that fails its applicable checks.
pub fn verify_downloads(
    results: &[DownloadResult],
    ctx: &TrustContext<'_>,
    printer: &Printer,
) -> Result<()> {
    let mut warned_legacy = false;
    for result in results {
        verify_download_hash(&result.local_path, &result.download_hash)
            .with_context(|| format!("verifying download for {}", result.store_path))?;

        let ia_hash = store_path_hash(&result.store_path);
        if ctx.enforced(ia_hash) {
            let blessed = ctx.blessed_nars(ia_hash);
            if blessed.is_empty() {
                bail!(
                    "no store/ record for {} in its source registry; refusing to \
                     install content the registry signature does not vouch for \
                     (the registry may be malformed or its realisation graph stripped)",
                    result.store_path,
                );
            }
            verify_nar_blessed(&result.local_path, &blessed).with_context(|| {
                format!(
                    "verifying {} against the registry store/ graph",
                    result.store_path
                )
            })?;
        } else {
            if !warned_legacy {
                printer.warning(
                    "registry publishes no store/ realisation graph; verifying NARs \
                     against unauthenticated cache narinfo hashes",
                );
                warned_legacy = true;
            }
            verify_nar_hash(&result.local_path, &result.nar_hash)
                .with_context(|| format!("verifying NAR hash for {}", result.store_path))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer 5: store path verification
// ---------------------------------------------------------------------------

/// Verify the store path after import (Layer 5).
///
/// Checks that the actual store path returned by `nix-store --import`
/// matches the expected store path from the package TOML. Both sides are
/// compared after trimming surrounding whitespace (the import output ends
/// with a newline).
///
/// # Errors
///
/// Returns [`AosError::HashMismatch`] if the trimmed paths differ.
pub fn verify_store_path(actual: &str, expected: &str) -> Result<()> {
    let actual_trimmed = actual.trim();
    let expected_trimmed = expected.trim();
    if actual_trimmed != expected_trimmed {
        return Err(AosError::HashMismatch {
            expected: expected_trimmed.to_string(),
            actual: actual_trimmed.to_string(),
        }
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-install verification
// ---------------------------------------------------------------------------

/// Compute the NAR hash for a store path by streaming `nix-store --dump`.
///
/// # Errors
///
/// Returns an error if `nix-store` cannot be spawned or exits with a
/// non-zero status (e.g. the store path does not exist).
pub async fn store_path_nar_hash(store_path: &str) -> Result<String> {
    Ok(dump_store_path(store_path).await?.0)
}

/// Dump a store path as a NAR and return its SHA-256 hash and size.
async fn dump_store_path(store_path: &str) -> Result<(String, u64)> {
    let output = tokio::process::Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--dump", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("running nix-store --dump {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AosError::DownloadError {
            message: format!("nix-store --dump failed for {store_path}: {stderr}"),
        }
        .into());
    }

    let hash = sha256_stream(output.stdout.as_slice())?;
    Ok((hash, output.stdout.len() as u64))
}

/// Verify an installed package against registry metadata.
///
/// Used by `apm verify <pkg>`:
/// 1. Run `nix-store --dump <store_path>` to get the current NAR.
/// 2. Compute SHA-256 of the NAR stream.
/// 3. Compare against `expected_nar_hash` from the registry.
///
/// On success, returns the freshly computed `sha256:<hex>` hash.
///
/// # Errors
///
/// Returns [`AosError::HashMismatch`] if the on-disk contents no longer
/// match the registry hash, or an error if `nix-store --dump` fails or
/// `expected_nar_hash` is a malformed SRI hash.
pub async fn verify_installed(store_path: &str, expected_nar_hash: &str) -> Result<String> {
    let actual = store_path_nar_hash(store_path).await?;
    if !sha256_hashes_equal(&actual, expected_nar_hash)? {
        return Err(AosError::HashMismatch {
            expected: expected_nar_hash.to_string(),
            actual,
        }
        .into());
    }
    Ok(actual)
}

/// Verify an installed store path against a path's blessed NAR set.
///
/// The multi-realisation analogue of [`verify_installed`]: re-dumps the
/// path and accepts iff *some* blessed NAR matches the freshly computed
/// digest and exact size - a path matching any blessed realisation is
/// intact, even when it is not the realisation a single-valued display
/// hash would name.
///
/// On success, returns the computed `sha256:<hex>` hash.
///
/// # Errors
///
/// Returns an error when `blessed` is empty, when `nix-store --dump` fails,
/// or - as [`AosError::HashMismatch`] - when no blessed NAR matches.
pub async fn verify_installed_blessed(store_path: &str, blessed: &[NarBytes]) -> Result<String> {
    if blessed.is_empty() {
        bail!("no blessed NAR to verify {store_path} against");
    }
    let (actual, size) = dump_store_path(store_path).await?;
    if blessed.iter().any(|nar| nar.matches(&actual, size)) {
        return Ok(actual);
    }
    Err(AosError::HashMismatch {
        expected: describe_blessed(blessed),
        actual: format!("{actual} ({size} bytes)"),
    }
    .into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// SHA-256 of the empty string, in our canonical format.
    const EMPTY_SHA256: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// SHA-256 of "hello\n".
    const HELLO_SHA256: &str =
        "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

    fn push_nix_string(encoded: &mut Vec<u8>, value: &[u8]) {
        encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
        encoded.extend_from_slice(value);
        encoded.resize(encoded.len().next_multiple_of(8), 0);
    }

    fn regular_file_nar(contents: &[u8], executable: bool) -> Vec<u8> {
        let mut nar = Vec::new();
        for token in [
            b"nix-archive-1".as_slice(),
            b"(".as_slice(),
            b"type".as_slice(),
            b"regular".as_slice(),
        ] {
            push_nix_string(&mut nar, token);
        }
        if executable {
            push_nix_string(&mut nar, b"executable");
            push_nix_string(&mut nar, b"");
        }
        push_nix_string(&mut nar, b"contents");
        push_nix_string(&mut nar, contents);
        push_nix_string(&mut nar, b")");
        nar
    }

    fn compressed_nar(nar: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let compressed = zstd::stream::encode_all(nar, 1).unwrap();
        file.write_all(&compressed).unwrap();
        file
    }

    #[test]
    fn extract_regular_file_nar_streams_exact_contents() {
        let contents = b"one canonical image file";
        let nar = regular_file_nar(contents, false);
        let compressed = compressed_nar(&nar);
        let mut extracted = Vec::new();

        extract_regular_file_nar(
            compressed.path(),
            &mut extracted,
            contents.len() as u64,
            nar.len() as u64,
        )
        .unwrap();

        assert_eq!(extracted, contents);
    }

    #[test]
    fn extract_regular_file_nar_rejects_executable_roots() {
        let nar = regular_file_nar(b"image", true);
        let compressed = compressed_nar(&nar);
        let error = extract_regular_file_nar(compressed.path(), Vec::new(), 5, nar.len() as u64)
            .unwrap_err();

        assert!(error.to_string().contains("non-executable file contents"));
    }

    #[test]
    fn extract_regular_file_nar_rejects_trailing_archive_data() {
        let mut nar = regular_file_nar(b"image", false);
        nar.push(0);
        let compressed = compressed_nar(&nar);
        let error = extract_regular_file_nar(compressed.path(), Vec::new(), 5, nar.len() as u64)
            .unwrap_err();

        assert!(error.to_string().contains("trailing archive data"));
    }

    #[test]
    fn extract_regular_file_nar_rejects_signed_size_disagreement() {
        let nar = regular_file_nar(b"image", false);
        let compressed = compressed_nar(&nar);
        let file_error =
            extract_regular_file_nar(compressed.path(), Vec::new(), 4, nar.len() as u64)
                .unwrap_err();
        assert!(file_error.to_string().contains("signed image size"));

        let nar_error =
            extract_regular_file_nar(compressed.path(), Vec::new(), 5, nar.len() as u64 + 1)
                .unwrap_err();
        assert!(nar_error.to_string().contains("signed NAR size"));
    }

    #[test]
    fn sha256_stream_empty() {
        let data: &[u8] = b"";
        let hash = sha256_stream(data).unwrap();
        assert_eq!(hash, EMPTY_SHA256);
    }

    #[test]
    fn sha256_stream_hello() {
        let data: &[u8] = b"hello\n";
        let hash = sha256_stream(data).unwrap();
        assert_eq!(hash, HELLO_SHA256);
    }

    #[test]
    fn sha256_stream_large_data() {
        // Ensure streaming works with data larger than the buffer size.
        let data = vec![0x42u8; HASH_BUF_SIZE * 3 + 7];
        let hash = sha256_stream(data.as_slice()).unwrap();
        // Verify the hash starts with the right prefix.
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn sha256_file_known_content() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello\n").unwrap();
        let hash = sha256_file(tmp.path()).unwrap();
        assert_eq!(hash, HELLO_SHA256);
    }

    #[test]
    fn sha256_file_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"").unwrap();
        let hash = sha256_file(tmp.path()).unwrap();
        assert_eq!(hash, EMPTY_SHA256);
    }

    #[test]
    fn sha256_file_nonexistent() {
        let result = sha256_file(Path::new("/nonexistent/file/path"));
        assert!(result.is_err());
    }

    #[test]
    fn verify_download_hash_match() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello\n").unwrap();
        let result = verify_download_hash(tmp.path(), HELLO_SHA256);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_download_hash_mismatch() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello\n").unwrap();
        let result = verify_download_hash(
            tmp.path(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());

        let err = result.unwrap_err();
        let aos_err = err.downcast_ref::<AosError>().unwrap();
        match aos_err {
            AosError::HashMismatch { expected, actual } => {
                assert_eq!(
                    expected,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                );
                assert_eq!(actual, HELLO_SHA256);
            }
            _ => panic!("expected HashMismatch error"),
        }
    }

    #[test]
    fn verify_nar_hash_zstd() {
        // Create a temporary file with zstd-compressed content, then verify.
        let content = b"this is test NAR content for hashing";

        // Compute the expected hash of the uncompressed content.
        let expected_hash = sha256_stream(content.as_slice()).unwrap();

        // Compress the content with zstd.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let file = File::create(tmp.path()).unwrap();
            let mut encoder = zstd::stream::write::Encoder::new(file, 3).unwrap();
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap();
        }

        // Verify should succeed with the correct hash.
        let result = verify_nar_hash(tmp.path(), &expected_hash);
        assert!(result.is_ok(), "verify_nar_hash should succeed: {result:?}");
    }

    #[test]
    fn verify_nar_hash_zstd_accepts_sri_hash() {
        let content = b"this is test NAR content for SRI hashing";
        let expected_hash = sha256_stream(content.as_slice()).unwrap();
        let expected_hex = expected_hash.strip_prefix("sha256:").unwrap();
        let expected_digest = hex::decode(expected_hex).unwrap();
        let expected_sri = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(expected_digest)
        );

        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let file = File::create(tmp.path()).unwrap();
            let mut encoder = zstd::stream::write::Encoder::new(file, 3).unwrap();
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap();
        }

        let result = verify_nar_hash(tmp.path(), &expected_sri);
        assert!(
            result.is_ok(),
            "verify_nar_hash should accept SRI: {result:?}"
        );
    }

    #[test]
    fn verify_nar_hash_mismatch() {
        let content = b"some NAR data";

        // Compress the content.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let file = File::create(tmp.path()).unwrap();
            let mut encoder = zstd::stream::write::Encoder::new(file, 3).unwrap();
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap();
        }

        // Verify with wrong hash.
        let result = verify_nar_hash(
            tmp.path(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());

        let err = result.unwrap_err();
        let aos_err = err.downcast_ref::<AosError>().unwrap();
        match aos_err {
            AosError::HashMismatch { expected, actual } => {
                assert_eq!(
                    expected,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                );
                // The actual hash should be the real hash of "some NAR data".
                let real_hash = sha256_stream(content.as_slice()).unwrap();
                assert_eq!(actual, &real_hash);
            }
            _ => panic!("expected HashMismatch error"),
        }
    }

    #[test]
    fn verify_store_path_match() {
        let result = verify_store_path(
            "/var/lib/store/abc123-curl-8.5.0",
            "/var/lib/store/abc123-curl-8.5.0",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_store_path_match_with_whitespace() {
        let result = verify_store_path(
            "/var/lib/store/abc123-curl-8.5.0\n",
            "/var/lib/store/abc123-curl-8.5.0",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_store_path_mismatch() {
        let result = verify_store_path(
            "/var/lib/store/abc123-curl-8.5.0",
            "/var/lib/store/def456-curl-8.5.0",
        );
        assert!(result.is_err());

        let err = result.unwrap_err();
        let aos_err = err.downcast_ref::<AosError>().unwrap();
        match aos_err {
            AosError::HashMismatch { expected, actual } => {
                assert_eq!(expected, "/var/lib/store/def456-curl-8.5.0");
                assert_eq!(actual, "/var/lib/store/abc123-curl-8.5.0");
            }
            _ => panic!("expected HashMismatch error"),
        }
    }

    #[test]
    fn sha256_stream_consistency() {
        // Verify that sha256_stream and sha256_file produce the same result.
        let content = b"consistency check data\n";
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), content).unwrap();

        let stream_hash = sha256_stream(content.as_slice()).unwrap();
        let file_hash = sha256_file(tmp.path()).unwrap();
        assert_eq!(stream_hash, file_hash);
    }

    /// Write zstd-compressed content to a temp file and return the file
    /// plus the content's `sha256:<hex>` hash.
    fn zstd_fixture(content: &[u8]) -> (tempfile::NamedTempFile, String) {
        let hash = sha256_stream(content).unwrap();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let file = File::create(tmp.path()).unwrap();
            let mut encoder = zstd::stream::write::Encoder::new(file, 3).unwrap();
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap();
        }
        (tmp, hash)
    }

    use crate::registry::store::{self, NarBytes, Realisation};

    fn blessed_nar(hash: &str, size: u64) -> NarBytes {
        NarBytes::from_hash(hash, size).unwrap()
    }

    #[test]
    fn verify_nar_blessed_accepts_matching_entry() {
        let content = b"blessed NAR content";
        let (tmp, hash) = zstd_fixture(content);
        let blessed = vec![blessed_nar(&hash, content.len() as u64)];

        let verified = verify_nar_blessed(tmp.path(), &blessed).unwrap();
        assert_eq!(verified, hash);
    }

    #[test]
    fn verify_nar_blessed_accepts_any_of_multiple_entries() {
        let content = b"second blessed realisation";
        let (tmp, hash) = zstd_fixture(content);
        let other = sha256_stream(b"first realisation".as_slice()).unwrap();
        let blessed = vec![
            blessed_nar(&other, 17),
            blessed_nar(&hash, content.len() as u64),
        ];

        assert!(verify_nar_blessed(tmp.path(), &blessed).is_ok());
    }

    #[test]
    fn verify_nar_blessed_rejects_wrong_content() {
        let content = b"tampered NAR content";
        let (tmp, _) = zstd_fixture(content);
        let other = sha256_stream(b"the blessed bytes".as_slice()).unwrap();
        let blessed = vec![blessed_nar(&other, content.len() as u64)];

        let err = verify_nar_blessed(tmp.path(), &blessed).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AosError>(),
            Some(AosError::HashMismatch { .. })
        ));
    }

    #[test]
    fn verify_nar_blessed_rejects_size_mismatch_with_right_hash() {
        // Same digest but a wrong blessed size must not verify.
        let content = b"size matters";
        let (tmp, hash) = zstd_fixture(content);
        let blessed = vec![blessed_nar(&hash, content.len() as u64 + 1)];

        // The stream (12 bytes) stays under the cap (13) but the exact-size
        // match fails.
        let err = verify_nar_blessed(tmp.path(), &blessed).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AosError>(),
            Some(AosError::HashMismatch { .. })
        ));
    }

    #[test]
    fn verify_nar_blessed_aborts_past_size_cap() {
        // A stream larger than every blessed size aborts decompression.
        let content = vec![0x5au8; 4096];
        let (tmp, _) = zstd_fixture(&content);
        let other = sha256_stream(b"small".as_slice()).unwrap();
        let blessed = vec![blessed_nar(&other, 5)];

        let err = verify_nar_blessed(tmp.path(), &blessed).unwrap_err();
        assert!(format!("{err:#}").contains("largest blessed size"));
    }

    #[test]
    fn verify_nar_blessed_requires_a_blessed_nar() {
        let (tmp, _) = zstd_fixture(b"anything");
        let err = verify_nar_blessed(tmp.path(), &[]).unwrap_err();
        assert!(format!("{err:#}").contains("no blessed NAR"));
    }

    /// Build a `DownloadResult` whose local file holds zstd-compressed
    /// `content`, with narinfo-style hashes filled in.
    fn download_result_fixture(
        store_path: &str,
        content: &[u8],
        narinfo_nar_hash: &str,
    ) -> (tempfile::NamedTempFile, DownloadResult) {
        let (tmp, _) = zstd_fixture(content);
        let download_hash = sha256_file(tmp.path()).unwrap();
        let result = DownloadResult {
            store_path: store_path.to_string(),
            local_path: tmp.path().to_path_buf(),
            download_hash,
            nar_hash: narinfo_nar_hash.to_string(),
            references: Vec::new(),
            deriver: None,
        };
        (tmp, result)
    }

    /// Bless `ia` with one IA-only realisation of `nar_hash`/`size` in a
    /// fresh registry dir, returning its loaded `StoreMap`.
    fn store_with(ia: &str, nar_hash: &str, size: u64) -> (tempfile::TempDir, store::StoreMap) {
        let reg = tempfile::TempDir::new().unwrap();
        store::upsert_realisation(
            reg.path(),
            ia,
            Realisation {
                nar: NarBytes::from_hash(nar_hash, size).unwrap(),
                ca: None,
                deps: vec![],
            },
            false,
        )
        .unwrap();
        let map = store::StoreMap::load(reg.path()).unwrap();
        (reg, map)
    }

    #[test]
    fn verify_downloads_uses_blessed_bytes_over_narinfo() {
        let content = b"trusted bytes";
        let ia = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let store_path = format!("/nix/store/{ia}-pkg-1.0");
        let nar_hash = sha256_stream(content.as_slice()).unwrap();
        // The narinfo lies; only the graph is right.
        let (_tmp, result) = download_result_fixture(&store_path, content, "sha256:bogus");

        let (_reg, map) = store_with(ia, &nar_hash, content.len() as u64);
        let mut ctx = TrustContext::new();
        ctx.insert(ia.to_string(), &map);
        let printer = Printer::new(0, true, false);

        verify_downloads(std::slice::from_ref(&result), &ctx, &printer).unwrap();
    }

    #[test]
    fn verify_downloads_enforcing_rejects_unmapped_path() {
        let content = b"unmapped bytes";
        let ia = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let store_path = format!("/nix/store/{ia}-pkg-1.0");
        let nar_hash = sha256_stream(content.as_slice()).unwrap();
        let (_tmp, result) = download_result_fixture(&store_path, content, &nar_hash);

        // The source registry publishes a graph but has no record for this
        // path: enforced, blessed-empty → hard fail.
        let (_reg, map) = store_with("cccccccccccccccccccccccccccccccc", &nar_hash, 9);
        let mut ctx = TrustContext::new();
        ctx.insert(ia.to_string(), &map);
        let printer = Printer::new(0, true, false);

        let err = verify_downloads(std::slice::from_ref(&result), &ctx, &printer).unwrap_err();
        assert!(format!("{err:#}").contains("no store/ record"));
    }

    #[test]
    fn verify_downloads_legacy_falls_back_to_narinfo_hash() {
        let content = b"legacy registry bytes";
        let ia = "dddddddddddddddddddddddddddddddd";
        let store_path = format!("/nix/store/{ia}-pkg-1.0");
        let nar_hash = sha256_stream(content.as_slice()).unwrap();
        let (_tmp, result) = download_result_fixture(&store_path, content, &nar_hash);

        // No store/ directory at all: legacy registry, narinfo hash decides.
        let reg = tempfile::TempDir::new().unwrap();
        let map = store::StoreMap::load(reg.path()).unwrap();
        let mut ctx = TrustContext::new();
        ctx.insert(ia.to_string(), &map);
        let printer = Printer::new(0, true, false);

        verify_downloads(std::slice::from_ref(&result), &ctx, &printer).unwrap();

        // And a lying narinfo still fails in legacy mode.
        let (_tmp2, bad) = download_result_fixture(&store_path, content, "sha256:bogus");
        assert!(verify_downloads(std::slice::from_ref(&bad), &ctx, &printer).is_err());
    }

    #[test]
    fn hash_format_is_canonical() {
        // All hashes must follow the "sha256:<hex>" format.
        let hash = sha256_stream(b"test".as_slice()).unwrap();
        assert!(hash.starts_with("sha256:"));
        let hex_part = &hash[7..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
