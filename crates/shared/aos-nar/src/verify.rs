//! Streaming content verification and bounded regular-file NAR extraction.
//!
//! Hashes accept hexadecimal, Nix base32, and SRI SHA-256 spellings. Decoders
//! support raw and zstd transport encodings; signed NAR identities bound output
//! before decompression can expand beyond the authenticated size. Callers own
//! registry trust decisions and installed-store admission.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Reports a content digest that differs from its authenticated expectation.
#[derive(Debug, Error)]
pub enum NarVerificationError {
    /// Indicates that downloaded or decompressed content has the wrong identity.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Records the expected identity spelling supplied by the caller.
        expected: String,
        /// Records the actual canonical hexadecimal SHA-256 identity.
        actual: String,
    },
}

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
    crate::cache::canonical_sha256_hex(hash)
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
/// Returns [`NarVerificationError::HashMismatch`] if the digests differ, or an error if
/// the file cannot be read or `expected` is a malformed SRI hash.
pub fn verify_download_hash(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if !sha256_hashes_equal(&actual, expected)? {
        return Err(NarVerificationError::HashMismatch {
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
/// Returns [`NarVerificationError::HashMismatch`] if the digests differ, or an error if
/// the file cannot be opened, is not valid zstd, or `expected` is a
/// malformed SRI hash.
pub fn verify_nar_hash(path: &Path, expected: &str) -> Result<()> {
    verify_nar_hash_with_compression(path, expected, "zstd")
}

/// Verifies a NAR hash using the transport encoding declared by narinfo.
///
/// # Errors
///
/// Returns an error when the payload cannot be read or decoded, the encoding
/// is unsupported, or the resulting NAR digest differs from `expected`.
pub fn verify_nar_hash_with_compression(
    path: &Path,
    expected: &str,
    compression: &str,
) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for NAR hash verification", path.display()))?;
    let reader = BufReader::new(file);
    let actual = match compression {
        "none" => sha256_stream(reader)?,
        "zstd" => {
            let decoder = zstd::stream::read::Decoder::new(reader)
                .with_context(|| format!("creating zstd decoder for {}", path.display()))?;
            sha256_stream(decoder)?
        }
        other => bail!("unsupported NAR compression '{other}'"),
    };
    if !sha256_hashes_equal(&actual, expected)? {
        return Err(NarVerificationError::HashMismatch {
            expected: expected.to_string(),
            actual,
        }
        .into());
    }
    Ok(())
}

/// Verifies the signed hash and byte length of a decompressed NAR stream.
///
/// The decoder reads at most one byte beyond `expected_size`, which bounds
/// work performed on a transport payload that expands beyond its signed NAR
/// identity.
///
/// # Errors
///
/// Returns an error when the payload cannot be read or decoded, the encoding
/// is unsupported, or the decompressed size or SHA-256 differs from the
/// expected identity.
pub fn verify_nar_identity_with_compression(
    path: &Path,
    expected_hash: &str,
    expected_size: u64,
    compression: &str,
) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for NAR identity verification", path.display()))?;
    let reader: Box<dyn Read> = match compression {
        "none" => Box::new(BufReader::new(file)),
        "zstd" => Box::new(
            zstd::stream::read::Decoder::new(BufReader::new(file))
                .with_context(|| format!("creating zstd decoder for {}", path.display()))?,
        ),
        other => bail!("unsupported NAR compression '{other}'"),
    };
    let limit = expected_size
        .checked_add(1)
        .context("expected NAR size cannot be bounded")?;
    let mut bounded = reader.take(limit);
    let mut hasher = Sha256::new();
    let mut actual_size = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUF_SIZE];
    loop {
        let read = bounded
            .read(&mut buffer)
            .context("reading decompressed NAR for identity verification")?;
        if read == 0 {
            break;
        }
        actual_size = actual_size
            .checked_add(u64::try_from(read)?)
            .context("decompressed NAR size overflow")?;
        hasher.update(&buffer[..read]);
    }
    if actual_size != expected_size {
        bail!("decompressed NAR size {actual_size} differs from expected size {expected_size}");
    }
    let actual_hash = format!("sha256:{}", hex::encode(hasher.finalize()));
    if !sha256_hashes_equal(&actual_hash, expected_hash)? {
        return Err(NarVerificationError::HashMismatch {
            expected: expected_hash.to_owned(),
            actual: actual_hash,
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
    output: impl Write,
    expected_file_size: u64,
    expected_nar_size: u64,
) -> Result<()> {
    extract_regular_file_nar_with_compression(
        path,
        output,
        expected_file_size,
        expected_nar_size,
        "zstd",
    )
}

/// Extracts an authenticated regular-file NAR using its declared transport encoding.
///
/// Applies the same canonical root, padding, trailing-data, and signed-size
/// checks as [`extract_regular_file_nar`]. Callers must verify the transport
/// hash and uncompressed NAR hash before extracting.
///
/// # Errors
///
/// Returns an error for unsupported compression, malformed NARs, signed-size
/// disagreements, decompression failures, or output I/O failures.
pub fn extract_regular_file_nar_with_compression(
    path: &Path,
    mut output: impl Write,
    expected_file_size: u64,
    expected_nar_size: u64,
    compression: &str,
) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for NAR extraction", path.display()))?;
    let reader = BufReader::new(file);
    let decoder: Box<dyn Read> = match compression {
        "none" => Box::new(reader),
        "zstd" => Box::new(
            zstd::stream::read::Decoder::new(reader)
                .with_context(|| format!("creating zstd decoder for {}", path.display()))?,
        ),
        other => bail!("unsupported NAR compression '{other}'"),
    };
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test failures are intentional panic signals"
)]
mod tests {
    use super::*;
    use base64::Engine as _;
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
        let aos_err = err.downcast_ref::<NarVerificationError>().unwrap();
        match aos_err {
            NarVerificationError::HashMismatch { expected, actual } => {
                assert_eq!(
                    expected,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                );
                assert_eq!(actual, HELLO_SHA256);
            }
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
        let aos_err = err.downcast_ref::<NarVerificationError>().unwrap();
        match aos_err {
            NarVerificationError::HashMismatch { expected, actual } => {
                assert_eq!(
                    expected,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                );
                // The actual hash should be the real hash of "some NAR data".
                let real_hash = sha256_stream(content.as_slice()).unwrap();
                assert_eq!(actual, &real_hash);
            }
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

    #[test]
    fn signed_nar_identity_rejects_expansion_beyond_declared_size() {
        let content = b"bounded decompressed NAR content";
        let (tmp, hash) = zstd_fixture(content);

        assert!(
            verify_nar_identity_with_compression(
                tmp.path(),
                &hash,
                u64::try_from(content.len()).unwrap(),
                "zstd",
            )
            .is_ok()
        );
        assert!(
            verify_nar_identity_with_compression(
                tmp.path(),
                &hash,
                u64::try_from(content.len() - 1).unwrap(),
                "zstd",
            )
            .is_err()
        );
    }
}
