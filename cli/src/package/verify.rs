use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::error::AosError;

// ---------------------------------------------------------------------------
// SHA-256 computation
// ---------------------------------------------------------------------------

/// Buffer size for streaming hash computation (64 KiB).
const HASH_BUF_SIZE: usize = 64 * 1024;

/// Compute SHA-256 of a file, returning `"sha256:<hex>"` format.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file =
        File::open(path).with_context(|| format!("opening {} for hashing", path.display()))?;
    let reader = BufReader::new(file);
    sha256_stream(reader)
}

/// Compute SHA-256 of a `Read` stream, returning `"sha256:<hex>"` format.
///
/// Reads in 64 KiB chunks to avoid loading the full content into memory.
pub fn sha256_stream(mut reader: impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    loop {
        let n = reader.read(&mut buf).context("reading stream for hashing")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    Ok(format!("sha256:{hex}"))
}

// ---------------------------------------------------------------------------
// Layer 4a: download hash verification
// ---------------------------------------------------------------------------

/// Verify the compressed NAR download hash (Layer 4a).
///
/// Computes SHA-256 of the file at `path` and compares against `expected`.
/// Both the expected and actual hash must be in `"sha256:<hex>"` format.
pub fn verify_download_hash(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if actual != expected {
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
pub fn verify_nar_hash(path: &Path, expected: &str) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for NAR hash verification", path.display()))?;
    let reader = BufReader::new(file);
    let decoder = zstd::stream::read::Decoder::new(reader)
        .with_context(|| format!("creating zstd decoder for {}", path.display()))?;

    let actual = sha256_stream(decoder)?;
    if actual != expected {
        return Err(AosError::HashMismatch {
            expected: expected.to_string(),
            actual,
        }
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer 5: store path verification
// ---------------------------------------------------------------------------

/// Verify the store path after import (Layer 5).
///
/// Checks that the actual store path returned by `nix-store --import`
/// matches the expected store path from the package TOML.
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

/// Verify an installed package against registry metadata.
///
/// Used by `apm verify <pkg>`:
/// 1. Run `nix-store --dump <store_path>` to get the current NAR.
/// 2. Compute SHA-256 of the NAR stream.
/// 3. Compare against `expected_nar_hash` from the registry.
pub async fn verify_installed(store_path: &str, expected_nar_hash: &str) -> Result<()> {
    let output = tokio::process::Command::new("nix-store")
        .args(["--dump", store_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("running nix-store --dump {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AosError::DownloadError {
            message: format!(
                "nix-store --dump failed for {store_path}: {stderr}"
            ),
        }
        .into());
    }

    let actual = sha256_stream(output.stdout.as_slice())?;
    if actual != expected_nar_hash {
        return Err(AosError::HashMismatch {
            expected: expected_nar_hash.to_string(),
            actual,
        }
        .into());
    }
    Ok(())
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
        let result = verify_download_hash(tmp.path(), "sha256:0000000000000000000000000000000000000000000000000000000000000000");
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
