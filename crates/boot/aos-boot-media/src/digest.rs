//! SHA-256 identities of files, file prefixes, and block devices.
//!
//! Digests are computed by the caller-selected `openssl` executable so the
//! crate stays free of linked cryptography. Every result is normalized to 64
//! lowercase hexadecimal characters, and malformed helper output is an error
//! rather than an empty or partial identity.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::{MediaError, Tools, stderr_reason};

/// Returns whether `value` is a canonical lowercase SHA-256 hex digest.
#[must_use]
pub fn is_canonical(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Computes the SHA-256 digest of a whole file.
///
/// # Errors
///
/// Returns [`MediaError`] when `openssl` cannot run, fails, or prints a
/// malformed digest.
pub fn sha256_file(tools: &Tools, path: &Path) -> Result<String, MediaError> {
    let output = Command::new(&tools.openssl)
        .args(["dgst", "-sha256", "-r"])
        .arg(path)
        .output()?;
    parse_openssl_digest(&output)
}

/// Computes the SHA-256 digest of the first `length` bytes of a file or device.
///
/// # Errors
///
/// Returns [`MediaError::Rejected`] when fewer than `length` bytes can be read,
/// and other [`MediaError`] variants when `openssl` fails.
pub fn sha256_prefix(tools: &Tools, path: &Path, length: u64) -> Result<String, MediaError> {
    let mut input = File::open(path)?.take(length);
    let mut child = Command::new(&tools.openssl)
        .args(["dgst", "-sha256", "-r"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| MediaError::Helper("openssl stdin was not created".into()))?;
    let copied = io::copy(&mut input, &mut stdin)?;
    drop(stdin);

    let output = child.wait_with_output()?;
    if copied != length {
        return Err(MediaError::Rejected(format!(
            "short read-back of {}: expected {length} bytes, read {copied}",
            path.display()
        )));
    }
    parse_openssl_digest(&output)
}

/// Verifies that a regular file has exactly the expected size and digest.
///
/// Symbolic links are rejected rather than followed.
///
/// # Errors
///
/// Returns [`MediaError::Rejected`] for a non-regular file or a size or digest
/// mismatch.
pub fn verify_file(
    tools: &Tools,
    path: &Path,
    byte_size: u64,
    sha256: &str,
) -> Result<(), MediaError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(MediaError::Rejected(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() != byte_size {
        return Err(MediaError::Rejected(format!(
            "{} size differs: expected {byte_size} bytes, found {}",
            path.display(),
            metadata.len()
        )));
    }
    if sha256_file(tools, path)? != sha256 {
        return Err(MediaError::Rejected(format!(
            "{} digest differs",
            path.display()
        )));
    }
    Ok(())
}

/// Requires a non-empty regular file no larger than `maximum` bytes.
///
/// # Errors
///
/// Returns [`MediaError::Rejected`] for a symlink, special node, empty file,
/// or oversized file.
pub fn bounded_regular(path: &Path, maximum: u64) -> Result<(), MediaError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(MediaError::Rejected(format!(
            "{} is not a regular file within its {maximum}-byte bound",
            path.display()
        )));
    }
    Ok(())
}

fn parse_openssl_digest(output: &Output) -> Result<String, MediaError> {
    if !output.status.success() {
        return Err(MediaError::Helper(stderr_reason(output)));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let digest = text
        .split_ascii_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if is_canonical(&digest) {
        Ok(digest)
    } else {
        Err(MediaError::Helper(
            "openssl returned a malformed SHA-256 digest".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::is_canonical;

    #[test]
    fn canonical_digests_are_lowercase_hex_of_exact_length() {
        assert!(is_canonical(&"a".repeat(64)));
        assert!(!is_canonical(&"A".repeat(64)));
        assert!(!is_canonical(&"a".repeat(63)));
        assert!(!is_canonical(&format!("sha256:{}", "a".repeat(57))));
    }
}
