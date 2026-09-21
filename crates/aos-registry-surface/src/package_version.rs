//! Validates exact upstream package versions without rewriting their identities.
//!
//! Registry release versions use semantic versioning. Individual package
//! versions also include upstream dates, patch suffixes, and bootstrap labels.

use anyhow::{ensure, Result};

/// Validates a bounded upstream package version suitable for a registry coordinate.
///
/// Preserves the original version, including leading zeroes and upstream
/// suffixes. This validation does not assign semantic-version ordering to it.
///
/// # Errors
///
/// Returns an error when the version is empty, exceeds 255 bytes, does not
/// start with an ASCII letter or digit, or contains characters other than ASCII
/// letters, digits, dots, underscores, plus signs, and hyphens.
pub fn validate_package_version(version: &str) -> Result<()> {
    ensure!(
        version.len() <= 255
            && version
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
            }),
        "invalid upstream package version",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_package_version;

    #[test]
    fn accepts_exact_upstream_version_schemes() {
        for version in [
            "1.2.3",
            "0",
            "4.4",
            "5.3p15",
            "1.07.1",
            "2026-05-14",
            "R2025_04_04",
            "edk2-stable202602",
            "1.5.8.pl02",
            "wrangler-4.119.0+miniflare-3.20240909.0",
        ] {
            assert!(validate_package_version(version).is_ok(), "{version}");
        }
    }

    #[test]
    fn rejects_unsafe_or_unbounded_coordinates() {
        for version in [
            "", ".", "..", "../1", "a/b", "a\\b", "a\n", "a b", "-1", "é",
        ] {
            assert!(validate_package_version(version).is_err(), "{version:?}");
        }
        assert!(validate_package_version(&"1".repeat(256)).is_err());
    }
}
