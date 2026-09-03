//! Closed publication platforms and fail-closed matrix cells.
//!
//! The package matrix contains exactly the four named target identities. Image
//! matrices use only the two Linux targets; Darwin image cells are invalid.

use std::collections::BTreeSet;
use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;

/// A platform identity supported by the canonical release contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Platform {
    /// 64-bit x86 Linux.
    #[serde(rename = "x86_64-linux")]
    X86_64Linux,
    /// 64-bit Arm Linux.
    #[serde(rename = "aarch64-linux")]
    Aarch64Linux,
    /// 64-bit x86 Darwin.
    #[serde(rename = "x86_64-darwin")]
    X86_64Darwin,
    /// 64-bit Arm Darwin.
    #[serde(rename = "aarch64-darwin")]
    Aarch64Darwin,
}

impl Platform {
    /// Every package platform in canonical order.
    pub const ALL: [Self; 4] = [
        Self::X86_64Linux,
        Self::Aarch64Linux,
        Self::X86_64Darwin,
        Self::Aarch64Darwin,
    ];

    /// Linux image platforms in canonical order.
    pub const LINUX: [Self; 2] = [Self::X86_64Linux, Self::Aarch64Linux];

    /// Returns whether this platform may carry AOS system images.
    #[must_use]
    pub const fn supports_images(self) -> bool {
        matches!(self, Self::X86_64Linux | Self::Aarch64Linux)
    }

    /// Returns the exact public platform spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64Linux => "x86_64-linux",
            Self::Aarch64Linux => "aarch64-linux",
            Self::X86_64Darwin => "x86_64-darwin",
            Self::Aarch64Darwin => "aarch64-darwin",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One explicit package or image matrix decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MatrixCell<T> {
    /// The cell resolves to an immutable artifact or artifact group.
    Artifact {
        /// The cell-specific artifact value.
        artifact: T,
    },
    /// A versioned eligibility rule proves the cell is inapplicable.
    NotApplicable {
        /// Stable identifier of the rule that made the decision.
        rule: String,
        /// Human-readable public rationale.
        reason: String,
    },
    /// Required work has not passed and the evidence is retained.
    Blocked {
        /// Concrete work needed to close the cell.
        required_work: String,
        /// Digest of failure evidence retained for the release.
        failure_evidence: Sha256Digest,
    },
}

impl<T> MatrixCell<T> {
    /// Returns whether the cell blocks stable publication.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// Validates non-artifact decision metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when an eligibility rule, reason, or required-work
    /// description is empty.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Artifact { .. } => Ok(()),
            Self::NotApplicable { rule, reason } => {
                require_text(rule, "matrix eligibility rule")?;
                require_text(reason, "matrix inapplicability reason")
            }
            Self::Blocked { required_work, .. } => {
                require_text(required_work, "matrix required work")
            }
        }
    }
}

/// Requires exactly one cell for every canonical package platform.
///
/// # Errors
///
/// Returns an error for a missing or duplicate platform.
pub fn require_complete_package_platforms<'a>(
    platforms: impl IntoIterator<Item = &'a Platform>,
) -> Result<()> {
    require_exact_platforms(platforms, &Platform::ALL, "package")
}

/// Requires exactly one cell for each Linux image platform and no Darwin cell.
///
/// # Errors
///
/// Returns an error for a missing, duplicate, or Darwin platform.
pub fn require_complete_image_platforms<'a>(
    platforms: impl IntoIterator<Item = &'a Platform>,
) -> Result<()> {
    require_exact_platforms(platforms, &Platform::LINUX, "image")
}

fn require_exact_platforms<'a>(
    platforms: impl IntoIterator<Item = &'a Platform>,
    expected: &[Platform],
    label: &str,
) -> Result<()> {
    let actual: BTreeSet<_> = platforms.into_iter().copied().collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != expected {
        bail!("{label} matrix platforms must be exactly {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn require_text(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} cannot be empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_platform_set_is_closed() {
        assert!(require_complete_package_platforms(Platform::ALL.iter()).is_ok());
        assert!(require_complete_package_platforms(Platform::LINUX.iter()).is_err());
    }

    #[test]
    fn image_platform_set_rejects_darwin() {
        assert!(require_complete_image_platforms(Platform::LINUX.iter()).is_ok());
        assert!(require_complete_image_platforms(Platform::ALL.iter()).is_err());
    }
}
