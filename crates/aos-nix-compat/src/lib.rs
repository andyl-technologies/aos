//! Nix store-format compatibility helpers for RFC-0007.
//!
//! This crate owns the Nix-specific wire formats and file-system helpers that
//! are not part of the reusable `ratchet` evaluator engine:
//!
//! - [`drv`] parses the narrow `.drv` ATerm surfaces used for fixed-output
//!   derivation discovery and closure traversal.
//! - [`drv_materialize`] safely installs native evaluator `.drv` bytes into the
//!   configured store directory.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

pub mod drv;
pub mod drv_materialize;

/// Selects the exact stock-Nix semantic compatibility contract.
///
/// This profile is deliberately separate from the string reported through
/// `builtins.nixVersion`: evaluator behavior branches on this enum, never on
/// user-visible version bytes. Patch releases are named explicitly because
/// embedded evaluator sources and other byte-observable surfaces can change
/// without a Nix language-version bump.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NixCompatProfile {
    /// Matches stock Nix 2.24.12.
    #[default]
    Nix2_24_12 = 0,
    /// Matches stock Nix 2.34.8.
    Nix2_34_8 = 1,
}

impl NixCompatProfile {
    /// Returns the stock version string associated with this semantic profile.
    pub const fn stock_version_str(self) -> &'static str {
        match self {
            Self::Nix2_24_12 => "2.24.12",
            Self::Nix2_34_8 => "2.34.8",
        }
    }

    /// Returns the stock version bytes associated with this semantic profile.
    pub const fn stock_version(self) -> &'static [u8] {
        self.stock_version_str().as_bytes()
    }

    /// Returns the Nix language version exposed by this semantic profile.
    pub const fn lang_version(self) -> i64 {
        match self {
            Self::Nix2_24_12 => 6,
            Self::Nix2_34_8 => 6,
        }
    }

    /// Returns the stable cache-identity bytes for this profile.
    pub const fn cache_identity_bytes(self) -> &'static [u8] {
        match self {
            Self::Nix2_24_12 => b"nix-2.24.12",
            Self::Nix2_34_8 => b"nix-2.34.8",
        }
    }
}

impl fmt::Display for NixCompatProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stock_version_str())
    }
}

impl FromStr for NixCompatProfile {
    type Err = ParseNixCompatProfileError;

    /// Parses an exact supported stock-Nix version.
    ///
    /// # Errors
    ///
    /// Returns [`ParseNixCompatProfileError`] when the input is not exactly
    /// `2.24.12` or `2.34.8`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "2.24.12" => Ok(Self::Nix2_24_12),
            "2.34.8" => Ok(Self::Nix2_34_8),
            _ => Err(ParseNixCompatProfileError {
                value: value.to_owned(),
            }),
        }
    }
}

/// Reports an unsupported exact stock-Nix compatibility version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseNixCompatProfileError {
    value: String,
}

impl fmt::Display for ParseNixCompatProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported Nix compatibility version {:?}; expected 2.24.12 or 2.34.8",
            self.value
        )
    }
}

impl std::error::Error for ParseNixCompatProfileError {}

#[cfg(test)]
mod tests {
    use super::NixCompatProfile;

    #[test]
    fn profiles_own_their_reported_language_version() {
        assert_eq!(NixCompatProfile::Nix2_24_12.lang_version(), 6);
        assert_eq!(NixCompatProfile::Nix2_34_8.lang_version(), 6);
    }

    #[test]
    fn profiles_parse_and_display_only_exact_supported_versions() {
        for profile in [NixCompatProfile::Nix2_24_12, NixCompatProfile::Nix2_34_8] {
            assert_eq!(
                profile
                    .to_string()
                    .parse::<NixCompatProfile>()
                    .expect("displayed profile parses"),
                profile
            );
        }

        let error = " 2.24.12"
            .parse::<NixCompatProfile>()
            .expect_err("parser rejects surrounding whitespace");
        assert_eq!(
            error.to_string(),
            "unsupported Nix compatibility version \" 2.24.12\"; expected 2.24.12 or 2.34.8"
        );
        assert!("2.34".parse::<NixCompatProfile>().is_err());
        assert!("latest".parse::<NixCompatProfile>().is_err());
    }
}
