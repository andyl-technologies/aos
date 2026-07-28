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

#[cfg(test)]
mod tests {
    use super::NixCompatProfile;

    #[test]
    fn profiles_own_their_reported_language_version() {
        assert_eq!(NixCompatProfile::Nix2_24_12.lang_version(), 6);
        assert_eq!(NixCompatProfile::Nix2_34_8.lang_version(), 6);
    }
}
