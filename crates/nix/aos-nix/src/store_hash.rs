//! Canonical identities for paths in a Nix store.
//!
//! A store path begins with a 32-character hash encoded with Nix's base32
//! alphabet:
//!
//! ```text
//! /nix/store/0123456789abcdfghijklmnpqrsvwxyz-package-name
//! ```

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

const STORE_HASH_LENGTH: usize = 32;
const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Identifies a Nix store path by its canonical base32 hash.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreHash(String);

impl StoreHash {
    /// Parses the hash prefix from a store path or store-path basename.
    ///
    /// # Errors
    ///
    /// Returns [`StoreHashError`] if the input has no basename, lacks a
    /// package-name separator, or has a non-canonical hash prefix.
    pub fn from_store_path(path: &str) -> Result<Self, StoreHashError> {
        let basename = path
            .rsplit('/')
            .next()
            .filter(|basename| !basename.is_empty())
            .ok_or(StoreHashError::MissingPathName)?;
        let (hash, name) = basename
            .split_once('-')
            .ok_or(StoreHashError::MissingPathName)?;

        if name.is_empty() {
            return Err(StoreHashError::MissingPathName);
        }

        hash.parse()
    }

    /// Returns the canonical hash text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for StoreHash {
    type Err = StoreHashError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != STORE_HASH_LENGTH {
            return Err(StoreHashError::Length {
                actual: value.len(),
            });
        }

        if let Some(character) = value
            .bytes()
            .find(|character| !NIX_BASE32.contains(character))
        {
            return Err(StoreHashError::Character { character });
        }

        Ok(Self(value.to_owned()))
    }
}

/// Describes why a Nix store hash is not canonical.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StoreHashError {
    /// The hash has a length other than 32 bytes.
    #[error("store hash has length {actual}; expected {STORE_HASH_LENGTH}")]
    Length {
        /// Observed byte length.
        actual: usize,
    },

    /// The hash contains a byte outside the Nix base32 alphabet.
    #[error("store hash contains invalid byte 0x{character:02x}")]
    Character {
        /// First invalid byte.
        character: u8,
    },

    /// A store path has no nonempty package name after its hash.
    #[error("store path must contain a hash and package name")]
    MissingPathName,
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";

    #[test]
    fn accepts_canonical_hashes_and_store_paths() {
        assert_eq!(
            VALID_HASH.parse::<StoreHash>().unwrap().as_str(),
            VALID_HASH
        );
        assert_eq!(
            StoreHash::from_store_path(&format!("/nix/store/{VALID_HASH}-demo-1.0"))
                .unwrap()
                .as_str(),
            VALID_HASH
        );
    }

    #[test]
    fn rejects_noncanonical_hashes() {
        for hash in [
            "short",
            "0123456789abcdefghijklmnopqrstuv",
            "0123456789ABCDFGHIJKLMNPQRSVWXYZ",
            "../0123456789abcdfghijklmnpqrsv",
        ] {
            assert!(hash.parse::<StoreHash>().is_err(), "accepted {hash:?}");
        }
    }

    #[test]
    fn store_paths_require_a_package_name() {
        assert!(StoreHash::from_store_path(VALID_HASH).is_err());
        assert!(StoreHash::from_store_path(&format!("{VALID_HASH}-")).is_err());
    }
}
