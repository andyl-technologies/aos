//! Hash-domain types for evaluator cache keys.
//!
//! RFC-0007 intentionally uses different hash algorithms for different
//! evaluator layers. This module gives those layers distinct Rust types so a
//! hot in-process hash cannot be passed around as a durable content address by
//! accident.
//!
//! ```text
//! HotXxh3Hash        -> evaluator-local map keys and cons-table probes
//! DurableBlake3Hash  -> durable evaluator cache content addresses
//! Nix-observed hashes stay in the store/hash builtin adapters, not here
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};

use xxhash_rust::xxh3::Xxh3;

/// An in-process xxh3 hash used only for hot evaluator maps.
///
/// The hash is non-cryptographic and is never persisted. Callers using it as a
/// lookup accelerator must still confirm equality before reusing an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HotXxh3Hash(u64);

impl HotXxh3Hash {
    /// Computes an in-process hash for a structurally hashable value.
    pub fn for_hashable<T: Hash + ?Sized>(value: &T) -> Self {
        let mut hasher = Xxh3::new();
        value.hash(&mut hasher);
        Self(hasher.finish())
    }

    /// Wraps an xxh3 result that was already computed in the hot hash domain.
    pub(crate) const fn from_xxh3(raw: u64) -> Self {
        Self(raw)
    }
}

/// A durable BLAKE3 hash used for evaluator cache content addresses.
///
/// This type is for internal evaluator caches only. Nix-observed store paths,
/// `.drv` hashes, fixed-output hashes, and hash builtins must continue to use
/// their store/hash-specific APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurableBlake3Hash([u8; 32]);

impl DurableBlake3Hash {
    /// Computes a durable content hash for bytes.
    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self::from_blake3_hash(blake3::hash(bytes))
    }

    /// Finalizes a BLAKE3 hasher into a durable cache hash.
    pub fn from_hasher(hasher: blake3::Hasher) -> Self {
        Self::from_blake3_hash(hasher.finalize())
    }

    /// Wraps an already-computed BLAKE3 digest in the durable cache domain.
    pub fn from_blake3_hash(hash: blake3::Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// Wraps raw BLAKE3 digest bytes in the durable cache domain.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte BLAKE3 digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the lowercase hexadecimal representation used in cache paths.
    pub fn to_hex(self) -> String {
        blake3::Hash::from(self.0).to_hex().to_string()
    }
}

impl fmt::Display for DurableBlake3Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_hash_is_stable_for_identical_hashable_values() {
        let first = HotXxh3Hash::for_hashable(b"same bytes".as_slice());
        let second = HotXxh3Hash::for_hashable(b"same bytes".as_slice());
        let other = HotXxh3Hash::for_hashable(b"other bytes".as_slice());

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn durable_hash_formats_as_blake3_hex() {
        let hash = DurableBlake3Hash::for_bytes(b"cache input");

        assert_eq!(hash.as_bytes().len(), 32);
        assert_eq!(hash.to_hex().len(), 64);
        assert_eq!(hash.to_string(), hash.to_hex());
        assert_eq!(DurableBlake3Hash::from_bytes(hash.as_bytes()), hash);
        assert_eq!(
            DurableBlake3Hash::from_blake3_hash(blake3::hash(b"cache input")),
            hash
        );
    }
}
