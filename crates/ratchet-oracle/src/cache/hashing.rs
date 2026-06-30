//! Hash-domain types for evaluator cache keys.
//!
//! RFC-0007 intentionally uses different hash algorithms for different
//! evaluator layers. This module gives those layers distinct Rust types so a
//! hot in-process hash cannot be passed around as a durable content address by
//! accident.
//!
//! ```text
//! HotXxh3Hash        -> evaluator-local map keys and cons-table probes
//! CacheExprSourceHash -> expression/artifact identity source components
//! DurableBlake3Hash  -> evaluator cache digests and confirmation hashes
//! ImpureInputIdentityHash -> filesystem/environment input identity keys
//! ImpureInputObservationHash -> observed filesystem/environment input results
//! LoweredIrFingerprint -> lowered-IR artifact/source-less module identities
//! ParseCacheSourceHash -> parse-cache source-byte artifact keys
//! ParseFileContentHash -> parse-file realpath/content memo keys
//! PersistFileBlobHash -> persisted `files/` blob payload addresses
//! NixSha256Digest    -> Nix-observed store path and `.drv` hash bytes
//! Nix-observed hash bytes cross cache code only through NixSha256Digest
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

    /// Returns the raw hash value for tests that inspect surface leaks.
    #[cfg(test)]
    pub(crate) const fn raw_for_tests(self) -> u64 {
        self.0
    }
}

/// A BLAKE3 digest used for evaluator cache content addresses and confirmations.
///
/// This type is for internal evaluator caches only. Some values become durable
/// content addresses, while others remain in-process confirmation digests for
/// hot lookup keys. Nix-observed store paths, `.drv` hashes, fixed-output
/// hashes, and hash builtins must continue to use their store/hash-specific
/// APIs.
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

/// A durable BLAKE3 hash for a cache expression identity source component.
///
/// This type separates the artifact/span-specific source component of
/// [`crate::cache::CacheExprIdentity`] from canonical Nix value hashes,
/// impure-input identity and observation hashes, parse-cache keys, persisted
/// blob addresses, and Nix-observed hash surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheExprSourceHash(DurableBlake3Hash);

impl CacheExprSourceHash {
    /// Wraps a digest computed in a cache-expression identity domain.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Wraps persisted or synthetic cache-expression identity source bytes.
    ///
    /// This constructor is for explicit low-level persistence-format
    /// boundaries and test fixtures that already own the identity preimage.
    pub const fn from_persisted_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for an impure input identity.
///
/// This type separates filesystem/environment identity keys from observed
/// input result hashes, canonical Nix value hashes, parse-cache keys,
/// persisted blob addresses, and Nix-observed hash surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImpureInputIdentityHash(DurableBlake3Hash);

impl ImpureInputIdentityHash {
    /// Wraps a digest computed in the impure-input identity domain.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Wraps persisted or synthetic impure-input identity hash bytes.
    ///
    /// This constructor is for explicit low-level persistence-format
    /// boundaries and test fixtures that already own the identity preimage.
    pub const fn from_persisted_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for an observed impure input result.
///
/// This type separates filesystem/environment observation hashes from impure
/// input identity hashes, canonical Nix value hashes, parse-cache keys,
/// persisted blob addresses, and Nix-observed hash surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImpureInputObservationHash(DurableBlake3Hash);

impl ImpureInputObservationHash {
    /// Wraps a digest computed in an impure-input observation domain.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Wraps persisted impure-input observation hash bytes.
    ///
    /// This constructor is for explicit persistence-format boundaries that
    /// already validated the input kind, mode, and identity subject separately.
    pub const fn from_persisted_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 fingerprint for serialized lowered-IR artifacts.
///
/// This type separates source-independent module identities and `facts.bin`
/// validation from parse-cache source keys, file-content memo keys, persisted
/// blob addresses, value hashes, and Nix-observed hash surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredIrFingerprint(DurableBlake3Hash);

impl LoweredIrFingerprint {
    /// Wraps a digest computed in the lowered-IR artifact fingerprint domain.
    pub(in crate::cache) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 key for parse artifacts derived from source bytes.
///
/// This type separates parse-cache source identities from file-content memo
/// keys, lowered-IR fingerprints, persisted artifact blob addresses, value
/// hashes, and Nix-observed hash surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ParseCacheSourceHash(DurableBlake3Hash);

impl ParseCacheSourceHash {
    /// Wraps a digest computed in the parse-cache source-key domain.
    pub(in crate::cache) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 content hash for source bytes read by the parse-file memo.
///
/// This type separates realpath/content memo identities from parse-cache source
/// keys, persisted artifact blob addresses, value hashes, and Nix-observed hash
/// surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParseFileContentHash(DurableBlake3Hash);

impl ParseFileContentHash {
    /// Computes the file-content memo hash for `source`.
    pub fn for_source(source: &[u8]) -> Self {
        Self(DurableBlake3Hash::for_bytes(source))
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 content address for payloads stored in the `files/` blob pack.
///
/// This type separates persisted frontend artifact payload hashes from other
/// BLAKE3 domains that also use [`DurableBlake3Hash`], such as parse-cache
/// identities, file-content memo keys, and value-cache confirmation hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistFileBlobHash(DurableBlake3Hash);

impl PersistFileBlobHash {
    /// Computes the `files/` blob content address for `payload`.
    pub fn for_payload(payload: &[u8]) -> Self {
        Self(DurableBlake3Hash::for_bytes(payload))
    }

    /// Wraps decoded persistent `files/` blob hash bytes.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A SHA-256 digest that is part of Nix-observed store or `.drv` identity.
///
/// This type marks the boundary where RFC-0007 requires internal xxh3 and
/// BLAKE3 cache hashes to stop. It is intentionally distinct from
/// [`DurableBlake3Hash`] even though both are 32 bytes, because derivation
/// modulo hashes and content-addressed store paths are Nix format data rather
/// than evaluator-cache addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NixSha256Digest([u8; 32]);

impl NixSha256Digest {
    /// Wraps bytes that were already produced by a Nix-observed SHA-256 hash.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw SHA-256 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the digest and returns the raw SHA-256 digest bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
impl From<[u8; 32]> for NixSha256Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
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

    #[test]
    fn persist_file_blob_hash_wraps_files_payload_hashes() {
        let durable = DurableBlake3Hash::for_bytes(b"serialized file artifact");
        let file_hash = PersistFileBlobHash::for_payload(b"serialized file artifact");

        assert_eq!(file_hash.as_durable_hash(), durable);
        assert_eq!(PersistFileBlobHash::from_durable_hash(durable), file_hash);
    }

    #[test]
    fn lowered_ir_fingerprint_wraps_artifact_hashes() {
        let durable = DurableBlake3Hash::for_bytes(b"serialized lowered ir");
        let fingerprint = LoweredIrFingerprint::from_durable_hash(durable);

        assert_eq!(fingerprint.as_durable_hash(), durable);
    }

    #[test]
    fn parse_file_content_hash_wraps_source_bytes() {
        let durable = DurableBlake3Hash::for_bytes(b"source bytes");
        let content_hash = ParseFileContentHash::for_source(b"source bytes");

        assert_eq!(content_hash.as_durable_hash(), durable);
    }

    #[test]
    fn nix_sha256_digest_is_distinct_from_durable_cache_hash() {
        let digest = NixSha256Digest::from_bytes([7; 32]);

        assert_eq!(digest.as_bytes(), &[7; 32]);
        assert_eq!(digest.into_bytes(), [7; 32]);
    }
}
