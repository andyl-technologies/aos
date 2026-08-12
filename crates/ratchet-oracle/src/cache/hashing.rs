//! Hash-domain types for evaluator cache keys.
//!
//! RFC-0007 intentionally uses different hash algorithms for different
//! evaluator layers. This module gives those layers distinct Rust types so a
//! hot in-process hash cannot be passed around as a durable content address by
//! accident.
//!
//! ```text
//! HotXxh3Hash        -> evaluator-local map keys and cons-table probes
//! DemandKeyHotHash -> demand-cache hot xxh3 probes
//! DemandKeyConfirmationHash -> demand-cache BLAKE3 confirmations
//! PersistNodeMetadataKeyHash -> persisted demand-node metadata/trace keys
//! CacheExprSourceHash -> expression/artifact identity source components
//! AttrPositionSourceHash -> positioned-payload source provenance
//! ForceCapturePositionSourceHash -> positioned captured-value source salts
//! StaticSelectPositionHash -> static-select binding position identities
//! ForceCapturedValueHash -> force-cache captured free-variable fingerprints
//! DerivationSidePayloadValueHash -> derivation side-record payload hashes
//! CachedExpressionPayloadValueHash -> cached expression payload hashes
//! DurableBlake3Hash  -> evaluator cache digests and confirmation hashes
//! ImpureInputIdentityHash -> filesystem/environment input identity keys
//! ImpureInputObservationHash -> observed filesystem/environment input results
//! LoweredIrFingerprint -> lowered-IR artifact/source-less module identities
//! CompiledBodyRecordHash -> persistent compiled-body memo record identities
//! ParseCacheSourceHash -> parse-cache source-byte artifact keys
//! ParseFileContentHash -> parse-file realpath/content memo keys
//! PersistFileBlobHash -> persisted `files/` blob payload addresses
//! NixSha256Digest    -> Nix-observed store path and `.drv` hash bytes
//! Nix-observed hash bytes cross cache code only through NixSha256Digest
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

use xxhash_rust::xxh3::Xxh3;

/// Selects the hash family used for evaluator-cache content addresses and keys.
///
/// A measurement knob (RFC-0007 §P4): BLAKE3 is the default and the shipping
/// choice; `xxh128` is an experiment to quantify what a non-cryptographic
/// populate hash would buy on the cold-populate BLAKE3 tax. The two families
/// produce different digests for the same preimage, so a cache populated under
/// one must never be read under the other; the family is folded into every
/// xxh128 digest's high half ([`XXH128_FAMILY_TAG`]) so the key spaces cannot
/// overlap even if a cache directory is reused across families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheHashFamily {
    /// Cryptographic BLAKE3 (default, shipping).
    Blake3,
    /// Non-cryptographic xxh3-128 (measurement experiment).
    Xxh128,
}

impl CacheHashFamily {
    /// Returns the stable manifest spelling of this family (`blake3`/`xxh128`).
    ///
    /// This is the identity written into a cache root's self-describing manifest
    /// so a later open reads the root's own family rather than the process env.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Xxh128 => "xxh128",
        }
    }

    /// Parses a manifest family spelling, accepting the `xxh3-128` alias.
    ///
    /// Returns `None` for an unrecognized spelling so a malformed manifest is a
    /// caller-handled error rather than a silent misread.
    pub fn from_str(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("blake3") {
            Some(Self::Blake3)
        } else if value.eq_ignore_ascii_case("xxh128") || value.eq_ignore_ascii_case("xxh3-128") {
            Some(Self::Xxh128)
        } else {
            None
        }
    }
}

/// High 16 bytes stamped into every xxh128 cache digest to domain-separate it
/// from a BLAKE3 digest (32 random bytes), so the two key spaces cannot collide.
const XXH128_FAMILY_TAG: [u8; 16] = *b"aos-nix-xxh128\0\0";

fn read_cache_hash_family() -> CacheHashFamily {
    std::env::var("AOS_NIX_CACHE_HASH")
        .ok()
        .and_then(|value| CacheHashFamily::from_str(&value))
        .unwrap_or(CacheHashFamily::Blake3)
}

/// Returns the process-wide cache hash family, read once from `AOS_NIX_CACHE_HASH`.
///
/// Defaults to [`CacheHashFamily::Blake3`]; set `AOS_NIX_CACHE_HASH=xxh128` (or
/// `xxh3-128`) to select the experiment family. The value is cached for the
/// process, so it must be set before the first cache hash is computed.
pub fn cache_hash_family() -> CacheHashFamily {
    static FAMILY: OnceLock<CacheHashFamily> = OnceLock::new();
    *FAMILY.get_or_init(read_cache_hash_family)
}

/// A streaming cache-digest hasher dispatching on [`cache_hash_family`].
///
/// This is the drop-in replacement for the raw BLAKE3 streaming hasher the cache
/// used to build directly: [`Self::new`] selects the family once, [`Self::update`]
/// feeds preimage bytes, and finalizing through [`DurableBlake3Hash::from_hasher`]
/// yields the 32-byte digest. Under the default family the digest is byte-for-byte
/// the BLAKE3 hash of the same preimage.
pub enum CacheDigestHasher {
    /// BLAKE3 streaming state.
    Blake3(blake3::Hasher),
    /// xxh3-128 streaming state.
    Xxh128(Xxh3),
}

impl CacheDigestHasher {
    /// Creates a hasher for the process [`cache_hash_family`].
    pub fn new() -> Self {
        Self::for_family(cache_hash_family())
    }

    /// Creates a hasher for an explicit [`CacheHashFamily`].
    ///
    /// This is the family-parameterized counterpart of [`Self::new`], used to
    /// re-derive a cache key under a location's own recorded family rather than
    /// the process family — for example when cross-probing a foreign-family
    /// secondary from an identity-carrying preimage (RFC-0007 §P4 Option C).
    pub fn for_family(family: CacheHashFamily) -> Self {
        match family {
            CacheHashFamily::Blake3 => Self::Blake3(blake3::Hasher::new()),
            CacheHashFamily::Xxh128 => Self::Xxh128(Xxh3::new()),
        }
    }

    /// Feeds preimage bytes into the running digest.
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Blake3(hasher) => {
                hasher.update(bytes);
            }
            Self::Xxh128(hasher) => hasher.update(bytes),
        }
    }

    /// Finalizes into a 32-byte cache digest.
    ///
    /// BLAKE3 fills all 32 bytes; xxh128 fills the low 16 with the little-endian
    /// digest and the high 16 with [`XXH128_FAMILY_TAG`].
    pub fn finalize_bytes(&self) -> [u8; 32] {
        match self {
            Self::Blake3(hasher) => *hasher.finalize().as_bytes(),
            Self::Xxh128(hasher) => {
                let mut out = [0u8; 32];
                out[..16].copy_from_slice(&hasher.digest128().to_le_bytes());
                out[16..].copy_from_slice(&XXH128_FAMILY_TAG);
                out
            }
        }
    }
}

impl Default for CacheDigestHasher {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Returns the raw 64-bit hash word.
    ///
    /// Used by the flat-value heap (RFC-0007 doc 30 FV-1) to store the
    /// hash-cons key inline in a flat object header.
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the raw hash value for tests that inspect surface leaks.
    #[cfg(test)]
    pub(crate) const fn raw_for_tests(self) -> u64 {
        self.0
    }
}

/// An in-process xxh3 probe for demand-cache keys.
///
/// This type marks the hot, non-authoritative half of a
/// [`crate::cache::DemandCacheKey`]. It remains in process and is always paired
/// with a BLAKE3 confirmation before a demand-graph entry can be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::cache) struct DemandKeyHotHash(HotXxh3Hash);

impl DemandKeyHotHash {
    /// Wraps an xxh3 result computed in the demand-cache key domain.
    pub(in crate::cache) const fn from_xxh3(raw: u64) -> Self {
        Self(HotXxh3Hash::from_xxh3(raw))
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
    /// Computes a durable content hash for bytes under the process hash family.
    pub fn for_bytes(bytes: &[u8]) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(bytes);
        Self::from_hasher(hasher)
    }

    /// Computes a durable content hash for bytes under an explicit hash family.
    ///
    /// This re-derives the digest under `family` rather than the process family,
    /// so an identity-carrying preimage can be re-keyed for a foreign-family
    /// cache location (RFC-0007 §P4 Option C cross-family probe).
    pub fn for_bytes_with_family(bytes: &[u8], family: CacheHashFamily) -> Self {
        let mut hasher = CacheDigestHasher::for_family(family);
        hasher.update(bytes);
        Self::from_hasher(hasher)
    }

    /// Finalizes a [`CacheDigestHasher`] into a durable cache hash.
    pub fn from_hasher(hasher: CacheDigestHasher) -> Self {
        Self(hasher.finalize_bytes())
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

/// A BLAKE3 confirmation digest for demand-cache keys.
///
/// This type marks the collision-confirmation half of a
/// [`crate::cache::DemandCacheKey`]. It is not a persisted value/blob address;
/// it only confirms equality for keys that share the same hot xxh3 probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::cache) struct DemandKeyConfirmationHash(DurableBlake3Hash);

impl DemandKeyConfirmationHash {
    /// Finalizes a BLAKE3 hasher in a demand-cache key confirmation domain.
    pub(in crate::cache) fn from_hasher(hasher: CacheDigestHasher) -> Self {
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Wraps a precomputed demand-key confirmation digest for tests.
    #[cfg(test)]
    pub(in crate::cache) const fn from_precomputed_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }
}

/// A BLAKE3 key for persisted demand-node metadata and trace sidecars.
///
/// This type marks durable node keys derived from expression identities plus
/// free-variable value hashes, or from impure-input identity hashes. The raw
/// digest remains available through the existing
/// `PersistNodeMetadataKey::hash` inspection accessor, and otherwise unwraps
/// when encoding stable sidecar keys or adapting to lower-level persistence
/// engine key types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::cache) struct PersistNodeMetadataKeyHash(DurableBlake3Hash);

impl PersistNodeMetadataKeyHash {
    /// Finalizes a BLAKE3 hasher in a persistent node-metadata key domain.
    pub(in crate::cache) fn from_hasher(hasher: CacheDigestHasher) -> Self {
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Wraps decoded persistent node-metadata key hash bytes.
    pub(in crate::cache) const fn from_persisted_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(in crate::cache) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
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

/// A durable BLAKE3 hash for positioned cached-payload source provenance.
///
/// This type marks the module/source identity attached to persistent
/// position-bearing attrset payloads so they can replay binding positions only
/// for an evaluator that proves the same source identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttrPositionSourceHash(DurableBlake3Hash);

impl AttrPositionSourceHash {
    /// Wraps a digest computed from a tree-walk module source identity.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Wraps persisted or synthetic positioned-payload source identity bytes.
    ///
    /// This constructor is for explicit persistence-format boundaries and test
    /// fixtures that already own the source-provenance preimage.
    pub const fn from_persisted_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for positioned captured-value source salting.
///
/// This type marks module/source identity hashes only while they salt the
/// force-captured value hash of position-bearing composite payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ForceCapturePositionSourceHash(DurableBlake3Hash);

impl ForceCapturePositionSourceHash {
    /// Wraps a digest computed from a tree-walk module source identity.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for static-select binding position identities.
///
/// This type marks selected binding source-name/module and span identities that
/// are folded into static-select captured-value projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct StaticSelectPositionHash(DurableBlake3Hash);

impl StaticSelectPositionHash {
    /// Wraps a digest computed from a static selected binding position.
    pub(crate) const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for force-cache captured free-variable fingerprints.
///
/// This type marks hashes computed under
/// `FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION` before they are intentionally
/// adapted into [`crate::cache::ValueHash`] key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ForceCapturedValueHash(DurableBlake3Hash);

impl ForceCapturedValueHash {
    /// Wraps a digest computed in the force-captured value hash domain.
    const fn from_durable_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Finalizes a BLAKE3 hasher in the force-captured value hash domain.
    pub(crate) fn from_hasher(hasher: CacheDigestHasher) -> Self {
        Self::from_durable_hash(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for cached derivation side-record payloads.
///
/// This type marks the value-hash identity for derivation ATerm-path and
/// static-output side payload records before they are intentionally adapted
/// into [`crate::cache::ValueHash`] graph material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DerivationSidePayloadValueHash(DurableBlake3Hash);

impl DerivationSidePayloadValueHash {
    /// Finalizes a BLAKE3 hasher in a derivation side-payload value domain.
    pub(crate) fn from_hasher(hasher: CacheDigestHasher) -> Self {
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 hash for cached expression payload bytes.
///
/// This type marks the value-hash identity for canonical cached-expression
/// persistent payload preimages before they are intentionally adapted into
/// [`crate::cache::ValueHash`] graph and value-blob material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CachedExpressionPayloadValueHash(DurableBlake3Hash);

impl CachedExpressionPayloadValueHash {
    /// Finalizes a BLAKE3 hasher in a cached-expression payload value domain.
    pub(crate) fn from_hasher(hasher: CacheDigestHasher) -> Self {
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Wraps a precomputed cached-expression payload digest for const constructors.
    pub(in crate::cache) const fn from_precomputed_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
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

    /// Returns the raw durable digest used by compiled-body cache keys.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the lowercase hexadecimal cache-key representation.
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(crate) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

/// A durable BLAKE3 key for one persistent compiled-body memo record.
///
/// The key is derived exclusively from lowering inputs: lowered module
/// identity, definition-site coordinates, compilation budget, record schema,
/// compiler version, and target triple. Executable addresses and encoded CLIF
/// bytes never participate, so independently opened cache locations address the
/// same pure artifact through one stable key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompiledBodyRecordHash(DurableBlake3Hash);

impl CompiledBodyRecordHash {
    /// Derives the durable key for one unary tier-2 compiled-body record.
    pub fn for_unary_tier2(
        lowered_ir: LoweredIrFingerprint,
        pattern: u32,
        body: u32,
        budget: i64,
        schema: u32,
        compiler_version: &str,
        target_triple: &str,
    ) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(b"aos-nix:compiled-body:unary-tier2:v1\0");
        hasher.update(&lowered_ir.as_bytes());
        hasher.update(&pattern.to_le_bytes());
        hasher.update(&body.to_le_bytes());
        hasher.update(&budget.to_le_bytes());
        hasher.update(&schema.to_le_bytes());
        update_compiled_body_key_field(&mut hasher, compiler_version.as_bytes());
        update_compiled_body_key_field(&mut hasher, target_triple.as_bytes());
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Derives the durable key for one fused-chain tier-2 compiled-body record.
    ///
    /// `semantic_identity` is the caller's canonical encoding of the chain
    /// root, inner body, self-callee, environment boundary, and every pinned
    /// callee. Its length prefix keeps the following schema and toolchain
    /// fields structurally unambiguous.
    pub fn for_fused_chain_tier2(
        lowered_ir: LoweredIrFingerprint,
        semantic_identity: &[u8],
        budget: i64,
        schema: u32,
        compiler_version: &str,
        target_triple: &str,
    ) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(b"aos-nix:compiled-body:fused-chain-tier2:v1\0");
        hasher.update(&lowered_ir.as_bytes());
        update_compiled_body_key_field(&mut hasher, semantic_identity);
        hasher.update(&budget.to_le_bytes());
        hasher.update(&schema.to_le_bytes());
        update_compiled_body_key_field(&mut hasher, compiler_version.as_bytes());
        update_compiled_body_key_field(&mut hasher, target_triple.as_bytes());
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Returns the raw durable key bytes for envelope self-validation.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0.as_bytes()
    }

    /// Returns the underlying durable BLAKE3 digest.
    pub(in crate::cache) const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }
}

fn update_compiled_body_key_field(hasher: &mut CacheDigestHasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
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
    /// Computes the file-content memo hash for `source` under an explicit family.
    ///
    /// Re-derives the content hash under `family` for a cross-family probe of a
    /// foreign-family cache location (RFC-0007 §P4 Option C).
    pub fn for_source_with_family(source: &[u8], family: CacheHashFamily) -> Self {
        Self(DurableBlake3Hash::for_bytes_with_family(source, family))
    }

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
    fn cache_hash_family_manifest_spelling_round_trips() {
        for family in [CacheHashFamily::Blake3, CacheHashFamily::Xxh128] {
            assert_eq!(CacheHashFamily::from_str(family.as_str()), Some(family));
        }
        assert_eq!(
            CacheHashFamily::from_str("xxh3-128"),
            Some(CacheHashFamily::Xxh128),
            "the xxh3-128 alias parses to the xxh128 family",
        );
        assert_eq!(CacheHashFamily::from_str("sha256"), None);
    }

    #[test]
    fn cache_digest_blake3_matches_blake3_hash() {
        let mut hasher = CacheDigestHasher::Blake3(blake3::Hasher::new());
        hasher.update(b"cache preimage");
        assert_eq!(
            hasher.finalize_bytes(),
            *blake3::hash(b"cache preimage").as_bytes(),
            "the BLAKE3 family must be byte-for-byte the BLAKE3 hash",
        );
    }

    #[test]
    fn cache_digest_xxh128_is_tagged_and_distinct_from_blake3() {
        let mut xxh = CacheDigestHasher::Xxh128(Xxh3::new());
        xxh.update(b"cache preimage");
        let out = xxh.finalize_bytes();

        // Low 16 bytes are the xxh3-128 digest; high 16 are the family tag.
        assert_eq!(
            &out[..16],
            &xxhash_rust::xxh3::xxh3_128(b"cache preimage").to_le_bytes(),
        );
        assert_eq!(&out[16..], &XXH128_FAMILY_TAG);

        // The family tag guarantees an xxh128 digest can never equal a BLAKE3 one.
        let mut b3 = CacheDigestHasher::Blake3(blake3::Hasher::new());
        b3.update(b"cache preimage");
        assert_ne!(out, b3.finalize_bytes());
    }

    #[test]
    fn hot_hash_is_stable_for_identical_hashable_values() {
        let first = HotXxh3Hash::for_hashable(b"same bytes".as_slice());
        let second = HotXxh3Hash::for_hashable(b"same bytes".as_slice());
        let other = HotXxh3Hash::for_hashable(b"other bytes".as_slice());

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn demand_key_hot_hash_wraps_xxh3_probes() {
        let first = DemandKeyHotHash::from_xxh3(7);
        let second = DemandKeyHotHash::from_xxh3(7);
        let other = DemandKeyHotHash::from_xxh3(8);

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn demand_key_confirmation_hash_wraps_blake3_confirmations() {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(b"confirmation");
        let from_hasher = DemandKeyConfirmationHash::from_hasher(hasher);
        let precomputed = DemandKeyConfirmationHash::from_precomputed_hash(
            DurableBlake3Hash::for_bytes(b"confirmation"),
        );
        let other = DemandKeyConfirmationHash::from_precomputed_hash(DurableBlake3Hash::for_bytes(
            b"other",
        ));

        assert_eq!(from_hasher, precomputed);
        assert_ne!(from_hasher, other);
    }

    #[test]
    fn persist_node_metadata_key_hash_wraps_metadata_hashes() {
        let durable = DurableBlake3Hash::for_bytes(b"node metadata key");
        let mut hasher = CacheDigestHasher::new();
        hasher.update(b"node metadata key");
        let from_hasher = PersistNodeMetadataKeyHash::from_hasher(hasher);
        let persisted = PersistNodeMetadataKeyHash::from_persisted_hash(durable);
        let other =
            PersistNodeMetadataKeyHash::from_persisted_hash(DurableBlake3Hash::for_bytes(b"other"));

        assert_eq!(from_hasher, persisted);
        assert_ne!(from_hasher, other);
        assert_eq!(persisted.as_durable_hash(), durable);
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
    fn compiled_body_record_hash_covers_lowering_and_target_identity() {
        let fingerprint = LoweredIrFingerprint::from_durable_hash(DurableBlake3Hash::for_bytes(
            b"lowered module",
        ));
        let key = CompiledBodyRecordHash::for_unary_tier2(
            fingerprint,
            3,
            7,
            128,
            2,
            "cranelift-1",
            "aarch64-test",
        );
        let same = CompiledBodyRecordHash::for_unary_tier2(
            fingerprint,
            3,
            7,
            128,
            2,
            "cranelift-1",
            "aarch64-test",
        );
        let other_target = CompiledBodyRecordHash::for_unary_tier2(
            fingerprint,
            3,
            7,
            128,
            2,
            "cranelift-1",
            "x86_64-test",
        );

        assert_eq!(key, same);
        assert_ne!(key, other_target);
    }

    #[test]
    fn fused_chain_record_hash_covers_semantic_identity_and_budget() {
        let fingerprint = LoweredIrFingerprint::from_durable_hash(DurableBlake3Hash::for_bytes(
            b"lowered chain module",
        ));
        let key = CompiledBodyRecordHash::for_fused_chain_tier2(
            fingerprint,
            b"root/self/pins",
            128,
            1,
            "cranelift-1",
            "aarch64-test",
        );
        let other_identity = CompiledBodyRecordHash::for_fused_chain_tier2(
            fingerprint,
            b"different pin",
            128,
            1,
            "cranelift-1",
            "aarch64-test",
        );
        let other_budget = CompiledBodyRecordHash::for_fused_chain_tier2(
            fingerprint,
            b"root/self/pins",
            64,
            1,
            "cranelift-1",
            "aarch64-test",
        );

        assert_ne!(key, other_identity);
        assert_ne!(key, other_budget);
        assert_eq!(key.as_bytes().len(), 32);
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
