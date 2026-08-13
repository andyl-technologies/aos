//! Demand-cache key construction.
//!
//! RFC-0007 cache keys combine an expression identity with caller-supplied
//! free-variable value hashes. This module owns the ordered, length-prefixed
//! combiner required by decision C-1; the demand graph decides when to allocate
//! nodes and which canonical free-variable hashes to pass.

use crate::cache::hashing::CacheDigestHasher;
use std::hash::{Hash, Hasher};

use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

use super::{
    ValueHash,
    hashing::{
        CacheExprSourceHash, DemandKeyConfirmationHash, DemandKeyHotHash, ImpureInputIdentityHash,
    },
};
use crate::compile::IrId;

const KEY_DOMAIN_VERSION: &[u8] = b"aos-nix-demand-cache-key-v1";
const IMPURE_INPUT_KEY_DOMAIN_VERSION: &[u8] = b"aos-nix-impure-input-cache-key-v1";
const KEY_CONFIRMATION_DOMAIN_VERSION: &[u8] = b"aos-nix-demand-cache-key-confirm-v1";
const IMPURE_INPUT_CONFIRMATION_DOMAIN_VERSION: &[u8] =
    b"aos-nix-impure-input-cache-key-confirm-v1";

/// The stable identity of one lowered expression within a source artifact.
///
/// The first component is a typed expression/artifact hash. Callers may supply
/// a plain parsed/lowered artifact digest or an expression-positioned digest
/// that already includes caller-owned salts such as a source span. [`IrId`]
/// preserves the lowered node discriminator within that artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CacheExprIdentity {
    source_hash: CacheExprSourceHash,
    node: IrId,
}

impl CacheExprIdentity {
    /// Creates an expression identity from an expression/artifact hash and IR node id.
    pub const fn new(source_hash: CacheExprSourceHash, node: IrId) -> Self {
        Self { source_hash, node }
    }

    /// Returns the typed expression/artifact hash component.
    pub const fn source_hash(self) -> CacheExprSourceHash {
        self.source_hash
    }

    /// Returns the lowered IR node component.
    pub const fn node(self) -> IrId {
        self.node
    }

    fn write_to(self, hasher: &mut Xxh3) {
        hasher.write(&self.source_hash.as_durable_hash().as_bytes());
        hasher.write(&self.node.as_u32().to_le_bytes());
    }
}

/// An in-process demand-cache key for `H(expr_identity || env)`.
///
/// Keys are deliberately opaque: callers can compare or hash them for maps, but
/// cannot serialize them as durable cache addresses. Equality includes a
/// durable confirmation hash so the hot xxh3 component is only a lookup
/// accelerator, not an authority for cache reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DemandCacheKey {
    hot: DemandKeyHotHash,
    confirmation: DemandKeyConfirmationHash,
}

impl Hash for DemandCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hot.hash(state);
    }
}

impl DemandCacheKey {
    /// Creates a demand-cache key for an impure input identity.
    ///
    /// This key domain is distinct from expression/free-variable keys. The
    /// caller supplies the typed identity hash from `cache::input`; the
    /// observed input result belongs in the node value hash, not in the key.
    pub fn for_impure_input(identity_hash: ImpureInputIdentityHash) -> Self {
        let identity_hash = identity_hash.as_durable_hash();
        let mut hasher = Xxh3::new();
        hasher.write(IMPURE_INPUT_KEY_DOMAIN_VERSION);
        hasher.write(&identity_hash.as_bytes());
        let mut confirmation = CacheDigestHasher::new();
        confirmation.update(IMPURE_INPUT_CONFIRMATION_DOMAIN_VERSION);
        confirmation.update(&identity_hash.as_bytes());
        Self {
            hot: DemandKeyHotHash::from_xxh3(hasher.finish()),
            confirmation: DemandKeyConfirmationHash::from_hasher(confirmation),
        }
    }

    /// Combines an expression identity with canonical free-variable value hashes.
    ///
    /// `free_var_value_hashes` must already be in canonical slot order. The
    /// combiner preserves that order and length-prefixes every value hash. It
    /// computes both a hot xxh3 probe and a BLAKE3 confirmation digest over the
    /// complete stream.
    ///
    /// # Errors
    ///
    /// Returns [`CacheKeyError::ChunkLengthOverflow`] if a value-hash chunk
    /// cannot be represented as a `u64` length prefix.
    pub fn for_free_vars<I>(
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Self, CacheKeyError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let hashes = free_var_value_hashes
            .into_iter()
            .map(|hash| hash.as_durable_hash().as_bytes());
        combine_value_hash_chunks(identity, hashes)
    }

    #[cfg(test)]
    pub(in crate::cache) const fn from_raw_parts_for_test(
        hot: DemandKeyHotHash,
        confirmation: DemandKeyConfirmationHash,
    ) -> Self {
        Self { hot, confirmation }
    }
}

/// Demand-cache key construction failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CacheKeyError {
    /// A length-prefixed chunk was too large to encode.
    #[error("cache-key chunk length {len} does not fit in u64")]
    ChunkLengthOverflow {
        /// The chunk length that could not be represented.
        len: usize,
    },
}

fn combine_value_hash_chunks<I, B>(
    identity: CacheExprIdentity,
    chunks: I,
) -> Result<DemandCacheKey, CacheKeyError>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    crate::cache::key_hash_probe::note_demand_confirmation_finalize();
    let mut hot = Xxh3::new();
    hot.write(KEY_DOMAIN_VERSION);
    identity.write_to(&mut hot);
    let mut confirmation = CacheDigestHasher::new();
    confirmation.update(KEY_CONFIRMATION_DOMAIN_VERSION);
    confirmation.update(&identity.source_hash().as_durable_hash().as_bytes());
    confirmation.update(&identity.node().as_u32().to_le_bytes());
    for chunk in chunks {
        let chunk = chunk.as_ref();
        write_len_prefixed(&mut hot, chunk)?;
        write_len_prefixed_blake3(&mut confirmation, chunk)?;
    }
    Ok(DemandCacheKey {
        hot: DemandKeyHotHash::from_xxh3(hot.finish()),
        confirmation: DemandKeyConfirmationHash::from_hasher(confirmation),
    })
}

fn write_len_prefixed(hasher: &mut Xxh3, chunk: &[u8]) -> Result<(), CacheKeyError> {
    let len = u64::try_from(chunk.len())
        .map_err(|_| CacheKeyError::ChunkLengthOverflow { len: chunk.len() })?;
    hasher.write(&len.to_le_bytes());
    hasher.write(chunk);
    Ok(())
}

fn write_len_prefixed_blake3(
    hasher: &mut CacheDigestHasher,
    chunk: &[u8],
) -> Result<(), CacheKeyError> {
    let len = u64::try_from(chunk.len())
        .map_err(|_| CacheKeyError::ChunkLengthOverflow { len: chunk.len() })?;
    hasher.update(&len.to_le_bytes());
    hasher.update(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::cache::DurableBlake3Hash;

    fn source(bytes: &[u8]) -> DurableBlake3Hash {
        DurableBlake3Hash::for_bytes(bytes)
    }

    fn demand_hot(raw: u64) -> DemandKeyHotHash {
        DemandKeyHotHash::from_xxh3(raw)
    }

    fn demand_confirmation(bytes: &[u8]) -> DemandKeyConfirmationHash {
        DemandKeyConfirmationHash::from_precomputed_hash(source(bytes))
    }

    fn expr_source(bytes: &[u8]) -> CacheExprSourceHash {
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn input_identity_hash(bytes: &[u8]) -> ImpureInputIdentityHash {
        ImpureInputIdentityHash::from_persisted_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn identity(node: u32) -> CacheExprIdentity {
        CacheExprIdentity::new(expr_source(b"source"), IrId::new(node))
    }

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    #[test]
    fn impure_input_keys_are_domain_separated_from_expression_keys() {
        let hash = source(b"same durable bytes");
        let input_key =
            DemandCacheKey::for_impure_input(ImpureInputIdentityHash::from_persisted_hash(hash));
        let expression_key = DemandCacheKey::for_free_vars(
            CacheExprIdentity::new(CacheExprSourceHash::from_persisted_hash(hash), IrId::new(0)),
            [ValueHash::from_canonical_value_hash(hash)],
        )
        .expect("expression key builds");

        assert_ne!(input_key, expression_key);
    }

    #[test]
    fn impure_input_identity_changes_key() {
        let first = DemandCacheKey::for_impure_input(input_identity_hash(b"input one"));
        let second = DemandCacheKey::for_impure_input(input_identity_hash(b"input two"));

        assert_ne!(first, second);
    }

    #[test]
    fn same_identity_and_free_vars_produce_same_key() {
        let first =
            DemandCacheKey::for_free_vars(identity(7), [value_hash(b"left"), value_hash(b"right")])
                .expect("key builds");
        let second =
            DemandCacheKey::for_free_vars(identity(7), [value_hash(b"left"), value_hash(b"right")])
                .expect("key builds");

        assert_eq!(first, second);
    }

    #[test]
    fn expression_identity_changes_key() {
        let source_changed = CacheExprIdentity::new(expr_source(b"other-source"), IrId::new(7));
        let node_changed = identity(8);
        let base =
            DemandCacheKey::for_free_vars(identity(7), [value_hash(b"value")]).expect("key builds");

        assert_ne!(
            base,
            DemandCacheKey::for_free_vars(source_changed, [value_hash(b"value")])
                .expect("key builds")
        );
        assert_ne!(
            base,
            DemandCacheKey::for_free_vars(node_changed, [value_hash(b"value")])
                .expect("key builds")
        );
    }

    #[test]
    fn free_var_order_is_observed() {
        let left_then_right =
            DemandCacheKey::for_free_vars(identity(7), [value_hash(b"left"), value_hash(b"right")])
                .expect("key builds");
        let right_then_left =
            DemandCacheKey::for_free_vars(identity(7), [value_hash(b"right"), value_hash(b"left")])
                .expect("key builds");

        assert_ne!(left_then_right, right_then_left);
    }

    #[test]
    fn free_var_multiplicity_is_observed() {
        let no_vars = DemandCacheKey::for_free_vars(identity(7), []).expect("empty key builds");
        let duplicate_vars =
            DemandCacheKey::for_free_vars(identity(7), [value_hash(b"same"), value_hash(b"same")])
                .expect("key builds");

        assert_ne!(no_vars, duplicate_vars);
    }

    #[test]
    fn length_prefix_distinguishes_adjacent_chunk_boundaries() {
        let ab_c = combine_value_hash_chunks(identity(7), [b"ab".as_slice(), b"c".as_slice()])
            .expect("key builds");
        let a_bc = combine_value_hash_chunks(identity(7), [b"a".as_slice(), b"bc".as_slice()])
            .expect("key builds");

        assert_ne!(ab_c, a_bc);
    }

    #[test]
    fn durable_confirmation_keeps_hot_hash_collisions_distinct() {
        let hot = demand_hot(0xfeed_face_cafe_beef);
        let first = DemandCacheKey::from_raw_parts_for_test(
            hot,
            demand_confirmation(b"first confirmation"),
        );
        let second = DemandCacheKey::from_raw_parts_for_test(
            hot,
            demand_confirmation(b"second confirmation"),
        );

        assert_ne!(first, second);

        let mut map = HashMap::new();
        assert_eq!(map.insert(first, "first"), None);
        assert_eq!(map.insert(second, "second"), None);

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&first), Some(&"first"));
        assert_eq!(map.get(&second), Some(&"second"));
    }
}
