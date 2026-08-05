//! Early-cutoff decisions for incremental evaluation.
//!
//! The demand graph owns invalidation and dependency propagation. This module
//! owns the red/green decision at one reconsidered node: if recomputation
//! produces the same value hash as the previous run, the caller can stop
//! propagation at that node; otherwise the caller must propagate to consumers.

use crate::cache::hashing::CacheDigestHasher;
use thiserror::Error;

use super::hashing::{
    CachedExpressionPayloadValueHash, DerivationSidePayloadValueHash, DurableBlake3Hash,
    ForceCapturedValueHash, ImpureInputObservationHash,
};
use crate::string::{ContextKind, StringContext};
use crate::value::{Value, ValueError, ValueTag};

pub(crate) const INLINE_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-inline-value-hash-v1";
pub(crate) const CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-context-free-string-value-hash-v1";
pub(crate) const CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-context-string-value-hash-v1";
pub(crate) const PATH_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-path-value-hash-v1";
pub(crate) const CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-context-path-value-hash-v1";
pub(crate) const LIST_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-list-value-hash-v1";
pub(crate) const ATTRS_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-attrs-value-hash-v1";
pub(crate) const DERIVATION_ATERM_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-derivation-aterm-value-hash-v1";

/// A durable hash of a canonical evaluated value.
///
/// The future value serializer computes this as `blake3(canonical(value))`.
/// This wrapper gives cutoff decisions a distinct semantic type before the full
/// value store exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValueHash(DurableBlake3Hash);

impl ValueHash {
    /// Wraps a durable BLAKE3 hash produced from a canonical value.
    pub const fn from_canonical_value_hash(hash: DurableBlake3Hash) -> Self {
        Self(hash)
    }

    /// Returns the durable BLAKE3 hash carried by this value hash.
    pub const fn as_durable_hash(self) -> DurableBlake3Hash {
        self.0
    }

    /// Hashes a validated inline WHNF scalar value.
    ///
    /// This is a precursor for the full `blake3(canonical(value))` layer. It
    /// supports only inline value payloads and hashes floats by their raw IEEE
    /// bit pattern, so it may over-propagate relative to future Nix numeric
    /// canonicalization but cannot cut off different bit patterns.
    ///
    /// # Errors
    ///
    /// Returns [`ValueHashError::InvalidValue`] if the value payload violates
    /// its tag invariant. Returns [`ValueHashError::UnsupportedTag`] for
    /// heap-backed values, including thunks.
    pub fn from_inline_value(value: Value) -> Result<Self, ValueHashError> {
        value
            .validate_payload()
            .map_err(|source| ValueHashError::InvalidValue { source })?;
        let mut hasher = CacheDigestHasher::new();
        hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
        match value.tag() {
            ValueTag::Int => {
                hasher.update(b"int");
                hasher.update(
                    &value
                        .as_int()
                        .map_err(|source| ValueHashError::InvalidValue { source })?
                        .to_le_bytes(),
                );
            }
            ValueTag::Float => {
                hasher.update(b"float");
                // A Candidate-C float is a boxed reservation cell, not an inline
                // value, so it has no context-free hash here; it is excluded from
                // the inline cutoff cache and re-evaluated instead.
                #[cfg(feature = "candidate_c_value")]
                return Err(ValueHashError::InvalidValue {
                    source: crate::value::ValueError::BoxedScalarRequiresHeap { kind: "float" },
                });
                #[cfg(not(feature = "candidate_c_value"))]
                hasher.update(
                    &value
                        .as_float()
                        .map_err(|source| ValueHashError::InvalidValue { source })?
                        .to_bits()
                        .to_le_bytes(),
                );
            }
            ValueTag::Bool => {
                hasher.update(b"bool");
                let byte = value
                    .as_bool()
                    .map_err(|source| ValueHashError::InvalidValue { source })?
                    as u8;
                hasher.update(&[byte]);
            }
            ValueTag::Null => {
                value
                    .as_null()
                    .map_err(|source| ValueHashError::InvalidValue { source })?;
                hasher.update(b"null");
            }
            tag => return Err(ValueHashError::UnsupportedTag { tag }),
        }
        Ok(Self(DurableBlake3Hash::from_hasher(hasher)))
    }

    /// Hashes a context-free Nix string's raw bytes as a canonical value.
    ///
    /// This is a precursor for the full string value serializer. Callers must
    /// ensure the source string carries no context before passing its bytes
    /// here; context-bearing strings require the full canonical context
    /// serialization before they can participate in early cutoff.
    pub fn from_context_free_string_bytes(bytes: &[u8]) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"string");
        hasher.update(&(bytes.len() as u128).to_le_bytes());
        hasher.update(bytes);
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Hashes a context-bearing Nix string as a canonical value precursor.
    ///
    /// The hash covers the raw string bytes plus the string context's canonical
    /// sorted element set. Context element kinds, paths, and single-output
    /// output names are encoded with explicit tags and length prefixes so
    /// context-observable string values do not share cutoff identity with
    /// context-free strings or with other context kinds carrying the same path.
    pub fn from_context_string_parts(bytes: &[u8], context: &StringContext) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"string");
        hasher.update(&(bytes.len() as u128).to_le_bytes());
        hasher.update(bytes);
        update_string_context_hash(&mut hasher, context);
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Hashes a Nix path value's raw bytes as a canonical value precursor.
    ///
    /// This is separate from context-free string hashing because Nix paths and
    /// strings are distinct WHNF value tags even when their byte payloads match.
    pub fn from_path_bytes(bytes: &[u8]) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(PATH_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"path");
        hasher.update(&(bytes.len() as u128).to_le_bytes());
        hasher.update(bytes);
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Hashes a context-bearing Nix path as a canonical value precursor.
    ///
    /// The hash covers the path bytes plus the path value's string context.
    /// This stays separate from both context-bearing string hashing and
    /// context-free path hashing because Nix paths and strings remain distinct
    /// WHNF tags even when their byte payloads and contexts match.
    pub fn from_context_path_parts(bytes: &[u8], context: &StringContext) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"path");
        hasher.update(&(bytes.len() as u128).to_le_bytes());
        hasher.update(bytes);
        update_string_context_hash(&mut hasher, context);
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Hashes an empty Nix list as a canonical value precursor.
    ///
    /// Non-empty list hashing requires canonical element payload hashes and
    /// thunk policy, so the force-cache precursor admits only the empty list
    /// constructor for now.
    pub fn from_empty_list() -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(LIST_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"list");
        hasher.update(&0u128.to_le_bytes());
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Hashes an empty Nix attrset as a canonical value precursor.
    ///
    /// Non-empty attrset hashing requires canonical key/value serialization and
    /// thunk policy, so the force-cache precursor admits only the empty attrset
    /// constructor for now.
    pub fn from_empty_attrs() -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"attrs");
        hasher.update(&0u128.to_le_bytes());
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Hashes serialized `.drv` ATerm bytes as a derivationStrict value-hash precursor.
    ///
    /// This is a derivationStrict comparison key only. It deliberately stays in
    /// the BLAKE3 value-hash domain and must not feed Nix-observed SHA-256
    /// store paths or `.drv` hashes.
    pub fn from_derivation_aterm_bytes(aterm: &[u8]) -> Self {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(DERIVATION_ATERM_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"derivation");
        hasher.update(&(aterm.len() as u128).to_le_bytes());
        hasher.update(aterm);
        Self(DurableBlake3Hash::from_hasher(hasher))
    }

    /// Wraps a durable BLAKE3 hash of an impure input observation.
    ///
    /// This constructor is for demand-graph leaf nodes whose "value" is an
    /// observed filesystem or environment result, not a canonical Nix value.
    pub const fn from_impure_input_observation_hash(hash: ImpureInputObservationHash) -> Self {
        Self(hash.as_durable_hash())
    }

    /// Wraps a durable BLAKE3 hash of a force-cache captured free-variable fingerprint.
    ///
    /// This constructor is for demand-key free-variable material computed from
    /// captured heap values, static-select projections, or synthetic visible
    /// inputs. It keeps that non-canonical value-hash precursor on an explicit
    /// typed path before it enters the shared demand-key `ValueHash` format.
    pub(crate) const fn from_force_captured_value_hash(hash: ForceCapturedValueHash) -> Self {
        Self(hash.as_durable_hash())
    }

    /// Wraps a durable BLAKE3 hash of a cached derivation side-record payload.
    ///
    /// This constructor is for graph nodes that represent reusable
    /// derivationStrict side records, not a canonical Nix value.
    pub(crate) const fn from_derivation_side_payload_hash(
        hash: DerivationSidePayloadValueHash,
    ) -> Self {
        Self(hash.as_durable_hash())
    }

    /// Wraps a durable BLAKE3 hash of a cached expression payload.
    ///
    /// This constructor is for the canonical bytes stored in the persistent
    /// `values/` pack and replayed through [`crate::cache::CachedExpressionValue`].
    pub(crate) const fn from_cached_expression_payload_hash(
        hash: CachedExpressionPayloadValueHash,
    ) -> Self {
        Self(hash.as_durable_hash())
    }
}

fn update_string_context_hash(hasher: &mut CacheDigestHasher, context: &StringContext) {
    hasher.update(b"context");
    hasher.update(&(context.len() as u128).to_le_bytes());
    for element in context.elements() {
        match element.kind() {
            ContextKind::OpaquePath => {
                hasher.update(&[0]);
                hasher.update(&(element.path().len() as u128).to_le_bytes());
                hasher.update(element.path());
            }
            ContextKind::SingleOutput => {
                hasher.update(&[1]);
                hasher.update(&(element.path().len() as u128).to_le_bytes());
                hasher.update(element.path());
                let output = element.output().unwrap_or_default();
                hasher.update(&(output.len() as u128).to_le_bytes());
                hasher.update(output);
            }
            ContextKind::DeepDerivation => {
                hasher.update(&[2]);
                hasher.update(&(element.path().len() as u128).to_le_bytes());
                hasher.update(element.path());
            }
        }
    }
}

/// Inline value hashing failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ValueHashError {
    /// The value payload violated its tag invariant.
    #[error("cannot hash invalid value payload: {source}")]
    InvalidValue {
        /// The invalid value payload error.
        source: ValueError,
    },
    /// The value tag is outside the inline scalar precursor.
    #[error("inline value hashing does not support {tag:?}")]
    UnsupportedTag {
        /// The unsupported value tag.
        tag: ValueTag,
    },
}

/// The propagation decision for one reconsidered cache node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutoffDecision {
    /// The recomputed value hash matched the previous value hash.
    CutOff,
    /// The node has no previous value hash or recomputed to a different hash.
    Propagate,
}

impl CutoffDecision {
    /// Returns whether consumers of the reconsidered node must be dirtied.
    pub const fn should_propagate(self) -> bool {
        matches!(self, Self::Propagate)
    }
}

/// Stateless early-cutoff decision logic.
#[derive(Clone, Copy, Debug, Default)]
pub struct EarlyCutoff;

impl EarlyCutoff {
    /// Compares the previous and recomputed value hashes for one node.
    pub fn decide(previous: Option<ValueHash>, recomputed: ValueHash) -> CutoffDecision {
        match previous {
            Some(previous) if previous == recomputed => CutoffDecision::CutOff,
            Some(_) | None => CutoffDecision::Propagate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::{ContextElement, StringContext};
    use crate::value::HeapObject;
    use std::ptr::NonNull;

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn input_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_impure_input_observation_hash(
            ImpureInputObservationHash::from_persisted_hash(DurableBlake3Hash::for_bytes(bytes)),
        )
    }

    fn inline_hash(value: Value) -> ValueHash {
        ValueHash::from_inline_value(value).expect("inline value hashes")
    }

    fn opaque(path: &[u8]) -> ContextElement {
        ContextElement::opaque_path(path.to_vec()).expect("opaque context builds")
    }

    fn output(path: &[u8], name: &[u8]) -> ContextElement {
        ContextElement::single_output(path.to_vec(), name.to_vec()).expect("output context builds")
    }

    fn deep(path: &[u8]) -> ContextElement {
        ContextElement::deep_derivation(path.to_vec()).expect("deep context builds")
    }

    // Baseline float ABI test; variant float path via scalars.rs + parity
    // battery (cutover plan section 7).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn inline_value_hashes_are_stable_for_identical_values() {
        assert_eq!(inline_hash(Value::int(7)), inline_hash(Value::int(7)));
        assert_eq!(
            inline_hash(Value::bool(true)),
            inline_hash(Value::bool(true))
        );
        assert_eq!(inline_hash(Value::null()), inline_hash(Value::null()));
        assert_eq!(
            inline_hash(Value::float(13.25)),
            inline_hash(Value::float(13.25))
        );
    }

    // Baseline float ABI test; variant float path via scalars.rs + parity
    // battery (cutover plan section 7).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn inline_value_hashes_include_type_and_payload() {
        assert_ne!(inline_hash(Value::int(1)), inline_hash(Value::int(2)));
        assert_ne!(inline_hash(Value::int(1)), inline_hash(Value::bool(true)));
        assert_ne!(inline_hash(Value::null()), inline_hash(Value::bool(false)));
        assert_ne!(
            inline_hash(Value::float(0.0)),
            inline_hash(Value::float(-0.0))
        );
    }

    #[test]
    fn context_free_string_hashes_include_type_length_and_payload() {
        let empty = ValueHash::from_context_free_string_bytes(b"");
        let same = ValueHash::from_context_free_string_bytes(b"same");

        assert_eq!(same, ValueHash::from_context_free_string_bytes(b"same"));
        assert_ne!(empty, same);
        assert_ne!(same, ValueHash::from_context_free_string_bytes(b"same\0"));
        assert_ne!(
            same,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"same"))
        );
    }

    #[test]
    fn context_string_hashes_include_bytes_and_canonical_context() {
        let source = opaque(b"/nix/store/source");
        let output = output(b"/nix/store/pkg.drv", b"out");
        let first = StringContext::new(vec![output.clone(), source.clone(), output.clone()]);
        let second = StringContext::new(vec![source, output]);
        let hash = ValueHash::from_context_string_parts(b"same", &first);

        assert_eq!(hash, ValueHash::from_context_string_parts(b"same", &second));
        assert_ne!(
            hash,
            ValueHash::from_context_string_parts(b"different", &second)
        );
        assert_ne!(hash, ValueHash::from_context_free_string_bytes(b"same"));
    }

    #[test]
    fn context_string_hashes_distinguish_context_kinds_and_outputs() {
        let output_out = StringContext::new(vec![output(b"/nix/store/pkg.drv", b"out")]);
        let output_dev = StringContext::new(vec![output(b"/nix/store/pkg.drv", b"dev")]);
        let deep = StringContext::new(vec![deep(b"/nix/store/pkg.drv")]);
        let opaque = StringContext::new(vec![opaque(b"/nix/store/pkg.drv")]);
        let hash = ValueHash::from_context_string_parts(b"same", &output_out);

        assert_ne!(
            hash,
            ValueHash::from_context_string_parts(b"same", &output_dev)
        );
        assert_ne!(hash, ValueHash::from_context_string_parts(b"same", &deep));
        assert_ne!(hash, ValueHash::from_context_string_parts(b"same", &opaque));
    }

    #[test]
    fn path_hashes_include_type_length_and_payload() {
        let empty = ValueHash::from_path_bytes(b"");
        let same = ValueHash::from_path_bytes(b"same");

        assert_eq!(same, ValueHash::from_path_bytes(b"same"));
        assert_ne!(empty, same);
        assert_ne!(same, ValueHash::from_path_bytes(b"same\0"));
        assert_ne!(same, ValueHash::from_context_free_string_bytes(b"same"));
        assert_ne!(
            same,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"same"))
        );
    }

    #[test]
    fn context_path_hashes_include_bytes_and_canonical_context() {
        let source = opaque(b"/nix/store/source");
        let output = output(b"/nix/store/pkg.drv", b"out");
        let first = StringContext::new(vec![output.clone(), source.clone(), output.clone()]);
        let second = StringContext::new(vec![source, output]);
        let hash = ValueHash::from_context_path_parts(b"same", &first);

        assert_eq!(hash, ValueHash::from_context_path_parts(b"same", &second));
        assert_ne!(
            hash,
            ValueHash::from_context_path_parts(b"different", &second)
        );
        assert_ne!(hash, ValueHash::from_path_bytes(b"same"));
        assert_ne!(hash, ValueHash::from_context_string_parts(b"same", &second));
    }

    #[test]
    fn empty_list_hashes_include_type_and_length() {
        let hash = ValueHash::from_empty_list();

        assert_eq!(hash, ValueHash::from_empty_list());
        assert_ne!(hash, inline_hash(Value::null()));
        assert_ne!(hash, ValueHash::from_context_free_string_bytes(b"[]"));
        assert_ne!(
            hash,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"list"))
        );
    }

    #[test]
    fn empty_attrs_hashes_include_type_and_length() {
        let hash = ValueHash::from_empty_attrs();

        assert_eq!(hash, ValueHash::from_empty_attrs());
        assert_ne!(hash, ValueHash::from_empty_list());
        assert_ne!(hash, inline_hash(Value::null()));
        assert_ne!(hash, ValueHash::from_context_free_string_bytes(b"{}"));
        assert_ne!(
            hash,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"attrs"))
        );
    }

    #[test]
    fn derivation_aterm_hashes_include_domain_and_payload() {
        let aterm = b"Derive([(\"out\",\"/nix/store/example\",\"\")],[],[],\":\",\":\",[],[])";
        let hash = ValueHash::from_derivation_aterm_bytes(aterm);

        assert_eq!(hash, ValueHash::from_derivation_aterm_bytes(aterm));
        assert_ne!(
            hash,
            ValueHash::from_derivation_aterm_bytes(
                b"Derive([(\"out\",\"/nix/store/changed\",\"\")],[],[],\":\",\":\",[],[])"
            )
        );
        assert_ne!(hash, ValueHash::from_context_free_string_bytes(aterm));
        assert_ne!(
            hash,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(aterm))
        );
    }

    #[test]
    fn derivation_aterm_hashes_participate_in_cutoff_decisions() {
        let hash = ValueHash::from_derivation_aterm_bytes(b"Derive([],[],[],\":\",\":\",[],[])");
        let decision = EarlyCutoff::decide(Some(hash), hash);

        assert_eq!(decision, CutoffDecision::CutOff);
    }

    #[test]
    fn inline_value_hashes_participate_in_cutoff_decisions() {
        let hash = inline_hash(Value::int(7));
        let decision = EarlyCutoff::decide(Some(hash), hash);

        assert_eq!(decision, CutoffDecision::CutOff);
    }

    // Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
    // reservation heap geometry (GC-stress record placement / chunked / fake
    // pointer) or reads a boxed wide scalar context-free — both unavailable under
    // the single-reservation Candidate-C carrier. Real eval is covered by the
    // byte-parity battery (cutover plan sections 2, 3.6).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn heap_values_are_not_inline_hashable() {
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::string(ptr).expect("string value builds");

        assert_eq!(
            ValueHash::from_inline_value(value),
            Err(ValueHashError::UnsupportedTag {
                tag: ValueTag::String
            })
        );
    }

    #[test]
    fn impure_input_observation_hashes_participate_in_cutoff_decisions() {
        let hash = input_hash(b"same input result");
        let decision = EarlyCutoff::decide(Some(hash), hash);

        assert_eq!(decision, CutoffDecision::CutOff);
    }

    #[test]
    fn unchanged_value_hash_cuts_off_propagation() {
        let hash = value_hash(b"same value");
        let decision = EarlyCutoff::decide(Some(hash), hash);

        assert_eq!(decision, CutoffDecision::CutOff);
        assert!(!decision.should_propagate());
    }

    #[test]
    fn changed_value_hash_propagates_to_consumers() {
        let decision = EarlyCutoff::decide(
            Some(value_hash(b"old value")),
            value_hash(b"recomputed value"),
        );

        assert_eq!(decision, CutoffDecision::Propagate);
        assert!(decision.should_propagate());
    }

    #[test]
    fn missing_previous_hash_propagates_to_consumers() {
        let decision = EarlyCutoff::decide(None, value_hash(b"first value"));

        assert_eq!(decision, CutoffDecision::Propagate);
        assert!(decision.should_propagate());
    }
}
