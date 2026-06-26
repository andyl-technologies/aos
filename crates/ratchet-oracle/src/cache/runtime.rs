//! Caller-owned evaluator cache runtime substrate.
//!
//! This module ties evaluator observation traces to the in-memory demand graph
//! while keeping evaluator policy decisions explicit at call sites. Callers
//! choose which computations to observe, which memoization subject applies, and
//! which value-hash cost signals are available.

use std::collections::{BTreeMap, HashMap};

use thiserror::Error;

use super::cutoff::{
    ATTRS_VALUE_HASH_DOMAIN_VERSION, CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION,
    CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION,
    INLINE_VALUE_HASH_DOMAIN_VERSION, LIST_VALUE_HASH_DOMAIN_VERSION,
    PATH_VALUE_HASH_DOMAIN_VERSION,
};
use super::{
    CacheExprIdentity, CacheableInputFingerprint, DemandCacheKey, DemandGraph, DemandGraphError,
    DemandNodeId, DirtyFrontier, DurableBlake3Hash, ImpureInputFingerprint, ImpureInputIdentity,
    ImpureTraceObservation, ImpureTraceStatus, MemoizationDecision, MemoizationDemand,
    MemoizationSubject, NodeFreshness, RecomputeReadyDirty, Reconsideration, UncacheableInput,
    ValueHash, ValueHashError,
};
use crate::string::{ContextElement, ContextKind, NixStringError, StringContext};
use crate::value::Value;

const MAX_CACHED_EXPRESSION_PAYLOAD_NESTING: usize = 64;
const DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-derivation-aterm-path-value-hash-v1";
const STATIC_DERIVATION_OUTPUT_PATHS_VALUE_HASH_DOMAIN_VERSION: &[u8] =
    b"aos-nix-static-derivation-output-paths-value-hash-v1";

/// A source of evaluator-observed impure input trace entries.
pub trait ImpureInputTraceSource {
    /// Returns impure inputs observed while evaluating a root computation.
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint];

    /// Returns whether the trace is complete enough to be cache-usable.
    fn impure_input_trace_complete(&self) -> bool;
}

/// Recomputes impure-input fingerprints for cached input identities.
pub trait ImpureInputRevalidator {
    /// Revalidates one previously observed cacheable input identity.
    ///
    /// Returning `None` means the input could not be revalidated without
    /// evaluating the original expression, so the cache lookup must miss.
    fn revalidate_impure_input(
        &mut self,
        identity: &ImpureInputIdentity,
    ) -> Option<ImpureInputFingerprint>;
}

/// Whether an observed expression evaluation is eligible for memoization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpressionCacheability {
    /// The expression is cacheable and has a demand-graph node.
    Cacheable(DemandNodeId),
    /// The evaluator could not produce a complete dependency trace.
    Incomplete,
    /// The expression observed an input that makes memoization unsound.
    Uncacheable(UncacheableInput),
}

/// The result of observing one expression evaluation's impure-input trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpressionTraceObservation {
    node: Option<DemandNodeId>,
    trace: ImpureTraceObservation,
    payload_reconsideration: Option<Reconsideration>,
}

impl ExpressionTraceObservation {
    fn new(node: Option<DemandNodeId>, trace: ImpureTraceObservation) -> Self {
        Self {
            node,
            trace,
            payload_reconsideration: None,
        }
    }

    fn with_payload_reconsideration(
        node: DemandNodeId,
        trace: ImpureTraceObservation,
        payload_reconsideration: Reconsideration,
    ) -> Self {
        Self {
            node: Some(node),
            trace,
            payload_reconsideration: Some(payload_reconsideration),
        }
    }

    /// Returns the expression node wired to cacheable input leaves, if any.
    pub const fn node(&self) -> Option<DemandNodeId> {
        self.node
    }

    /// Returns the observed impure trace cacheability and leaves.
    pub const fn trace(&self) -> &ImpureTraceObservation {
        &self.trace
    }

    /// Returns the value-hash reconsideration from payload observation, if any.
    pub fn payload_reconsideration(&self) -> Option<&Reconsideration> {
        self.payload_reconsideration.as_ref()
    }

    /// Returns whether this expression evaluation can be memoized.
    pub fn cacheability(&self) -> ExpressionCacheability {
        match self.trace.status() {
            ImpureTraceStatus::Cacheable => self
                .node
                .map(ExpressionCacheability::Cacheable)
                .unwrap_or(ExpressionCacheability::Incomplete),
            ImpureTraceStatus::Incomplete => ExpressionCacheability::Incomplete,
            ImpureTraceStatus::Uncacheable(input) => ExpressionCacheability::Uncacheable(input),
        }
    }

    /// Consumes this observation into its node and trace parts.
    pub fn into_parts(self) -> (Option<DemandNodeId>, ImpureTraceObservation) {
        (self.node, self.trace)
    }
}

/// A same-run memoization demand observation and its admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoizationObservation {
    demand: MemoizationDemand,
    decision: MemoizationDecision,
}

impl MemoizationObservation {
    const fn new(demand: MemoizationDemand, decision: MemoizationDecision) -> Self {
        Self { demand, decision }
    }

    /// Returns the demand count after recording the current demand.
    pub const fn demand(self) -> MemoizationDemand {
        self.demand
    }

    /// Returns the policy decision for the updated demand and caller signals.
    pub const fn decision(self) -> MemoizationDecision {
        self.decision
    }
}

/// A memoized force-cache payload that can be replayed by an evaluator.
///
/// Immediate values can be returned directly because they carry their payload
/// in the [`Value`] word. Heap-backed values must instead store canonical data
/// and be rehydrated by the evaluator that consumes the hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedExpressionValue {
    payload: InlineValuePayload,
}

/// A cached derivation output store path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CachedDerivationOutputPath {
    name: Vec<u8>,
    path: Vec<u8>,
}

impl CachedDerivationOutputPath {
    /// Creates a cached output path entry from an output name and absolute path bytes.
    pub(crate) fn new(name: Vec<u8>, path: Vec<u8>) -> Self {
        Self { name, path }
    }

    /// Returns the output name bytes.
    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the absolute output path bytes.
    pub(crate) fn path(&self) -> &[u8] {
        &self.path
    }
}

/// Cached static output paths for a resolved `derivationStrict` expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CachedDerivationOutputPaths {
    hash_derivation_modulo: [u8; 32],
    output_paths: Vec<CachedDerivationOutputPath>,
}

impl CachedDerivationOutputPaths {
    /// Creates a cached static-output-path record.
    pub(crate) fn new(
        hash_derivation_modulo: [u8; 32],
        mut output_paths: Vec<CachedDerivationOutputPath>,
    ) -> Self {
        output_paths.sort_unstable_by(|left, right| {
            left.name.cmp(&right.name).then(left.path.cmp(&right.path))
        });
        Self {
            hash_derivation_modulo,
            output_paths,
        }
    }

    /// Returns the resolved derivation hash modulo bytes.
    pub(crate) const fn hash_derivation_modulo(&self) -> [u8; 32] {
        self.hash_derivation_modulo
    }

    /// Returns the cached output path entries.
    pub(crate) fn output_paths(&self) -> &[CachedDerivationOutputPath] {
        &self.output_paths
    }

    fn value_hash(&self, pre_output_aterm: &[u8]) -> ValueHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STATIC_DERIVATION_OUTPUT_PATHS_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"pre-output-aterm");
        update_derivation_side_payload_hash_chunk(&mut hasher, pre_output_aterm);
        hasher.update(b"hash-derivation-modulo");
        hasher.update(&self.hash_derivation_modulo);
        hasher.update(b"output-paths");
        hasher.update(&(self.output_paths.len() as u128).to_le_bytes());
        for output_path in &self.output_paths {
            update_derivation_side_payload_hash_chunk(&mut hasher, &output_path.name);
            update_derivation_side_payload_hash_chunk(&mut hasher, &output_path.path);
        }
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::from_hasher(hasher))
    }
}

impl CachedExpressionValue {
    /// Creates a cached immediate scalar value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueHashError`] if `value` is invalid or is not an inline
    /// scalar supported by the current force-cache payload precursor.
    pub fn immediate(value: Value) -> Result<Self, ValueHashError> {
        Ok(Self {
            payload: InlineValuePayload::from_value(value)?,
        })
    }

    /// Creates a cached context-free Nix string payload from canonical bytes.
    pub fn context_free_string(bytes: Vec<u8>) -> Self {
        Self {
            payload: InlineValuePayload::ContextFreeString(bytes),
        }
    }

    /// Creates a cached Nix string payload from canonical bytes and context.
    ///
    /// Empty contexts are canonicalized to [`Self::context_free_string`].
    pub fn context_string(bytes: Vec<u8>, context: StringContext) -> Self {
        if context.is_empty() {
            return Self::context_free_string(bytes);
        }
        Self {
            payload: InlineValuePayload::ContextString { bytes, context },
        }
    }

    /// Creates a cached Nix path payload from canonical path bytes.
    pub fn path(bytes: Vec<u8>) -> Self {
        Self {
            payload: InlineValuePayload::Path(bytes),
        }
    }

    /// Creates a cached Nix path payload from canonical path bytes and context.
    ///
    /// Empty contexts are canonicalized to [`Self::path`].
    pub fn context_path(bytes: Vec<u8>, context: StringContext) -> Self {
        if context.is_empty() {
            return Self::path(bytes);
        }
        Self {
            payload: InlineValuePayload::ContextPath { bytes, context },
        }
    }

    /// Creates a cached empty Nix list payload.
    pub const fn empty_list() -> Self {
        Self {
            payload: InlineValuePayload::EmptyList,
        }
    }

    /// Creates a cached strict Nix list payload from replayable element payloads.
    ///
    /// This represents a list spine whose elements are already replayable
    /// values. It does not represent lazy element thunks; callers must not force
    /// elements just to build this payload.
    pub fn strict_list(elements: Vec<Self>) -> Self {
        if elements.is_empty() {
            return Self::empty_list();
        }
        Self {
            payload: InlineValuePayload::List(
                elements.into_iter().map(|value| value.payload).collect(),
            ),
        }
    }

    /// Creates a cached strict Nix attrset payload from replayable bindings.
    ///
    /// This represents an attrset whose binding values are already replayable
    /// values. It does not represent lazy binding thunks; callers must not
    /// force bindings just to build this payload.
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName`]
    /// if two bindings have the same attribute name.
    pub fn strict_attrs(
        mut entries: Vec<(Vec<u8>, Self)>,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if entries.is_empty() {
            return Ok(Self::empty_attrs());
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        for (index, pair) in entries.windows(2).enumerate() {
            if pair[0].0 == pair[1].0 {
                return Err(
                    CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName {
                        index: index + 1,
                    },
                );
            }
        }
        Ok(Self {
            payload: InlineValuePayload::Attrs(
                entries
                    .into_iter()
                    .map(|(name, value)| AttrPayloadEntry {
                        name,
                        value: value.payload,
                    })
                    .collect(),
            ),
        })
    }

    /// Creates a cached empty Nix attrset payload.
    pub const fn empty_attrs() -> Self {
        Self {
            payload: InlineValuePayload::EmptyAttrs,
        }
    }

    /// Returns the durable value hash for this cached payload.
    ///
    /// # Errors
    ///
    /// Returns [`ValueHashError`] if an immediate scalar payload cannot be
    /// represented as a supported inline value.
    pub fn value_hash(&self) -> Result<ValueHash, ValueHashError> {
        self.payload.value_hash()
    }

    /// Encodes this payload for the persistent `values/` pack.
    ///
    /// The encoded bytes are the canonical BLAKE3 preimage used by
    /// [`Self::value_hash`]. Consequently
    /// `DurableBlake3Hash::for_bytes(encoded) == self.value_hash().as_durable_hash()`,
    /// allowing the persistent pack to address payload bytes by the same value
    /// hash the demand graph records.
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError`] if the encoded payload
    /// cannot reserve enough byte storage.
    pub fn encode_persistent_payload(&self) -> Result<Vec<u8>, CachedExpressionValuePayloadError> {
        self.payload.encode_persistent_payload()
    }

    /// Decodes a payload produced by [`Self::encode_persistent_payload`].
    ///
    /// # Errors
    ///
    /// Returns [`CachedExpressionValuePayloadError`] if `bytes` are not a
    /// complete, canonical cached-expression payload.
    pub fn decode_persistent_payload(
        bytes: &[u8],
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        Ok(Self {
            payload: InlineValuePayload::decode_persistent_payload(bytes)?,
        })
    }

    /// Returns the immediate scalar value, if this payload is immediate.
    pub fn immediate_value(&self) -> Option<Value> {
        self.payload.immediate_value()
    }

    /// Returns the cached context-free string bytes, if this payload is a string.
    pub fn context_free_string_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            InlineValuePayload::ContextFreeString(bytes) => Some(bytes),
            InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns cached string bytes and context, if this payload is a contextual string.
    pub fn context_string_parts(&self) -> Option<(&[u8], &StringContext)> {
        match &self.payload {
            InlineValuePayload::ContextString { bytes, context } => Some((bytes, context)),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns the cached path bytes, if this payload is a context-free path.
    pub fn path_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            InlineValuePayload::Path(bytes) => Some(bytes),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns cached path bytes and context, if this payload is a contextual path.
    pub fn context_path_parts(&self) -> Option<(&[u8], &StringContext)> {
        match &self.payload {
            InlineValuePayload::ContextPath { bytes, context } => Some((bytes, context)),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_)
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::Attrs(_)
            | InlineValuePayload::Null => None,
        }
    }

    /// Returns whether this payload is the empty Nix list.
    pub const fn is_empty_list(&self) -> bool {
        matches!(&self.payload, InlineValuePayload::EmptyList)
    }

    /// Returns the cached list spine length, if this payload is a list.
    pub fn list_len(&self) -> Option<usize> {
        match &self.payload {
            InlineValuePayload::EmptyList => Some(0),
            InlineValuePayload::List(elements) => Some(elements.len()),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyAttrs
            | InlineValuePayload::Attrs(_) => None,
        }
    }

    pub(crate) fn list_element_payloads(&self) -> Option<Vec<Self>> {
        match &self.payload {
            InlineValuePayload::EmptyList => Some(Vec::new()),
            InlineValuePayload::List(elements) => {
                let mut out = Vec::new();
                out.try_reserve_exact(elements.len()).ok()?;
                out.extend(
                    elements
                        .iter()
                        .cloned()
                        .map(|payload| CachedExpressionValue { payload }),
                );
                Some(out)
            }
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyAttrs => None,
            InlineValuePayload::Attrs(_) => None,
        }
    }

    /// Returns whether this payload is the empty Nix attrset.
    pub const fn is_empty_attrs(&self) -> bool {
        matches!(&self.payload, InlineValuePayload::EmptyAttrs)
    }

    /// Returns the cached attrset binding count, if this payload is an attrset.
    pub fn attrs_len(&self) -> Option<usize> {
        match &self.payload {
            InlineValuePayload::EmptyAttrs => Some(0),
            InlineValuePayload::Attrs(entries) => Some(entries.len()),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_) => None,
        }
    }

    pub(crate) fn attrs_entries(&self) -> Option<Vec<(Vec<u8>, Self)>> {
        match &self.payload {
            InlineValuePayload::EmptyAttrs => Some(Vec::new()),
            InlineValuePayload::Attrs(entries) => {
                let mut out = Vec::new();
                out.try_reserve_exact(entries.len()).ok()?;
                out.extend(entries.iter().map(|entry| {
                    (
                        entry.name.clone(),
                        CachedExpressionValue {
                            payload: entry.value.clone(),
                        },
                    )
                }));
                Some(out)
            }
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null
            | InlineValuePayload::ContextFreeString(_)
            | InlineValuePayload::ContextString { .. }
            | InlineValuePayload::Path(_)
            | InlineValuePayload::ContextPath { .. }
            | InlineValuePayload::EmptyList
            | InlineValuePayload::List(_) => None,
        }
    }
}

/// Persistent cached-expression payload encoding failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CachedExpressionValuePayloadError {
    /// Payload byte storage could not be reserved.
    #[error("failed to reserve cached expression payload storage for {len} bytes")]
    PayloadAllocationFailed {
        /// The requested byte capacity.
        len: usize,
    },
    /// Payload byte length arithmetic overflowed.
    #[error("cached expression payload length overflow: {current} + {additional}")]
    PayloadLengthOverflow {
        /// The current payload length.
        current: usize,
        /// The additional bytes being appended.
        additional: usize,
    },
    /// Context element storage could not be reserved while decoding.
    #[error("failed to reserve cached expression context storage for {len} elements")]
    ContextAllocationFailed {
        /// The requested context element capacity.
        len: usize,
    },
    /// List element storage could not be reserved while decoding.
    #[error("failed to reserve cached expression list storage for {len} elements")]
    ListAllocationFailed {
        /// The requested list element capacity.
        len: usize,
    },
    /// Attrset binding storage could not be reserved while decoding.
    #[error("failed to reserve cached expression attrset storage for {len} bindings")]
    AttrsAllocationFailed {
        /// The requested attrset binding capacity.
        len: usize,
    },
    /// A length field cannot fit in `usize` on this host.
    #[error("cached expression payload length {len} cannot fit in usize")]
    LengthOverflow {
        /// The oversized encoded length.
        len: u128,
    },
    /// The payload did not carry a known value-hash domain prefix.
    #[error("cached expression payload has an unknown value-hash domain")]
    UnknownDomain,
    /// A payload section had an unexpected tag.
    #[error("cached expression payload has invalid {section} tag {tag}")]
    InvalidTag {
        /// The malformed payload section.
        section: &'static str,
        /// The unexpected tag byte.
        tag: u8,
    },
    /// A decoded bool payload byte was not `0` or `1`.
    #[error("cached expression bool payload has invalid byte {byte}")]
    InvalidBool {
        /// The invalid bool byte.
        byte: u8,
    },
    /// The payload ended before a required section was complete.
    #[error("cached expression payload has {actual} bytes, expected at least {expected}")]
    ShortPayload {
        /// The minimum required payload length.
        expected: usize,
        /// The available payload length.
        actual: usize,
    },
    /// A fixed payload marker was absent at the current cursor position.
    #[error("cached expression payload is missing {marker}")]
    MissingMarker {
        /// The marker name.
        marker: &'static str,
    },
    /// The decoder did not consume the whole payload.
    #[error("cached expression payload has {remaining} trailing bytes")]
    TrailingBytes {
        /// The number of unconsumed bytes.
        remaining: usize,
    },
    /// A decoded string-context element violated context invariants.
    #[error("cached expression payload has invalid string context: {source}")]
    Context {
        /// The underlying string-context error.
        source: NixStringError,
    },
    /// A decoded string-context element was out of canonical order or duplicated.
    #[error("cached expression payload has non-canonical string context element at index {index}")]
    NonCanonicalStringContext {
        /// The zero-based index of the out-of-order or duplicate element.
        index: usize,
    },
    /// A context-bearing payload used the contextual domain with no context elements.
    #[error("cached expression {payload} payload has an empty string context")]
    EmptyStringContext {
        /// The malformed contextual payload kind.
        payload: &'static str,
    },
    /// An attrset payload binding name was out of canonical order or duplicated.
    #[error("cached expression attrset payload has non-canonical binding name at index {index}")]
    NonCanonicalAttrsPayloadName {
        /// The zero-based index of the out-of-order or duplicate binding name.
        index: usize,
    },
    /// Nested payload decoding exceeded the supported recursion depth.
    #[error("cached expression payload nesting exceeded {limit} levels")]
    PayloadNestingLimitExceeded {
        /// The maximum supported nesting depth.
        limit: usize,
    },
}

/// Explicit evaluator cache state owned by the caller.
#[derive(Clone, Debug, Default)]
pub struct EvalCache {
    graph: DemandGraph,
    inline_values: BTreeMap<DemandNodeId, InlineValueRecord>,
    derivation_aterm_paths: BTreeMap<DemandNodeId, DerivationAtermPathRecord>,
    static_derivation_output_paths: BTreeMap<DemandNodeId, StaticDerivationOutputPathRecord>,
    memoization_demands: HashMap<DemandCacheKey, MemoizationDemand>,
}

impl EvalCache {
    /// Creates an empty evaluator cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an evaluator cache from an existing demand graph.
    pub fn from_graph(graph: DemandGraph) -> Self {
        Self {
            graph,
            inline_values: BTreeMap::new(),
            derivation_aterm_paths: BTreeMap::new(),
            static_derivation_output_paths: BTreeMap::new(),
            memoization_demands: HashMap::new(),
        }
    }

    /// Returns the number of nodes in the underlying demand graph.
    pub fn len(&self) -> usize {
        self.graph.len()
    }

    /// Returns whether the underlying demand graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.graph.is_empty()
    }

    /// Returns the underlying demand graph.
    pub const fn graph(&self) -> &DemandGraph {
        &self.graph
    }

    #[cfg(test)]
    pub(crate) fn derivation_aterm_path_record_count(&self) -> usize {
        self.derivation_aterm_paths.len()
    }

    #[cfg(test)]
    pub(crate) fn static_derivation_output_path_record_count(&self) -> usize {
        self.static_derivation_output_paths.len()
    }

    /// Consumes this cache into its demand graph.
    pub fn into_graph(self) -> DemandGraph {
        self.graph
    }

    /// Returns a deterministic scheduling snapshot for dirty graph nodes.
    ///
    /// This is a read-only adapter over [`DemandGraph::dirty_frontier`]. It
    /// does not recompute nodes, mutate freshness, or schedule evaluator work.
    pub fn dirty_frontier(&self) -> DirtyFrontier {
        self.graph.dirty_frontier()
    }

    /// Records same-run memoization demand and evaluates the subject policy.
    ///
    /// This API stores admission signals beside the demand graph without
    /// allocating graph nodes or probing/persisting value payloads. Callers
    /// supply the computation subject and whether the value hash is cheap or
    /// already available; the cache records one current-run demand for the
    /// expression key and returns the default policy decision for the updated
    /// demand.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn record_memoization_demand<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        subject: MemoizationSubject,
        cheap_value_hash: bool,
    ) -> Result<MemoizationObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let demand = self
            .memoization_demands
            .entry(key)
            .or_default()
            .record_current_demand();
        self.memoization_demands.insert(key, demand);
        let decision = subject
            .default_class()
            .decide(demand.signals(cheap_value_hash));
        Ok(MemoizationObservation::new(demand, decision))
    }

    /// Returns same-run memoization demand for an expression key.
    ///
    /// This read path is telemetry-only: it does not allocate demand-graph
    /// nodes, mutate demand counters, or evaluate admission policy.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn memoization_demand<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<MemoizationDemand>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        Ok(self.memoization_demands.get(&key).copied())
    }

    /// Recomputes ready dirty graph nodes through a caller-supplied callback.
    ///
    /// This is an explicit adapter over
    /// [`DemandGraph::recompute_ready_dirty_nodes`]. It schedules ready dirty
    /// demand nodes and applies graph early cutoff, but the caller still owns
    /// evaluator recomputation, value hashing, dynamic dependency capture, and
    /// persistence.
    ///
    /// # Errors
    ///
    /// Returns graph scheduling/reconsideration errors converted through `E`, or
    /// any caller error returned by `recompute`. If `recompute` fails after
    /// earlier nodes in the same call were reconsidered, those graph mutations
    /// are retained and the partial [`RecomputeReadyDirty`] result is not
    /// returned.
    pub fn recompute_ready_dirty_nodes<E, F>(
        &mut self,
        recompute: F,
    ) -> Result<RecomputeReadyDirty, E>
    where
        E: From<DemandGraphError>,
        F: FnMut(DemandNodeId) -> Result<ValueHash, E>,
    {
        self.graph.recompute_ready_dirty_nodes(recompute)
    }

    /// Looks up a clean memoized expression payload.
    ///
    /// This is a precursor memo path for force-time cache hits. It returns a
    /// payload only when the expression key already exists, its demand node is
    /// clean, the side payload record is reusable without input revalidation,
    /// and that payload still matches the node's value hash. Unknown, dirty,
    /// missing-payload, trace-backed, and stale-payload nodes are cache misses.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn lookup_inline_expression_payload<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if !record.is_reusable_without_revalidation() {
            return Ok(None);
        }
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        Ok(Some(record.value()))
    }

    /// Looks up a clean memoized immediate expression result.
    ///
    /// This compatibility path returns only immediate scalar values. Heap-backed
    /// payloads are misses for callers that cannot rehydrate them into their own
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub fn lookup_inline_expression_result<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        Ok(self
            .lookup_inline_expression_payload(identity, free_var_value_hashes)?
            .and_then(|value| value.immediate_value()))
    }

    /// Looks up a clean cached derivation `.drv` path for matching ATerm bytes.
    ///
    /// This is a path-lookup precursor for future derivationStrict SHA-256
    /// short-circuiting. It returns stored `.drv` path bytes only when the
    /// caller-supplied expression key exists, the demand node is clean, a
    /// derivation path side record exists, the side record's ATerm hash matches
    /// `aterm`, and the graph node's value hash still matches the full side
    /// payload hash. Unknown, dirty, missing, and stale records are misses.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub(crate) fn lookup_derivation_aterm_path<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Vec<u8>>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.derivation_aterm_paths.get(&node) else {
            return Ok(None);
        };
        let aterm_value_hash = ValueHash::from_derivation_aterm_bytes(aterm);
        if record.aterm_value_hash != aterm_value_hash
            || graph_node.value_hash() != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        Ok(Some(record.path_bytes()))
    }

    /// Looks up clean cached static derivation output paths for matching ATerm bytes.
    ///
    /// This is a pre-output-path precursor for future `derivationStrict`
    /// SHA-256 short-circuiting. It returns stored output paths and the final
    /// derivation hash modulo only when the caller-supplied expression key
    /// exists, the demand node is clean, a static-output side record exists,
    /// the side record's pre-output hash matches `pre_output_aterm`, and the
    /// graph node's value hash still matches the full side payload hash.
    /// Unknown, dirty, missing, and stale records are misses.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails.
    pub(crate) fn lookup_static_derivation_output_paths<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedDerivationOutputPaths>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.static_derivation_output_paths.get(&node) else {
            return Ok(None);
        };
        let pre_output_value_hash = ValueHash::from_derivation_aterm_bytes(pre_output_aterm);
        if record.pre_output_value_hash != pre_output_value_hash
            || graph_node.value_hash() != Some(record.payload_value_hash)
        {
            return Ok(None);
        }
        Ok(Some(record.output_paths()))
    }

    /// Looks up a clean expression payload after impure-input revalidation.
    ///
    /// Pure payload records are handled identically to
    /// [`EvalCache::lookup_inline_expression_payload`]. Trace-backed payload
    /// records are returned only if every stored cacheable input identity can be
    /// revalidated, the fresh identity still matches the stored identity, the
    /// fresh observation hash still matches the stored observation hash, and the
    /// expression node remains clean with the recorded value hash. Revalidation
    /// observes fresh input leaves through the demand graph so changed inputs
    /// dirty dependents through the ordinary cutoff path.
    ///
    /// Inputs that cannot be revalidated, revalidate to an uncacheable
    /// fingerprint, or revalidate to a different identity invalidate the
    /// expression payload and return a miss.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, graph
    /// node lookup fails, fresh input observation fails, or dirty marking
    /// fails.
    pub fn lookup_inline_expression_payload_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(None);
        };
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        let Some(record) = self.inline_values.get(&node).cloned() else {
            return Ok(None);
        };
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        if record.is_reusable_without_revalidation() {
            return Ok(Some(record.value()));
        }
        if !self.revalidate_inline_record_inputs(node, &record, revalidator)? {
            return Ok(None);
        }
        let graph_node = self.graph.node(node)?;
        if graph_node.freshness() != NodeFreshness::Clean {
            return Ok(None);
        }
        if graph_node.value_hash() != Some(record.value_hash) {
            return Ok(None);
        }
        Ok(Some(record.value()))
    }

    /// Looks up a clean immediate result after impure-input revalidation.
    ///
    /// This compatibility path returns only immediate scalar values. Heap-backed
    /// payloads are misses for callers that cannot rehydrate them into their own
    /// heap.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, graph
    /// node lookup fails, fresh input observation fails, or dirty marking
    /// fails.
    pub fn lookup_inline_expression_result_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        Ok(self
            .lookup_inline_expression_payload_with_impure_inputs(
                identity,
                free_var_value_hashes,
                revalidator,
            )?
            .and_then(|value| value.immediate_value()))
    }

    /// Gets or inserts an expression node in the underlying demand graph.
    ///
    /// This is an explicit graph-allocation helper. Callers still supply the
    /// expression identity, ordered free-variable value hashes, and optional
    /// current value hash.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails or if the
    /// underlying graph cannot reserve node/key storage.
    pub fn get_or_insert_expression_node<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        self.graph
            .get_or_insert_expression_node(identity, free_var_value_hashes, value_hash)
    }

    /// Observes impure inputs from one completed evaluator trace source.
    ///
    /// This delegates to [`DemandGraph::observe_impure_trace`]. It records only
    /// cacheable input leaves and cacheability status; it does not create
    /// evaluating-node demand edges or memoized value records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the underlying graph cannot reserve
    /// storage or cannot insert/reconsider a cacheable input leaf.
    pub fn observe_impure_inputs<T>(
        &mut self,
        source: &T,
    ) -> Result<ImpureTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        self.graph.observe_impure_trace(
            source.impure_input_trace(),
            source.impure_input_trace_complete(),
        )
    }

    /// Observes impure inputs and wires cacheable leaves to an existing node.
    ///
    /// `dependent` must be a caller-supplied node in this cache's demand graph.
    /// This delegates to [`DemandGraph::observe_impure_trace_for_node`] and
    /// does not create evaluating nodes or memoized value records.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the dependent node is unknown, if
    /// trace observation fails, or if dependency edge insertion fails.
    pub fn observe_impure_inputs_for_node<T>(
        &mut self,
        dependent: DemandNodeId,
        source: &T,
    ) -> Result<ImpureTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        self.graph.observe_impure_trace_for_node(
            dependent,
            source.impure_input_trace(),
            source.impure_input_trace_complete(),
        )
    }

    /// Observes an expression evaluation trace and wires cacheable leaves to its node.
    ///
    /// This first computes the expression key and observes the trace.
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node; if the expression key already exists, any side
    /// inline payload is invalidated and its stale dependencies are cleared.
    /// Complete cacheable traces get or insert the caller-supplied expression
    /// node, invalidate any prior side inline payload, and then replace that
    /// node's dependencies with the observed input leaves.
    ///
    /// This is still an explicit adapter: callers supply expression identity,
    /// ordered free-variable value hashes, and the optional current value hash.
    /// It does not compute evaluator identities, perform memo lookup, or own
    /// dynamic evaluator node lifecycle.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation or edge replacement later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, an existing payload cannot be
    /// invalidated, or dependency edge replacement fails.
    pub fn observe_expression_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let existing_node = self.graph.node_id_for_key(key);
        let trace = self.observe_impure_inputs(source)?;
        self.invalidate_existing_inline_payload_if_present(existing_node)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            if let Some(node) = existing_node {
                self.graph
                    .replace_dependencies(node, std::iter::empty::<DemandNodeId>())?;
            }
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        let node = self.graph.get_or_insert_node(key, value_hash)?;
        self.graph
            .replace_dependencies(node, trace.leaves().iter().map(|leaf| leaf.node()))?;
        Ok(ExpressionTraceObservation::new(Some(node), trace))
    }

    /// Observes one recomputed expression payload.
    ///
    /// This is the first force-path integration point for the demand graph:
    /// callers still provide the expression identity and ordered free-variable
    /// hashes, and the cache only records/reconsiders the payload value hash.
    /// It does not perform memo lookup, compute free-variable hashes, or
    /// serialize general heap-backed values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub fn observe_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let record = InlineValueRecord::reusable_without_revalidation(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        self.inline_values.insert(node, record);
        Ok(reconsideration)
    }

    /// Observes one recomputed derivation ATerm expression.
    ///
    /// Callers still provide the expression identity and ordered free-variable
    /// hashes. The cache hashes the recorded `.drv` ATerm bytes as a comparison
    /// key and reconsiders the expression node, but it does not memoize a value
    /// payload or compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub fn observe_derivation_aterm_expression<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        self.graph.reconsider_derivation_aterm_node(node, aterm)
    }

    /// Observes one recomputed derivation ATerm expression and `.drv` path.
    ///
    /// This extends [`Self::observe_derivation_aterm_expression`] with a side
    /// record containing caller-supplied `.drv` path bytes. The path record is
    /// usable only through [`Self::lookup_derivation_aterm_path`] when the graph
    /// node remains clean, the same ATerm hash still matches, and the graph
    /// node still carries the full ATerm/path payload hash. This API does not
    /// compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub(crate) fn observe_derivation_aterm_expression_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let record = DerivationAtermPathRecord::new(aterm, drv_path);
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        self.derivation_aterm_paths.insert(node, record);
        Ok(reconsideration)
    }

    /// Observes resolved static derivation output paths for pre-output ATerm bytes.
    ///
    /// This records a side payload containing caller-supplied output paths and
    /// the final derivation hash modulo. The payload is usable only through
    /// [`Self::lookup_static_derivation_output_paths`] while the graph node
    /// remains clean, the same pre-output ATerm hash still matches, and the
    /// graph node still carries the full side payload hash. This API does not
    /// compute Nix-observed SHA-256 output paths itself.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, or the node cannot be reconsidered.
    pub(crate) fn observe_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let node = self.get_or_insert_expression_node(identity, free_var_value_hashes, None)?;
        let record = StaticDerivationOutputPathRecord::new(pre_output_aterm, output_paths);
        let reconsideration = self
            .graph
            .reconsider_node(node, record.payload_value_hash)?;
        self.static_derivation_output_paths.insert(node, record);
        Ok(reconsideration)
    }

    /// Invalidates an existing inline expression payload.
    ///
    /// If the expression key already exists, the node is marked dirty and any
    /// side payload is removed. Missing keys return `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails or the
    /// existing node cannot be marked dirty.
    pub fn invalidate_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<bool, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let Some(node) = self.graph.node_id_for_key(key) else {
            return Ok(false);
        };
        self.invalidate_existing_inline_payload(Some(node))?;
        Ok(true)
    }

    /// Observes one recomputed immediate expression result.
    ///
    /// This compatibility path accepts only immediate scalar values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if cache-key construction fails, node
    /// insertion fails, the node cannot be reconsidered, or the value is not an
    /// inline scalar supported by [`ValueHash::from_inline_value`].
    pub fn observe_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
    ) -> Result<Reconsideration, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let value = CachedExpressionValue::immediate(value)
            .map_err(|source| DemandGraphError::ValueHash { source })?;
        self.observe_inline_expression_payload(identity, free_var_value_hashes, value)
    }

    /// Observes one recomputed expression payload with its impure inputs.
    ///
    /// Cacheable traces get or insert the expression node, replace its
    /// dependencies with the observed input leaves, reconsider the node from
    /// the payload value hash, and store the side payload plus the cacheable
    /// input fingerprints
    /// required by
    /// [`EvalCache::lookup_inline_expression_payload_with_impure_inputs`].
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node or payload; if the expression key already exists,
    /// its prior inline payload and stale dependencies are removed and the node
    /// is marked dirty.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation, edge replacement, or value reconsideration later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, dependency edge replacement
    /// fails, dirty marking fails, or node reconsideration fails.
    pub fn observe_inline_expression_payload_with_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        self.observe_inline_expression_payload_for_key_with_impure_inputs(key, value, source)
    }

    fn observe_inline_expression_payload_for_key_with_impure_inputs<T>(
        &mut self,
        key: DemandCacheKey,
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let existing_node = self.graph.node_id_for_key(key);
        let trace = self.observe_impure_inputs(source)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            self.invalidate_existing_inline_payload(existing_node)?;
            if let Some(node) = existing_node {
                self.graph
                    .replace_dependencies(node, std::iter::empty::<DemandNodeId>())?;
            }
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        let record = match InlineValueRecord::requires_revalidation(value, source) {
            Ok(record) => record,
            Err(error) => {
                self.invalidate_existing_inline_payload(existing_node)?;
                if let Some(node) = existing_node {
                    self.graph
                        .replace_dependencies(node, std::iter::empty::<DemandNodeId>())?;
                }
                return Err(error);
            }
        };
        let node = self.graph.get_or_insert_node(key, None)?;
        self.graph
            .replace_dependencies(node, trace.leaves().iter().map(|leaf| leaf.node()))?;
        let payload_reconsideration = self.graph.reconsider_node(node, record.value_hash)?;
        self.inline_values.insert(node, record);
        Ok(ExpressionTraceObservation::with_payload_reconsideration(
            node,
            trace,
            payload_reconsideration,
        ))
    }

    /// Observes one recomputed immediate expression result with its impure inputs.
    ///
    /// This compatibility path accepts only immediate scalar values.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if inline value hashing fails, trace
    /// observation fails, expression cache-key construction or insertion fails,
    /// dependency edge insertion fails, dirty marking fails, or node
    /// reconsideration fails.
    pub fn observe_inline_expression_result_with_impure_inputs<I, T>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
        source: &T,
    ) -> Result<ExpressionTraceObservation, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        T: ImpureInputTraceSource + ?Sized,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        let value = match CachedExpressionValue::immediate(value) {
            Ok(value) => value,
            Err(source) => {
                let existing_node = self.graph.node_id_for_key(key);
                self.invalidate_existing_inline_payload(existing_node)?;
                return Err(DemandGraphError::ValueHash { source });
            }
        };
        self.observe_inline_expression_payload_for_key_with_impure_inputs(key, value, source)
    }

    /// Reconsiders one node from a recomputed inline scalar value.
    ///
    /// This delegates to [`DemandGraph::reconsider_inline_value_node`]. It does
    /// not implement heap-backed canonical value hashing or memo lookup.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if inline value hashing fails or if the
    /// node is unknown.
    pub fn reconsider_inline_value_node(
        &mut self,
        id: DemandNodeId,
        value: Value,
    ) -> Result<Reconsideration, DemandGraphError> {
        self.graph.reconsider_inline_value_node(id, value)
    }

    /// Reconsiders one node from recomputed derivation ATerm bytes.
    ///
    /// This delegates to [`DemandGraph::reconsider_derivation_aterm_node`]. It
    /// does not compute Nix-observed SHA-256 `.drv` hashes or store paths.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if the node is unknown.
    pub fn reconsider_derivation_aterm_node(
        &mut self,
        id: DemandNodeId,
        aterm: &[u8],
    ) -> Result<Reconsideration, DemandGraphError> {
        self.graph.reconsider_derivation_aterm_node(id, aterm)
    }

    fn invalidate_existing_inline_payload(
        &mut self,
        node: Option<DemandNodeId>,
    ) -> Result<(), DemandGraphError> {
        if let Some(node) = node {
            self.graph.mark_dirty(node)?;
            self.inline_values.remove(&node);
            self.derivation_aterm_paths.remove(&node);
            self.static_derivation_output_paths.remove(&node);
        }
        Ok(())
    }

    fn invalidate_existing_inline_payload_if_present(
        &mut self,
        node: Option<DemandNodeId>,
    ) -> Result<(), DemandGraphError> {
        if let Some(node) = node {
            if self.inline_values.contains_key(&node) {
                self.invalidate_existing_inline_payload(Some(node))?;
            }
        }
        Ok(())
    }

    fn revalidate_inline_record_inputs<R>(
        &mut self,
        node: DemandNodeId,
        record: &InlineValueRecord,
        revalidator: &mut R,
    ) -> Result<bool, DemandGraphError>
    where
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(inputs) = record.revalidation_inputs() else {
            return Ok(false);
        };
        for expected in inputs {
            let Some(fresh) = revalidator.revalidate_impure_input(expected.identity()) else {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            };
            let ImpureInputFingerprint::Cacheable(fresh) = fresh else {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            };
            if fresh.identity() != expected.identity() {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            }
            self.graph.observe_impure_input(&fresh)?;
            if fresh.observation_hash() != expected.observation_hash() {
                self.invalidate_existing_inline_payload(Some(node))?;
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InlineValueRecord {
    payload: InlineValuePayload,
    value_hash: ValueHash,
    reusable_without_revalidation: bool,
    revalidation_inputs: Option<Vec<CacheableInputFingerprint>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DerivationAtermPathRecord {
    aterm_value_hash: ValueHash,
    payload_value_hash: ValueHash,
    path: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StaticDerivationOutputPathRecord {
    pre_output_value_hash: ValueHash,
    payload_value_hash: ValueHash,
    output_paths: CachedDerivationOutputPaths,
}

impl DerivationAtermPathRecord {
    fn new(aterm: &[u8], path: &[u8]) -> Self {
        let payload_value_hash = derivation_aterm_path_payload_value_hash(aterm, path);
        Self {
            aterm_value_hash: ValueHash::from_derivation_aterm_bytes(aterm),
            payload_value_hash,
            path: path.to_vec(),
        }
    }

    fn path_bytes(&self) -> Vec<u8> {
        self.path.clone()
    }
}

fn derivation_aterm_path_payload_value_hash(aterm: &[u8], path: &[u8]) -> ValueHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DERIVATION_ATERM_PATH_VALUE_HASH_DOMAIN_VERSION);
    hasher.update(b"aterm");
    update_derivation_side_payload_hash_chunk(&mut hasher, aterm);
    hasher.update(b"drv-path");
    update_derivation_side_payload_hash_chunk(&mut hasher, path);
    ValueHash::from_canonical_value_hash(DurableBlake3Hash::from_hasher(hasher))
}

impl StaticDerivationOutputPathRecord {
    fn new(pre_output_aterm: &[u8], output_paths: CachedDerivationOutputPaths) -> Self {
        let payload_value_hash = output_paths.value_hash(pre_output_aterm);
        Self {
            pre_output_value_hash: ValueHash::from_derivation_aterm_bytes(pre_output_aterm),
            payload_value_hash,
            output_paths,
        }
    }

    fn output_paths(&self) -> CachedDerivationOutputPaths {
        self.output_paths.clone()
    }
}

fn update_derivation_side_payload_hash_chunk(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u128).to_le_bytes());
    hasher.update(bytes);
}

impl InlineValueRecord {
    fn reusable_without_revalidation(value: CachedExpressionValue) -> Result<Self, ValueHashError> {
        Self::from_cached_value(value, true, None)
    }

    fn requires_revalidation<T>(
        value: CachedExpressionValue,
        source: &T,
    ) -> Result<Self, DemandGraphError>
    where
        T: ImpureInputTraceSource + ?Sized,
    {
        let inputs = cacheable_trace_inputs(source.impure_input_trace())?;
        Self::from_cached_value(value, false, Some(inputs))
            .map_err(|source| DemandGraphError::ValueHash { source })
    }

    fn from_cached_value(
        value: CachedExpressionValue,
        reusable_without_revalidation: bool,
        revalidation_inputs: Option<Vec<CacheableInputFingerprint>>,
    ) -> Result<Self, ValueHashError> {
        let value_hash = value.payload.value_hash()?;
        Ok(Self {
            payload: value.payload,
            value_hash,
            reusable_without_revalidation,
            revalidation_inputs,
        })
    }

    fn value(&self) -> CachedExpressionValue {
        CachedExpressionValue {
            payload: self.payload.clone(),
        }
    }

    const fn is_reusable_without_revalidation(&self) -> bool {
        self.reusable_without_revalidation
    }

    fn revalidation_inputs(&self) -> Option<&[CacheableInputFingerprint]> {
        self.revalidation_inputs.as_deref()
    }
}

fn cacheable_trace_inputs(
    trace: &[ImpureInputFingerprint],
) -> Result<Vec<CacheableInputFingerprint>, DemandGraphError> {
    let mut inputs = Vec::new();
    inputs.try_reserve_exact(trace.len()).map_err(|_| {
        DemandGraphError::TraceObservationAllocationFailed {
            observations: trace.len(),
        }
    })?;
    for fingerprint in trace {
        let ImpureInputFingerprint::Cacheable(fingerprint) = fingerprint else {
            continue;
        };
        inputs.push(fingerprint.clone());
    }
    Ok(inputs)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InlineValuePayload {
    Int(i64),
    Float(u64),
    Bool(bool),
    Null,
    ContextFreeString(Vec<u8>),
    ContextString {
        bytes: Vec<u8>,
        context: StringContext,
    },
    Path(Vec<u8>),
    ContextPath {
        bytes: Vec<u8>,
        context: StringContext,
    },
    EmptyList,
    List(Vec<InlineValuePayload>),
    EmptyAttrs,
    Attrs(Vec<AttrPayloadEntry>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttrPayloadEntry {
    name: Vec<u8>,
    value: InlineValuePayload,
}

impl InlineValuePayload {
    fn from_value(value: Value) -> Result<Self, ValueHashError> {
        value
            .validate_payload()
            .map_err(|source| ValueHashError::InvalidValue { source })?;
        match value.tag() {
            crate::value::ValueTag::Int => value
                .as_int()
                .map(Self::Int)
                .map_err(|source| ValueHashError::InvalidValue { source }),
            crate::value::ValueTag::Float => value
                .as_float()
                .map(f64::to_bits)
                .map(Self::Float)
                .map_err(|source| ValueHashError::InvalidValue { source }),
            crate::value::ValueTag::Bool => value
                .as_bool()
                .map(Self::Bool)
                .map_err(|source| ValueHashError::InvalidValue { source }),
            crate::value::ValueTag::Null => {
                value
                    .as_null()
                    .map_err(|source| ValueHashError::InvalidValue { source })?;
                Ok(Self::Null)
            }
            tag => Err(ValueHashError::UnsupportedTag { tag }),
        }
    }

    fn immediate_value(&self) -> Option<Value> {
        match self {
            Self::Int(value) => Some(Value::int(*value)),
            Self::Float(bits) => Some(Value::float(f64::from_bits(*bits))),
            Self::Bool(value) => Some(Value::bool(*value)),
            Self::Null => Some(Value::null()),
            Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::List(_)
            | Self::EmptyAttrs
            | Self::Attrs(_) => None,
        }
    }

    fn value_hash(&self) -> Result<ValueHash, ValueHashError> {
        match self {
            Self::Int(value) => ValueHash::from_inline_value(Value::int(*value)),
            Self::Float(bits) => ValueHash::from_inline_value(Value::float(f64::from_bits(*bits))),
            Self::Bool(value) => ValueHash::from_inline_value(Value::bool(*value)),
            Self::Null => ValueHash::from_inline_value(Value::null()),
            Self::ContextFreeString(bytes) => Ok(ValueHash::from_context_free_string_bytes(bytes)),
            Self::ContextString { bytes, context } => {
                Ok(ValueHash::from_context_string_parts(bytes, context))
            }
            Self::Path(bytes) => Ok(ValueHash::from_path_bytes(bytes)),
            Self::ContextPath { bytes, context } => {
                Ok(ValueHash::from_context_path_parts(bytes, context))
            }
            Self::EmptyList => Ok(ValueHash::from_empty_list()),
            Self::List(_) => Ok(self.value_hash_from_persistent_payload()),
            Self::EmptyAttrs => Ok(ValueHash::from_empty_attrs()),
            Self::Attrs(_) => Ok(self.value_hash_from_persistent_payload()),
        }
    }

    fn value_hash_from_persistent_payload(&self) -> ValueHash {
        let mut hasher = blake3::Hasher::new();
        self.update_persistent_payload_preimage(&mut hasher);
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::from_hasher(hasher))
    }

    fn update_persistent_payload_preimage(&self, hasher: &mut blake3::Hasher) {
        match self {
            Self::Int(value) => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"int");
                hasher.update(&value.to_le_bytes());
            }
            Self::Float(bits) => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"float");
                hasher.update(&bits.to_le_bytes());
            }
            Self::Bool(value) => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"bool");
                hasher.update(&[u8::from(*value)]);
            }
            Self::Null => {
                hasher.update(INLINE_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"null");
            }
            Self::ContextFreeString(bytes) => {
                hasher.update(CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"string");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
            }
            Self::ContextString { bytes, context } => {
                hasher.update(CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"string");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
                update_string_context_payload_preimage(hasher, context);
            }
            Self::Path(bytes) => {
                hasher.update(PATH_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"path");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
            }
            Self::ContextPath { bytes, context } => {
                hasher.update(CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"path");
                hasher.update(&(bytes.len() as u128).to_le_bytes());
                hasher.update(bytes);
                update_string_context_payload_preimage(hasher, context);
            }
            Self::EmptyList => {
                hasher.update(LIST_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"list");
                hasher.update(&0u128.to_le_bytes());
            }
            Self::List(elements) => {
                hasher.update(LIST_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"list");
                hasher.update(&(elements.len() as u128).to_le_bytes());
                for element in elements {
                    hasher.update(&element.persistent_payload_len().to_le_bytes());
                    element.update_persistent_payload_preimage(hasher);
                }
            }
            Self::EmptyAttrs => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"attrs");
                hasher.update(&0u128.to_le_bytes());
            }
            Self::Attrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(b"attrs");
                hasher.update(&(entries.len() as u128).to_le_bytes());
                for entry in entries {
                    hasher.update(&(entry.name.len() as u128).to_le_bytes());
                    hasher.update(&entry.name);
                    hasher.update(&entry.value.persistent_payload_len().to_le_bytes());
                    entry.value.update_persistent_payload_preimage(hasher);
                }
            }
        }
    }

    fn persistent_payload_len(&self) -> u128 {
        match self {
            Self::Int(_) => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 3 + 8,
            Self::Float(_) => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 5 + 8,
            Self::Bool(_) => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4 + 1,
            Self::Null => INLINE_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4,
            Self::ContextFreeString(bytes) => {
                CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 6
                    + 16
                    + bytes.len() as u128
            }
            Self::ContextString { bytes, context } => {
                CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 6
                    + 16
                    + bytes.len() as u128
                    + string_context_payload_len(context)
            }
            Self::Path(bytes) => {
                PATH_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4 + 16 + bytes.len() as u128
            }
            Self::ContextPath { bytes, context } => {
                CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 4
                    + 16
                    + bytes.len() as u128
                    + string_context_payload_len(context)
            }
            Self::EmptyList => LIST_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 4 + 16,
            Self::List(elements) => {
                LIST_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 4
                    + 16
                    + elements
                        .iter()
                        .map(|element| 16 + element.persistent_payload_len())
                        .sum::<u128>()
            }
            Self::EmptyAttrs => ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128 + 5 + 16,
            Self::Attrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + 5
                    + 16
                    + entries
                        .iter()
                        .map(|entry| {
                            16 + entry.name.len() as u128
                                + 16
                                + entry.value.persistent_payload_len()
                        })
                        .sum::<u128>()
            }
        }
    }

    fn encode_persistent_payload(&self) -> Result<Vec<u8>, CachedExpressionValuePayloadError> {
        let mut out = Vec::new();
        match self {
            Self::Int(value) => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"int")?;
                append_payload_bytes(&mut out, &value.to_le_bytes())?;
            }
            Self::Float(bits) => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"float")?;
                append_payload_bytes(&mut out, &bits.to_le_bytes())?;
            }
            Self::Bool(value) => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"bool")?;
                append_payload_byte(&mut out, u8::from(*value))?;
            }
            Self::Null => {
                append_payload_bytes(&mut out, INLINE_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"null")?;
            }
            Self::ContextFreeString(bytes) => {
                append_payload_bytes(&mut out, CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"string")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
            }
            Self::ContextString { bytes, context } => {
                append_payload_bytes(&mut out, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"string")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
                append_string_context_payload(&mut out, context)?;
            }
            Self::Path(bytes) => {
                append_payload_bytes(&mut out, PATH_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"path")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
            }
            Self::ContextPath { bytes, context } => {
                append_payload_bytes(&mut out, CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"path")?;
                append_payload_u128(&mut out, bytes.len() as u128)?;
                append_payload_bytes(&mut out, bytes)?;
                append_string_context_payload(&mut out, context)?;
            }
            Self::EmptyList => {
                append_payload_bytes(&mut out, LIST_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"list")?;
                append_payload_u128(&mut out, 0)?;
            }
            Self::List(elements) => {
                append_payload_bytes(&mut out, LIST_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"list")?;
                append_payload_u128(&mut out, elements.len() as u128)?;
                for element in elements {
                    append_payload_u128(&mut out, element.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &element.encode_persistent_payload()?)?;
                }
            }
            Self::EmptyAttrs => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"attrs")?;
                append_payload_u128(&mut out, 0)?;
            }
            Self::Attrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, b"attrs")?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
        }
        Ok(out)
    }

    fn decode_persistent_payload(bytes: &[u8]) -> Result<Self, CachedExpressionValuePayloadError> {
        Self::decode_persistent_payload_with_depth(bytes, 0)
    }

    fn decode_persistent_payload_with_depth(
        bytes: &[u8],
        depth: usize,
    ) -> Result<Self, CachedExpressionValuePayloadError> {
        if depth > MAX_CACHED_EXPRESSION_PAYLOAD_NESTING {
            return Err(
                CachedExpressionValuePayloadError::PayloadNestingLimitExceeded {
                    limit: MAX_CACHED_EXPRESSION_PAYLOAD_NESTING,
                },
            );
        }
        if bytes.starts_with(INLINE_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(INLINE_VALUE_HASH_DOMAIN_VERSION, "inline value domain")?;
            let payload = decode_inline_value_payload(&mut cursor)?;
            cursor.finish()?;
            return Ok(payload);
        }
        if bytes.starts_with(CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                CONTEXT_FREE_STRING_VALUE_HASH_DOMAIN_VERSION,
                "context-free string value domain",
            )?;
            cursor.take_marker(b"string", "string payload tag")?;
            let payload = Self::ContextFreeString(cursor.take_length_prefixed_bytes()?);
            cursor.finish()?;
            return Ok(payload);
        }
        if bytes.starts_with(CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION,
                "context string value domain",
            )?;
            cursor.take_marker(b"string", "string payload tag")?;
            let string_bytes = cursor.take_length_prefixed_bytes()?;
            let context = cursor.take_string_context()?;
            if context.is_empty() {
                return Err(CachedExpressionValuePayloadError::EmptyStringContext {
                    payload: "context string",
                });
            }
            cursor.finish()?;
            return Ok(Self::ContextString {
                bytes: string_bytes,
                context,
            });
        }
        if bytes.starts_with(PATH_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(PATH_VALUE_HASH_DOMAIN_VERSION, "path value domain")?;
            cursor.take_marker(b"path", "path payload tag")?;
            let payload = Self::Path(cursor.take_length_prefixed_bytes()?);
            cursor.finish()?;
            return Ok(payload);
        }
        if bytes.starts_with(CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(
                CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION,
                "context path value domain",
            )?;
            cursor.take_marker(b"path", "path payload tag")?;
            let path_bytes = cursor.take_length_prefixed_bytes()?;
            let context = cursor.take_string_context()?;
            if context.is_empty() {
                return Err(CachedExpressionValuePayloadError::EmptyStringContext {
                    payload: "context path",
                });
            }
            cursor.finish()?;
            return Ok(Self::ContextPath {
                bytes: path_bytes,
                context,
            });
        }
        if bytes.starts_with(LIST_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(LIST_VALUE_HASH_DOMAIN_VERSION, "list value domain")?;
            cursor.take_marker(b"list", "list payload tag")?;
            let len = cursor.take_len()?;
            if len == 0 {
                cursor.finish()?;
                return Ok(Self::EmptyList);
            }
            let mut elements = Vec::new();
            elements
                .try_reserve_exact(len)
                .map_err(|_| CachedExpressionValuePayloadError::ListAllocationFailed { len })?;
            for _ in 0..len {
                let element = cursor.take_length_prefixed_bytes()?;
                elements.push(Self::decode_persistent_payload_with_depth(
                    &element,
                    depth.saturating_add(1),
                )?);
            }
            cursor.finish()?;
            return Ok(Self::List(elements));
        }
        if bytes.starts_with(ATTRS_VALUE_HASH_DOMAIN_VERSION) {
            let mut cursor = PayloadCursor::new(bytes);
            cursor.take_marker(ATTRS_VALUE_HASH_DOMAIN_VERSION, "attrs value domain")?;
            cursor.take_marker(b"attrs", "attrs payload tag")?;
            let len = cursor.take_len()?;
            if len == 0 {
                cursor.finish()?;
                return Ok(Self::EmptyAttrs);
            }
            let mut entries: Vec<AttrPayloadEntry> = Vec::new();
            entries
                .try_reserve_exact(len)
                .map_err(|_| CachedExpressionValuePayloadError::AttrsAllocationFailed { len })?;
            for index in 0..len {
                let name = cursor.take_length_prefixed_bytes()?;
                if let Some(previous) = entries.last()
                    && previous.name.as_slice() >= name.as_slice()
                {
                    return Err(
                        CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index },
                    );
                }
                let value = cursor.take_length_prefixed_bytes()?;
                entries.push(AttrPayloadEntry {
                    name,
                    value: Self::decode_persistent_payload_with_depth(
                        &value,
                        depth.saturating_add(1),
                    )?,
                });
            }
            cursor.finish()?;
            return Ok(Self::Attrs(entries));
        }
        Err(CachedExpressionValuePayloadError::UnknownDomain)
    }
}

fn append_payload_byte(
    out: &mut Vec<u8>,
    byte: u8,
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_bytes(out, &[byte])
}

fn append_payload_u128(
    out: &mut Vec<u8>,
    value: u128,
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_bytes(out, &value.to_le_bytes())
}

fn append_payload_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CachedExpressionValuePayloadError> {
    let len = out.len().checked_add(bytes.len()).ok_or(
        CachedExpressionValuePayloadError::PayloadLengthOverflow {
            current: out.len(),
            additional: bytes.len(),
        },
    )?;
    out.try_reserve_exact(bytes.len())
        .map_err(|_| CachedExpressionValuePayloadError::PayloadAllocationFailed { len })?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn append_length_prefixed_payload_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_u128(out, bytes.len() as u128)?;
    append_payload_bytes(out, bytes)
}

fn append_string_context_payload(
    out: &mut Vec<u8>,
    context: &StringContext,
) -> Result<(), CachedExpressionValuePayloadError> {
    append_payload_bytes(out, b"context")?;
    append_payload_u128(out, context.len() as u128)?;
    for element in context.elements() {
        match element.kind() {
            ContextKind::OpaquePath => {
                append_payload_byte(out, 0)?;
                append_length_prefixed_payload_bytes(out, element.path())?;
            }
            ContextKind::SingleOutput => {
                append_payload_byte(out, 1)?;
                append_length_prefixed_payload_bytes(out, element.path())?;
                let output = match element.output() {
                    Some(output) => output,
                    None => &[],
                };
                append_length_prefixed_payload_bytes(out, output)?;
            }
            ContextKind::DeepDerivation => {
                append_payload_byte(out, 2)?;
                append_length_prefixed_payload_bytes(out, element.path())?;
            }
        }
    }
    Ok(())
}

fn string_context_payload_len(context: &StringContext) -> u128 {
    7 + 16
        + context
            .elements()
            .iter()
            .map(|element| {
                let path_len = element.path().len() as u128;
                match element.kind() {
                    ContextKind::OpaquePath | ContextKind::DeepDerivation => 1 + 16 + path_len,
                    ContextKind::SingleOutput => {
                        let output_len = element.output().unwrap_or_default().len() as u128;
                        1 + 16 + path_len + 16 + output_len
                    }
                }
            })
            .sum::<u128>()
}

fn update_string_context_payload_preimage(hasher: &mut blake3::Hasher, context: &StringContext) {
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

fn decode_inline_value_payload(
    cursor: &mut PayloadCursor<'_>,
) -> Result<InlineValuePayload, CachedExpressionValuePayloadError> {
    if cursor.remaining().starts_with(b"int") {
        cursor.take_marker(b"int", "int payload tag")?;
        return Ok(InlineValuePayload::Int(cursor.take_i64()?));
    }
    if cursor.remaining().starts_with(b"float") {
        cursor.take_marker(b"float", "float payload tag")?;
        return Ok(InlineValuePayload::Float(cursor.take_u64()?));
    }
    if cursor.remaining().starts_with(b"bool") {
        cursor.take_marker(b"bool", "bool payload tag")?;
        let byte = cursor.take_byte()?;
        return match byte {
            0 => Ok(InlineValuePayload::Bool(false)),
            1 => Ok(InlineValuePayload::Bool(true)),
            byte => Err(CachedExpressionValuePayloadError::InvalidBool { byte }),
        };
    }
    if cursor.remaining().starts_with(b"null") {
        cursor.take_marker(b"null", "null payload tag")?;
        return Ok(InlineValuePayload::Null);
    }
    let tag = match cursor.remaining().first().copied() {
        Some(tag) => tag,
        None => 0,
    };
    Err(CachedExpressionValuePayloadError::InvalidTag {
        section: "inline value",
        tag,
    })
}

struct PayloadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn finish(&self) -> Result<(), CachedExpressionValuePayloadError> {
        let remaining = self.bytes.len() - self.offset;
        if remaining == 0 {
            Ok(())
        } else {
            Err(CachedExpressionValuePayloadError::TrailingBytes { remaining })
        }
    }

    fn take_marker(
        &mut self,
        marker: &'static [u8],
        name: &'static str,
    ) -> Result<(), CachedExpressionValuePayloadError> {
        let actual = self.take_bytes(marker.len())?;
        if actual == marker {
            Ok(())
        } else {
            Err(CachedExpressionValuePayloadError::MissingMarker { marker: name })
        }
    }

    fn take_byte(&mut self) -> Result<u8, CachedExpressionValuePayloadError> {
        Ok(self.take_bytes(1)?[0])
    }

    fn take_i64(&mut self) -> Result<i64, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(8)?;
        let mut out = [0; 8];
        out.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(out))
    }

    fn take_u64(&mut self) -> Result<u64, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(8)?;
        let mut out = [0; 8];
        out.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(out))
    }

    fn take_u128(&mut self) -> Result<u128, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(16)?;
        let mut out = [0; 16];
        out.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(out))
    }

    fn take_len(&mut self) -> Result<usize, CachedExpressionValuePayloadError> {
        let len = self.take_u128()?;
        usize::try_from(len).map_err(|_| CachedExpressionValuePayloadError::LengthOverflow { len })
    }

    fn take_length_prefixed_bytes(&mut self) -> Result<Vec<u8>, CachedExpressionValuePayloadError> {
        let len = self.take_len()?;
        let bytes = self.take_bytes(len)?;
        let mut out = Vec::new();
        out.try_reserve_exact(bytes.len()).map_err(|_| {
            CachedExpressionValuePayloadError::PayloadAllocationFailed { len: bytes.len() }
        })?;
        out.extend_from_slice(bytes);
        Ok(out)
    }

    fn take_string_context(&mut self) -> Result<StringContext, CachedExpressionValuePayloadError> {
        self.take_marker(b"context", "string context tag")?;
        let len = self.take_len()?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(len)
            .map_err(|_| CachedExpressionValuePayloadError::ContextAllocationFailed { len })?;
        for index in 0..len {
            let tag = self.take_byte()?;
            let path = self.take_length_prefixed_bytes()?;
            let element = match tag {
                0 => ContextElement::opaque_path(path),
                1 => {
                    let output = self.take_length_prefixed_bytes()?;
                    ContextElement::single_output(path, output)
                }
                2 => ContextElement::deep_derivation(path),
                tag => {
                    return Err(CachedExpressionValuePayloadError::InvalidTag {
                        section: "string context",
                        tag,
                    });
                }
            }
            .map_err(|source| CachedExpressionValuePayloadError::Context { source })?;
            if let Some(previous) = elements.last()
                && previous >= &element
            {
                return Err(CachedExpressionValuePayloadError::NonCanonicalStringContext { index });
            }
            elements.push(element);
        }
        Ok(StringContext::new(elements))
    }

    fn take_bytes(&mut self, len: usize) -> Result<&'a [u8], CachedExpressionValuePayloadError> {
        let end = self.offset.checked_add(len).ok_or(
            CachedExpressionValuePayloadError::PayloadLengthOverflow {
                current: self.offset,
                additional: len,
            },
        )?;
        if end > self.bytes.len() {
            return Err(CachedExpressionValuePayloadError::ShortPayload {
                expected: end,
                actual: self.bytes.len(),
            });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}

/// Optional evaluator cache runtime state.
#[derive(Clone, Debug, Default)]
pub enum EvalCacheRuntime {
    /// Cache observation is disabled and all operations are no-ops.
    #[default]
    Disabled,
    /// Cache observation is enabled against an in-memory [`EvalCache`].
    Enabled(EvalCache),
}

impl EvalCacheRuntime {
    /// Creates a disabled cache runtime.
    pub fn disabled() -> Self {
        Self::Disabled
    }

    /// Creates an enabled cache runtime with an empty cache.
    pub fn enabled() -> Self {
        Self::Enabled(EvalCache::new())
    }

    /// Creates a cache runtime from an enable switch.
    pub fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::enabled()
        } else {
            Self::disabled()
        }
    }

    /// Returns whether cache observation is enabled.
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    /// Returns the enabled cache, if observation is enabled.
    pub const fn cache(&self) -> Option<&EvalCache> {
        match self {
            Self::Disabled => None,
            Self::Enabled(cache) => Some(cache),
        }
    }

    /// Returns the enabled cache mutably, if observation is enabled.
    pub fn cache_mut(&mut self) -> Option<&mut EvalCache> {
        match self {
            Self::Disabled => None,
            Self::Enabled(cache) => Some(cache),
        }
    }

    /// Returns a dirty-frontier snapshot when cache observation is enabled.
    ///
    /// Disabled runtimes return `None`; enabled runtimes delegate to
    /// [`EvalCache::dirty_frontier`]. This method is read-only and does not
    /// validate or recompute graph nodes.
    pub fn dirty_frontier(&self) -> Option<DirtyFrontier> {
        self.cache().map(EvalCache::dirty_frontier)
    }

    /// Recomputes ready dirty graph nodes when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without invoking `recompute`.
    /// Enabled runtimes delegate to [`EvalCache::recompute_ready_dirty_nodes`].
    /// The caller still owns evaluator recomputation, value hashing, dynamic
    /// dependency capture, and persistence.
    ///
    /// # Errors
    ///
    /// Returns graph scheduling/reconsideration errors converted through `E`
    /// from the enabled cache, or any caller error returned by `recompute`. If
    /// `recompute` fails after earlier nodes in the same call were reconsidered,
    /// those graph mutations are retained and the partial
    /// [`RecomputeReadyDirty`] result is not returned.
    pub fn recompute_ready_dirty_nodes<E, F>(
        &mut self,
        recompute: F,
    ) -> Result<Option<RecomputeReadyDirty>, E>
    where
        E: From<DemandGraphError>,
        F: FnMut(DemandNodeId) -> Result<ValueHash, E>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.recompute_ready_dirty_nodes(recompute).map(Some)
    }

    /// Observes evaluator impure-input traces when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without examining `source` or
    /// allocating demand-graph nodes. Enabled runtimes delegate to
    /// [`EvalCache::observe_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe the trace.
    pub fn observe_impure_inputs<S>(
        &mut self,
        source: &S,
    ) -> Result<Option<ImpureTraceObservation>, DemandGraphError>
    where
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.observe_impure_inputs(source).map(Some)
    }

    /// Observes evaluator impure-input traces and wires them to a node when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating `dependent`.
    /// Enabled runtimes delegate to [`EvalCache::observe_impure_inputs_for_node`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe or wire the trace.
    pub fn observe_impure_inputs_for_node<S>(
        &mut self,
        dependent: DemandNodeId,
        source: &S,
    ) -> Result<Option<ImpureTraceObservation>, DemandGraphError>
    where
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_impure_inputs_for_node(dependent, source)
            .map(Some)
    }

    /// Observes one expression evaluation trace when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without examining `source` or
    /// allocating demand-graph nodes. Enabled runtimes delegate to
    /// [`EvalCache::observe_expression_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe, allocate, or wire the expression trace.
    pub fn observe_expression_impure_inputs<I, S>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
        source: &S,
    ) -> Result<Option<ExpressionTraceObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_expression_impure_inputs(identity, free_var_value_hashes, value_hash, source)
            .map(Some)
    }

    /// Records same-run memoization demand when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::record_memoization_demand`]. This records telemetry and
    /// evaluates the caller-selected subject policy; it does not probe, insert,
    /// or invalidate memoized value payloads.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub fn record_memoization_demand<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        subject: MemoizationSubject,
        cheap_value_hash: bool,
    ) -> Result<Option<MemoizationObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .record_memoization_demand(identity, free_var_value_hashes, subject, cheap_value_hash)
            .map(Some)
    }

    /// Returns same-run memoization demand when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to [`EvalCache::memoization_demand`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub fn memoization_demand<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<MemoizationDemand>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.memoization_demand(identity, free_var_value_hashes)
    }

    /// Looks up a clean inline expression result when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_result`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub fn lookup_inline_expression_result<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_result(identity, free_var_value_hashes)
    }

    /// Looks up a clean expression payload when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_payload`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub fn lookup_inline_expression_payload<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_payload(identity, free_var_value_hashes)
    }

    /// Looks up a clean inline result with impure-input revalidation when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or calling `revalidator`. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_result_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key, observe a fresh input, or
    /// invalidate an unusable payload.
    pub fn lookup_inline_expression_result_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<Value>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_result_with_impure_inputs(
            identity,
            free_var_value_hashes,
            revalidator,
        )
    }

    /// Looks up a cached derivation `.drv` path for matching ATerm bytes when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or ATerm bytes. Enabled runtimes delegate to
    /// [`EvalCache::lookup_derivation_aterm_path`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub(crate) fn lookup_derivation_aterm_path<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Vec<u8>>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.lookup_derivation_aterm_path(identity, free_var_value_hashes, aterm)
    }

    /// Looks up cached static derivation output paths for matching ATerm bytes when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or pre-output ATerm bytes. Enabled runtimes delegate to
    /// [`EvalCache::lookup_static_derivation_output_paths`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key.
    pub(crate) fn lookup_static_derivation_output_paths<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
    ) -> Result<Option<CachedDerivationOutputPaths>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache() else {
            return Ok(None);
        };
        cache.lookup_static_derivation_output_paths(
            identity,
            free_var_value_hashes,
            pre_output_aterm,
        )
    }

    /// Looks up a clean expression payload with impure-input revalidation when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or calling `revalidator`. Enabled runtimes delegate to
    /// [`EvalCache::lookup_inline_expression_payload_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression cache key, observe a fresh input, or
    /// invalidate an unusable payload.
    pub fn lookup_inline_expression_payload_with_impure_inputs<I, R>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache.lookup_inline_expression_payload_with_impure_inputs(
            identity,
            free_var_value_hashes,
            revalidator,
        )
    }

    /// Observes one inline expression result when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or value. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_result`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node or hash the inline value.
    pub fn observe_inline_expression_result<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_result(identity, free_var_value_hashes, value)
            .map(Some)
    }

    /// Observes one expression payload when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or value. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_payload`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node or hash the payload.
    pub fn observe_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_payload(identity, free_var_value_hashes, value)
            .map(Some)
    }

    /// Observes one derivation ATerm expression when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity or ATerm bytes. Enabled runtimes delegate to
    /// [`EvalCache::observe_derivation_aterm_expression`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node.
    pub fn observe_derivation_aterm_expression<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_derivation_aterm_expression(identity, free_var_value_hashes, aterm)
            .map(Some)
    }

    /// Observes one derivation ATerm expression and `.drv` path when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, ATerm bytes, or path bytes. Enabled runtimes delegate to
    /// [`EvalCache::observe_derivation_aterm_expression_path`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node.
    pub(crate) fn observe_derivation_aterm_expression_path<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        aterm: &[u8],
        drv_path: &[u8],
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_derivation_aterm_expression_path(
                identity,
                free_var_value_hashes,
                aterm,
                drv_path,
            )
            .map(Some)
    }

    /// Observes resolved static derivation output paths when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, pre-output ATerm bytes, or output path payload. Enabled
    /// runtimes delegate to [`EvalCache::observe_static_derivation_output_paths`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to insert/reconsider the expression node.
    pub(crate) fn observe_static_derivation_output_paths<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        pre_output_aterm: &[u8],
        output_paths: CachedDerivationOutputPaths,
    ) -> Result<Option<Reconsideration>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_static_derivation_output_paths(
                identity,
                free_var_value_hashes,
                pre_output_aterm,
                output_paths,
            )
            .map(Some)
    }

    /// Invalidates one inline expression payload when cache observation is enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity. Enabled runtimes delegate to
    /// [`EvalCache::invalidate_inline_expression_payload`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to build the expression key or mark an existing node dirty.
    pub fn invalidate_inline_expression_payload<I>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
    ) -> Result<Option<bool>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .invalidate_inline_expression_payload(identity, free_var_value_hashes)
            .map(Some)
    }

    /// Observes one inline expression result and its impure inputs when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, value, or trace. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_result_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe or wire the expression trace, hash the inline value, or
    /// insert/reconsider the expression node.
    pub fn observe_inline_expression_result_with_impure_inputs<I, S>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: Value,
        source: &S,
    ) -> Result<Option<ExpressionTraceObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                free_var_value_hashes,
                value,
                source,
            )
            .map(Some)
    }

    /// Observes one expression payload and its impure inputs when enabled.
    ///
    /// Disabled runtimes return `Ok(None)` without validating the expression
    /// identity, value, or trace. Enabled runtimes delegate to
    /// [`EvalCache::observe_inline_expression_payload_with_impure_inputs`].
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] only when the enabled underlying cache
    /// fails to observe or wire the expression trace, hash the payload, or
    /// insert/reconsider the expression node.
    pub fn observe_inline_expression_payload_with_impure_inputs<I, S>(
        &mut self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value: CachedExpressionValue,
        source: &S,
    ) -> Result<Option<ExpressionTraceObservation>, DemandGraphError>
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
        S: ImpureInputTraceSource + ?Sized,
    {
        let Some(cache) = self.cache_mut() else {
            return Ok(None);
        };
        cache
            .observe_inline_expression_payload_with_impure_inputs(
                identity,
                free_var_value_hashes,
                value,
                source,
            )
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        CutoffDecision, DemandCacheKey, ImpureTraceStatus, MemoizationDecision, MemoizationDemand,
        MemoizationSubject, NodeFreshness, UncacheableInput,
    };
    use crate::compile::IrId;
    use crate::string::{ContextElement, StringContext};

    #[derive(Clone, Debug)]
    struct TraceSource {
        trace: Vec<ImpureInputFingerprint>,
        complete: bool,
    }

    impl ImpureInputTraceSource for TraceSource {
        fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
            &self.trace
        }

        fn impure_input_trace_complete(&self) -> bool {
            self.complete
        }
    }

    #[derive(Clone, Debug)]
    struct StaticRevalidator {
        trace: Vec<ImpureInputFingerprint>,
        calls: usize,
    }

    impl StaticRevalidator {
        fn new(trace: Vec<ImpureInputFingerprint>) -> Self {
            Self { trace, calls: 0 }
        }

        const fn calls(&self) -> usize {
            self.calls
        }
    }

    impl ImpureInputRevalidator for StaticRevalidator {
        fn revalidate_impure_input(
            &mut self,
            identity: &ImpureInputIdentity,
        ) -> Option<ImpureInputFingerprint> {
            self.calls = self.calls.saturating_add(1);
            self.trace.iter().find_map(|fingerprint| {
                let cacheable = fingerprint.as_cacheable()?;
                if cacheable.identity() == identity {
                    Some(fingerprint.clone())
                } else {
                    None
                }
            })
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RecomputeTestError {
        Graph(DemandGraphError),
        Rejected(DemandNodeId),
    }

    impl From<DemandGraphError> for RecomputeTestError {
        fn from(error: DemandGraphError) -> Self {
            Self::Graph(error)
        }
    }

    fn read_file_trace(path: &[u8], contents: &[u8]) -> ImpureInputFingerprint {
        ImpureInputFingerprint::read_file(path, contents).expect("input fingerprints")
    }

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn derivation_aterm_hash(aterm: &[u8]) -> ValueHash {
        ValueHash::from_derivation_aterm_bytes(aterm)
    }

    fn durable_hash(bytes: &[u8]) -> DurableBlake3Hash {
        DurableBlake3Hash::for_bytes(bytes)
    }

    fn identity(source: &[u8], node: u32) -> CacheExprIdentity {
        CacheExprIdentity::new(durable_hash(source), IrId::new(node))
    }

    fn opaque_context(path: &[u8]) -> StringContext {
        StringContext::singleton(
            ContextElement::opaque_path(path.to_vec()).expect("opaque context builds"),
        )
        .expect("context allocates")
    }

    fn all_context_kinds() -> StringContext {
        StringContext::new(vec![
            ContextElement::single_output(b"/nix/store/pkg.drv".to_vec(), b"out".to_vec())
                .expect("single-output context builds"),
            ContextElement::opaque_path(b"/nix/store/source".to_vec())
                .expect("opaque context builds"),
            ContextElement::deep_derivation(b"/nix/store/toolchain.drv".to_vec())
                .expect("deep context builds"),
        ])
    }

    fn context_string_payload_with_opaque_paths(paths: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"string").expect("tag appends");
        append_payload_u128(&mut encoded, 0).expect("string length appends");
        append_payload_bytes(&mut encoded, b"context").expect("context tag appends");
        append_payload_u128(&mut encoded, paths.len() as u128).expect("context count appends");
        for path in paths {
            append_payload_byte(&mut encoded, 0).expect("context kind appends");
            append_payload_u128(&mut encoded, path.len() as u128).expect("path length appends");
            append_payload_bytes(&mut encoded, path).expect("path appends");
        }
        encoded
    }

    fn context_path_payload_with_opaque_paths(paths: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, CONTEXT_PATH_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"path").expect("tag appends");
        append_payload_u128(&mut encoded, 0).expect("path length appends");
        append_payload_bytes(&mut encoded, b"context").expect("context tag appends");
        append_payload_u128(&mut encoded, paths.len() as u128).expect("context count appends");
        for path in paths {
            append_payload_byte(&mut encoded, 0).expect("context kind appends");
            append_payload_u128(&mut encoded, path.len() as u128).expect("path length appends");
            append_payload_bytes(&mut encoded, path).expect("path appends");
        }
        encoded
    }

    fn list_payload_with_len(len: u128) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, LIST_VALUE_HASH_DOMAIN_VERSION).expect("domain appends");
        append_payload_bytes(&mut encoded, b"list").expect("tag appends");
        append_payload_u128(&mut encoded, len).expect("list length appends");
        encoded
    }

    fn attrs_payload_with_len(len: u128) -> Vec<u8> {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, ATTRS_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"attrs").expect("tag appends");
        append_payload_u128(&mut encoded, len).expect("attrs length appends");
        encoded
    }

    fn key(node: u32, label: &[u8]) -> DemandCacheKey {
        DemandCacheKey::for_free_vars(identity(label, node), [durable_hash(label)])
            .expect("key builds")
    }

    #[test]
    fn memoization_demand_admits_conditional_subject_on_second_cheap_demand() {
        let identity = identity(b"source", 1);
        let free_vars = [durable_hash(b"captured")];
        let mut cache = EvalCache::new();

        let first = cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, true)
            .expect("first demand records");
        assert_eq!(first.demand(), MemoizationDemand::new(1));
        assert_eq!(first.decision(), MemoizationDecision::Bypass);
        assert!(
            cache.is_empty(),
            "policy telemetry must not allocate demand-graph nodes"
        );

        let second = cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, true)
            .expect("second demand records");
        assert_eq!(second.demand(), MemoizationDemand::new(2));
        assert_eq!(second.decision(), MemoizationDecision::Admit);
        assert_eq!(
            cache
                .memoization_demand(identity, free_vars)
                .expect("demand reads"),
            Some(MemoizationDemand::new(2))
        );
        assert!(
            cache.is_empty(),
            "policy telemetry remains separate from expression nodes"
        );
    }

    #[test]
    fn memoization_demand_keeps_conditional_subject_bypassed_when_hash_is_expensive() {
        let identity = identity(b"source", 2);
        let free_vars = [durable_hash(b"captured")];
        let mut cache = EvalCache::new();

        cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, false)
            .expect("first demand records");
        let second = cache
            .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, false)
            .expect("second demand records");

        assert_eq!(second.demand(), MemoizationDemand::new(2));
        assert_eq!(second.decision(), MemoizationDecision::Bypass);
    }

    #[test]
    fn memoization_demand_uses_subject_default_class() {
        let mut cache = EvalCache::new();

        let derivation = cache
            .record_memoization_demand(
                identity(b"drv", 3),
                std::iter::empty::<DurableBlake3Hash>(),
                MemoizationSubject::DerivationStrict,
                false,
            )
            .expect("always-cache demand records");
        assert_eq!(derivation.demand(), MemoizationDemand::new(1));
        assert_eq!(derivation.decision(), MemoizationDecision::Admit);

        let trivial = cache
            .record_memoization_demand(
                identity(b"trivial", 4),
                std::iter::empty::<DurableBlake3Hash>(),
                MemoizationSubject::Trivial,
                true,
            )
            .expect("never-cache demand records");
        assert_eq!(trivial.demand(), MemoizationDemand::new(1));
        assert_eq!(trivial.decision(), MemoizationDecision::Bypass);
    }

    #[test]
    fn disabled_runtime_memoization_demand_is_noop() {
        let identity = identity(b"source", 5);
        let free_vars = [durable_hash(b"captured")];
        let mut runtime = EvalCacheRuntime::disabled();

        assert_eq!(
            runtime
                .record_memoization_demand(identity, free_vars, MemoizationSubject::Thunk, true)
                .expect("disabled demand records"),
            None
        );
        assert_eq!(
            runtime
                .memoization_demand(identity, free_vars)
                .expect("disabled demand reads"),
            None
        );
    }

    fn node_with_hash(graph: &mut DemandGraph, node: u32, label: &'static [u8]) -> DemandNodeId {
        graph
            .get_or_insert_node(key(node, label), Some(value_hash(label)))
            .expect("node inserts")
    }

    #[test]
    fn cached_expression_payloads_round_trip_through_persistent_encoding() {
        let payloads = vec![
            CachedExpressionValue::immediate(Value::int(-7)).expect("int payload builds"),
            CachedExpressionValue::immediate(Value::float(1.25)).expect("float payload builds"),
            CachedExpressionValue::immediate(Value::bool(false)).expect("bool payload builds"),
            CachedExpressionValue::immediate(Value::null()).expect("null payload builds"),
            CachedExpressionValue::context_free_string(b"plain bytes".to_vec()),
            CachedExpressionValue::context_string(b"context bytes".to_vec(), all_context_kinds()),
            CachedExpressionValue::path(b"/nix/store/path".to_vec()),
            CachedExpressionValue::context_path(
                b"/nix/store/context-path".to_vec(),
                all_context_kinds(),
            ),
            CachedExpressionValue::empty_list(),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                CachedExpressionValue::context_string(
                    b"context element".to_vec(),
                    all_context_kinds(),
                ),
                CachedExpressionValue::context_path(
                    b"/nix/store/context-list-path".to_vec(),
                    all_context_kinds(),
                ),
                CachedExpressionValue::strict_list(vec![
                    CachedExpressionValue::empty_list(),
                    CachedExpressionValue::empty_attrs(),
                ]),
            ]),
            CachedExpressionValue::empty_attrs(),
            CachedExpressionValue::strict_attrs(vec![
                (
                    b"b".to_vec(),
                    CachedExpressionValue::context_free_string(b"value".to_vec()),
                ),
                (
                    b"a".to_vec(),
                    CachedExpressionValue::strict_list(vec![
                        CachedExpressionValue::immediate(Value::bool(true))
                            .expect("bool payload builds"),
                        CachedExpressionValue::empty_attrs(),
                    ]),
                ),
            ])
            .expect("strict attrs payload builds"),
        ];

        for payload in payloads {
            let encoded = payload
                .encode_persistent_payload()
                .expect("payload encodes");
            assert_eq!(
                DurableBlake3Hash::for_bytes(&encoded),
                payload
                    .value_hash()
                    .expect("payload hashes")
                    .as_durable_hash()
            );
            assert_eq!(
                CachedExpressionValue::decode_persistent_payload(&encoded)
                    .expect("payload decodes"),
                payload
            );
        }
    }

    #[test]
    fn cached_expression_payload_constructors_canonicalize_empty_contexts() {
        let string =
            CachedExpressionValue::context_string(b"plain bytes".to_vec(), StringContext::empty());
        let path = CachedExpressionValue::context_path(
            b"/nix/store/path".to_vec(),
            StringContext::empty(),
        );

        assert_eq!(
            string.context_free_string_bytes(),
            Some(b"plain bytes".as_slice())
        );
        assert!(string.context_string_parts().is_none());
        assert_eq!(path.path_bytes(), Some(b"/nix/store/path".as_slice()));
        assert!(path.context_path_parts().is_none());
    }

    #[test]
    fn cached_expression_payload_decode_rejects_unknown_domain() {
        let error = CachedExpressionValue::decode_persistent_payload(b"not-a-cache-payload")
            .expect_err("unknown domains error");

        assert_eq!(error, CachedExpressionValuePayloadError::UnknownDomain);
    }

    #[test]
    fn cached_expression_payload_decode_rejects_trailing_bytes() {
        let mut encoded = CachedExpressionValue::immediate(Value::int(7))
            .expect("payload builds")
            .encode_persistent_payload()
            .expect("payload encodes");
        encoded.extend_from_slice(b"trailing");

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("trailing bytes error");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::TrailingBytes {
                remaining: b"trailing".len()
            }
        );
    }

    #[test]
    fn cached_expression_payload_decode_rejects_truncated_payload() {
        let mut encoded = CachedExpressionValue::context_free_string(b"abc".to_vec())
            .encode_persistent_payload()
            .expect("payload encodes");
        encoded.pop();

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("truncated bytes error");

        assert!(matches!(
            error,
            CachedExpressionValuePayloadError::ShortPayload { .. }
        ));
    }

    #[test]
    fn cached_expression_payload_decode_rejects_empty_contextual_domains() {
        for (encoded, payload) in [
            (
                context_string_payload_with_opaque_paths(&[]),
                "context string",
            ),
            (context_path_payload_with_opaque_paths(&[]), "context path"),
        ] {
            let error = CachedExpressionValue::decode_persistent_payload(&encoded)
                .expect_err("empty context errors");

            assert_eq!(
                error,
                CachedExpressionValuePayloadError::EmptyStringContext { payload }
            );
        }
    }

    #[test]
    fn cached_expression_payload_decode_validates_context_elements() {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, CONTEXT_STRING_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"string").expect("tag appends");
        append_payload_u128(&mut encoded, 0).expect("string length appends");
        append_payload_bytes(&mut encoded, b"context").expect("context tag appends");
        append_payload_u128(&mut encoded, 1).expect("context count appends");
        append_payload_byte(&mut encoded, 0).expect("context kind appends");
        append_payload_u128(&mut encoded, 0).expect("empty path length appends");

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("empty context path errors");

        assert!(matches!(
            error,
            CachedExpressionValuePayloadError::Context {
                source: NixStringError::EmptyContextPath
            }
        ));
    }

    #[test]
    fn cached_expression_payload_decode_rejects_unsorted_context_elements() {
        let encoded = context_string_payload_with_opaque_paths(&[
            b"/nix/store/z".as_slice(),
            b"/nix/store/a".as_slice(),
        ]);

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("non-canonical context order errors");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::NonCanonicalStringContext { index: 1 }
        );
    }

    #[test]
    fn cached_expression_payload_decode_rejects_duplicate_context_elements() {
        let encoded = context_string_payload_with_opaque_paths(&[
            b"/nix/store/a".as_slice(),
            b"/nix/store/a".as_slice(),
        ]);

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("duplicate context element errors");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::NonCanonicalStringContext { index: 1 }
        );
    }

    #[test]
    fn cached_expression_payload_decode_rejects_truncated_list_elements() {
        let encoded = list_payload_with_len(1);

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("truncated list element payload errors");

        assert!(matches!(
            error,
            CachedExpressionValuePayloadError::ShortPayload { .. }
        ));
    }

    #[test]
    fn cached_expression_payload_decode_rejects_excessive_list_nesting() {
        let mut payload =
            CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds");
        for _ in 0..=MAX_CACHED_EXPRESSION_PAYLOAD_NESTING {
            payload = CachedExpressionValue::strict_list(vec![payload]);
        }
        let encoded = payload
            .encode_persistent_payload()
            .expect("deep list payload encodes");

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("excessive nesting errors");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::PayloadNestingLimitExceeded {
                limit: MAX_CACHED_EXPRESSION_PAYLOAD_NESTING
            }
        );
    }

    #[test]
    fn cached_expression_payload_decode_rejects_truncated_attrset_bindings() {
        let encoded = attrs_payload_with_len(1);

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("truncated attrset binding payload errors");

        assert!(matches!(
            error,
            CachedExpressionValuePayloadError::ShortPayload { .. }
        ));
    }

    #[test]
    fn cached_expression_payload_decode_rejects_noncanonical_attrset_names() {
        let mut encoded = Vec::new();
        append_payload_bytes(&mut encoded, ATTRS_VALUE_HASH_DOMAIN_VERSION)
            .expect("domain appends");
        append_payload_bytes(&mut encoded, b"attrs").expect("tag appends");
        append_payload_u128(&mut encoded, 2).expect("attrs length appends");
        let value = CachedExpressionValue::immediate(Value::int(1))
            .expect("int payload builds")
            .encode_persistent_payload()
            .expect("value encodes");
        for name in [b"b".as_slice(), b"a".as_slice()] {
            append_payload_u128(&mut encoded, name.len() as u128).expect("name length appends");
            append_payload_bytes(&mut encoded, name).expect("name appends");
            append_payload_u128(&mut encoded, value.len() as u128).expect("value length appends");
            append_payload_bytes(&mut encoded, &value).expect("value appends");
        }

        let error = CachedExpressionValue::decode_persistent_payload(&encoded)
            .expect_err("out-of-order attrset names error");

        assert_eq!(
            error,
            CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index: 1 }
        );
    }

    #[test]
    fn eval_cache_observes_cacheable_trace_source() {
        let source = TraceSource {
            trace: vec![
                read_file_trace(b"/tmp/one", b"same"),
                read_file_trace(b"/tmp/two", b"same"),
            ],
            complete: true,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_impure_inputs(&source)
            .expect("trace observes");

        assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
        assert_eq!(observation.leaves().len(), 2);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.graph().len(), 2);
        assert_eq!(cache.into_graph().len(), 2);
    }

    #[test]
    fn disabled_eval_cache_runtime_observation_is_noop() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::disabled();

        let observation = runtime
            .observe_impure_inputs(&source)
            .expect("disabled observation succeeds");

        assert_eq!(observation, None);
        assert!(!runtime.is_enabled());
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn disabled_eval_cache_runtime_does_not_classify_uncacheable_traces() {
        let source = TraceSource {
            trace: vec![ImpureInputFingerprint::current_time()],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::disabled();

        let observation = runtime
            .observe_impure_inputs(&source)
            .expect("disabled observation succeeds");

        assert_eq!(observation, None);
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_trace_observation() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::enabled();

        let observation = runtime
            .observe_impure_inputs(&source)
            .expect("enabled observation succeeds")
            .expect("enabled runtime observes traces");

        assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
        assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_trace_edges() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(DemandGraph::new()));
        let dependent = runtime
            .cache_mut()
            .expect("cache is enabled")
            .get_or_insert_expression_node(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"dependent")),
            )
            .expect("dependent inserts");

        let observation = runtime
            .observe_impure_inputs_for_node(dependent, &source)
            .expect("enabled observation succeeds")
            .expect("enabled runtime observes traces");

        assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
        let dependency = observation.leaves()[0].node();
        assert!(
            runtime
                .cache()
                .expect("cache is enabled")
                .graph()
                .node(dependent)
                .expect("dependent exists")
                .dependencies()
                .contains(&dependency)
        );
    }

    #[test]
    fn eval_cache_observes_trace_source_for_node_edges() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut graph = DemandGraph::new();
        let dependent = node_with_hash(&mut graph, 7, b"dependent");
        let mut cache = EvalCache::from_graph(graph);

        let observation = cache
            .observe_impure_inputs_for_node(dependent, &source)
            .expect("trace observes and wires");

        assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
        let dependency = observation.leaves()[0].node();
        assert!(
            cache
                .graph()
                .node(dependent)
                .expect("dependent exists")
                .dependencies()
                .contains(&dependency)
        );
        assert!(
            cache
                .graph()
                .node(dependency)
                .expect("dependency exists")
                .dependents()
                .contains(&dependent)
        );
    }

    #[test]
    fn eval_cache_changed_input_dirties_dependent_node() {
        let first = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let changed = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"2")],
            complete: true,
        };
        let mut graph = DemandGraph::new();
        let dependent = node_with_hash(&mut graph, 7, b"dependent");
        let mut cache = EvalCache::from_graph(graph);
        cache
            .observe_impure_inputs_for_node(dependent, &first)
            .expect("trace observes and wires");

        let observation = cache
            .observe_impure_inputs(&changed)
            .expect("changed trace observes");

        assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
        assert_eq!(
            cache
                .graph()
                .node(dependent)
                .expect("dependent exists")
                .freshness(),
            NodeFreshness::Dirty
        );
    }

    #[test]
    fn eval_cache_exposes_dirty_frontier() {
        let mut graph = DemandGraph::new();
        let a = node_with_hash(&mut graph, 1, b"a-old");
        let b = node_with_hash(&mut graph, 2, b"b-stable");
        let c = node_with_hash(&mut graph, 3, b"c-stale");
        graph.add_dependency(b, a).expect("b depends on a");
        graph.add_dependency(c, b).expect("c depends on b");
        graph.mark_dirty(a).expect("a dirties");
        graph.mark_dirty(c).expect("c dirties");
        let cache = EvalCache::from_graph(graph);

        let frontier = cache.dirty_frontier();

        assert_eq!(frontier.ready_nodes(), &[a]);
        let [blocked] = frontier.blocked_nodes() else {
            panic!("c is blocked by dirty upstream a");
        };
        assert_eq!(blocked.node(), c);
        assert_eq!(blocked.blockers(), &[a]);
    }

    #[test]
    fn eval_cache_delegates_ready_dirty_recompute_loop() {
        let mut graph = DemandGraph::new();
        let a = node_with_hash(&mut graph, 1, b"a-old");
        let b = node_with_hash(&mut graph, 2, b"b-old");
        let c = node_with_hash(&mut graph, 3, b"c-stable");
        graph.add_dependency(b, a).expect("b depends on a");
        graph.add_dependency(c, b).expect("c depends on b");
        graph.mark_dirty(a).expect("a dirties");
        let mut cache = EvalCache::from_graph(graph);

        let result = cache
            .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
                if node == a {
                    return Ok(value_hash(b"a-new"));
                }
                if node == b {
                    return Ok(value_hash(b"b-new"));
                }
                if node == c {
                    return Ok(value_hash(b"c-stable"));
                }
                panic!("unexpected recomputation for {node:?}");
            })
            .expect("runtime cache recomputes");

        let reconsidered: Vec<_> = result
            .reconsiderations()
            .iter()
            .map(Reconsideration::node)
            .collect();
        assert_eq!(reconsidered, vec![a, b, c]);
        assert!(result.remaining_frontier().is_empty());
        assert_eq!(
            cache.graph().dirty_nodes().collect::<Vec<_>>(),
            Vec::<DemandNodeId>::new()
        );
    }

    #[test]
    fn eval_cache_runtime_dirty_frontier_is_disabled_noop() {
        let runtime = EvalCacheRuntime::disabled();

        assert_eq!(runtime.dirty_frontier(), None);
    }

    #[test]
    fn eval_cache_runtime_ready_dirty_recompute_is_disabled_noop() {
        let mut runtime = EvalCacheRuntime::disabled();

        let result = runtime
            .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
                panic!("disabled runtime should not recompute {node:?}");
            })
            .expect("disabled recompute succeeds");

        assert_eq!(result, None);
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_dirty_frontier() {
        let mut graph = DemandGraph::new();
        let a = node_with_hash(&mut graph, 1, b"a-old");
        let b = node_with_hash(&mut graph, 2, b"b-stable");
        let c = node_with_hash(&mut graph, 3, b"c-stale");
        graph.add_dependency(b, a).expect("b depends on a");
        graph.add_dependency(c, b).expect("c depends on b");
        graph.mark_dirty(a).expect("a dirties");
        graph.mark_dirty(c).expect("c dirties");
        let runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(graph));

        let frontier = runtime
            .dirty_frontier()
            .expect("enabled runtime returns a frontier");

        assert_eq!(frontier.ready_nodes(), &[a]);
        let [blocked] = frontier.blocked_nodes() else {
            panic!("c is blocked by dirty upstream a");
        };
        assert_eq!(blocked.node(), c);
        assert_eq!(blocked.blockers(), &[a]);
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_ready_dirty_recompute_loop() {
        let mut graph = DemandGraph::new();
        let a = node_with_hash(&mut graph, 1, b"a-old");
        let b = node_with_hash(&mut graph, 2, b"b-old");
        graph.add_dependency(b, a).expect("b depends on a");
        graph.mark_dirty(a).expect("a dirties");
        let mut runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(graph));

        let result = runtime
            .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
                if node == a {
                    return Ok(value_hash(b"a-new"));
                }
                if node == b {
                    return Ok(value_hash(b"b-stable"));
                }
                panic!("unexpected recomputation for {node:?}");
            })
            .expect("enabled runtime recomputes")
            .expect("enabled runtime returns loop result");

        let reconsidered: Vec<_> = result
            .reconsiderations()
            .iter()
            .map(Reconsideration::node)
            .collect();
        assert_eq!(reconsidered, vec![a, b]);
        assert!(result.remaining_frontier().is_empty());
        assert_eq!(
            runtime
                .cache()
                .expect("cache is enabled")
                .graph()
                .dirty_nodes()
                .collect::<Vec<_>>(),
            Vec::<DemandNodeId>::new()
        );
    }

    #[test]
    fn enabled_eval_cache_runtime_keeps_prior_progress_on_later_recompute_error() {
        let mut graph = DemandGraph::new();
        let a = node_with_hash(&mut graph, 1, b"a-old");
        let b = node_with_hash(&mut graph, 2, b"b");
        let c = node_with_hash(&mut graph, 3, b"c");
        graph.add_dependency(b, a).expect("b depends on a");
        graph.mark_dirty(a).expect("a dirties");
        graph.mark_dirty(c).expect("c dirties");
        let mut runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(graph));

        let error = runtime
            .recompute_ready_dirty_nodes::<RecomputeTestError, _>(|node| {
                if node == a {
                    return Ok(value_hash(b"a-new"));
                }
                Err(RecomputeTestError::Rejected(node))
            })
            .expect_err("later recompute error stops runtime recompute");

        assert_eq!(error, RecomputeTestError::Rejected(c));
        assert_eq!(
            runtime
                .cache()
                .expect("cache is enabled")
                .graph()
                .dirty_nodes()
                .collect::<Vec<_>>(),
            vec![b, c]
        );
    }

    #[test]
    fn eval_cache_expression_node_can_observe_impure_edges() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let dependent = cache
            .get_or_insert_expression_node(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
            )
            .expect("expression node inserts");

        let observation = cache
            .observe_impure_inputs_for_node(dependent, &source)
            .expect("trace observes and wires");

        assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
        let dependency = observation.leaves()[0].node();
        assert!(
            cache
                .graph()
                .node(dependent)
                .expect("dependent exists")
                .dependencies()
                .contains(&dependency)
        );
    }

    #[test]
    fn eval_cache_expression_trace_adapter_wires_cacheable_inputs() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_expression_impure_inputs(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &source,
            )
            .expect("expression trace observes");

        assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
        let node = observation.node().expect("cacheable trace creates node");
        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Cacheable(node)
        );
        let dependency = observation.trace().leaves()[0].node();
        assert!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .contains(&dependency)
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn eval_cache_expression_trace_adapter_skips_node_for_uncacheable_trace() {
        let source = TraceSource {
            trace: vec![
                read_file_trace(b"/tmp/version", b"1"),
                ImpureInputFingerprint::current_time(),
            ],
            complete: true,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_expression_impure_inputs(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &source,
            )
            .expect("expression trace observes");

        assert_eq!(
            observation.trace().status(),
            ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert_eq!(observation.node(), None);
        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn eval_cache_expression_trace_adapter_uncacheable_trace_clears_prior_edges() {
        let first_source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/first", b"same")],
            complete: true,
        };
        let second_source = TraceSource {
            trace: vec![
                read_file_trace(b"/tmp/second", b"same"),
                ImpureInputFingerprint::current_time(),
            ],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let first_observation = cache
            .observe_expression_impure_inputs(
                identity,
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &first_source,
            )
            .expect("first expression trace observes");
        let node = first_observation
            .node()
            .expect("cacheable trace creates node");
        let first_dependency = first_observation.trace().leaves()[0].node();

        let second_observation = cache
            .observe_expression_impure_inputs(
                identity,
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &second_source,
            )
            .expect("uncacheable expression trace observes");

        assert_eq!(
            second_observation.trace().status(),
            ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert_eq!(second_observation.node(), None);
        assert!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .is_empty()
        );
        assert!(
            !cache
                .graph()
                .node(first_dependency)
                .expect("first dependency exists")
                .dependents()
                .contains(&node)
        );

        cache
            .observe_impure_inputs(&TraceSource {
                trace: vec![read_file_trace(b"/tmp/first", b"changed")],
                complete: true,
            })
            .expect("stale input reconsiders");
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .freshness(),
            NodeFreshness::Clean
        );
    }

    #[test]
    fn eval_cache_expression_trace_adapter_marks_incomplete_trace_not_memoizable() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: false,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_expression_impure_inputs(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &source,
            )
            .expect("expression trace observes");

        assert_eq!(observation.trace().status(), ImpureTraceStatus::Incomplete);
        assert_eq!(observation.node(), None);
        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Incomplete
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn disabled_eval_cache_runtime_expression_trace_is_noop() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::disabled();

        let observation = runtime
            .observe_expression_impure_inputs(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &source,
            )
            .expect("disabled expression observation succeeds");

        assert_eq!(observation, None);
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_expression_trace_delegates() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::enabled();

        let observation = runtime
            .observe_expression_impure_inputs(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(value_hash(b"value")),
                &source,
            )
            .expect("enabled expression observation succeeds")
            .expect("enabled runtime observes expression trace");

        assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
        assert!(observation.node().is_some());
        assert_eq!(runtime.cache().expect("cache is enabled").len(), 2);
    }

    #[test]
    fn eval_cache_observes_inline_expression_results_with_impure_edges_without_hits() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("inline result and trace observe");

        assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
        let node = observation.node().expect("cacheable trace creates node");
        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Cacheable(node)
        );
        let dependency = observation.trace().leaves()[0].node();
        assert!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .contains(&dependency)
        );
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(
            value.is_none(),
            "trace-backed payloads require input revalidation before reuse"
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn eval_cache_recomputed_trace_backed_payload_replaces_prior_input_edges() {
        let first_source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/first", b"same")],
            complete: true,
        };
        let second_source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/second", b"same")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let first_observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &first_source,
            )
            .expect("first inline result and trace observe");
        let node = first_observation
            .node()
            .expect("cacheable trace creates node");
        let first_dependency = first_observation.trace().leaves()[0].node();

        let second_observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &second_source,
            )
            .expect("second inline result and trace observe");
        assert_eq!(second_observation.node(), Some(node));
        let second_dependency = second_observation.trace().leaves()[0].node();

        assert!(
            !cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .contains(&first_dependency)
        );
        assert!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .contains(&second_dependency)
        );
        assert!(
            !cache
                .graph()
                .node(first_dependency)
                .expect("first dependency exists")
                .dependents()
                .contains(&node)
        );
        assert!(
            cache
                .graph()
                .node(second_dependency)
                .expect("second dependency exists")
                .dependents()
                .contains(&node)
        );

        cache
            .observe_impure_inputs(&TraceSource {
                trace: vec![read_file_trace(b"/tmp/first", b"changed")],
                complete: true,
            })
            .expect("stale input reconsiders");
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .freshness(),
            NodeFreshness::Clean
        );

        cache
            .observe_impure_inputs(&TraceSource {
                trace: vec![read_file_trace(b"/tmp/second", b"changed")],
                complete: true,
            })
            .expect("current input reconsiders");
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .freshness(),
            NodeFreshness::Dirty
        );
    }

    #[test]
    fn eval_cache_trace_backed_payload_reports_early_cutoff_reconsideration() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"same")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        let first_observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("first inline result and trace observe");
        assert_eq!(
            first_observation
                .payload_reconsideration()
                .expect("payload reconsideration is reported")
                .decision(),
            CutoffDecision::Propagate
        );

        let second_observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("second inline result and trace observes");
        assert_eq!(
            second_observation
                .payload_reconsideration()
                .expect("payload reconsideration is reported")
                .decision(),
            CutoffDecision::CutOff
        );
    }

    #[test]
    fn eval_cache_expression_trace_adapter_invalidates_existing_trace_backed_payload() {
        let first_fingerprint = read_file_trace(b"/tmp/first", b"same");
        let first_source = TraceSource {
            trace: vec![first_fingerprint.clone()],
            complete: true,
        };
        let second_source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/second", b"same")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let first_observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &first_source,
            )
            .expect("first inline result and trace observe");
        let node = first_observation
            .node()
            .expect("cacheable trace creates node");
        let first_dependency = first_observation.trace().leaves()[0].node();

        let mut first_revalidator = StaticRevalidator::new(vec![first_fingerprint.clone()]);
        let value = cache
            .lookup_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                &mut first_revalidator,
            )
            .expect("lookup revalidates");
        assert_eq!(value.expect("cache hit").as_int(), Ok(3));

        let second_observation = cache
            .observe_expression_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Some(value_hash(b"value")),
                &second_source,
            )
            .expect("trace-only observation succeeds");
        assert_eq!(second_observation.node(), Some(node));
        let second_dependency = second_observation.trace().leaves()[0].node();

        assert!(
            !cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .contains(&first_dependency)
        );
        assert!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .dependencies()
                .contains(&second_dependency)
        );
        assert_eq!(
            cache
                .graph()
                .node(node)
                .expect("expression node exists")
                .freshness(),
            NodeFreshness::Dirty
        );

        let mut stale_revalidator = StaticRevalidator::new(vec![first_fingerprint]);
        let value = cache
            .lookup_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                &mut stale_revalidator,
            )
            .expect("lookup succeeds");
        assert!(value.is_none());
        assert_eq!(stale_revalidator.calls(), 0);
    }

    #[test]
    fn eval_cache_revalidates_trace_backed_inline_expression_results() {
        let fingerprint = read_file_trace(b"/tmp/version", b"1");
        let source = TraceSource {
            trace: vec![fingerprint.clone()],
            complete: true,
        };
        let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("inline result and trace observe");
        let value = cache
            .lookup_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                &mut revalidator,
            )
            .expect("lookup revalidates");

        assert_eq!(value.expect("cache hit").as_int(), Ok(3));
        assert_eq!(revalidator.calls(), 1);
    }

    #[test]
    fn changed_revalidated_input_dirties_trace_backed_inline_expression() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut revalidator = StaticRevalidator::new(vec![read_file_trace(b"/tmp/version", b"2")]);
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("inline result and trace observe");
        let node = observation.node().expect("cacheable trace creates node");

        let value = cache
            .lookup_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                &mut revalidator,
            )
            .expect("lookup revalidates");

        assert!(value.is_none());
        assert_eq!(revalidator.calls(), 1);
        assert_eq!(
            cache.graph().node(node).expect("node exists").freshness(),
            NodeFreshness::Dirty
        );
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("public lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn unavailable_revalidated_input_invalidates_trace_backed_inline_expression() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut revalidator = StaticRevalidator::new(Vec::new());
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("inline result and trace observe");
        let node = observation.node().expect("cacheable trace creates node");

        let value = cache
            .lookup_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                &mut revalidator,
            )
            .expect("lookup handles unavailable input");

        assert!(value.is_none());
        assert_eq!(revalidator.calls(), 1);
        assert_eq!(
            cache.graph().node(node).expect("node exists").freshness(),
            NodeFreshness::Dirty
        );
    }

    #[test]
    fn changed_impure_edge_dirties_inline_expression_payload_node() {
        let first = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let changed = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"2")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &first,
            )
            .expect("inline result and trace observe");
        let node = observation.node().expect("cacheable trace creates node");

        cache
            .observe_impure_inputs(&changed)
            .expect("changed input observes");

        assert_eq!(
            cache.graph().node(node).expect("node exists").freshness(),
            NodeFreshness::Dirty
        );
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn inline_expression_result_with_uncacheable_trace_skips_payload() {
        let source = TraceSource {
            trace: vec![ImpureInputFingerprint::current_time()],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("uncacheable trace classifies");

        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert!(cache.is_empty());
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn uncacheable_trace_invalidates_existing_reusable_inline_payload() {
        let source = TraceSource {
            trace: vec![ImpureInputFingerprint::current_time()],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let previous = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("previous pure result observes");

        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(4),
                &source,
            )
            .expect("uncacheable trace classifies");

        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert_eq!(
            cache
                .graph()
                .node(previous.node())
                .expect("previous node still exists")
                .freshness(),
            NodeFreshness::Dirty
        );
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn inline_expression_result_with_incomplete_trace_skips_payload() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: false,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
                &source,
            )
            .expect("incomplete trace classifies");

        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Incomplete
        );
        assert!(cache.is_empty());
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn incomplete_trace_invalidates_existing_reusable_inline_payload() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: false,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let previous = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("previous pure result observes");

        let observation = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(4),
                &source,
            )
            .expect("incomplete trace classifies");

        assert_eq!(
            observation.cacheability(),
            ExpressionCacheability::Incomplete
        );
        assert_eq!(
            cache
                .graph()
                .node(previous.node())
                .expect("previous node still exists")
                .freshness(),
            NodeFreshness::Dirty
        );
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn unsupported_trace_backed_value_invalidates_existing_reusable_inline_payload() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let previous = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("previous pure result observes");
        let heap_value = Value::string(std::ptr::NonNull::<crate::value::HeapObject>::dangling())
            .expect("dangling heap pointer is aligned");

        let error = cache
            .observe_inline_expression_result_with_impure_inputs(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                heap_value,
                &source,
            )
            .expect_err("heap-backed values are not inline-cacheable");

        assert!(matches!(
            error,
            DemandGraphError::ValueHash {
                source: ValueHashError::UnsupportedTag {
                    tag: crate::value::ValueTag::String
                }
            }
        ));
        assert_eq!(
            cache
                .graph()
                .node(previous.node())
                .expect("previous node still exists")
                .freshness(),
            NodeFreshness::Dirty
        );
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");
        assert!(value.is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_observes_inline_expression_trace_results() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::enabled();

        let observation = runtime
            .observe_inline_expression_result_with_impure_inputs(
                identity(b"source", 7),
                std::iter::empty::<DurableBlake3Hash>(),
                Value::bool(true),
                &source,
            )
            .expect("enabled inline trace result observes")
            .expect("enabled runtime observes inline trace results");

        assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
        assert!(observation.node().is_some());
        assert_eq!(runtime.cache().expect("cache is enabled").len(), 2);
    }

    #[test]
    fn disabled_eval_cache_runtime_inline_expression_trace_result_is_noop() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: true,
        };
        let mut runtime = EvalCacheRuntime::disabled();

        let observation = runtime
            .observe_inline_expression_result_with_impure_inputs(
                identity(b"source", 7),
                std::iter::empty::<DurableBlake3Hash>(),
                Value::bool(true),
                &source,
            )
            .expect("disabled inline trace result observation succeeds");

        assert_eq!(observation, None);
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn disabled_eval_cache_runtime_revalidating_lookup_is_noop() {
        let mut runtime = EvalCacheRuntime::disabled();
        let mut revalidator = StaticRevalidator::new(vec![read_file_trace(b"/tmp/version", b"1")]);

        let value = runtime
            .lookup_inline_expression_result_with_impure_inputs(
                identity(b"source", 7),
                std::iter::empty::<DurableBlake3Hash>(),
                &mut revalidator,
            )
            .expect("disabled lookup succeeds");

        assert!(value.is_none());
        assert_eq!(revalidator.calls(), 0);
    }

    #[test]
    fn eval_cache_observes_inline_expression_results() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        let first = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("first result observes");
        let second = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("second result observes");

        assert_eq!(first.decision(), crate::cache::CutoffDecision::Propagate);
        assert_eq!(second.node(), first.node());
        assert_eq!(second.decision(), crate::cache::CutoffDecision::CutOff);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn eval_cache_looks_up_clean_inline_expression_results() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("result observes");
        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds")
            .expect("memoized inline result is present");

        assert_eq!(value.as_int(), Ok(3));
    }

    #[test]
    fn eval_cache_looks_up_context_free_string_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::context_free_string(b"cached string".to_vec()),
            )
            .expect("string payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized string payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");

        assert_eq!(
            payload.context_free_string_bytes(),
            Some(b"cached string".as_slice())
        );
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_context_string_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let context = opaque_context(b"/nix/store/source");

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::context_string(b"cached string".to_vec(), context.clone()),
            )
            .expect("context string payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized context string payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");
        let (bytes, cached_context) = payload
            .context_string_parts()
            .expect("context string payload is present");

        assert_eq!(bytes, b"cached string");
        assert_eq!(cached_context, &context);
        assert!(payload.context_free_string_bytes().is_none());
        assert!(payload.path_bytes().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_path_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::path(b"/tmp/cached-path".to_vec()),
            )
            .expect("path payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized path payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");

        assert_eq!(payload.path_bytes(), Some(b"/tmp/cached-path".as_slice()));
        assert!(payload.context_free_string_bytes().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_context_path_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let context = opaque_context(b"/nix/store/source");

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::context_path(
                    b"/nix/store/context-path".to_vec(),
                    context.clone(),
                ),
            )
            .expect("context path payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized context path payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");
        let (bytes, cached_context) = payload
            .context_path_parts()
            .expect("context path payload is present");

        assert_eq!(bytes, b"/nix/store/context-path");
        assert_eq!(cached_context, &context);
        assert!(payload.context_string_parts().is_none());
        assert!(payload.path_bytes().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_empty_list_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::empty_list(),
            )
            .expect("empty list payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized empty list payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");

        assert!(payload.is_empty_list());
        assert!(payload.context_free_string_bytes().is_none());
        assert!(payload.context_string_parts().is_none());
        assert!(payload.path_bytes().is_none());
        assert!(payload.context_path_parts().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_strict_list_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::strict_list(vec![
                    CachedExpressionValue::immediate(Value::int(1)).expect("int payload builds"),
                    CachedExpressionValue::context_free_string(b"element".to_vec()),
                ]),
            )
            .expect("strict list payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized strict list payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");

        assert_eq!(payload.list_len(), Some(2));
        assert!(!payload.is_empty_list());
        assert!(payload.context_free_string_bytes().is_none());
        assert!(payload.context_string_parts().is_none());
        assert!(payload.path_bytes().is_none());
        assert!(payload.context_path_parts().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_empty_attrs_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::empty_attrs(),
            )
            .expect("empty attrset payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized empty attrset payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");

        assert!(payload.is_empty_attrs());
        assert!(!payload.is_empty_list());
        assert!(payload.context_free_string_bytes().is_none());
        assert!(payload.context_string_parts().is_none());
        assert!(payload.path_bytes().is_none());
        assert!(payload.context_path_parts().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_looks_up_strict_attrs_payloads() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);

        cache
            .observe_inline_expression_payload(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                CachedExpressionValue::strict_attrs(vec![
                    (
                        b"b".to_vec(),
                        CachedExpressionValue::context_free_string(b"value".to_vec()),
                    ),
                    (
                        b"a".to_vec(),
                        CachedExpressionValue::immediate(Value::int(1))
                            .expect("int payload builds"),
                    ),
                ])
                .expect("strict attrs payload builds"),
            )
            .expect("strict attrset payload observes");
        let payload = cache
            .lookup_inline_expression_payload(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("payload lookup succeeds")
            .expect("memoized strict attrset payload is present");
        let immediate = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("immediate lookup succeeds");

        assert_eq!(payload.attrs_len(), Some(2));
        assert!(!payload.is_empty_attrs());
        assert!(!payload.is_empty_list());
        assert!(payload.context_free_string_bytes().is_none());
        assert!(payload.context_string_parts().is_none());
        assert!(payload.path_bytes().is_none());
        assert!(payload.context_path_parts().is_none());
        assert!(payload.immediate_value().is_none());
        assert!(
            immediate.is_none(),
            "generic Value lookup must not return heap-backed payload pointers"
        );
    }

    #[test]
    fn eval_cache_lookup_requires_side_payload_record() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        cache
            .get_or_insert_expression_node(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Some(ValueHash::from_inline_value(Value::int(3)).expect("inline value hashes")),
            )
            .expect("node inserts");

        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");

        assert!(value.is_none());
    }

    #[test]
    fn eval_cache_lookup_rejects_dirty_inline_expression_nodes() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let observation = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("result observes");
        cache
            .graph
            .mark_dirty(observation.node())
            .expect("node can be marked dirty");

        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");

        assert!(value.is_none());
    }

    #[test]
    fn eval_cache_lookup_rejects_stale_inline_payload_records() {
        let mut cache = EvalCache::new();
        let identity = identity(b"source", 7);
        let observation = cache
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("result observes");
        cache
            .graph
            .reconsider_node(
                observation.node(),
                ValueHash::from_inline_value(Value::int(4)).expect("inline value hashes"),
            )
            .expect("node can be reconsidered independently");

        let value = cache
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds");

        assert!(value.is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_observes_inline_expression_results() {
        let mut runtime = EvalCacheRuntime::enabled();
        let identity = identity(b"source", 7);

        let first = runtime
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("first result observes")
            .expect("enabled runtime observes expression results");
        let second = runtime
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("second result observes")
            .expect("enabled runtime observes expression results");

        assert_eq!(first.decision(), crate::cache::CutoffDecision::Propagate);
        assert_eq!(second.node(), first.node());
        assert_eq!(second.decision(), crate::cache::CutoffDecision::CutOff);
        assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
    }

    #[test]
    fn enabled_eval_cache_runtime_looks_up_inline_expression_results() {
        let mut runtime = EvalCacheRuntime::enabled();
        let identity = identity(b"source", 7);

        runtime
            .observe_inline_expression_result(
                identity,
                std::iter::empty::<DurableBlake3Hash>(),
                Value::bool(true),
            )
            .expect("result observes")
            .expect("enabled runtime observes expression results");
        let value = runtime
            .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
            .expect("lookup succeeds")
            .expect("memoized inline result is present");

        assert_eq!(value.as_bool(), Ok(true));
    }

    #[test]
    fn disabled_eval_cache_runtime_expression_result_observation_is_noop() {
        let mut runtime = EvalCacheRuntime::disabled();

        let observation = runtime
            .observe_inline_expression_result(
                identity(b"source", 7),
                std::iter::empty::<DurableBlake3Hash>(),
                Value::int(3),
            )
            .expect("disabled expression result observation succeeds");

        assert_eq!(observation, None);
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn disabled_eval_cache_runtime_expression_result_lookup_is_noop() {
        let runtime = EvalCacheRuntime::disabled();

        let value = runtime
            .lookup_inline_expression_result(
                identity(b"source", 7),
                std::iter::empty::<DurableBlake3Hash>(),
            )
            .expect("disabled lookup succeeds");

        assert!(value.is_none());
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn eval_cache_reconsiders_expression_node_from_inline_value() {
        let mut cache = EvalCache::new();
        let node = cache
            .get_or_insert_expression_node(
                identity(b"source", 7),
                [durable_hash(b"free-var")],
                Some(ValueHash::from_inline_value(Value::int(1)).expect("inline value hashes")),
            )
            .expect("expression node inserts");

        let reconsideration = cache
            .reconsider_inline_value_node(node, Value::int(2))
            .expect("node reconsiders");

        assert_eq!(
            reconsideration.decision(),
            crate::cache::CutoffDecision::Propagate
        );
        assert_eq!(
            cache.graph().node(node).expect("node exists").value_hash(),
            Some(ValueHash::from_inline_value(Value::int(2)).expect("inline value hashes"))
        );
    }

    #[test]
    fn eval_cache_observes_derivation_aterm_expression() {
        let mut cache = EvalCache::new();
        let prior = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"old\")])";
        let changed = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"new\")])";

        let first = cache
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                prior,
            )
            .expect("first derivation ATerm observes");
        let same = cache
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                prior,
            )
            .expect("same derivation ATerm observes");
        let changed_reconsideration = cache
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                changed,
            )
            .expect("changed derivation ATerm observes");
        let node = cache
            .get_or_insert_expression_node(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                None,
            )
            .expect("existing expression node returns");

        assert_eq!(first.decision(), CutoffDecision::Propagate);
        assert_eq!(same.decision(), CutoffDecision::CutOff);
        assert_eq!(
            changed_reconsideration.decision(),
            CutoffDecision::Propagate
        );
        assert_eq!(
            cache.graph().node(node).expect("node exists").value_hash(),
            Some(derivation_aterm_hash(changed))
        );
    }

    #[test]
    fn eval_cache_looks_up_clean_derivation_aterm_path() {
        let mut cache = EvalCache::new();
        let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";
        let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";

        let reconsideration = cache
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
                drv_path,
            )
            .expect("derivation ATerm path observes");
        let lookup = cache
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("derivation ATerm path lookup succeeds");

        assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
        assert_eq!(lookup.as_deref(), Some(drv_path.as_slice()));
    }

    #[test]
    fn eval_cache_looks_up_clean_static_derivation_output_paths() {
        let mut cache = EvalCache::new();
        let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
        let output_paths = CachedDerivationOutputPaths::new(
            [7; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
            )],
        );

        let reconsideration = cache
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                output_paths.clone(),
            )
            .expect("static derivation output paths observe");
        let lookup = cache
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("static derivation output path lookup succeeds");

        assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
        assert_eq!(lookup, Some(output_paths));
    }

    #[test]
    fn derivation_aterm_path_lookup_misses_without_path_record() {
        let mut cache = EvalCache::new();
        let aterm = b"Derive([],[],[],\":\",\":\",[],[])";
        cache
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("derivation ATerm observes");

        let lookup = cache
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("derivation ATerm path lookup succeeds");

        assert!(lookup.is_none());
    }

    #[test]
    fn derivation_aterm_path_lookup_misses_for_changed_or_dirty_nodes() {
        let mut cache = EvalCache::new();
        let prior = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"old\")])";
        let changed = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
        cache
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                prior,
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
            )
            .expect("derivation ATerm path observes");

        let changed_lookup = cache
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                changed,
            )
            .expect("changed derivation ATerm lookup succeeds");
        assert!(changed_lookup.is_none());

        let node = cache
            .get_or_insert_expression_node(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                None,
            )
            .expect("existing derivation node returns");
        cache.graph.mark_dirty(node).expect("node dirties");
        let dirty_lookup = cache
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                prior,
            )
            .expect("dirty derivation ATerm lookup succeeds");

        assert!(dirty_lookup.is_none());
    }

    #[test]
    fn derivation_aterm_path_observation_reconsiders_full_payload() {
        let mut cache = EvalCache::new();
        let aterm = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"same\")])";

        let first = cache
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
            )
            .expect("first derivation ATerm path observes");
        let changed_path = cache
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
                b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv",
            )
            .expect("changed derivation ATerm path observes");
        let same = cache
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
                b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv",
            )
            .expect("same derivation ATerm path observes");
        let lookup = cache
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("derivation ATerm path lookup succeeds");

        assert_eq!(first.decision(), CutoffDecision::Propagate);
        assert_eq!(changed_path.decision(), CutoffDecision::Propagate);
        assert_eq!(same.decision(), CutoffDecision::CutOff);
        assert_eq!(
            lookup.as_deref(),
            Some(b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x.drv".as_slice())
        );
    }

    #[test]
    fn static_derivation_output_path_lookup_misses_for_changed_or_dirty_nodes() {
        let mut cache = EvalCache::new();
        let prior = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
        let changed =
            b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
        let output_paths = CachedDerivationOutputPaths::new(
            [8; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
            )],
        );
        cache
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                prior,
                output_paths,
            )
            .expect("static derivation output paths observe");

        let changed_lookup = cache
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                changed,
            )
            .expect("changed static derivation output path lookup succeeds");
        assert!(changed_lookup.is_none());

        let node = cache
            .get_or_insert_expression_node(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                None,
            )
            .expect("existing static derivation output node returns");
        cache.graph.mark_dirty(node).expect("node dirties");
        let dirty_lookup = cache
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                prior,
            )
            .expect("dirty static derivation output path lookup succeeds");

        assert!(dirty_lookup.is_none());
    }

    #[test]
    fn static_derivation_output_path_observation_reconsiders_full_payload() {
        let mut cache = EvalCache::new();
        let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
        let first = CachedDerivationOutputPaths::new(
            [1; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
            )],
        );
        let changed_path = CachedDerivationOutputPaths::new(
            [1; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x".to_vec(),
            )],
        );
        let changed_hash = CachedDerivationOutputPaths::new(
            [2; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x".to_vec(),
            )],
        );

        let first_reconsideration = cache
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                first,
            )
            .expect("first static output observation succeeds");
        let changed_path_reconsideration = cache
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                changed_path,
            )
            .expect("changed-path static output observation succeeds");
        let changed_hash_reconsideration = cache
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                changed_hash.clone(),
            )
            .expect("changed-hash static output observation succeeds");
        let same_reconsideration = cache
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                changed_hash.clone(),
            )
            .expect("same static output observation succeeds");
        let lookup = cache
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("static output lookup succeeds");

        assert_eq!(first_reconsideration.decision(), CutoffDecision::Propagate);
        assert_eq!(
            changed_path_reconsideration.decision(),
            CutoffDecision::Propagate
        );
        assert_eq!(
            changed_hash_reconsideration.decision(),
            CutoffDecision::Propagate
        );
        assert_eq!(same_reconsideration.decision(), CutoffDecision::CutOff);
        assert_eq!(lookup, Some(changed_hash));
    }

    #[test]
    fn disabled_eval_cache_runtime_skips_derivation_aterm_path_lookup_and_observation() {
        let mut runtime = EvalCacheRuntime::disabled();
        let aterm = b"Derive([],[],[],\":\",\":\",[],[])";

        let observation = runtime
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
            )
            .expect("disabled observation succeeds");
        let lookup = runtime
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("disabled lookup succeeds");

        assert!(observation.is_none());
        assert!(lookup.is_none());
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn disabled_eval_cache_runtime_skips_static_derivation_output_path_lookup_and_observation() {
        let mut runtime = EvalCacheRuntime::disabled();
        let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
        let output_paths = CachedDerivationOutputPaths::new(
            [9; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
            )],
        );

        let observation = runtime
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                output_paths,
            )
            .expect("disabled static output observation succeeds");
        let lookup = runtime
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("disabled static output lookup succeeds");

        assert!(observation.is_none());
        assert!(lookup.is_none());
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_derivation_aterm_path_roundtrip() {
        let mut runtime = EvalCacheRuntime::enabled();
        let aterm = b"Derive([],[],[],\":\",\":\",[],[])";
        let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";

        let observation = runtime
            .observe_derivation_aterm_expression_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
                drv_path,
            )
            .expect("enabled observation succeeds")
            .expect("enabled runtime observes derivation ATerm path");
        let lookup = runtime
            .lookup_derivation_aterm_path(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("enabled lookup succeeds");

        assert_eq!(observation.decision(), CutoffDecision::Propagate);
        assert_eq!(lookup.as_deref(), Some(drv_path.as_slice()));
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_static_derivation_output_path_roundtrip() {
        let mut runtime = EvalCacheRuntime::enabled();
        let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
        let output_paths = CachedDerivationOutputPaths::new(
            [10; 32],
            vec![CachedDerivationOutputPath::new(
                b"out".to_vec(),
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
            )],
        );

        let observation = runtime
            .observe_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
                output_paths.clone(),
            )
            .expect("enabled static output observation succeeds")
            .expect("enabled runtime observes static output paths");
        let lookup = runtime
            .lookup_static_derivation_output_paths(
                identity(b"derivation-outputs", 7),
                [durable_hash(b"free-var")],
                pre_output_aterm,
            )
            .expect("enabled static output lookup succeeds");

        assert_eq!(observation.decision(), CutoffDecision::Propagate);
        assert_eq!(lookup, Some(output_paths));
    }

    #[test]
    fn disabled_eval_cache_runtime_skips_derivation_aterm_observation() {
        let mut runtime = EvalCacheRuntime::disabled();

        let observation = runtime
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                b"Derive([],[],[],\":\",\":\",[],[])",
            )
            .expect("disabled observation succeeds");

        assert!(observation.is_none());
        assert!(runtime.cache().is_none());
    }

    #[test]
    fn enabled_eval_cache_runtime_delegates_derivation_aterm_observation() {
        let mut runtime = EvalCacheRuntime::enabled();
        let aterm = b"Derive([],[],[],\":\",\":\",[],[])";

        let first = runtime
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("enabled observation succeeds")
            .expect("enabled runtime observes derivation ATerm");
        let same = runtime
            .observe_derivation_aterm_expression(
                identity(b"derivation", 7),
                [durable_hash(b"free-var")],
                aterm,
            )
            .expect("enabled observation succeeds")
            .expect("enabled runtime observes derivation ATerm");

        assert_eq!(first.decision(), CutoffDecision::Propagate);
        assert_eq!(same.decision(), CutoffDecision::CutOff);
        assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
    }

    #[test]
    fn eval_cache_rejects_incomplete_trace_source_without_mutation() {
        let source = TraceSource {
            trace: vec![read_file_trace(b"/tmp/version", b"1")],
            complete: false,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_impure_inputs(&source)
            .expect("trace observes");

        assert_eq!(observation.status(), ImpureTraceStatus::Incomplete);
        assert!(observation.leaves().is_empty());
        assert!(cache.is_empty());
    }

    #[test]
    fn eval_cache_rejects_uncacheable_trace_source_without_mutation() {
        let source = TraceSource {
            trace: vec![
                read_file_trace(b"/tmp/version", b"1"),
                ImpureInputFingerprint::current_time(),
            ],
            complete: true,
        };
        let mut cache = EvalCache::new();

        let observation = cache
            .observe_impure_inputs(&source)
            .expect("trace observes");

        assert_eq!(
            observation.status(),
            ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert!(observation.leaves().is_empty());
        assert!(cache.is_empty());
    }
}
