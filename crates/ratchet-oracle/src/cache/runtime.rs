//! Caller-owned evaluator cache runtime substrate.
//!
//! This module ties evaluator observation traces to the in-memory demand graph
//! while keeping evaluator policy decisions explicit at call sites. Callers
//! choose which computations to observe, which memoization subject applies, and
//! which value-hash cost signals are available.

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
use crate::attrs::AttrPosition;
use crate::string::{ContextElement, ContextKind, NixStringError, StringContext};
use crate::syntax::Span;
use crate::value::Value;

mod derivation_payload;
mod eval_cache_runtime;
mod expression_value;

#[allow(unused_imports)]
pub(crate) use derivation_payload::CachedDerivationSidePayloadError;
pub(crate) use derivation_payload::{
    CachedDerivationAtermPath, CachedDerivationOutputPath, CachedDerivationOutputPaths,
    CachedStaticDerivationOutputPathsPayload,
};
use derivation_payload::{DerivationAtermPathRecord, StaticDerivationOutputPathRecord};
pub use eval_cache_runtime::EvalCacheRuntime;
pub use expression_value::{CachedAttrEntryWithPosition, CachedExpressionValue};

const MAX_CACHED_EXPRESSION_PAYLOAD_NESTING: usize = 64;
const SOURCE_ORDERED_ATTRS_PAYLOAD_TAG: &[u8] = b"attrs-source-order";
const POSITIONED_ATTRS_PAYLOAD_TAG: &[u8] = b"attrs-positioned";
const SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG: &[u8] = b"attrs-source-order-positioned";
const ATTR_POSITION_SOURCE_PAYLOAD_ENVELOPE_TAG: &[u8] = b"attrs-position-source-v1";
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
    /// A positioned attrset payload used a positioned tag without any positions.
    #[error("cached expression positioned attrset payload has no positioned bindings")]
    PositionlessPositionedAttrsPayload,
    /// A position-source envelope wrapped a payload with no retained positions.
    #[error("cached expression attr-position source envelope has no positioned bindings")]
    PositionSourceWithoutPositions,
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
        if let Some(node) = node
            && self.inline_values.contains_key(&node)
        {
            self.invalidate_existing_inline_payload(Some(node))?;
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
    attr_position_source_hash: Option<DurableBlake3Hash>,
    value_hash: ValueHash,
    reusable_without_revalidation: bool,
    revalidation_inputs: Option<Vec<CacheableInputFingerprint>>,
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
        let value_hash = value.value_hash()?;
        Ok(Self {
            payload: value.payload,
            attr_position_source_hash: value.attr_position_source_hash,
            value_hash,
            reusable_without_revalidation,
            revalidation_inputs,
        })
    }

    fn value(&self) -> CachedExpressionValue {
        CachedExpressionValue {
            payload: self.payload.clone(),
            attr_position_source_hash: self.attr_position_source_hash,
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
    SourceOrderedAttrs(Vec<AttrPayloadEntry>),
    PositionedAttrs(Vec<PositionedAttrPayloadEntry>),
    SourceOrderedPositionedAttrs(Vec<PositionedAttrPayloadEntry>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttrPayloadEntry {
    name: Vec<u8>,
    value: InlineValuePayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PositionedAttrPayloadEntry {
    name: Vec<u8>,
    position: Option<AttrPosition>,
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
            | Self::Attrs(_)
            | Self::SourceOrderedAttrs(_)
            | Self::PositionedAttrs(_)
            | Self::SourceOrderedPositionedAttrs(_) => None,
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
            Self::Attrs(_)
            | Self::SourceOrderedAttrs(_)
            | Self::PositionedAttrs(_)
            | Self::SourceOrderedPositionedAttrs(_) => {
                Ok(self.value_hash_from_persistent_payload())
            }
        }
    }

    fn retains_attr_positions(&self) -> bool {
        match self {
            Self::PositionedAttrs(_) | Self::SourceOrderedPositionedAttrs(_) => true,
            Self::List(elements) => elements.iter().any(Self::retains_attr_positions),
            Self::Attrs(entries) | Self::SourceOrderedAttrs(entries) => entries
                .iter()
                .any(|entry| entry.value.retains_attr_positions()),
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::EmptyAttrs => false,
        }
    }

    fn attr_positions_all_in_module(&self, module: u32) -> bool {
        match self {
            Self::PositionedAttrs(entries) | Self::SourceOrderedPositionedAttrs(entries) => {
                entries.iter().all(|entry| {
                    entry
                        .position
                        .map(|position| position.module == module)
                        .unwrap_or(true)
                        && entry.value.attr_positions_all_in_module(module)
                })
            }
            Self::List(elements) => elements
                .iter()
                .all(|element| element.attr_positions_all_in_module(module)),
            Self::Attrs(entries) | Self::SourceOrderedAttrs(entries) => entries
                .iter()
                .all(|entry| entry.value.attr_positions_all_in_module(module)),
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::EmptyAttrs => true,
        }
    }

    fn collect_attr_position_modules(&self, modules: &mut BTreeSet<u32>) {
        match self {
            Self::PositionedAttrs(entries) | Self::SourceOrderedPositionedAttrs(entries) => {
                for entry in entries {
                    if let Some(position) = entry.position {
                        modules.insert(position.module);
                    }
                    entry.value.collect_attr_position_modules(modules);
                }
            }
            Self::List(elements) => {
                for element in elements {
                    element.collect_attr_position_modules(modules);
                }
            }
            Self::Attrs(entries) | Self::SourceOrderedAttrs(entries) => {
                for entry in entries {
                    entry.value.collect_attr_position_modules(modules);
                }
            }
            Self::Int(_)
            | Self::Float(_)
            | Self::Bool(_)
            | Self::Null
            | Self::ContextFreeString(_)
            | Self::ContextString { .. }
            | Self::Path(_)
            | Self::ContextPath { .. }
            | Self::EmptyList
            | Self::EmptyAttrs => {}
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
            Self::SourceOrderedAttrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(SOURCE_ORDERED_ATTRS_PAYLOAD_TAG);
                hasher.update(&(entries.len() as u128).to_le_bytes());
                for entry in entries {
                    hasher.update(&(entry.name.len() as u128).to_le_bytes());
                    hasher.update(&entry.name);
                    hasher.update(&entry.value.persistent_payload_len().to_le_bytes());
                    entry.value.update_persistent_payload_preimage(hasher);
                }
            }
            Self::PositionedAttrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(POSITIONED_ATTRS_PAYLOAD_TAG);
                update_positioned_attr_entries_preimage(hasher, entries);
            }
            Self::SourceOrderedPositionedAttrs(entries) => {
                hasher.update(ATTRS_VALUE_HASH_DOMAIN_VERSION);
                hasher.update(SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG);
                update_positioned_attr_entries_preimage(hasher, entries);
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
            Self::SourceOrderedAttrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + SOURCE_ORDERED_ATTRS_PAYLOAD_TAG.len() as u128
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
            Self::PositionedAttrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + POSITIONED_ATTRS_PAYLOAD_TAG.len() as u128
                    + 16
                    + entries
                        .iter()
                        .map(positioned_attr_entry_payload_len)
                        .sum::<u128>()
            }
            Self::SourceOrderedPositionedAttrs(entries) => {
                ATTRS_VALUE_HASH_DOMAIN_VERSION.len() as u128
                    + SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG.len() as u128
                    + 16
                    + entries
                        .iter()
                        .map(positioned_attr_entry_payload_len)
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
            Self::SourceOrderedAttrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, SOURCE_ORDERED_ATTRS_PAYLOAD_TAG)?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
            Self::PositionedAttrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, POSITIONED_ATTRS_PAYLOAD_TAG)?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_attr_position_payload(&mut out, entry.position)?;
                    append_payload_u128(&mut out, entry.value.persistent_payload_len())?;
                    append_payload_bytes(&mut out, &entry.value.encode_persistent_payload()?)?;
                }
            }
            Self::SourceOrderedPositionedAttrs(entries) => {
                append_payload_bytes(&mut out, ATTRS_VALUE_HASH_DOMAIN_VERSION)?;
                append_payload_bytes(&mut out, SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG)?;
                append_payload_u128(&mut out, entries.len() as u128)?;
                for entry in entries {
                    append_payload_u128(&mut out, entry.name.len() as u128)?;
                    append_payload_bytes(&mut out, &entry.name)?;
                    append_attr_position_payload(&mut out, entry.position)?;
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
            let (source_ordered, positioned) = if cursor
                .remaining()
                .starts_with(SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG)
            {
                cursor.take_marker(
                    SOURCE_ORDERED_POSITIONED_ATTRS_PAYLOAD_TAG,
                    "source-order positioned attrs payload tag",
                )?;
                (true, true)
            } else if cursor.remaining().starts_with(POSITIONED_ATTRS_PAYLOAD_TAG) {
                cursor.take_marker(POSITIONED_ATTRS_PAYLOAD_TAG, "positioned attrs payload tag")?;
                (false, true)
            } else if cursor
                .remaining()
                .starts_with(SOURCE_ORDERED_ATTRS_PAYLOAD_TAG)
            {
                cursor.take_marker(
                    SOURCE_ORDERED_ATTRS_PAYLOAD_TAG,
                    "source-order attrs payload tag",
                )?;
                (true, false)
            } else {
                cursor.take_marker(b"attrs", "attrs payload tag")?;
                (false, false)
            };
            let len = cursor.take_len()?;
            if len == 0 {
                cursor.finish()?;
                if positioned {
                    return Err(
                        CachedExpressionValuePayloadError::PositionlessPositionedAttrsPayload,
                    );
                }
                return Ok(Self::EmptyAttrs);
            }
            if positioned {
                let mut entries: Vec<PositionedAttrPayloadEntry> = Vec::new();
                entries.try_reserve_exact(len).map_err(|_| {
                    CachedExpressionValuePayloadError::AttrsAllocationFailed { len }
                })?;
                let mut has_position = false;
                for index in 0..len {
                    let name = cursor.take_length_prefixed_bytes()?;
                    if !source_ordered
                        && let Some(previous) = entries.last()
                        && previous.name.as_slice() >= name.as_slice()
                    {
                        return Err(
                            CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName {
                                index,
                            },
                        );
                    }
                    let position = cursor.take_attr_position()?;
                    has_position |= position.is_some();
                    let value = cursor.take_length_prefixed_bytes()?;
                    entries.push(PositionedAttrPayloadEntry {
                        name,
                        position,
                        value: Self::decode_persistent_payload_with_depth(
                            &value,
                            depth.saturating_add(1),
                        )?,
                    });
                }
                cursor.finish()?;
                if !has_position {
                    return Err(
                        CachedExpressionValuePayloadError::PositionlessPositionedAttrsPayload,
                    );
                }
                if source_ordered {
                    ensure_unique_attr_payload_names(
                        entries.iter().map(|entry| entry.name.as_slice()),
                    )?;
                    return Ok(Self::SourceOrderedPositionedAttrs(entries));
                }
                return Ok(Self::PositionedAttrs(entries));
            }
            let mut entries: Vec<AttrPayloadEntry> = Vec::new();
            entries
                .try_reserve_exact(len)
                .map_err(|_| CachedExpressionValuePayloadError::AttrsAllocationFailed { len })?;
            for index in 0..len {
                let name = cursor.take_length_prefixed_bytes()?;
                if !source_ordered
                    && let Some(previous) = entries.last()
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
            if source_ordered {
                ensure_unique_attr_payload_names(
                    entries.iter().map(|entry| entry.name.as_slice()),
                )?;
                return Ok(Self::SourceOrderedAttrs(entries));
            }
            return Ok(Self::Attrs(entries));
        }
        Err(CachedExpressionValuePayloadError::UnknownDomain)
    }
}

fn ensure_unique_attr_payload_names<'a, I>(
    names: I,
) -> Result<(), CachedExpressionValuePayloadError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut seen = BTreeMap::<Vec<u8>, usize>::new();
    for (index, name) in names.into_iter().enumerate() {
        if seen.contains_key(name) {
            return Err(CachedExpressionValuePayloadError::NonCanonicalAttrsPayloadName { index });
        }
        seen.insert(name.to_vec(), index);
    }
    Ok(())
}

fn update_positioned_attr_entries_preimage(
    hasher: &mut blake3::Hasher,
    entries: &[PositionedAttrPayloadEntry],
) {
    hasher.update(&(entries.len() as u128).to_le_bytes());
    for entry in entries {
        hasher.update(&(entry.name.len() as u128).to_le_bytes());
        hasher.update(&entry.name);
        update_attr_position_preimage(hasher, entry.position);
        hasher.update(&entry.value.persistent_payload_len().to_le_bytes());
        entry.value.update_persistent_payload_preimage(hasher);
    }
}

fn update_attr_position_preimage(hasher: &mut blake3::Hasher, position: Option<AttrPosition>) {
    match position {
        Some(position) => {
            hasher.update(&[1]);
            hasher.update(&position.module.to_le_bytes());
            hasher.update(&position.span.start.to_le_bytes());
            hasher.update(&position.span.end.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn positioned_attr_entry_payload_len(entry: &PositionedAttrPayloadEntry) -> u128 {
    16 + entry.name.len() as u128
        + attr_position_payload_len(entry.position)
        + 16
        + entry.value.persistent_payload_len()
}

const fn attr_position_payload_len(position: Option<AttrPosition>) -> u128 {
    if position.is_some() { 13 } else { 1 }
}

fn append_attr_position_payload(
    out: &mut Vec<u8>,
    position: Option<AttrPosition>,
) -> Result<(), CachedExpressionValuePayloadError> {
    match position {
        Some(position) => {
            append_payload_byte(out, 1)?;
            append_payload_bytes(out, &position.module.to_le_bytes())?;
            append_payload_bytes(out, &position.span.start.to_le_bytes())?;
            append_payload_bytes(out, &position.span.end.to_le_bytes())
        }
        None => append_payload_byte(out, 0),
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
    let tag = cursor.remaining().first().copied().unwrap_or_default();
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

    fn take_u32(&mut self) -> Result<u32, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(4)?;
        let mut out = [0; 4];
        out.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(out))
    }

    fn take_u128(&mut self) -> Result<u128, CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(16)?;
        let mut out = [0; 16];
        out.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(out))
    }

    fn take_digest(&mut self) -> Result<[u8; 32], CachedExpressionValuePayloadError> {
        let bytes = self.take_bytes(32)?;
        let mut out = [0; 32];
        out.copy_from_slice(bytes);
        Ok(out)
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

    fn take_attr_position(
        &mut self,
    ) -> Result<Option<AttrPosition>, CachedExpressionValuePayloadError> {
        match self.take_byte()? {
            0 => Ok(None),
            1 => {
                let module = self.take_u32()?;
                let start = self.take_u32()?;
                let end = self.take_u32()?;
                Ok(Some(AttrPosition::new(module, Span::new(start, end))))
            }
            tag => Err(CachedExpressionValuePayloadError::InvalidTag {
                section: "attr position",
                tag,
            }),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrPosition;
    use crate::cache::{
        CutoffDecision, DemandCacheKey, ImpureTraceStatus, MemoizationDecision, MemoizationDemand,
        MemoizationSubject, NodeFreshness, UncacheableInput,
    };
    use crate::compile::IrId;
    use crate::string::{ContextElement, StringContext};
    use crate::syntax::Span;

    mod derivation_payload;
    mod expression_trace;
    mod inline_payload;
    mod inline_trace_payload;
    mod payload_encoding;
    mod trace_frontier;

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
