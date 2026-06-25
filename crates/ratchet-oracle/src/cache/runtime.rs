//! Caller-owned evaluator cache runtime substrate.
//!
//! This module ties evaluator observation traces to the in-memory demand graph
//! without owning evaluation or memoization policy. Callers explicitly decide
//! when to observe a completed evaluation outcome.

use std::collections::BTreeMap;

use super::{
    CacheExprIdentity, CacheableInputFingerprint, DemandCacheKey, DemandGraph, DemandGraphError,
    DemandNodeId, DurableBlake3Hash, ImpureInputFingerprint, ImpureInputIdentity,
    ImpureTraceObservation, ImpureTraceStatus, NodeFreshness, Reconsideration, UncacheableInput,
    ValueHash, ValueHashError,
};
use crate::value::Value;

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
}

impl ExpressionTraceObservation {
    fn new(node: Option<DemandNodeId>, trace: ImpureTraceObservation) -> Self {
        Self { node, trace }
    }

    /// Returns the expression node wired to cacheable input leaves, if any.
    pub const fn node(&self) -> Option<DemandNodeId> {
        self.node
    }

    /// Returns the observed impure trace cacheability and leaves.
    pub const fn trace(&self) -> &ImpureTraceObservation {
        &self.trace
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

/// A memoized force-cache payload that can be replayed by an evaluator.
///
/// Immediate values can be returned directly because they carry their payload
/// in the [`Value`] word. Heap-backed values must instead store canonical data
/// and be rehydrated by the evaluator that consumes the hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedExpressionValue {
    payload: InlineValuePayload,
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

    /// Returns the immediate scalar value, if this payload is immediate.
    pub fn immediate_value(&self) -> Option<Value> {
        self.payload.immediate_value()
    }

    /// Returns the cached context-free string bytes, if this payload is a string.
    pub fn context_free_string_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            InlineValuePayload::ContextFreeString(bytes) => Some(bytes),
            InlineValuePayload::Int(_)
            | InlineValuePayload::Float(_)
            | InlineValuePayload::Bool(_)
            | InlineValuePayload::Null => None,
        }
    }
}

/// Explicit evaluator cache state owned by the caller.
#[derive(Clone, Debug, Default)]
pub struct EvalCache {
    graph: DemandGraph,
    inline_values: BTreeMap<DemandNodeId, InlineValueRecord>,
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

    /// Consumes this cache into its demand graph.
    pub fn into_graph(self) -> DemandGraph {
        self.graph
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
    /// This first observes the trace. Incomplete or uncacheable traces return
    /// their status without creating an expression node. Complete cacheable
    /// traces get or insert the caller-supplied expression node and then add
    /// dependencies from that node to the observed input leaves.
    ///
    /// This is still an explicit adapter: callers supply expression identity,
    /// ordered free-variable value hashes, and the optional current value hash.
    /// It does not compute evaluator identities, perform memo lookup, or own
    /// dynamic evaluator node lifecycle.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation or edge wiring later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, or dependency edge insertion
    /// fails.
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
        let trace = self.observe_impure_inputs(source)?;
        if trace.status() != ImpureTraceStatus::Cacheable {
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        let node =
            self.get_or_insert_expression_node(identity, free_var_value_hashes, value_hash)?;
        for leaf in trace.leaves() {
            self.graph.add_dependency(node, leaf.node())?;
        }
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
    /// Cacheable traces get or insert the expression node, wire observed input
    /// leaves as dependencies, reconsider the node from the payload value hash,
    /// and store the side payload plus the cacheable input fingerprints
    /// required by
    /// [`EvalCache::lookup_inline_expression_payload_with_impure_inputs`].
    /// Incomplete or uncacheable traces return their status without creating a
    /// new expression node or payload; if the expression key already exists,
    /// its prior inline payload is removed and the node is marked dirty.
    ///
    /// Successful leaf observations are not rolled back if expression-node
    /// allocation, edge wiring, or value reconsideration later fails.
    ///
    /// # Errors
    ///
    /// Returns a [`DemandGraphError`] if trace observation fails, expression
    /// cache-key construction or insertion fails, dependency edge insertion
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
            return Ok(ExpressionTraceObservation::new(None, trace));
        }

        let record = match InlineValueRecord::requires_revalidation(value, source) {
            Ok(record) => record,
            Err(error) => {
                self.invalidate_existing_inline_payload(existing_node)?;
                return Err(error);
            }
        };
        let node = self
            .graph
            .get_or_insert_node(key, Some(record.value_hash))?;
        for leaf in trace.leaves() {
            self.graph.add_dependency(node, leaf.node())?;
        }
        self.graph.reconsider_node(node, record.value_hash)?;
        self.inline_values.insert(node, record);
        Ok(ExpressionTraceObservation::new(Some(node), trace))
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

    fn invalidate_existing_inline_payload(
        &mut self,
        node: Option<DemandNodeId>,
    ) -> Result<(), DemandGraphError> {
        if let Some(node) = node {
            self.graph.mark_dirty(node)?;
            self.inline_values.remove(&node);
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
            Self::ContextFreeString(_) => None,
        }
    }

    fn value_hash(&self) -> Result<ValueHash, ValueHashError> {
        match self {
            Self::Int(value) => ValueHash::from_inline_value(Value::int(*value)),
            Self::Float(bits) => ValueHash::from_inline_value(Value::float(f64::from_bits(*bits))),
            Self::Bool(value) => ValueHash::from_inline_value(Value::bool(*value)),
            Self::Null => ValueHash::from_inline_value(Value::null()),
            Self::ContextFreeString(bytes) => Ok(ValueHash::from_context_free_string_bytes(bytes)),
        }
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
    use crate::cache::{DemandCacheKey, ImpureTraceStatus, NodeFreshness, UncacheableInput};
    use crate::compile::IrId;

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

    fn read_file_trace(path: &[u8], contents: &[u8]) -> ImpureInputFingerprint {
        ImpureInputFingerprint::read_file(path, contents).expect("input fingerprints")
    }

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn durable_hash(bytes: &[u8]) -> DurableBlake3Hash {
        DurableBlake3Hash::for_bytes(bytes)
    }

    fn identity(source: &[u8], node: u32) -> CacheExprIdentity {
        CacheExprIdentity::new(durable_hash(source), IrId::new(node))
    }

    fn key(node: u32, label: &[u8]) -> DemandCacheKey {
        DemandCacheKey::for_free_vars(identity(label, node), [durable_hash(label)])
            .expect("key builds")
    }

    fn node_with_hash(graph: &mut DemandGraph, node: u32, label: &'static [u8]) -> DemandNodeId {
        graph
            .get_or_insert_node(key(node, label), Some(value_hash(label)))
            .expect("node inserts")
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
