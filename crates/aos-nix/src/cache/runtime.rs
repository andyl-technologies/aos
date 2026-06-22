//! Caller-owned evaluator cache runtime substrate.
//!
//! This module ties evaluator observation traces to the in-memory demand graph
//! without owning evaluation or memoization policy. Callers explicitly decide
//! when to observe a completed evaluation outcome.

use super::{
    CacheExprIdentity, DemandGraph, DemandGraphError, DemandNodeId, DurableBlake3Hash,
    ImpureInputFingerprint, ImpureTraceObservation, ImpureTraceStatus, Reconsideration, ValueHash,
};
use crate::value::Value;

/// A source of evaluator-observed impure input trace entries.
pub trait ImpureInputTraceSource {
    /// Returns impure inputs observed while evaluating a root computation.
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint];

    /// Returns whether the trace is complete enough to be cache-usable.
    fn impure_input_trace_complete(&self) -> bool;
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

    /// Consumes this observation into its node and trace parts.
    pub fn into_parts(self) -> (Option<DemandNodeId>, ImpureTraceObservation) {
        (self.node, self.trace)
    }
}

/// Explicit evaluator cache state owned by the caller.
#[derive(Clone, Debug, Default)]
pub struct EvalCache {
    graph: DemandGraph,
}

impl EvalCache {
    /// Creates an empty evaluator cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an evaluator cache from an existing demand graph.
    pub fn from_graph(graph: DemandGraph) -> Self {
        Self { graph }
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
