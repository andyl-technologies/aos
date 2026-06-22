//! Caller-owned evaluator cache runtime substrate.
//!
//! This module ties evaluator observation traces to the in-memory demand graph
//! without owning evaluation or memoization policy. Callers explicitly decide
//! when to observe a completed evaluation outcome.

use super::{
    DemandGraph, DemandGraphError, DemandNodeId, ImpureInputFingerprint, ImpureTraceObservation,
};

/// A source of evaluator-observed impure input trace entries.
pub trait ImpureInputTraceSource {
    /// Returns impure inputs observed while evaluating a root computation.
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint];

    /// Returns whether the trace is complete enough to be cache-usable.
    fn impure_input_trace_complete(&self) -> bool;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        CacheExprIdentity, DemandCacheKey, DurableBlake3Hash, ImpureTraceStatus, NodeFreshness,
        UncacheableInput, ValueHash,
    };
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

    fn key(node: u32, label: &[u8]) -> DemandCacheKey {
        let identity = CacheExprIdentity::new(DurableBlake3Hash::for_bytes(label), IrId::new(node));
        DemandCacheKey::for_free_vars(identity, [DurableBlake3Hash::for_bytes(label)])
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
