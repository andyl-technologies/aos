//! Shared demand-graph node-table admission for future parallel evaluators.

use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;

use super::*;

/// The outcome of admitting one demand node into a shared graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DemandNodeAdmission {
    node: DemandNodeId,
    inserted: bool,
}

impl DemandNodeAdmission {
    fn inserted(node: DemandNodeId) -> Self {
        Self {
            node,
            inserted: true,
        }
    }

    fn existing(node: DemandNodeId) -> Self {
        Self {
            node,
            inserted: false,
        }
    }

    /// Returns the admitted demand node.
    pub const fn node(self) -> DemandNodeId {
        self.node
    }

    /// Returns whether this admission inserted a new node.
    pub const fn was_inserted(self) -> bool {
        self.inserted
    }
}

/// A same-process shared demand graph with serialized node-table admission.
///
/// This is a correctness substrate for concurrent callers that may miss on the
/// same cache key at the same time. It deliberately serializes the current
/// single-threaded [`DemandGraph`] behind a process-local mutex; the future
/// P3.5 lock-free CAS table can replace this boundary without changing the
/// insert-or-get semantics proven here.
#[derive(Clone, Debug)]
pub struct SharedDemandGraph {
    inner: Arc<Mutex<DemandGraph>>,
}

impl SharedDemandGraph {
    /// Creates an empty shared demand graph.
    pub fn new() -> Self {
        Self::from_graph(DemandGraph::new())
    }

    /// Wraps an existing demand graph for same-process shared admission.
    pub fn from_graph(graph: DemandGraph) -> Self {
        Self {
            inner: Arc::new(Mutex::new(graph)),
        }
    }

    /// Returns the number of nodes in the graph.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock.
    pub fn len(&self) -> Result<usize, SharedDemandGraphError> {
        Ok(self.lock()?.len())
    }

    /// Returns whether the graph has no nodes.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock.
    pub fn is_empty(&self) -> Result<bool, SharedDemandGraphError> {
        Ok(self.lock()?.is_empty())
    }

    /// Returns a cloned node by id.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock. Returns
    /// [`DemandGraphError::UnknownNode`] through
    /// [`SharedDemandGraphError::Graph`] if `id` does not belong to this graph.
    pub fn node(&self, id: DemandNodeId) -> Result<DemandNode, SharedDemandGraphError> {
        let graph = self.lock()?;
        graph.node(id).cloned().map_err(Into::into)
    }

    /// Returns the id for `key`, if a node with that key already exists.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock.
    pub fn node_id_for_key(
        &self,
        key: DemandCacheKey,
    ) -> Result<Option<DemandNodeId>, SharedDemandGraphError> {
        Ok(self.lock()?.node_id_for_key(key))
    }

    /// Gets or inserts a node keyed by `key`.
    ///
    /// Existing nodes keep their current value hash; callers update hashes by
    /// reconsidering the node.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock. Returns graph allocation failures
    /// through [`SharedDemandGraphError::Graph`].
    pub fn get_or_insert_node(
        &self,
        key: DemandCacheKey,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, SharedDemandGraphError> {
        self.get_or_insert_node_with_status(key, value_hash)
            .map(DemandNodeAdmission::node)
    }

    /// Gets or inserts a node keyed by `key` and reports the admission outcome.
    ///
    /// The key lookup and possible insertion happen while holding one shared
    /// lock, so racing same-key misses converge on one inserted node and all
    /// losing callers observe that same node as existing.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock. Returns graph allocation failures
    /// through [`SharedDemandGraphError::Graph`].
    pub fn get_or_insert_node_with_status(
        &self,
        key: DemandCacheKey,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeAdmission, SharedDemandGraphError> {
        let mut graph = self.lock()?;
        if let Some(node) = graph.node_id_for_key(key) {
            return Ok(DemandNodeAdmission::existing(node));
        }
        graph
            .get_or_insert_node(key, value_hash)
            .map(DemandNodeAdmission::inserted)
            .map_err(Into::into)
    }

    /// Gets or inserts a node keyed by an expression identity and free variables.
    ///
    /// Existing nodes keep their current value hash; callers update hashes by
    /// reconsidering the node.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock. Returns cache-key construction or
    /// graph allocation failures through [`SharedDemandGraphError::Graph`].
    pub fn get_or_insert_expression_node<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeId, SharedDemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        self.get_or_insert_expression_node_with_status(identity, free_var_value_hashes, value_hash)
            .map(DemandNodeAdmission::node)
    }

    /// Gets or inserts an expression node and reports the admission outcome.
    ///
    /// The expression key is built before the shared table lock is acquired;
    /// the key lookup and possible insertion then happen as one serialized
    /// admission step.
    ///
    /// # Errors
    ///
    /// Returns [`SharedDemandGraphError::LockPoisoned`] if another caller
    /// panicked while holding the graph lock. Returns cache-key construction or
    /// graph allocation failures through [`SharedDemandGraphError::Graph`].
    pub fn get_or_insert_expression_node_with_status<I>(
        &self,
        identity: CacheExprIdentity,
        free_var_value_hashes: I,
        value_hash: Option<ValueHash>,
    ) -> Result<DemandNodeAdmission, SharedDemandGraphError>
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let key = DemandCacheKey::for_free_vars(identity, free_var_value_hashes)
            .map_err(|source| DemandGraphError::CacheKey { source })?;
        self.get_or_insert_node_with_status(key, value_hash)
    }

    fn lock(&self) -> Result<MutexGuard<'_, DemandGraph>, SharedDemandGraphError> {
        self.inner
            .lock()
            .map_err(|_| SharedDemandGraphError::LockPoisoned)
    }
}

impl Default for SharedDemandGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared demand-graph admission failed.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SharedDemandGraphError {
    /// The shared graph mutex was poisoned by a prior panic.
    #[error("shared demand graph lock was poisoned")]
    LockPoisoned,
    /// The underlying demand graph rejected the operation.
    #[error("shared demand graph operation failed: {source}")]
    Graph {
        /// The demand-graph failure.
        source: DemandGraphError,
    },
}

impl From<DemandGraphError> for SharedDemandGraphError {
    fn from(source: DemandGraphError) -> Self {
        Self::Graph { source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cache::{CacheExprSourceHash, DurableBlake3Hash},
        compile::IrId,
    };
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn expr_source_hash(bytes: &[u8]) -> CacheExprSourceHash {
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn identity(source: &[u8], node: u32) -> CacheExprIdentity {
        CacheExprIdentity::new(expr_source_hash(source), IrId::new(node))
    }

    fn key(node: u32, label: &[u8]) -> DemandCacheKey {
        DemandCacheKey::for_free_vars(identity(label, node), [value_hash(label)])
            .expect("key builds")
    }

    #[test]
    fn shared_demand_graph_single_flights_concurrent_same_key_misses() {
        let graph = SharedDemandGraph::new();
        let key = key(7, b"same-key");
        let worker_count = 8;
        let barrier = Arc::new(Barrier::new(worker_count));
        let mut handles = Vec::new();

        for worker in 0..worker_count {
            let graph = graph.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let label = format!("value-{worker}");
                let admission = graph
                    .get_or_insert_node_with_status(key, Some(value_hash(label.as_bytes())))
                    .expect("node admission succeeds");
                (worker, admission)
            }));
        }

        let mut admissions = Vec::new();
        for handle in handles {
            admissions.push(handle.join().expect("worker joins"));
        }

        let first_node = admissions[0].1.node();
        assert!(
            admissions
                .iter()
                .all(|(_, admission)| admission.node() == first_node)
        );
        let inserted: Vec<_> = admissions
            .iter()
            .filter(|(_, admission)| admission.was_inserted())
            .collect();
        assert_eq!(inserted.len(), 1);
        assert_eq!(graph.len().expect("graph length reads"), 1);

        let inserted_worker = inserted[0].0;
        let inserted_label = format!("value-{inserted_worker}");
        assert_eq!(
            graph.node(first_node).expect("node reads").value_hash(),
            Some(value_hash(inserted_label.as_bytes()))
        );
    }

    #[test]
    fn shared_demand_graph_existing_node_keeps_original_value_hash() {
        let graph = SharedDemandGraph::new();
        let key = key(7, b"same-key");

        let first = graph
            .get_or_insert_node_with_status(key, Some(value_hash(b"first")))
            .expect("first node inserts");
        let second = graph
            .get_or_insert_node_with_status(key, Some(value_hash(b"second")))
            .expect("second node reuses");

        assert!(first.was_inserted());
        assert!(!second.was_inserted());
        assert_eq!(first.node(), second.node());
        assert_eq!(
            graph.node(first.node()).expect("node reads").value_hash(),
            Some(value_hash(b"first"))
        );
    }

    #[test]
    fn shared_demand_graph_reports_poisoned_node_table_lock() {
        let graph = SharedDemandGraph::new();
        let poisoner = graph.clone();

        let poison = thread::spawn(move || {
            let _guard = poisoner.inner.lock().expect("test lock is available");
            panic!("poison shared demand graph");
        });
        assert!(poison.join().is_err());

        let error = graph
            .get_or_insert_node(key(7, b"same-key"), Some(value_hash(b"value")))
            .expect_err("poison is reported");

        assert_eq!(error, SharedDemandGraphError::LockPoisoned);
    }
}
