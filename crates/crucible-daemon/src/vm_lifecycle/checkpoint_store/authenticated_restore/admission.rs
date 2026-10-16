//! Admits concrete reconstructed container storage before its allocation.

use super::*;

pub(super) fn admit_shared<T>() -> Result<(), LifecycleApiError> {
    // The pinned Arc allocation is the two-count prefix followed by aligned T.
    // The opaque original owner remains outside that control through its free.
    let (layout, _) = std::alloc::Layout::new::<[usize; 2]>()
        .extend(std::alloc::Layout::new::<T>())
        .map_err(|_| loop_factory_error("checkpoint shared control layout overflow"))?;
    let bytes = u64::try_from(layout.pad_to_align().size())
        .map_err(|_| loop_factory_error("checkpoint shared control size overflow"))?;
    crucible::owned_decode::charge_bytes(bytes)
        .map_err(|_| loop_factory_error("original shared checkpoint allocation refused"))
}

pub(super) fn admit_array<T>(count: usize) -> Result<(), LifecycleApiError> {
    crucible::owned_decode::charge_array::<T>(count)
        .map_err(|_| loop_factory_error("original checkpoint array allocation refused"))
}

pub(super) fn admit_entry<K, V>() -> Result<(), LifecycleApiError> {
    crucible::owned_decode::charge_btree_entry::<K, V>()
        .map_err(|_| loop_factory_error("original checkpoint map allocation refused"))
}

pub(super) fn copy_node(node: &str) -> Result<NodeId, LifecycleApiError> {
    admit_array::<u8>(node.len())?;
    let mut name = String::new();
    name.try_reserve_exact(node.len())
        .map_err(|_| loop_factory_error("allocate authenticated checkpoint node"))?;
    name.push_str(node);
    Ok(NodeId { name })
}

pub(in crate::vm_lifecycle::checkpoint_store) fn node_set<'a>(
    nodes: impl Iterator<Item = &'a NodeId>,
) -> Result<BTreeSet<NodeId>, LifecycleApiError> {
    let mut set = BTreeSet::new();
    for node in nodes {
        let node = copy_node(&node.name)?;
        admit_entry::<NodeId, ()>()?;
        set.insert(node);
    }
    Ok(set)
}

/// Pays each temporary DAG read against the actual retained source extent.
///
/// The backing MemoryDagStore remains unchanged, including its deliberate
/// simultaneous copies. No object size is guessed from an encoded envelope.
pub(super) struct SemanticDagReads<'a> {
    pub(super) store: &'a MemoryDagStore,
    pub(super) events: &'a BTreeMap<ContentHash, Vec<u8>>,
    pub(super) signals: &'a BTreeMap<ContentHash, Vec<u8>>,
}

impl DagStore for SemanticDagReads<'_> {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, crucible::DagStoreError> {
        crucible::owned_decode::charge_array::<u8>(bytes.len())
            .and_then(|()| crucible::owned_decode::charge_btree_entry::<ContentHash, Vec<u8>>())
            .map_err(|_| crucible::DagStoreError::StorePoisoned {
                operation: "original checkpoint DAG admission",
            })?;
        self.store.put(bytes)
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, crucible::DagStoreError> {
        if let Some(bytes) = self.events.get(key).or_else(|| self.signals.get(key)) {
            crucible::owned_decode::charge_array::<u8>(bytes.len()).map_err(|_| {
                crucible::DagStoreError::StorePoisoned {
                    operation: "original checkpoint DAG read admission",
                }
            })?;
        }
        self.store.get(key)
    }

    fn exists(&self, key: &ContentHash) -> Result<bool, crucible::DagStoreError> {
        self.store.exists(key)
    }

    fn delete(&self, key: &ContentHash) -> Result<bool, crucible::DagStoreError> {
        self.store.delete(key)
    }
}

/// Reconciles a typed child-account refusal before the legacy API diagnostic.
pub(super) fn model_failure(error: crucible::EngineError) -> LifecycleApiError {
    if let crucible::EngineError::ArtifactDecodeAdmission { source } = &error
        && let Some(original) = crucible::owned_decode::current_budget()
    {
        original.record_failure(source.clone());
    }
    loop_factory_error(error.to_string())
}
