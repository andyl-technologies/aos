//! Counts actual Host17 backing independently of the portable record's policy.
//!
//! Each field is destructured exhaustively so an added owning field cannot
//! silently escape this census. Existing Runtime7/Scheduling1 visitors count
//! pending deliveries, payloads, completed inputs and connection histories.

use super::*;
use crate::node_contract::NodeRuntime;
use crate::node_contract::runtime_owned_counter::OwnedStorage;

impl OwnedStorage for RestoredHostSemanticAncestor {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self { node, object } = self;
        add(node.owned_storage()?, object.owned_storage()?)
    }
}

impl OwnedStorage for RestoredHostAncestry17 {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            parent_archive_index,
            first_host,
            first_semantic,
        } = self;
        let mut bytes = add(
            parent_archive_index.owned_storage()?,
            first_host.owned_storage()?,
        )?;
        for semantic in first_semantic {
            bytes = add(bytes, semantic.owned_storage()?)?;
        }
        Ok(bytes)
    }
}

impl OwnedStorage for HostSchedulingRestoredContinuationRecord17 {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            schema_version,
            source,
            runtime,
            scheduling,
            objects,
            ancestry,
            admission_policy,
        } = self;
        require_copy(schema_version);
        let RestoredHostAdmissionPolicy17 {
            maximum_nodes,
            maximum_owners,
            maximum_operations,
            maximum_retained_outputs,
        } = admission_policy;
        require_copy(maximum_nodes);
        require_copy(maximum_owners);
        require_copy(maximum_operations);
        require_copy(maximum_retained_outputs);
        [
            source.owned_storage()?,
            runtime.owned_storage()?,
            scheduling.owned_storage()?,
            objects.owned_storage()?,
            ancestry.owned_storage()?,
        ]
        .into_iter()
        .try_fold(0usize, add)
    }
}

impl NodeRuntime {
    /// Counts actual nested Host17 heaps while its containing owner prices root.
    pub(crate) fn capture_restored_host_record_storage_data(
        record: &HostSchedulingRestoredContinuationRecord17,
    ) -> Result<usize, RuntimeError> {
        record.owned_storage()
    }
}

fn add(left: usize, right: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right).ok_or(RuntimeError::ResourceLimit)
}

fn require_copy<T: Copy>(_: &T) {}
