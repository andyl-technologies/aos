//! Counts actual runtime-owned allocations without allocating another inventory.
//!
//! Shared addresses are temporary observations under the original immutable loan.
//! Equal labels or content never alias storage. The fixed identity bank is a
//! separately named traversal scratch term, not an allocation permission.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, align_of_val, size_of, size_of_val},
    rc::Rc,
};

pub(crate) use crate::node_contract::runtime::RuntimeOwnedStorage as OwnedStorage;

use crate::node_contract::{NodeRuntime, RuntimeError};

const SHARED_ROOTS: usize = 512;

#[derive(Clone, Copy)]
struct Shared {
    identity: *const (),
    bytes: usize,
}

/// Retains no references or authority after its synchronous owning walk ends.
pub(crate) struct RetainedRuntimeCounter {
    bytes: usize,
    maximum: usize,
    shared: [Option<Shared>; SHARED_ROOTS],
    used: usize,
}

impl RetainedRuntimeCounter {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            bytes: 0,
            maximum,
            shared: [None; SHARED_ROOTS],
            used: 0,
        }
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn maximum(&self) -> usize {
        self.maximum
    }

    pub(crate) fn remaining(&self) -> usize {
        self.maximum - self.bytes
    }

    pub(crate) fn add(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    /// Adds a complete shared descriptor, including its independent child heaps.
    pub(crate) fn shared(
        &mut self,
        identity: *const (),
        bytes: usize,
    ) -> Result<bool, RuntimeError> {
        if identity.is_null() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if let Some(previous) = self.shared[..self.used]
            .iter()
            .flatten()
            .find(|entry| entry.identity == identity)
        {
            return if previous.bytes == bytes {
                Ok(false)
            } else {
                Err(RuntimeError::ForeignAuthority)
            };
        }
        if self.used == SHARED_ROOTS {
            return Err(RuntimeError::ResourceLimit);
        }
        self.add(bytes)?;
        self.shared[self.used] = Some(Shared { identity, bytes });
        self.used += 1;
        Ok(true)
    }

    /// Adds a shared root whose child allocations will be visited separately.
    pub(crate) fn rc<T: ?Sized>(&mut self, value: &Rc<T>) -> Result<bool, RuntimeError> {
        let header = NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of_val(value.as_ref()),
            self.maximum,
        )?;
        let bytes = size_of_val(value.as_ref())
            .checked_add(header)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.shared(Rc::as_ptr(value).cast(), bytes)
    }

    pub(crate) fn rc_payload<T: ?Sized>(
        &mut self,
        value: &Rc<T>,
        payload: usize,
    ) -> Result<bool, RuntimeError> {
        if payload < size_of_val(value.as_ref()) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let header = NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of_val(value.as_ref()),
            self.maximum,
        )?;
        self.shared(
            Rc::as_ptr(value).cast(),
            payload
                .checked_add(header)
                .ok_or(RuntimeError::ResourceLimit)?,
        )
    }

    pub(crate) fn activation(
        &mut self,
        value: &crate::node_contract::WorldActivation,
    ) -> Result<(), RuntimeError> {
        let facts = value.retained_requested_storage_data(self.maximum)?;
        self.views(
            facts.independent_bytes(),
            facts
                .shared_allocations()
                .map(|row| (row.identity(), row.requested_bytes())),
        )
    }

    pub(crate) fn preparations(
        &mut self,
        value: &Rc<[crate::node_contract::ValidatedNodePreparation]>,
    ) -> Result<(), RuntimeError> {
        let payload = value
            .len()
            .checked_mul(size_of::<crate::node_contract::ValidatedNodePreparation>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let payload = value.iter().try_fold(payload, |total, entry| {
            total
                .checked_add(entry.owned_storage()?)
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        self.rc_payload(value, payload)?;
        Ok(())
    }

    pub(crate) fn publication(
        &mut self,
        value: &Rc<crate::node_contract::PreparedWorldPublication>,
    ) -> Result<(), RuntimeError> {
        let crate::node_contract::PreparedWorldPublication {
            nodes,
            owners,
            coordinator,
        } = value.as_ref();
        let owners = owners.owned_storage()?;
        let coordinator = coordinator.owned_storage()?;
        let payload = size_of_val(value.as_ref())
            .checked_add(owners)
            .and_then(|bytes| bytes.checked_add(coordinator))
            .ok_or(RuntimeError::ResourceLimit)?;
        self.rc_payload(value, payload)?;
        self.preparations(nodes)
    }

    pub(crate) fn connection(
        &mut self,
        value: &crucible_node_format::ConnectionDescriptor,
    ) -> Result<(), RuntimeError> {
        let crucible_node_format::ConnectionDescriptor {
            schema_version: _,
            id,
            producer,
            consumer,
            interface_id,
            features,
            payload_schema,
            minimum_latency_ps: _,
            policy_ref,
            capture_owner_id,
            extensions,
        } = value;
        self.owned(id)?;
        self.owned(producer)?;
        self.owned(consumer)?;
        self.owned(interface_id)?;
        self.owned(features)?;
        self.owned(payload_schema)?;
        self.owned(policy_ref)?;
        self.owned(capture_owner_id)?;
        self.owned(extensions)
    }

    pub(crate) fn connection_policy(
        &mut self,
        value: &crate::node_admission::ConnectionPolicy,
    ) -> Result<(), RuntimeError> {
        use crate::node_admission::VisibilityConversion;
        let crate::node_admission::ConnectionPolicy {
            schema_version: _,
            maximum_payload_bytes: _,
            maximum_pending_events: _,
            maximum_pending_bytes: _,
            visibility,
            delivery,
            causal_proof_ref,
            state_domain_ids,
        } = value;
        match visibility {
            VisibilityConversion::Direct => {}
            VisibilityConversion::PublicationPreserving { contract_ref }
            | VisibilityConversion::BoundarySampling { contract_ref }
            | VisibilityConversion::Adapter { contract_ref } => self.owned(contract_ref)?,
        }
        match delivery {
            crate::node_admission::ConnectionDelivery::Fixed { latency_ps: _ } => {}
        }
        self.owned(causal_proof_ref)?;
        self.owned(state_domain_ids)
    }

    pub(crate) fn world(
        &mut self,
        value: &crucible_node_format::WorldBinding,
    ) -> Result<(), RuntimeError> {
        let crucible_node_format::WorldBinding {
            schema_version: _,
            scenario_ref,
            node_bindings,
            connections,
            ownership_ref,
            coordinator_contract_ref,
            ordering_profile,
            initialization_ref,
            extensions,
        } = value;
        self.owned(scenario_ref)?;
        self.owned(node_bindings)?;
        self.slots(connections)?;
        for connection in connections {
            self.connection(connection)?;
        }
        self.owned(ownership_ref)?;
        self.owned(coordinator_contract_ref)?;
        self.owned(ordering_profile)?;
        self.owned(initialization_ref)?;
        self.owned(extensions)
    }

    pub(crate) fn views(
        &mut self,
        independent: usize,
        shared: impl Iterator<Item = (*const (), usize)>,
    ) -> Result<(), RuntimeError> {
        self.add(independent)?;
        for (identity, bytes) in shared {
            self.shared(identity, bytes)?;
        }
        Ok(())
    }

    pub(crate) fn map<K, V>(&mut self, value: &BTreeMap<K, V>) -> Result<(), RuntimeError> {
        let entry_bytes = size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or(RuntimeError::ResourceLimit)?;
        self.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            value.len(),
            entry_bytes,
            align_of::<K>().max(align_of::<V>()),
            self.remaining(),
        )?)
    }

    pub(crate) fn set<T>(&mut self, value: &BTreeSet<T>) -> Result<(), RuntimeError> {
        self.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            value.len(),
            size_of::<T>(),
            align_of::<T>(),
            self.remaining(),
        )?)
    }

    pub(crate) fn owned<T: OwnedStorage + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), RuntimeError> {
        self.add(value.owned_storage()?)
    }

    pub(crate) fn slots<T>(&mut self, value: &Vec<T>) -> Result<(), RuntimeError> {
        self.add(
            value
                .capacity()
                .checked_mul(size_of::<T>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_shared_identity_deduplicates_only_the_same_complete_width() -> Result<(), RuntimeError>
    {
        let original = Rc::new(7u8);
        let different = Rc::new(7u8);
        let mut counter = RetainedRuntimeCounter::new(1024);
        assert!(counter.rc(&original)?);
        let first = counter.bytes();
        assert!(!counter.rc(&Rc::clone(&original))?);
        assert_eq!(counter.bytes(), first);
        assert!(counter.rc(&different)?);
        assert_eq!(counter.bytes(), first * 2);
        assert_eq!(
            counter.shared(Rc::as_ptr(&original).cast(), first + 1),
            Err(RuntimeError::ForeignAuthority),
        );
        Ok(())
    }

    #[test]
    fn unused_vector_slots_and_requested_limit_are_not_logical_lengths() -> Result<(), RuntimeError>
    {
        let values = Vec::<u64>::with_capacity(37);
        let bytes = values.capacity() * size_of::<u64>();
        let mut exact = RetainedRuntimeCounter::new(bytes);
        exact.slots(&values)?;
        assert_eq!(exact.bytes(), bytes);
        assert_eq!(
            RetainedRuntimeCounter::new(bytes - 1).slots(&values),
            Err(RuntimeError::ResourceLimit),
        );
        assert_eq!(exact.add(usize::MAX), Err(RuntimeError::ResourceLimit),);
        Ok(())
    }
}
