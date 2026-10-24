//! Observes actual opaque Core owners without creating origin or runtime rights.
//!
//! Tokens have no creator field. The owning Cnp caller authenticates its original
//! PID/thread before and after borrowing retained owners. Data observation needs
//! no old Child or kernel-currentness check. Actual source/runtime currentness
//! remains an independent permission-boundary requirement. No pointer is
//! dereferenced, serialized or accepted as authority.

use super::*;
use crate::node_contract::{
    NodeRuntime, OperationAdmission, OperationToken, PreparedWorldPublication, ReadyAttestation,
    ValidatedNodePreparation, WorldActivation,
};
use crate::node_scheduling::{InputCustodyCommit, RuntimeInputBatch};
use std::{
    mem::{align_of, size_of},
    rc::Rc,
};

const SHARED_ROOTS: usize = 12;

/// Describes one actual shared allocation, excluding any nested shared roots.
#[derive(Clone, Copy)]
pub struct RetainedCoreSharedAllocation {
    identity: *const (),
    requested_bytes: usize,
}

impl RetainedCoreSharedAllocation {
    /// Returns the actual live allocation's data address for local deduplication.
    pub fn identity(&self) -> *const () {
        self.identity
    }

    /// Returns its requested root/header and independently owned nested heaps.
    pub fn requested_bytes(&self) -> usize {
        self.requested_bytes
    }
}

/// Separates independent clone heaps from actual shared Core allocation roots.
///
/// The enclosing owner's inline slot is excluded. These facts are not a source,
/// currentness, token, readiness or native allocation permit. The returned
/// lifetime retains the original borrowed owner while its descriptors are used;
/// raw identities must not be cached across a released owner or capture cut.
pub struct RetainedCoreOwnerStorage<'a> {
    independent: usize,
    shared: [Option<RetainedCoreSharedAllocation>; SHARED_ROOTS],
    used: usize,
    maximum: usize,
    retained: std::marker::PhantomData<&'a ()>,
}

impl RetainedCoreOwnerStorage<'_> {
    fn new(maximum: usize) -> Self {
        Self {
            independent: 0,
            shared: [None; SHARED_ROOTS],
            used: 0,
            maximum,
            retained: std::marker::PhantomData,
        }
    }

    /// Returns independently owned heap capacities, excluding enclosing inline layout.
    pub fn independent_bytes(&self) -> usize {
        self.independent
    }

    /// Borrows actual shared roots; equal data in different allocations stays distinct.
    pub fn shared_allocations(&self) -> impl Iterator<Item = &RetainedCoreSharedAllocation> {
        self.shared[..self.used].iter().flatten()
    }

    fn independent(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.independent = storage::add(self.independent, bytes)?;
        self.admit()
    }

    fn allocation(
        &mut self,
        identity: *const (),
        data: usize,
        alignment: usize,
    ) -> Result<(), RuntimeError> {
        let header =
            NodeRuntime::capture_protocol_shared_header_storage(1, alignment, self.maximum)?;
        let requested_bytes = storage::add(data, header)?;
        if let Some(previous) = self
            .shared_allocations()
            .find(|entry| entry.identity == identity)
        {
            return if previous.requested_bytes == requested_bytes {
                Ok(())
            } else {
                Err(RuntimeError::ForeignAuthority)
            };
        }
        if identity.is_null() || self.used == SHARED_ROOTS {
            return Err(RuntimeError::ResourceLimit);
        }
        self.shared[self.used] = Some(RetainedCoreSharedAllocation {
            identity,
            requested_bytes,
        });
        self.used += 1;
        self.admit()
    }

    fn admit(&self) -> Result<(), RuntimeError> {
        let total = self
            .shared_allocations()
            .try_fold(self.independent, |total, allocation| {
                storage::add(total, allocation.requested_bytes)
            })?;
        if total > self.maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    fn activation_backings(&mut self, value: &WorldActivation) -> Result<(), RuntimeError> {
        let WorldActivation {
            authority,
            record: _,
            nodes,
            preparation,
        } = value;
        self.allocation(
            Rc::as_ptr(authority).cast(),
            size_of::<()>(),
            align_of::<()>(),
        )?;
        self.preparations(nodes)?;
        if let Some(publication) = preparation {
            let PreparedWorldPublication {
                nodes,
                owners,
                coordinator,
            } = publication.as_ref();
            let payload = storage::add(
                size_of::<PreparedWorldPublication>(),
                storage::add(owners.owned_storage()?, coordinator.owned_storage()?)?,
            )?;
            self.allocation(
                Rc::as_ptr(publication).cast(),
                payload,
                align_of::<PreparedWorldPublication>(),
            )?;
            self.preparations(nodes)?;
        }
        Ok(())
    }

    fn preparations(
        &mut self,
        values: &Rc<[ValidatedNodePreparation]>,
    ) -> Result<(), RuntimeError> {
        let mut payload = values
            .len()
            .checked_mul(size_of::<ValidatedNodePreparation>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for value in values.iter() {
            payload = storage::add(payload, value.owned_storage()?)?;
        }
        self.allocation(
            Rc::as_ptr(values).cast(),
            payload,
            align_of::<ValidatedNodePreparation>(),
        )
    }

    fn token(&mut self, value: &OperationToken) -> Result<(), RuntimeError> {
        let OperationToken {
            authority,
            operation,
            route,
        } = value;
        self.independent(storage::add(
            operation.owned_storage()?,
            route.owned_storage()?,
        )?)?;
        self.allocation(
            Rc::as_ptr(authority).cast(),
            size_of::<()>(),
            align_of::<()>(),
        )
    }

    fn input_backing(&mut self, value: &Rc<RuntimeInputBatch>) -> Result<(), RuntimeError> {
        let payload = storage::add(
            size_of::<RuntimeInputBatch>(),
            NodeRuntime::capture_lineage_batch_storage(value)?,
        )?;
        self.allocation(
            Rc::as_ptr(value).cast(),
            payload,
            align_of::<RuntimeInputBatch>(),
        )?;
        self.activation_backings(&value.activation)
    }
}

impl OwnedStorage for ReadyAttestation {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            owners,
            boundary: _,
            state_inventory,
            ready_receipt,
        } = self;
        storage::add(
            owners.owned_storage()?,
            storage::add(
                state_inventory.owned_storage()?,
                ready_receipt.owned_storage()?,
            )?,
        )
    }
}

impl OwnedStorage for crucible_node_format::PreparedOwner {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            owner_id,
            incarnation_id,
            owner_generation: _,
            binding_hashes,
            prepared_token,
            ready_receipt,
            extensions,
        } = self;
        [
            owner_id.owned_storage()?,
            incarnation_id.owned_storage()?,
            binding_hashes.owned_storage()?,
            prepared_token.owned_storage()?,
            ready_receipt.owned_storage()?,
            extensions.owned_storage()?,
        ]
        .into_iter()
        .try_fold(0, storage::add)
    }
}

impl OwnedStorage for ValidatedNodePreparation {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            node,
            readiness,
            prepared_owners,
        } = self;
        storage::add(
            node.owned_storage()?,
            storage::add(readiness.owned_storage()?, prepared_owners.owned_storage()?)?,
        )
    }
}

impl OperationToken {
    /// Observes actual independent token clones and its shared original authority.
    ///
    /// # Errors
    /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.token(self)?;
        Ok(facts)
    }
}

impl PreparedWorldPublication {
    /// Observes independent coordinator/owner clones and the same shared preparations.
    ///
    /// The enclosing inline slot is excluded. This read-only layout observation
    /// does not authenticate durability or grant activation permission.
    ///
    /// # Errors
    /// Refuses unsupported fields, checked overflow or the supplied maximum.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let Self {
            nodes,
            owners,
            coordinator,
        } = self;
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.independent(storage::add(
            owners.owned_storage()?,
            coordinator.owned_storage()?,
        )?)?;
        facts.preparations(nodes)?;
        Ok(facts)
    }
}

impl WorldActivation {
    /// Observes actual record clones and separate original shared activation roots.
    ///
    /// # Errors
    /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.independent(self.record.owned_storage()?)?;
        facts.activation_backings(self)?;
        Ok(facts)
    }
}

impl OperationAdmission {
    /// Observes the same admission without cloning a token, activation or input cut.
    ///
    /// The existing closed exact-request walker refuses other operation families.
    ///
    /// # Errors
    /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.token(&self.token)?;
        facts.independent(self.request.owned_storage()?)?;
        facts.independent(self.activation.record.owned_storage()?)?;
        facts.activation_backings(&self.activation)?;
        if let Some(inputs) = &self.inputs {
            facts.input_backing(inputs)?;
        }
        Ok(facts)
    }
}

impl NodeRuntime {
    /// Observes the exact same full batch descriptor used by an admission.
    ///
    /// The enclosing Rc handle is excluded. Its original batch root/header and
    /// independent heaps share one descriptor; nested activation roots remain
    /// separate and therefore deduplicate identically across borrowed views.
    ///
    /// # Errors
    /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
    pub(crate) fn capture_input_batch_rc_storage_data(
        value: &Rc<RuntimeInputBatch>,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.input_backing(value)?;
        Ok(facts)
    }

    /// Observes distinct lineage-data and original-batch allocation roots.
    ///
    /// The enclosing lineage handle is excluded. The batch descriptor matches
    /// admission inputs, including its actual shared activation backing roots.
    ///
    /// # Errors
    /// Refuses unsupported shapes, overflow or the requested storage maximum.
    pub(crate) fn capture_original_lineage_storage_data(
        value: &crate::node_contract::OriginalInputLineage,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let parts = value.retained_storage_parts(maximum)?;
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.allocation(parts.identity, parts.payload_bytes, parts.alignment)?;
        facts.input_backing(parts.original)?;
        Ok(facts)
    }
}

impl RuntimeInputBatch {
    /// Observes independent batch buffers, excluding its enclosing slot or Rc header.
    ///
    /// # Errors
    /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.independent(NodeRuntime::capture_lineage_batch_storage(self)?)?;
        facts.activation_backings(&self.activation)?;
        Ok(facts)
    }
}

impl InputCustodyCommit {
    /// Observes original commit clones and separate shared activation backings.
    ///
    /// # Errors
    /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<RetainedCoreOwnerStorage<'_>, RuntimeError> {
        let Self {
            activation,
            node,
            stage_operation,
            batch,
            inventory,
            cutoff: _,
        } = self;
        let mut facts = RetainedCoreOwnerStorage::new(maximum);
        facts.independent(
            [
                activation.record.owned_storage()?,
                node.owned_storage()?,
                stage_operation.owned_storage()?,
                batch.owned_storage()?,
                inventory.owned_storage()?,
            ]
            .into_iter()
            .try_fold(0, storage::add)?,
        )?;
        facts.activation_backings(activation)?;
        Ok(facts)
    }
}

macro_rules! plain {
    ($method:ident, $ty:ty) => {
        impl NodeRuntime {
            /// Counts independent nested heaps under the existing closed data grammar.
            ///
            /// # Errors
            /// Refuses unsupported shapes, arithmetic overflow or the requested bound.
            pub(crate) fn $method(value: &$ty, maximum: usize) -> Result<usize, RuntimeError> {
                let bytes = value.owned_storage()?;
                if bytes > maximum {
                    return Err(RuntimeError::ResourceLimit);
                }
                Ok(bytes)
            }
        }
    };
}

impl OwnedStorage for crate::node_contract::NativeReclamationReceipt {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self { owner, receipt } = self;
        storage::add(owner.owned_storage()?, receipt.owned_storage()?)
    }
}

plain!(
    capture_activation_storage_data,
    crate::node_contract::ActivationRecord
);
plain!(capture_route_storage_data, crate::node_contract::NodeRoute);
plain!(capture_ready_storage_data, ReadyAttestation);
plain!(
    capture_prepared_owner_storage_data,
    crucible_node_format::PreparedOwner
);
plain!(
    capture_outcome_storage_data,
    crate::node_contract::OperationOutcome
);
plain!(
    capture_failure_storage_data,
    crate::node_contract::OperationFailure
);
plain!(
    capture_input_ack_storage_data,
    crate::node_scheduling::NativeInputAcknowledgement
);
plain!(
    capture_scheduling_observation_storage_data,
    crate::node_scheduling::NativeSchedulingObservation
);
plain!(
    capture_reclamation_storage_data,
    crate::node_contract::NativeReclamationReceipt
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::runtime::tests::capture_ticket_fixture;
    use crucible_node_format::Id;

    fn total(facts: &RetainedCoreOwnerStorage<'_>) -> usize {
        facts.independent_bytes()
            + facts
                .shared_allocations()
                .map(|row| row.requested_bytes())
                .sum::<usize>()
    }

    #[test]
    fn original_admission_clone_preserves_shared_ids_but_counts_independent_spare_strings()
    -> Result<(), RuntimeError> {
        let (runtime, _) = capture_ticket_fixture();
        let mut original = runtime
            .operations
            .values()
            .next()
            .ok_or(RuntimeError::InvalidReceipt)?
            .admission
            .clone();
        let mut name = String::with_capacity(65536);
        name.push_str(original.token.operation.as_str());
        original.token.operation = Id::new(name).map_err(|_| RuntimeError::InvalidReceipt)?;
        let cloned = original.clone();
        let first = original.retained_requested_storage_data(32 * 1024 * 1024)?;
        let second = cloned.retained_requested_storage_data(32 * 1024 * 1024)?;
        let first_ids: Vec<_> = first
            .shared_allocations()
            .map(|row| (row.identity(), row.requested_bytes()))
            .collect();
        let second_ids: Vec<_> = second
            .shared_allocations()
            .map(|row| (row.identity(), row.requested_bytes()))
            .collect();
        assert_eq!(first_ids, second_ids);
        assert_eq!(
            first.independent_bytes() - second.independent_bytes(),
            original.token.operation.allocated_capacity()
                - cloned.token.operation.allocated_capacity()
        );
        assert!(
            original
                .retained_requested_storage_data(total(&first) - 1)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn actual_input_rc_backing_is_reported_once_with_original_payload_spare_capacity()
    -> Result<(), RuntimeError> {
        let (runtime, _) = capture_ticket_fixture();
        let mut admission = runtime
            .operations
            .values()
            .next()
            .ok_or(RuntimeError::InvalidReceipt)?
            .admission
            .clone();
        let mut bytes = Vec::with_capacity(65536);
        bytes.push(7);
        let reference =
            crucible_node_format::canonical::content_ref(&bytes, "application/octet-stream")
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        let id = Id::new("model-input").map_err(|_| RuntimeError::InvalidReceipt)?;
        let batch = Rc::new(RuntimeInputBatch {
            activation: admission.activation.clone(),
            node: id.clone(),
            stage_operation: id.clone(),
            batch: id,
            owners: admission.activation.record.owners.clone(),
            cutoff: admission.activation.record.boundary,
            inventory: reference.clone(),
            deliveries: Vec::new(),
            payloads: vec![InputPayload { reference, bytes }],
        });
        admission.inputs = Some(Rc::clone(&batch));
        let facts = admission.retained_requested_storage_data(32 * 1024 * 1024)?;
        let direct = NodeRuntime::capture_input_batch_rc_storage_data(&batch, 32 * 1024 * 1024)?;
        let identity = Rc::as_ptr(&batch).cast();
        let direct_rows: Vec<_> = direct
            .shared_allocations()
            .map(|row| (row.identity(), row.requested_bytes()))
            .collect();
        let admission_rows: Vec<_> = facts
            .shared_allocations()
            .filter(|row| direct_rows.iter().any(|direct| direct.0 == row.identity()))
            .map(|row| (row.identity(), row.requested_bytes()))
            .collect();
        for row in &direct_rows {
            assert!(admission_rows.contains(row));
        }
        let rows: Vec<_> = facts
            .shared_allocations()
            .filter(|row| row.identity() == identity)
            .collect();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].requested_bytes()
                >= batch.payloads[0].bytes.capacity() + size_of::<RuntimeInputBatch>()
        );
        Ok(())
    }
}

impl NodeRuntime {
    /// Observes independent preparation backing without serializing readiness.
    ///
    /// The enclosing inline slot is excluded; this creates no native permission.
    ///
    /// # Errors
    /// Refuses unsupported fields, checked overflow or the supplied bound.
    pub fn original_prepared_node_requested_storage_data(
        value: &ValidatedNodePreparation,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Observes an actual outcome's independent retained fields without callbacks.
    ///
    /// # Errors
    /// Refuses unsupported fields, checked overflow or the supplied bound.
    pub fn original_outcome_requested_storage_data(
        value: &crate::node_contract::OperationOutcome,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    /// Observes actual retained descriptor backing without serialization or callbacks.
    ///
    /// The enclosing inline slot is excluded. No source or native right is issued.
    ///
    /// # Errors
    /// Refuses unsupported fields, overflow or requested storage above the bound.
    pub fn original_descriptor_requested_storage_data(
        value: &crucible_node_format::NodeDescriptor,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    /// Observes actual retained binding backing without serialization or callbacks.
    ///
    /// The enclosing inline slot is excluded. No source or native right is issued.
    ///
    /// # Errors
    /// Refuses unsupported fields, overflow or requested storage above the bound.
    pub fn original_binding_requested_storage_data(
        value: &crucible_node_format::BindingCompatibility,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    /// Observes actual retained owner binding backing without serialization or callbacks.
    ///
    /// The enclosing inline slot is excluded. No source or native right is issued.
    ///
    /// # Errors
    /// Refuses unsupported fields, overflow or requested storage above the bound.
    pub fn original_owner_binding_requested_storage_data(
        value: &crucible_node_format::OwnerBinding,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    /// Observes actual native input acknowledgement backing without execution.
    ///
    /// # Errors
    /// Refuses unsupported fields, overflow or the supplied bound.
    pub fn original_input_ack_requested_storage_data(
        value: &crate::node_scheduling::NativeInputAcknowledgement,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    /// Quotes the concrete fixed opaque-owner observation bank and descriptor.
    ///
    /// This includes the twelve original shared slots before deduplication. It
    /// does not certify compiler/recursive frames or physical allocator peaks.
    pub fn capture_opaque_owner_observer_scratch_data() -> usize {
        size_of::<RetainedCoreOwnerStorage<'_>>() + size_of::<RetainedCoreSharedAllocation>()
    }
}

impl NodeRuntime {
    /// Observes a retained snapshot's real capacities without creating another snapshot.
    ///
    /// # Errors
    /// Refuses unsupported input families, checked overflow or the requested bound.
    pub fn original_snapshot_requested_storage_data(
        value: &crate::node_contract::RuntimeSnapshot,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }
}

impl NodeRuntime {
    /// Observes actual retained JSON capacities without serializing another copy.
    ///
    /// The enclosing Value slot is excluded. This pure owner walk grants no
    /// Source, native, publication or allocation permission.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or requested storage above the supplied bound.
    pub fn original_json_value_requested_storage_data(
        value: &serde_json::Value,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let bytes = value.owned_storage()?;
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Names fixed raw JSON owner and child-cursor observation views.
    pub fn original_json_value_counter_scratch_data() -> usize {
        size_of::<&serde_json::Value>()
            + size_of::<&String>()
            + size_of::<(&String, &serde_json::Value)>()
            + size_of::<std::slice::Iter<'static, serde_json::Value>>()
            + size_of::<serde_json::map::Iter<'static>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, serde_json::Value>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + 3 * size_of::<usize>()
    }
}
