//! Retains every partial scope/proof owner before final context issuance.
//!
//! These are construction owners, not proof authority. Only the same installed
//! window may use a completed scope after repeating all three real Source-fenced
//! native validators and the fourth actual Host2 validator. Failed constructors
//! preserve original archive/tickets and every retained draft bank.

use super::scope_storage::{
    OriginalRestorationScopeProofProjection, SCOPE_PROOF_FORMAT, SCOPE_PROOF_MEDIA,
};
use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;
use crate::node_contract::{
    OriginalLineageJournal, OriginalLineageNativeScope, OriginalLineageOwnerMapping,
    SavedOriginalInputScope, SavedRuntimeResult,
};

pub(super) struct OriginalRestorationScopeOwner {
    started: bool,
    owners: Vec<OriginalLineageOwnerMapping>,
    first_scopes: Vec<SavedOriginalInputScope>,
    journals: Vec<OriginalLineageJournal>,
    acknowledgements: Vec<crate::node_scheduling::NativeInputAcknowledgement>,
    proof_value: Option<serde_json::Value>,
    proof_bytes: Option<Vec<u8>>,
    proof_reference: Option<ContentRef>,
    completed: Option<OriginalLineageNativeScope>,
}

impl OriginalRestorationScopeOwner {
    pub(super) fn empty() -> Self {
        Self {
            started: false,
            owners: Vec::new(),
            first_scopes: Vec::new(),
            journals: Vec::new(),
            acknowledgements: Vec::new(),
            proof_value: None,
            proof_bytes: None,
            proof_reference: None,
            completed: None,
        }
    }

    pub(super) fn construct_fields(
        &mut self,
        archive: &CompleteOriginalRestorationSource,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        if self.started {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.started = true;
        let record = archive.original_runtime_record_data()?;
        if record.owners.len() != 4 || activation.owners.len() != 4 {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.owners
            .try_reserve_exact(record.owners.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for saved in &record.owners {
            let mut matched = None;
            for target in &activation.owners {
                if target.owner == saved.identity.owner {
                    if matched.replace(target).is_some() {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                }
            }
            let target = matched.ok_or(RuntimeError::ForeignAuthority)?;
            if target == &saved.identity
                || target.generation <= saved.identity.generation
                || target.incarnation == saved.identity.incarnation
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            self.owners.push(OriginalLineageOwnerMapping {
                source: saved.identity.clone(),
                target: target.clone(),
            });
        }
        let mut first_count = 0usize;
        for input in &record.inputs {
            if input.lineage.is_some() {
                first_count += 1;
            }
        }
        self.first_scopes
            .try_reserve_exact(first_count)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for input in &record.inputs {
            if let Some(lineage) = &input.lineage {
                self.first_scopes.push(lineage.source.clone());
            }
        }

        // Four source participants are already authenticated by the complete
        // archive. Build in canonical node order without an allocating sort.
        self.journals
            .try_reserve_exact(4)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for _ in 0..4 {
            let previous = self.journals.last().map(|last| &last.node);
            let mut next: Option<&Id> = None;
            for owner in archive.archive().owners() {
                let [node] = owner.participants.as_slice() else {
                    continue;
                };
                if previous.is_none_or(|last| last < node)
                    && next.is_none_or(|current| node < current)
                {
                    next = Some(node);
                }
            }
            let next = next.ok_or(RuntimeError::InvalidReceipt)?;
            self.journals.push(OriginalLineageJournal {
                node: next.clone(),
                operations: Vec::new(),
                pending_operations: Vec::new(),
                acknowledged_operations: Vec::new(),
                input_stages: Vec::new(),
            });
            let journal = self
                .journals
                .last_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let mut operation_count = 0usize;
            let mut pending_count = 0usize;
            let mut acknowledged_count = 0usize;
            for entry in &record.operations {
                if entry.route.node != journal.node {
                    continue;
                }
                operation_count += 1;
                match &entry.result {
                    SavedRuntimeResult::Pending => pending_count += 1,
                    SavedRuntimeResult::Acknowledged(_) => acknowledged_count += 1,
                    SavedRuntimeResult::Complete(_) | SavedRuntimeResult::Failed(_) => {}
                }
            }
            journal
                .operations
                .try_reserve_exact(operation_count)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            journal
                .pending_operations
                .try_reserve_exact(pending_count)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            journal
                .acknowledged_operations
                .try_reserve_exact(acknowledged_count)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            for entry in &record.operations {
                if entry.route.node != journal.node {
                    continue;
                }
                journal.operations.push(entry.operation.clone());
                match &entry.result {
                    SavedRuntimeResult::Pending => {
                        journal.pending_operations.push(entry.operation.clone())
                    }
                    SavedRuntimeResult::Acknowledged(_) => journal
                        .acknowledged_operations
                        .push(entry.operation.clone()),
                    SavedRuntimeResult::Complete(_) | SavedRuntimeResult::Failed(_) => {}
                }
            }
            let mut input_count = 0usize;
            for input in &record.inputs {
                if input.node == journal.node {
                    input_count += 1;
                }
            }
            journal
                .input_stages
                .try_reserve_exact(input_count)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            for input in &record.inputs {
                if input.node == journal.node {
                    journal.input_stages.push(input.stage_operation.clone());
                }
            }
        }
        Ok(())
    }

    pub(super) fn owner_mappings_data(&self) -> &[OriginalLineageOwnerMapping] {
        &self.owners
    }
    pub(super) fn journals_data(&self) -> &[OriginalLineageJournal] {
        &self.journals
    }

    // This materializes inert evidence only. The window repeats all native and
    // Host2 predicates before the private opaque context constructor accepts it.
    pub(super) fn construct_proof_and_scope(
        &mut self,
        archive: &CompleteOriginalRestorationSource,
        activation: &ActivationRecord,
        identities: [[u8; 32]; 3],
    ) -> Result<(), RuntimeError> {
        if !self.started
            || self.completed.is_some()
            || self.proof_value.is_some()
            || self.proof_bytes.is_some()
            || self.proof_reference.is_some()
            || !self.acknowledgements.is_empty()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let projection = OriginalRestorationScopeProofProjection {
            schema: SCOPE_PROOF_FORMAT,
            source_artifact: archive.archive().artifact(),
            source_runtime: archive.runtime_object(),
            target: activation,
            native_held_reference_identities: identities,
        };
        self.proof_value =
            Some(serde_json::to_value(&projection).map_err(|_| RuntimeError::InvalidReceipt)?);
        self.proof_bytes = Some(Vec::new());
        let value = self
            .proof_value
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let bytes = self
            .proof_bytes
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        crucible_node_format::canonical::canonical_json_to_writer(value, &mut *bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.proof_reference = Some(
            crucible_node_format::canonical::content_ref(bytes, SCOPE_PROOF_MEDIA)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let proof = self
            .proof_reference
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let record = archive.original_runtime_record_data()?;
        let mut acknowledgement_count = 0usize;
        for input in &record.inputs {
            if input.acknowledgement.is_some() {
                acknowledgement_count += 1;
            }
        }
        self.acknowledgements
            .try_reserve_exact(acknowledgement_count)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for input in &record.inputs {
            let Some(original) = &input.acknowledgement else {
                continue;
            };
            let mut owners = Vec::new();
            owners
                .try_reserve_exact(input.owners.len())
                .map_err(|_| RuntimeError::ResourceLimit)?;
            // Install the owning partial ACK before copying its target owner
            // vector, so a later malformed mapping cannot discard earlier data.
            self.acknowledgements
                .push(crate::node_scheduling::NativeInputAcknowledgement {
                    stage_operation: original.stage_operation.clone(),
                    batch: original.batch.clone(),
                    node: original.node.clone(),
                    owners,
                    cutoff: original.cutoff,
                    inventory: original.inventory.clone(),
                    proof_ref: proof.clone(),
                });
            let acknowledgement = self
                .acknowledgements
                .last_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            for saved in &input.owners {
                let mut matched = None;
                for mapping in &self.owners {
                    if &mapping.source == saved {
                        matched = Some(&mapping.target);
                        break;
                    }
                }
                acknowledgement
                    .owners
                    .push(matched.ok_or(RuntimeError::ForeignAuthority)?.clone());
            }
        }
        self.completed = Some(OriginalLineageNativeScope {
            coordinator_schema: 7,
            source_record: archive.runtime_object().clone(),
            source_capture: record.source_activation.clone(),
            target: activation.clone(),
            owners: std::mem::take(&mut self.owners),
            first_scopes: std::mem::take(&mut self.first_scopes),
            journals: std::mem::take(&mut self.journals),
            input_acknowledgements: std::mem::take(&mut self.acknowledgements),
            proof: self
                .proof_reference
                .take()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        });
        Ok(())
    }

    pub(super) fn scope_data(&self) -> Result<&OriginalLineageNativeScope, RuntimeError> {
        self.completed
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(super) fn proof_body_data(&self, reference: &ContentRef) -> Option<&[u8]> {
        let scope = self.completed.as_ref()?;
        (reference == &scope.proof).then_some(self.proof_bytes.as_ref()?.as_slice())
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            started: _,
            owners,
            first_scopes,
            journals,
            acknowledgements,
            proof_value,
            proof_bytes,
            proof_reference,
            completed,
        } = self;
        checked_sum(
            &[
                owners.owned_storage()?,
                first_scopes.owned_storage()?,
                journals.owned_storage()?,
                acknowledgements.owned_storage()?,
                proof_value.owned_storage()?,
                proof_bytes.owned_storage()?,
                proof_reference.owned_storage()?,
                completed.owned_storage()?,
            ],
            maximum,
        )
    }
}

impl OwnedStorage for OriginalLineageOwnerMapping {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self { source, target } = self;
        checked_sum(
            &[source.owned_storage()?, target.owned_storage()?],
            usize::MAX,
        )
    }
}

impl OwnedStorage for OriginalLineageJournal {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            node,
            operations,
            pending_operations,
            acknowledged_operations,
            input_stages,
        } = self;
        checked_sum(
            &[
                node.owned_storage()?,
                operations.owned_storage()?,
                pending_operations.owned_storage()?,
                acknowledged_operations.owned_storage()?,
                input_stages.owned_storage()?,
            ],
            usize::MAX,
        )
    }
}

impl OwnedStorage for OriginalLineageNativeScope {
    fn owned_storage(&self) -> Result<usize, RuntimeError> {
        let Self {
            coordinator_schema: _,
            source_record,
            source_capture,
            target,
            owners,
            first_scopes,
            journals,
            input_acknowledgements,
            proof,
        } = self;
        checked_sum(
            &[
                source_record.owned_storage()?,
                source_capture.owned_storage()?,
                target.owned_storage()?,
                owners.owned_storage()?,
                first_scopes.owned_storage()?,
                journals.owned_storage()?,
                input_acknowledgements.owned_storage()?,
                proof.owned_storage()?,
            ],
            usize::MAX,
        )
    }
}

impl OriginalRestorationScopeOwner {
    pub(super) fn proof_value_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&serde_json::Value, RuntimeError> {
        if &self.scope_data()?.proof != reference {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.proof_value
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Phase, Position, Tick, U64, canonical};

    // These are inert owning/serialization fixtures. They never construct a
    // Window, Source evidence, context, claim, readiness or live native owner.
    fn inert_scope(proof: ContentRef) -> OriginalLineageNativeScope {
        let target = ActivationRecord {
            generation: U64::new(2),
            activation_id: Id::new("scope-control/target").unwrap(),
            world_binding_hash: canonical::hash("scope.control.world.v1", b"world").unwrap(),
            owners: Vec::new(),
            boundary: Position::new(Tick::new(0), U64::new(0), Phase::BoundaryControl),
        };
        OriginalLineageNativeScope {
            coordinator_schema: 7,
            source_record: proof.clone(),
            source_capture: crate::node_contract::SavedRuntimeActivation::from(&target),
            target,
            owners: Vec::new(),
            first_scopes: Vec::new(),
            journals: Vec::new(),
            input_acknowledgements: Vec::new(),
            proof,
        }
    }

    #[test]
    fn raw_proof_banks_without_a_completed_owner_do_not_lend_scope_or_proof() {
        let mut owner = OriginalRestorationScopeOwner::empty();
        let bytes = b"{}".to_vec();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        owner.proof_bytes = Some(bytes);
        owner.proof_value = Some(serde_json::json!({}));
        owner.proof_reference = Some(reference.clone());

        assert!(matches!(
            owner.scope_data(),
            Err(RuntimeError::OwnerUnavailable)
        ));
        assert!(owner.proof_body_data(&reference).is_none());
        assert!(matches!(
            owner.proof_value_data(&reference),
            Err(RuntimeError::OwnerUnavailable)
        ));
    }

    #[test]
    fn a_foreign_full_reference_cannot_borrow_the_retained_proof() {
        let mut owner = OriginalRestorationScopeOwner::empty();
        let bytes = b"{}".to_vec();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        owner.proof_bytes = Some(bytes);
        owner.proof_value = Some(serde_json::json!({}));
        owner.completed = Some(inert_scope(reference.clone()));
        let mut foreign = reference.clone();
        foreign.media_type = "application/octet-stream".into();

        assert_eq!(owner.proof_body_data(&reference), Some(b"{}".as_slice()));
        assert!(owner.proof_body_data(&foreign).is_none());
        assert!(matches!(
            owner.proof_value_data(&foreign),
            Err(RuntimeError::ForeignAuthority)
        ));
    }

    #[test]
    fn selected_target_and_journal_drift_change_the_full_scope_projection() {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let mut scope = inert_scope(reference);
        let original = serde_json::to_value(
            super::super::coordinator_projection::ActualScopeProjection(&scope),
        )
        .unwrap();
        assert_eq!(original["target"].as_array().unwrap().len(), 5);
        assert_eq!(original.as_object().unwrap().len(), 9);

        scope.target.generation = U64::new(3);
        let changed_target = serde_json::to_value(
            super::super::coordinator_projection::ActualScopeProjection(&scope),
        )
        .unwrap();
        assert_ne!(original, changed_target);
        scope.journals.push(OriginalLineageJournal {
            node: Id::new("scope-control/node").unwrap(),
            operations: vec![Id::new("scope-control/operation").unwrap()],
            pending_operations: Vec::new(),
            acknowledged_operations: Vec::new(),
            input_stages: Vec::new(),
        });
        let changed_journal = serde_json::to_value(
            super::super::coordinator_projection::ActualScopeProjection(&scope),
        )
        .unwrap();
        assert_ne!(changed_target, changed_journal);
        assert_ne!(
            canonical::canonical_json(&original).unwrap(),
            canonical::canonical_json(&changed_journal).unwrap()
        );
    }
}

impl OriginalRestorationScopeOwner {
    pub(super) fn counter_scratch_data() -> usize {
        use crate::node_contract::{
            OriginalLineageInputRecord, OwnerIdentity, SavedRuntimeOperation, SavedRuntimeOwner,
        };
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<OriginalLineageNativeScope>()
            + size_of::<Result<&OriginalLineageNativeScope, RuntimeError>>()
            + size_of::<Option<&OriginalLineageNativeScope>>()
            + size_of::<Result<&serde_json::Value, RuntimeError>>()
            + size_of::<Option<&serde_json::Value>>()
            + size_of::<Option<&[u8]>>()
            + size_of::<Option<&Vec<u8>>>()
            + size_of::<Option<&mut Vec<u8>>>()
            + size_of::<Option<&ContentRef>>()
            + size_of::<Option<&OwnerIdentity>>()
            + size_of::<Result<&OwnerIdentity, RuntimeError>>()
            + size_of::<Option<&Id>>()
            + size_of::<Result<&Id, RuntimeError>>()
            + size_of::<Option<&OriginalLineageJournal>>()
            + size_of::<Option<&mut OriginalLineageJournal>>()
            + size_of::<Result<&mut OriginalLineageJournal, RuntimeError>>()
            + size_of::<Option<&mut crate::node_scheduling::NativeInputAcknowledgement>>()
            + size_of::<Result<&mut crate::node_scheduling::NativeInputAcknowledgement, RuntimeError>>(
            )
            + size_of::<std::slice::Iter<'static, OwnerIdentity>>()
            + size_of::<std::slice::Iter<'static, SavedRuntimeOwner>>()
            + size_of::<std::slice::Iter<'static, crate::node_state::NativeOwnerState>>()
            + size_of::<std::slice::Iter<'static, SavedRuntimeOperation>>()
            + size_of::<std::slice::Iter<'static, OriginalLineageInputRecord>>()
            + size_of::<std::slice::Iter<'static, OriginalLineageOwnerMapping>>()
            + size_of::<std::slice::Iter<'static, OriginalLineageJournal>>()
            + size_of::<std::slice::Iter<'static, SavedOriginalInputScope>>()
            + size_of::<std::slice::Iter<'static, crate::node_scheduling::NativeInputAcknowledgement>>(
            )
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), crucible_node_format::ContractError>>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<Result<ContentRef, crucible_node_format::ContractError>>()
            + size_of::<[usize; 8]>()
            + size_of::<usize>()
            + size_of::<bool>()
    }
}
