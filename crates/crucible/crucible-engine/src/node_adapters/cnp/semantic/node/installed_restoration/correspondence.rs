//! Compares complete restored custody while its genuine Source fence is armed.
//!
//! These comparisons cannot issue a context, association, ACK or readiness.
//! Callers must lend the actual retained Window scope through its opaque
//! association; an independently decoded matching scope is not accepted there.

use crate::{
    node_contract::{
        NodeRoute, OriginalLineageInputRecord, OriginalLineageNativeScope,
        OriginalLineageRuntimeRecord, RuntimeError, WorldActivation,
    },
    node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch},
    node_state::VerifiedStateContent,
};

pub(super) fn input<'a>(
    route: &NodeRoute,
    activation: &WorldActivation,
    batch: &RuntimeInputBatch,
    record: &'a OriginalLineageRuntimeRecord,
    scope: &OriginalLineageNativeScope,
    content: &VerifiedStateContent,
) -> Result<&'a OriginalLineageInputRecord, RuntimeError> {
    if batch.node() != &route.node
        || batch.owners() != route.owners
        || !batch.activation().same_authority(activation)
        || activation.record() != &scope.target
        || scope.source_capture != record.source_activation
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let mut matched = None;
    for saved in &record.inputs {
        if saved.node == route.node && &saved.stage_operation == batch.stage_operation() {
            if matched.replace(saved).is_some() {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
    }
    let saved = matched.ok_or(RuntimeError::InvalidReceipt)?;
    if &saved.batch != batch.batch()
        || saved.cutoff != batch.cutoff()
        || &saved.inventory != batch.inventory()
        || saved.deliveries != batch.deliveries()
        || saved.payloads.len() != batch.payloads().len()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for (reference, actual) in saved.payloads.iter().zip(batch.payloads()) {
        if reference != &actual.reference || content.get(reference) != Some(actual.bytes.as_slice())
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(saved)
}

pub(super) fn acknowledgement(
    batch: &RuntimeInputBatch,
    saved: &OriginalLineageInputRecord,
    scope: &OriginalLineageNativeScope,
    actual: &NativeInputAcknowledgement,
) -> Result<(), RuntimeError> {
    if actual.stage_operation != *batch.stage_operation()
        || actual.batch != *batch.batch()
        || actual.node != *batch.node()
        || actual.owners != batch.owners()
        || actual.cutoff != batch.cutoff()
        || actual.inventory != *batch.inventory()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    fresh_acknowledgement(
        saved,
        &scope.input_acknowledgements,
        &scope.proof,
        batch.owners(),
        actual,
    )
}

fn fresh_acknowledgement(
    saved: &OriginalLineageInputRecord,
    roster: &[NativeInputAcknowledgement],
    proof: &crucible_node_format::ContentRef,
    target_owners: &[crate::node_contract::OwnerIdentity],
    actual: &NativeInputAcknowledgement,
) -> Result<(), RuntimeError> {
    let previous = saved
        .acknowledgement
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    let mut matched = None;
    for ack in roster {
        if ack.node == saved.node && ack.stage_operation == saved.stage_operation {
            if matched.replace(ack).is_some() {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
    }
    let fresh = matched.ok_or(RuntimeError::InvalidReceipt)?;
    if target_owners.is_empty()
        || fresh != actual
        || actual.node != saved.node
        || actual.stage_operation != saved.stage_operation
        || actual.batch != saved.batch
        || actual.cutoff != saved.cutoff
        || actual.inventory != saved.inventory
        || actual.owners != target_owners
        || &actual.proof_ref != proof
        || actual.proof_ref == previous.proof_ref
        || previous.node != saved.node
        || previous.stage_operation != saved.stage_operation
        || previous.batch != saved.batch
        || previous.owners != saved.owners
        || previous.cutoff != saved.cutoff
        || previous.inventory != saved.inventory
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::OwnerIdentity;
    use crucible_node_format::{Id, Phase, Position, Tick, U64, canonical};

    fn fixture() -> (
        OriginalLineageInputRecord,
        NativeInputAcknowledgement,
        Vec<OwnerIdentity>,
        crucible_node_format::ContentRef,
    ) {
        let node = Id::new("saved-node").unwrap();
        let stage = Id::new("original-stage").unwrap();
        let batch = Id::new("original-batch").unwrap();
        let old_owner = OwnerIdentity {
            owner: Id::new("same-logical-owner").unwrap(),
            incarnation: Id::new("source-incarnation").unwrap(),
            generation: U64::new(1),
        };
        let target = vec![OwnerIdentity {
            incarnation: Id::new("actual-target-incarnation").unwrap(),
            generation: U64::new(2),
            ..old_owner.clone()
        }];
        let inventory = canonical::content_ref(b"original-inventory", "application/json").unwrap();
        let old_proof = canonical::content_ref(b"old-stage-proof", "application/json").unwrap();
        let proof = canonical::content_ref(b"fresh-four-owner-scope", "application/json").unwrap();
        let cutoff = Position::new(Tick::new(3), U64::new(4), Phase::Delivery);
        let old = NativeInputAcknowledgement {
            node: node.clone(),
            stage_operation: stage.clone(),
            batch: batch.clone(),
            owners: vec![old_owner.clone()],
            cutoff,
            inventory: inventory.clone(),
            proof_ref: old_proof,
        };
        let fresh = NativeInputAcknowledgement {
            owners: target.clone(),
            proof_ref: proof.clone(),
            ..old.clone()
        };
        let saved = OriginalLineageInputRecord {
            node,
            stage_operation: stage,
            batch,
            owners: vec![old_owner],
            cutoff,
            inventory,
            deliveries: Vec::new(),
            payloads: Vec::new(),
            provenance: None,
            lineage: None,
            acknowledgement: Some(old),
            failure: None,
            committed: true,
            coordinator_committed: true,
        };
        (saved, fresh, target, proof)
    }

    #[test]
    fn fresh_ack_requires_distinct_proof_actual_target_and_complete_original_identity() {
        // Portable records exercise DATA comparisons only. They cannot create
        // an association/context, stage an input or attest a native Hold.
        let (saved, fresh, target, proof) = fixture();
        assert!(fresh_acknowledgement(&saved, &[fresh.clone()], &proof, &target, &fresh).is_ok());
        for axis in 0..6 {
            let mut changed = fresh.clone();
            match axis {
                0 => changed.proof_ref = saved.acknowledgement.as_ref().unwrap().proof_ref.clone(),
                1 => changed.owners = saved.owners.clone(),
                2 => {
                    changed.inventory =
                        canonical::content_ref(b"foreign-inventory", "application/json").unwrap()
                }
                3 => changed.stage_operation = Id::new("foreign-stage").unwrap(),
                4 => changed.batch = Id::new("foreign-batch").unwrap(),
                _ => changed.cutoff.microstep = U64::new(5),
            }
            assert!(
                fresh_acknowledgement(&saved, &[changed.clone()], &proof, &target, &changed)
                    .is_err()
            );
        }
    }

    #[test]
    fn fresh_ack_refuses_empty_duplicate_and_changed_historical_rosters() {
        let (mut saved, fresh, target, proof) = fixture();
        assert!(fresh_acknowledgement(&saved, &[], &proof, &target, &fresh).is_err());
        assert!(
            fresh_acknowledgement(
                &saved,
                &[fresh.clone(), fresh.clone()],
                &proof,
                &target,
                &fresh
            )
            .is_err()
        );
        assert!(fresh_acknowledgement(&saved, &[fresh.clone()], &proof, &[], &fresh).is_err());
        saved.acknowledgement.as_mut().unwrap().batch = Id::new("changed-history").unwrap();
        assert!(fresh_acknowledgement(&saved, &[fresh.clone()], &proof, &target, &fresh).is_err());
    }
}

pub(super) fn operation(
    route: &NodeRoute,
    activation: &WorldActivation,
    admission: &crate::node_contract::OperationAdmission,
    record: &OriginalLineageRuntimeRecord,
) -> Result<(), RuntimeError> {
    if !admission.activation().same_authority(activation) || admission.token().route() != route {
        return Err(RuntimeError::ForeignAuthority);
    }
    let mut matched = None;
    for saved in &record.operations {
        if &saved.operation == admission.token().operation() {
            if matched.replace(saved).is_some() {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
    }
    let saved = matched.ok_or(RuntimeError::InvalidReceipt)?;
    if saved.route.node != route.node
        || &saved.request != admission.request()
        || saved.input_batch.as_ref() != admission.inputs().map(RuntimeInputBatch::batch)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}
