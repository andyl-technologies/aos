//! Prices new common Runtime7 ledgers before restoring any native model.
//!
//! Every payload occurrence is an independent copy. Existing archive/runtime
//! owners, native callbacks and context validation have separate caller rows.
//! This module observes borrowed metadata only and cannot authorize restoration.

use super::*;
use crate::node_contract::runtime::RuntimeOwnedStorage;
use crate::node_state::VerifiedStateContent;
use std::collections::BTreeSet;
use std::mem::{align_of, size_of};

struct Requested {
    bytes: usize,
    maximum: usize,
}

impl Requested {
    fn new(maximum: usize) -> Self {
        Self { bytes: 0, maximum }
    }

    fn add(&mut self, next: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(next)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn owned<T: RuntimeOwnedStorage + ?Sized>(&mut self, value: &T) -> Result<(), RuntimeError> {
        self.add(value.owned_storage()?)
    }

    fn slots<T>(&mut self, count: usize) -> Result<(), RuntimeError> {
        self.add(
            count
                .checked_mul(size_of::<T>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )
    }

    fn tree<K, V>(&mut self, count: usize) -> Result<(), RuntimeError> {
        self.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            count,
            size_of::<K>()
                .checked_add(size_of::<V>())
                .ok_or(RuntimeError::ResourceLimit)?,
            align_of::<K>().max(align_of::<V>()),
            self.maximum,
        )?)
    }
}

// Future scope validation requires these exact ContentRef string bounds before
// common code clones any fresh ACK. String::clone requests its length, not the
// capacity of an untrusted native response. The original response remains under
// the independently funded native/Source owner; it is not omitted here.
fn validated_fresh_reference_clone_data() -> usize {
    "blake3-256".len() + "cnp.blob.v1".len() + 64 + 128
}

fn fresh_ack_clone(
    saved: &crate::node_scheduling::NativeInputAcknowledgement,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.owned(&saved.node)?;
    counter.owned(&saved.stage_operation)?;
    counter.owned(&saved.batch)?;
    counter.owned(&saved.inventory)?;
    // The current scope compares exact target routes before it is opaque.
    // The complete target roster conservatively covers every selected subset.
    counter.owned(&target.owners)?;
    counter.add(validated_fresh_reference_clone_data())
}

fn payload_copies(
    references: &[ContentRef],
    content: &VerifiedStateContent,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.slots::<InputPayload>(references.len())?;
    for reference in references {
        let bytes = content.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
        counter.owned(reference)?;
        // copy_payloads uses try_reserve_exact(actual.len()), then copies the
        // same verified typed role. Equal references do not share these Vecs.
        counter.add(bytes.len())?;
    }
    Ok(())
}

fn batch_clone_backing(
    saved: &OriginalLineageInputRecord,
    route: &NodeRoute,
    target: &ActivationRecord,
    content: &VerifiedStateContent,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.owned(target)?; // WorldActivation's independent record clone.
    counter.owned(&saved.node)?;
    counter.owned(&saved.stage_operation)?;
    counter.owned(&saved.batch)?;
    counter.owned(&route.owners)?;
    counter.owned(&saved.inventory)?;
    counter.owned(&saved.deliveries)?;
    payload_copies(&saved.payloads, content, counter)
}

fn input_ledgers(
    runtime: &NodeRuntime,
    record: &OriginalLineageRuntimeRecord,
    target: &ActivationRecord,
    content: &VerifiedStateContent,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.tree::<Id, super::super::super::super::inputs::RetainedInput>(record.inputs.len())?;
    counter.tree::<Id, Rc<RuntimeInputBatch>>(record.inputs.len())?;
    for saved in &record.inputs {
        let route = &runtime
            .snapshots
            .get(&saved.node)
            .ok_or(RuntimeError::UnknownNode)?
            .route;
        counter.owned(&saved.stage_operation)?; // Input ledger key.
        counter.owned(&saved.batch)?; // Independent handle-map key.
        counter.add(NodeRuntime::capture_shared_allocation_storage::<
            RuntimeInputBatch,
        >())?;
        batch_clone_backing(saved, route, target, content, counter)?;
        batch_clone_backing(saved, route, target, content, counter)?;
        if let Some(proof) = &saved.provenance {
            counter.owned(target)?;
            counter.owned(&proof.node)?;
            counter.owned(&proof.stage_operation)?;
            counter.owned(&proof.batch)?;
            counter.owned(&proof.inventory)?;
            counter.owned(&proof.roots)?;
            payload_copies(&proof.objects, content, counter)?;
        }
        if let Some(lineage) = &saved.lineage {
            counter.add(NodeRuntime::capture_shared_allocation_storage::<
                super::super::OriginalInputLineageData,
            >())?;
            counter.owned(&lineage.source)?;
            counter.slots::<OriginalPublicationClaim>(lineage.publications.len())?;
            for publication in &lineage.publications {
                let bytes = content
                    .get(&publication.published)
                    .ok_or(RuntimeError::InvalidReceipt)?;
                // restore_inputs decodes an independent Event after the same
                // event was validated in the context. Its complete parse/DTO
                // work stays additional; no prior validation earns a refund.
                counter.add(NodeRuntime::capture_selected_json_decode_storage(
                    bytes,
                    size_of::<Event>(),
                    NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
                    counter.maximum,
                )?)?;
                counter.owned(&publication.origin)?;
                counter.owned(&publication.published)?;
                counter.owned(&publication.rows)?;
                payload_copies(&publication.objects, content, counter)?;
            }
        }
        if let Some(ack) = &saved.acknowledgement {
            fresh_ack_clone(ack, target, counter)?;
        }
        counter.owned(&saved.failure)?;
        if saved.coordinator_committed {
            counter.owned(target)?;
            counter.owned(&saved.node)?;
            counter.owned(&saved.stage_operation)?;
            counter.owned(&saved.batch)?;
            counter.owned(&saved.inventory)?;
        }
    }
    Ok(())
}

fn operation_admission_clone(
    saved: &SavedRuntimeOperation,
    route: &NodeRoute,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.owned(&saved.operation)?;
    counter.owned(route)?;
    counter.owned(&saved.request)?;
    counter.owned(target)
}

// Submission has no generic OwnedStorage implementation. Price its actual
// independent clone exhaustively without introducing another observer family.
fn submission_clone_backing(
    submission: &Option<Submission>,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    match submission {
        Some(Submission::Refused(refusal)) => counter.owned(&refusal.reason),
        Some(Submission::Uncertain(effects)) => counter.owned(effects),
        Some(Submission::Accepted) | None => Ok(()),
    }
}

fn operation_ledgers(
    runtime: &NodeRuntime,
    record: &OriginalLineageRuntimeRecord,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.tree::<Id, super::super::super::super::RetainedOperation>(record.operations.len())?;
    for saved in &record.operations {
        let route = &runtime
            .snapshots
            .get(&saved.route.node)
            .ok_or(RuntimeError::UnknownNode)?
            .route;
        counter.owned(route)?; // Local route clone coexists with admission.
        counter.owned(&saved.operation)?; // Map key.
        operation_admission_clone(saved, route, target, counter)?;
        counter.owned(&saved.result)?;
        if let SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) =
            &saved.result
        {
            // Cloning the source outcome precedes replacing its owner roster;
            // both the original clone and fresh target allocation are charged.
            counter.owned(&route.owners)?;
            if outcome.scheduling.is_some() {
                counter.owned(&route.owners)?;
            }
        }
        submission_clone_backing(&saved.close_submission, counter)?;
        counter.owned(&saved.submission_effects)?;
        if let Some(commit) = &saved.scheduling_commit {
            counter.owned(target)?;
            counter.owned(&commit.node)?;
            counter.owned(&commit.operation)?;
            counter.owned(&commit.retained_outputs)?;
        }
        // Per-node native-install arguments own an independent admission clone.
        // The same Rc batch/authority references do not allocate new payloads;
        // those actual shared roots are charged above and by the common scope.
        counter.slots::<OperationAdmission>(1)?;
        operation_admission_clone(saved, route, target, counter)?;
    }
    // Argument arrays are exact-count reserve() Vecs. Conservatively retain
    // every node's complete input-handle array, including callbacks that fail.
    counter.slots::<Rc<RuntimeInputBatch>>(record.inputs.len())
}

fn owner_ledgers(
    runtime: &NodeRuntime,
    record: &OriginalLineageRuntimeRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.tree::<Id, OwnerCustody>(record.owners.len())?;
    for saved in &record.owners {
        let current = runtime
            .owners
            .get(&saved.identity.owner)
            .ok_or(RuntimeError::InvalidRoute)?;
        counter.owned(&saved.identity.owner)?;
        counter.owned(&current.identity)?;
        // BTreeSet::clone allocates independent nodes and clones every Id;
        // this is not the archived domains Vec or a body-length surrogate.
        counter.tree::<Id, ()>(current.domains.len())?;
        for domain in &current.domains {
            counter.owned(domain)?;
        }
        counter.owned(&saved.operation)?;
    }
    Ok(())
}

pub(super) fn ledger_storage_data(
    runtime: &NodeRuntime,
    record: &OriginalLineageRuntimeRecord,
    target: &ActivationRecord,
    content: &VerifiedStateContent,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    if record
        .operations
        .len()
        .checked_add(record.inputs.len())
        .ok_or(RuntimeError::ResourceLimit)?
        > runtime.limits.maximum_operations
        || record.owners.len() > runtime.limits.maximum_owners
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut counter = Requested::new(maximum);
    input_ledgers(runtime, record, target, content, &mut counter)?;
    operation_ledgers(runtime, record, target, &mut counter)?;
    owner_ledgers(runtime, record, &mut counter)?;
    // The real published return remains in ConformanceRuntime. Window then
    // retains one additional handle, with another independent record clone.
    counter.add(size_of::<WorldActivation>())?;
    counter.owned(target)?;
    counter.add(size_of::<WorldActivation>())?;
    counter.owned(target)?;
    // install_original_lineage stores source/scheduler/target independently in
    // its existing OriginalSchedulingState cells; no fresh scheduler Rc minted.
    counter.add(validated_fresh_reference_clone_data())?;
    counter.add("blake3-256".len() + 128 + 64)?;
    counter.owned(target)?;
    // Error containment builds this exact fresh NodeRoute before callbacks.
    counter.add(size_of::<NodeRoute>())?;
    counter.owned(&target.activation_id)?;
    counter.owned(&target.owners)?;
    Ok(counter.bytes)
}

fn hash_clone_bound() -> usize {
    "blake3-256".len() + 128 + 64
}

// Window authenticates the exact installed three-CNP/one-Host constructors
// before this DATA projection. Their prepared owners have one binding hash,
// one owner per node and empty Extensions; arbitrary SimulationNode families
// or publisher callbacks are not covered by this closed term.
fn prepared_owner_backing(
    owner: &OwnerIdentity,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.owned(&owner.owner)?;
    counter.owned(&owner.incarnation)?;
    counter.add(128)?; // Validated Id clone: prepared token.
    counter.slots::<HashRef>(1)?;
    counter.add(hash_clone_bound())?;
    counter.add(validated_fresh_reference_clone_data())?;
    // The existing defining owner observer counts an empty Extensions root.
    // Preserve that logical row even though an empty std BTreeMap owns no heap.
    counter.tree::<String, serde_json::Value>(0)
}

fn future_publication_roots(
    runtime: &NodeRuntime,
    target: &ActivationRecord,
    coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    if runtime.snapshots.len() != 4 || target.owners.len() != 4 {
        return Err(RuntimeError::UnsupportedFacet);
    }
    // All4 preparation Vec slots coexist with the new immutable Rc slice.
    counter.slots::<ValidatedNodePreparation>(4)?;
    counter.slots::<ValidatedNodePreparation>(4)?;
    // StoredWorldActivationPublisher retains a separate cloned node Vec and
    // activation record before its prepare_coordinator callback returns bytes.
    counter.slots::<ValidatedNodePreparation>(4)?;
    counter.owned(target)?;
    counter.add(NodeRuntime::capture_protocol_shared_header_storage(
        1,
        align_of::<ValidatedNodePreparation>(),
        counter.maximum,
    )?)?;
    // arm_all's record and per-node original_route clones are independent of
    // the barrier's existing target. Readiness's FromIterator additionally
    // holds a growable collect Vec while bulk-building its tree.
    counter.owned(target)?;
    counter.tree::<OwnerIdentity, ()>(4)?;
    counter.slots::<OwnerIdentity>(16)?;
    counter.tree::<Id, Vec<HashRef>>(4)?;
    counter.tree::<Id, crucible_node_format::PreparedOwner>(4)?;
    counter.slots::<crucible_node_format::PreparedOwner>(4)?;
    for snapshot in runtime.snapshots.values() {
        let [owner] = snapshot.route.owners.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if !target.owners.contains(owner) {
            return Err(RuntimeError::ForeignAuthority);
        }
        counter.owned(&snapshot.route)?;
        counter.owned(&owner.owner)?; // bindings entry key.
        counter.slots::<HashRef>(4)?; // push into one initially empty bank.
        counter.add(hash_clone_bound())?; // identity() local.
        counter.add(hash_clone_bound())?; // independently retained binding hash.
        counter.owned(&snapshot.route.node)?;
        counter.owned(&snapshot.route.owners)?;
        counter.add(validated_fresh_reference_clone_data())?; // state_inventory.
        counter.add(validated_fresh_reference_clone_data())?; // ready_receipt.
        counter.slots::<crucible_node_format::PreparedOwner>(1)?;
        prepared_owner_backing(owner, counter)?;
        // The retained publisher's independent node-preparation clone.
        counter.owned(&snapshot.route.node)?;
        counter.owned(&snapshot.route.owners)?;
        counter.add(validated_fresh_reference_clone_data())?;
        counter.add(validated_fresh_reference_clone_data())?;
        counter.slots::<crucible_node_format::PreparedOwner>(1)?;
        prepared_owner_backing(owner, counter)?;
        // ActivationBarrier's ready set retains an independent owner identity.
        counter.owned(owner)?;
        // publish's owner map clones the complete record and its independent key.
        counter.owned(&owner.owner)?;
        prepared_owner_backing(owner, counter)?;
        // validate_owner_mapping binds exactly this same actual graph binding.
        counter.add(
            NodeRuntime::original_runtime_constructor_serialization_storage_data(
                &snapshot.binding,
                counter.maximum,
            )?,
        )?;
    }
    counter.add(NodeRuntime::capture_shared_allocation_storage::<
        crate::node_contract::PreparedWorldPublication,
    >())?;
    // Names' actual closed coordinator producer owns/funds Window's original
    // bank and node-copy roster. Publisher handoff and later barrier callback
    // each clone the body/reference independently; neither aliases Window's Vec.
    counter.add(coordinator.requested_bytes_data()?)?;
    counter.add(coordinator.maximum_encoded_bytes_data())?;
    counter.add(validated_fresh_reference_clone_data())?;
    counter.add(coordinator.maximum_encoded_bytes_data())?;
    counter.add(validated_fresh_reference_clone_data())?;
    // Genuine WorldActivation authority aliases retain this actual Core root;
    // equal public IDs do not replace the source-owned runtime association.
    counter.add(NodeRuntime::capture_shared_allocation_storage::<()>())
}

impl OriginalRuntimeRestorationInstallationConstructionData {
    /// Returns the complete conservative new constructor/owner byte conjunction.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns the independently admitted inert paused-scheduler clone backing.
    ///
    /// The original Window owner remains separately retained. Selected callers
    /// authenticate this same fixed row and cap the clone before allocation.
    pub fn paused_scheduler_duplicate_requested_bytes_data(&self) -> usize {
        self.paused_scheduler_duplicate
    }

    /// Returns fixed counter/constructor views admitted before any quote walk.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(crate) fn authenticate_inputs_data(
        &self,
        runtime: &NodeRuntime,
        record: &OriginalLineageRuntimeRecord,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        target: &ActivationRecord,
        content: &VerifiedStateContent,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.authority.ptr_eq(&Rc::downgrade(&runtime.authority))
            || !std::ptr::eq(self.record, record)
            || !std::ptr::eq(self.scheduling, scheduling)
            || !std::ptr::eq(self.target, target)
            || !std::ptr::eq(self.content, content)
            || !std::ptr::eq(self.coordinator, coordinator)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl NodeRuntime {
    pub(crate) fn original_runtime_restoration_installation_construction_data(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        record: &OriginalLineageRuntimeRecord,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        target: &ActivationRecord,
        content: &VerifiedStateContent,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum: usize,
    ) -> Result<OriginalRuntimeRestorationInstallationConstructionData, RuntimeError> {
        if self.activated
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || self.barrier.record() != target
            || self.snapshots.len() != 4
            || graph.node_ids().count() != 4
            || self.collecting.is_none()
            || !self.barrier.can_arm()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let scratch = Self::original_runtime_restoration_installation_counter_scratch_data()?;
        let mut requested = Requested::new(maximum);
        requested.add(ledger_storage_data(self, record, target, content, maximum)?)?;
        requested.add(crate::node_scheduling::PreparedSchedulingRestore::original_lineage_construction_storage_data(
            graph, record, scheduling, target, maximum,
        )?)?;
        let paused_scheduler_duplicate = crate::node_scheduling::PreparedSchedulingRestore::original_lineage_retained_installation_duplicate_storage_data(
            record, scheduling, target, maximum,
        )?;
        requested.add(paused_scheduler_duplicate)?;
        future_publication_roots(self, target, coordinator, &mut requested)?;
        requested
            .bytes
            .checked_add(scratch)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(OriginalRuntimeRestorationInstallationConstructionData {
            requested: requested.bytes,
            paused_scheduler_duplicate,
            scratch,
            process: std::process::id(),
            thread: std::thread::current().id(),
            authority: Rc::downgrade(&self.authority),
            record,
            scheduling,
            target,
            content,
            coordinator,
        })
    }

    pub(crate) fn original_runtime_restoration_installation_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let rows = [
            size_of::<OriginalRuntimeRestorationInstallationConstructionData>(),
            size_of::<Result<OriginalRuntimeRestorationInstallationConstructionData, RuntimeError>>(),
            size_of::<Requested>(),
            size_of::<blake3::Hasher>(),
            // RefMut has the same defining pointer/borrow-flag layout for each
            // Sized payload. Both restored-identity and scheduler cell loans
            // coexist in OriginalSchedulingState::install_original_lineage.
            2 * size_of::<std::cell::RefMut<'static, ()>>(),
            2 * size_of::<Result<std::cell::RefMut<'static, ()>, RuntimeError>>(),
            size_of::<BTreeMap<Id, super::super::super::super::inputs::RetainedInput>>(),
            size_of::<BTreeMap<Id, Rc<RuntimeInputBatch>>>(),
            size_of::<BTreeMap<Id, super::super::super::super::RetainedOperation>>(),
            size_of::<BTreeMap<Id, OwnerCustody>>(),
            size_of::<Result<RestoredInputLedgers, RuntimeError>>(),
            size_of::<Result<BTreeMap<Id, super::super::super::super::RetainedOperation>, RuntimeError>>(),
            size_of::<Result<BTreeMap<Id, OwnerCustody>, RuntimeError>>(),
            size_of::<Result<Vec<InputPayload>, RuntimeError>>(),
            size_of::<Result<Vec<OperationAdmission>, RuntimeError>>(),
            size_of::<Result<Vec<Rc<RuntimeInputBatch>>, RuntimeError>>(),
            size_of::<Result<Option<InputProvenanceClosure>, RuntimeError>>(),
            size_of::<Result<Option<OriginalInputLineage>, RuntimeError>>(),
            size_of::<Result<Event, crucible_node_format::ContractError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Vec<InputPayload>>(),
            size_of::<Vec<OriginalPublicationClaim>>(),
            size_of::<Vec<OperationAdmission>>(),
            size_of::<Vec<Rc<RuntimeInputBatch>>>(),
            size_of::<NodeRoute>(),
            size_of::<OperationAdmission>(),
            size_of::<WorldActivation>(),
            size_of::<ActivationRecord>(),
            size_of::<ValidatedNodePreparation>(),
            size_of::<Result<ValidatedNodePreparation, RuntimeError>>(),
            size_of::<Result<WorldActivation, RuntimeError>>(),
            size_of::<crate::node_contract::PreparedWorldPublication>(),
            size_of::<BTreeSet<OwnerIdentity>>(),
            size_of::<Vec<OwnerIdentity>>(),
            size_of::<Vec<ValidatedNodePreparation>>(),
            size_of::<BTreeMap<Id, Vec<HashRef>>>(),
            size_of::<BTreeMap<Id, crucible_node_format::PreparedOwner>>(),
            size_of::<Vec<crucible_node_format::PreparedOwner>>(),
            size_of::<Result<HashRef, crucible_node_format::ContractError>>(),
            size_of::<std::collections::btree_map::Values<'static, Id, super::super::super::super::NodeSnapshot>>(),
            size_of::<std::collections::btree_set::Iter<'static, Id>>(),
            size_of::<std::slice::Iter<'static, ValidatedNodePreparation>>(),
            size_of::<std::collections::btree_map::IntoValues<Id, crucible_node_format::PreparedOwner>>(),
            size_of::<std::slice::Iter<'static, OriginalLineageInputRecord>>(),
            size_of::<std::slice::Iter<'static, SavedRuntimeOperation>>(),
            size_of::<std::slice::Iter<'static, SavedRuntimeOwner>>(),
            size_of::<std::slice::Iter<'static, ContentRef>>(),
            size_of::<std::slice::Iter<'static, SavedOriginalPublication>>(),
            size_of::<std::slice::Iter<'static, OwnerIdentity>>(),
            size_of::<std::collections::btree_map::Iter<'static, Id, super::super::super::super::RetainedOperation>>(),
            size_of::<std::collections::btree_map::Values<'static, Id, super::super::super::super::RetainedOperation>>(),
            size_of::<std::collections::btree_map::Values<'static, Id, Rc<RuntimeInputBatch>>>(),
            size_of::<std::collections::btree_map::Iter<'static, Id, Box<dyn SimulationNode>>>(),
            size_of::<std::rc::Weak<()>>(),
            size_of::<Option<&crate::node_scheduling::NativeInputAcknowledgement>>(),
            size_of::<[u8; 20]>(),
            size_of::<[u8; 132]>(),
            Self::capture_serialization_counter_scratch_data(),
            Self::capture_selected_json_decode_counter_scratch_data(),
            crate::node_scheduling::PreparedSchedulingRestore::original_lineage_construction_counter_scratch_data()?,
        ];
        // This getter's own fixed row array and its slice cursor are declared
        // logical views too; no compiler frame or unrelated padding is inferred.
        let fixed_views = std::mem::size_of_val(&rows)
            .checked_add(size_of::<std::slice::Iter<'static, usize>>())
            .ok_or(RuntimeError::ResourceLimit)?;
        rows.iter().try_fold(fixed_views, |sum, bytes| {
            sum.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are inert typed content/owner fixtures. No runtime, native proof,
    // context, preparation token authority or WorldActivation is constructed.
    #[test]
    fn independent_payload_occurrences_fund_both_banks_and_refuse_one_short() {
        let mut bytes = Vec::with_capacity(8192);
        bytes.extend_from_slice(b"one actual immutable payload");
        let reference = canonical::content_ref(&bytes, "application/test-runtime7").unwrap();
        let original = InputPayload {
            reference: reference.clone(),
            bytes,
        };
        let content = crate::node_state::synthetic_typed_content(&[original]).unwrap();
        let references = vec![reference.clone(), reference.clone()];
        let mut quoted = Requested::new(usize::MAX);
        payload_copies(&references, &content, &mut quoted).unwrap();
        payload_copies(&references, &content, &mut quoted).unwrap();

        let actual_banks: Vec<Vec<InputPayload>> = (0..2)
            .map(|_| {
                references
                    .iter()
                    .map(|reference| InputPayload {
                        reference: reference.clone(),
                        bytes: content.get(reference).unwrap().to_vec(),
                    })
                    .collect()
            })
            .collect();
        let actual = actual_banks
            .iter()
            .map(|bank| bank.owned_storage().unwrap())
            .sum::<usize>();
        assert!(quoted.bytes >= actual);
        assert_ne!(
            actual_banks[0][0].bytes.as_ptr(),
            actual_banks[0][1].bytes.as_ptr()
        );
        assert_ne!(
            actual_banks[0][0].bytes.as_ptr(),
            actual_banks[1][0].bytes.as_ptr()
        );
        let mut exact = Requested::new(quoted.bytes);
        payload_copies(&references, &content, &mut exact).unwrap();
        payload_copies(&references, &content, &mut exact).unwrap();
        let mut short = Requested::new(quoted.bytes - 1);
        payload_copies(&references, &content, &mut short).unwrap();
        assert!(matches!(
            payload_copies(&references, &content, &mut short),
            Err(RuntimeError::ResourceLimit)
        ));

        let mut wrong_role = reference;
        wrong_role.media_type = "application/other-role".into();
        assert!(matches!(
            payload_copies(&[wrong_role], &content, &mut Requested::new(usize::MAX)),
            Err(RuntimeError::InvalidReceipt)
        ));
    }

    #[test]
    fn closed_prepared_owner_bound_includes_independent_reference_and_empty_root() {
        let owner = OwnerIdentity {
            owner: Id::new("real-shaped-owner").unwrap(),
            incarnation: Id::new("real-shaped-incarnation").unwrap(),
            generation: 2.into(),
        };
        let actual = crucible_node_format::PreparedOwner {
            owner_id: owner.owner.clone(),
            incarnation_id: owner.incarnation.clone(),
            owner_generation: owner.generation,
            binding_hashes: vec![
                canonical::content_ref(b"binding", "application/json")
                    .unwrap()
                    .hash,
            ],
            prepared_token: Id::new("t".repeat(128)).unwrap(),
            ready_receipt: canonical::content_ref(b"ready", "application/json").unwrap(),
            extensions: Default::default(),
        };
        let mut quoted = Requested::new(usize::MAX);
        prepared_owner_backing(&owner, &mut quoted).unwrap();
        assert!(quoted.bytes >= actual.clone().owned_storage().unwrap());
        let mut short = Requested::new(quoted.bytes - 1);
        assert!(matches!(
            prepared_owner_backing(&owner, &mut short),
            Err(RuntimeError::ResourceLimit)
        ));
    }

    #[test]
    fn submission_clone_census_keeps_refusal_and_uncertain_prefix_backing() {
        let mut reason = String::with_capacity(4096);
        reason.push_str("actual refusal body");
        let refused = Some(Submission::Refused(crate::node_contract::Refusal {
            reason,
        }));
        let mut quoted = Requested::new(usize::MAX);
        submission_clone_backing(&refused, &mut quoted).unwrap();
        let clone = refused.clone();
        let Some(Submission::Refused(actual)) = &clone else {
            panic!("refusal clone changed variant")
        };
        assert!(quoted.bytes >= actual.reason.capacity());
        assert!(quoted.bytes >= 4096);
        assert!(matches!(
            submission_clone_backing(&refused, &mut Requested::new(quoted.bytes - 1)),
            Err(RuntimeError::ResourceLimit)
        ));

        let uncertain = Some(Submission::Uncertain(EffectKnowledge::CommittedPrefix(
            vec![
                Id::new("original-committed-a").unwrap(),
                Id::new("original-committed-b").unwrap(),
            ],
        )));
        let mut bound = Requested::new(usize::MAX);
        submission_clone_backing(&uncertain, &mut bound).unwrap();
        let Some(Submission::Uncertain(actual)) = uncertain.clone() else {
            panic!("uncertain clone changed variant")
        };
        assert!(bound.bytes >= actual.owned_storage().unwrap());
        assert!(bound.bytes > 0);
        let mut inline = Requested::new(0);
        submission_clone_backing(&Some(Submission::Accepted), &mut inline).unwrap();
        submission_clone_backing(&None, &mut inline).unwrap();
        assert_eq!(inline.bytes, 0);
    }
}
