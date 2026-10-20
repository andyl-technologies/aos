//! Joins current Controller Stop completion with literal Source A8 settlement.
//!
//! The actual caller retains its paid native C/Source owners and owed posts.
//! This owner reuses their canonical Source projection and the existing owning
//! operation/A8 selectors. It preserves the failed old Source attempt and grants
//! neither a native operation nor authority from a historical Root confirmation.

use super::*;
use crate::journal::RecordNamespace;
use crate::lifecycle::protected_journal::{
    LifecycleProtectedRecordKindV1, LifecycleReplayReceivingV1,
};
use aos_sandbox_core::{
    ObjectDigest, ProjectId, ResourceDimension as D, ResourceVector, SandboxId,
};
use aos_sandbox_protocol::{
    domain_ledger::{
        effect_history::{
            EffectLedgerRecord, EffectState, LifecycleEffectReceiptDataV1,
            PublicMutationEffectHistoryV1, decode_effect, decode_lifecycle_effect_receipt_v1,
        },
        operation::{OperationRecord, decode_operation, effect_key},
        public_operation::OperationState,
        readonly::HistoricalLedgerRowsDataV2,
        stop_completion::LifecycleStopCompletionDataV1,
    },
    host_stopped_namespace::HostStoppedNamespaceDataV4,
    public_api::{PublicOperationMethodV1, request::DormantSandboxRequestKindV1},
};
use sha2::{Digest as _, Sha256};
use std::mem::size_of;

/// Carries a historical relation earned from the full retained C/Source models.
#[derive(Clone, Copy)]
pub(crate) struct CompletedStopHistoryDataV1 {
    completion: Option<LifecycleStopCompletionDataV1>,
    scope: HostStoppedNamespaceDataV4,
    operation: OperationId,
    record: ObjectDigest,
    project: ProjectId,
    sandbox: SandboxId,
    source_fence: crate::lifecycle::LiveRuntimeFenceV1,
}

impl CompletedStopHistoryDataV1 {
    pub(crate) const fn operation_v1(&self) -> OperationId {
        self.operation
    }
    pub(crate) fn recovery_v1(&self) -> Option<OperationId> {
        self.completion.map(|value| value.binding_v1().recovery)
    }
    pub(crate) const fn project_v1(&self) -> ProjectId {
        self.project
    }
    pub(crate) const fn sandbox_v1(&self) -> SandboxId {
        self.sandbox
    }
    pub(crate) fn historical_scope_v1(&self) -> &HostStoppedNamespaceDataV4 {
        &self.scope
    }
    pub(crate) const fn completion_v1(&self) -> Option<&LifecycleStopCompletionDataV1> {
        self.completion.as_ref()
    }
    /// Returns the literal Source runtime fence, without current authority.
    pub(crate) const fn source_fence_v1(&self) -> crate::lifecycle::LiveRuntimeFenceV1 {
        self.source_fence
    }

    pub(crate) const fn record_digest_v1(&self) -> ObjectDigest {
        self.record
    }

    /// Joins a new census to the unchanged authenticated chain leaf in A8.
    /// Only the fresh query/boot/interval may change; no old outcome is adopted.
    pub(crate) fn require_cleanup_v1(
        &self,
        current: &aos_sandbox_protocol::host_cleanup_lineage::HostCleanupLineageDataV1,
    ) -> Result<(), JournalError> {
        use aos_sandbox_protocol::domain_ledger::stop_completion::LifecycleStopCompletionEvidenceDataV1;
        let old = match self.completion.as_ref().ok_or(CLOSED)?.evidence_v1() {
            LifecycleStopCompletionEvidenceDataV1::ObservedLineage(row)
            | LifecycleStopCompletionEvidenceDataV1::ExecutedLineage(row) => row,
            LifecycleStopCompletionEvidenceDataV1::ObservedComplete(_) => return Err(CLOSED),
        };
        if old.subject_v1() != current.subject_v1()
            || old.child_v1() != current.child_v1()
            || old.chain_commitment_v1() != current.chain_commitment_v1()
        {
            return Err(CLOSED);
        }
        Ok(())
    }
}

struct Entry {
    source: LifecycleCurrentOperationSelectionOriginalV1,
    completion: super::stop_dispatch::StopDispatchReadOriginalV1,
    operation: Option<OperationRecord>,
    effect: Option<EffectLedgerRecord>,
    context: Option<PublicMutationEffectHistoryV1>,
    request: Option<DormantSandboxRequestKindV1>,
    ordinary: Option<(
        OperationId,
        ProjectId,
        SandboxId,
        crate::lifecycle::LiveRuntimeFenceV1,
        aos_sandbox_protocol::host_stopped_namespace::HostStoppedRequestIdentityDataV4,
        ObjectDigest,
    )>,
    data: Option<CompletedStopHistoryDataV1>,
}

impl Entry {
    fn new() -> Self {
        Self {
            source: LifecycleCurrentOperationSelectionOriginalV1::new(),
            completion: super::stop_dispatch::StopDispatchReadOriginalV1::new(),
            operation: None,
            effect: None,
            context: None,
            request: None,
            ordinary: None,
            data: None,
        }
    }

    fn observe(
        &mut self,
        rows: HistoricalLedgerRowsDataV2<'_>,
        source: &LifecycleHistoricalReadOriginalV1,
        id: OperationId,
    ) -> Result<(), Cause> {
        let (projection, verifier) = source.projection_ready_v1()?;
        self.source.select_once_v1(projection, verifier, id)?;
        let (_, operation, record) = self.source.completed_v1().ok_or(CLOSED)?;
        let crate::lifecycle::LifecycleIntentV1::Stop { sandbox, fence } = operation.intent()
        else {
            return Ok(());
        };
        let has_completion = super::stop_dispatch::optional_selected_members(
            projection,
            id,
            super::stop_dispatch::StopSelection::Completion,
        )?
        .is_some();
        let completion = if has_completion {
            self.completion.observe_once(
                projection,
                verifier,
                operation,
                *record,
                super::stop_dispatch::StopSelection::Completion,
            )?;
            Some(*self.completion.completed_settlement()?)
        } else {
            if operation.phase() != crate::lifecycle::LifecyclePhaseV1::Terminal
                || operation.terminal_result()
                    != Some(crate::lifecycle::LifecycleTerminalResultV1::Succeeded)
            {
                return Ok(());
            }
            // Historical legacy success without an A7 is not upgraded into
            // this new proof. It remains outside the selected family, without
            // preventing an unrelated exact A8 from being compared.
            if super::stop_dispatch::optional_selected_members(
                projection,
                id,
                super::stop_dispatch::StopSelection::Dispatch,
            )?
            .is_none()
            {
                return Ok(());
            }
            self.completion.observe_once(
                projection,
                verifier,
                operation,
                *record,
                super::stop_dispatch::StopSelection::HistoricalDispatch,
            )?;
            None
        };

        self.operation = Some(decode_operation(row(
            rows,
            RecordNamespace::Operation,
            id.as_bytes(),
        )?)?);
        let controller = self.operation.as_ref().ok_or(CLOSED)?;
        // A8 may precede C terminal during a legitimate crash. It is not yet
        // completed history and therefore cannot whitelist that Source family.
        if controller.state() != OperationState::Succeeded {
            return Ok(());
        }
        if controller.effect_count() != 1
            || controller
                .public_operation()
                .is_none_or(|public| public.method() != PublicOperationMethodV1::StopSandbox)
        {
            return Err(CLOSED.into());
        }
        self.effect = Some(decode_effect(row(
            rows,
            RecordNamespace::Effect,
            &effect_key(id, 0),
        )?)?);
        let effect = self.effect.as_ref().ok_or(CLOSED)?;
        if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::StopSandbox)
            || effect.plan().authority().is_some()
        {
            return Err(CLOSED.into());
        }
        let digest = if completion.is_some() {
            self.completion.completed_record()?.complete_digest()
        } else {
            record.digest()
        };
        require_receipt(effect.state(), id, digest)?;

        self.context = effect.plan().public_mutation_context()?;
        let context = self.context.as_ref().ok_or(CLOSED)?;
        self.request = Some(context.validated_request()?);
        let Some(DormantSandboxRequestKindV1::Stop(request)) = self.request.as_ref() else {
            return Err(CLOSED.into());
        };
        let mutation = request.mutation.as_option().ok_or(CLOSED)?;
        let admitted_at = u64::try_from(context.accepted_wall_seconds())?
            .checked_mul(1_000_000_000)
            .ok_or(CLOSED)?;
        if request.sandbox_id.as_slice() != sandbox.as_bytes()
            || context.project() != operation.project()
            || context.caller() != operation.caller()
            || crate::lifecycle::LifecycleIdempotencyDigestV1::commit(&mutation.idempotency_key)
                != operation.idempotency()
            || admitted_at != operation.accepted_at().get()
        {
            return Err(CLOSED.into());
        }

        if let Some(completion) = completion {
            let scope = *completion.evidence_v1().historical_scope_v1();
            require_source_fence(&scope, *fence)?;
            self.data = Some(CompletedStopHistoryDataV1 {
                completion: Some(completion),
                scope,
                operation: id,
                record: digest,
                project: context.project(),
                sandbox: *sandbox,
                source_fence: *fence,
            });
        } else {
            self.ordinary = Some((
                id,
                context.project(),
                *sandbox,
                *fence,
                self.completion.completed()?.sdk_request_data_v1(),
                digest,
            ));
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .failure_v1()
            .or_else(|| self.completion.failure())
    }
}

/// Retains each canonical A8 selector and its actual current Controller models.
pub(crate) struct CompletedStopHistoryOriginalV1 {
    entries: Vec<Entry>,
    controller: Option<[u8; 32]>,
    source: Option<ObjectDigest>,
    returned: Option<Result<(), Cause>>,
    reentered: bool,
}

impl CompletedStopHistoryOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            controller: None,
            source: None,
            returned: None,
            reentered: false,
        }
    }

    /// Prices actual rows and the existing Source/Effect decoder suppliers.
    /// No parser, native IO or currentness decision occurs in this supplier.
    pub(crate) fn receiving_demand_v1(
        controller: HistoricalLedgerRowsDataV2<'_>,
        source: HistoricalLedgerRowsDataV2<'_>,
    ) -> Option<ResourceVector> {
        let count = source.all_records().count();
        let selection =
            LifecycleReplayReceivingV1::additional_selection_receiving_v1(source.all_records())?;
        // Latest selection coexists with both retained auxiliary members and
        // their incoming scratch. Each supplier covers two complete model
        // planes; Entry owns their fixed carriers.
        let plane = selection.checked_add(selection).ok()?;
        let mut demand = ResourceVector::ZERO;
        for _ in 0..count {
            demand = demand.checked_add(plane).ok()?;
        }
        let mut bytes = size_of::<Self>()
            .checked_mul(3)?
            .checked_add(size_of::<Entry>().checked_mul(count)?.checked_mul(3)?)?
            .checked_add(size_of::<Sha256>().checked_mul(3)?)?;
        for (namespace, _, value) in controller.all_records() {
            if namespace == RecordNamespace::Effect {
                bytes = bytes.checked_add(aos_sandbox_protocol::domain_ledger::effect_history::
                    effect_decoding_receiving_bytes_v1(value.len())?)?;
            }
        }
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
            .ok()
    }

    /// Reuses the same fully validated Source projection without another reader.
    pub(crate) fn observe_once_v1(
        &mut self,
        controller: HistoricalLedgerRowsDataV2<'_>,
        source: &LifecycleHistoricalReadOriginalV1,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered = true;
            return Err(CLOSED);
        }
        self.returned = Some((|| {
            let (projection, _) = source.projection_ready_v1()?;
            self.source = Some(projection.root());
            for envelope in projection.records() {
                if envelope.key().kind() != LifecycleProtectedRecordKindV1::Operation {
                    continue;
                }
                let id = OperationId::from_bytes(envelope.key().identity()[32..48].try_into()?);
                if self.entries.iter().any(|entry| {
                    entry
                        .source
                        .completed_v1()
                        .is_some_and(|(_, operation, _)| operation.operation_id() == id)
                }) {
                    continue;
                }
                self.entries
                    .try_reserve_exact(1)
                    .map_err(|_| JournalError::JournalTooLarge)?;
                self.entries.push(Entry::new());
                self.entries
                    .last_mut()
                    .ok_or(CLOSED)?
                    .observe(controller, source, id)?;
            }
            self.controller = Some(controller_commitment(controller, &self.entries)?);
            Ok(())
        })());
        self.entries_v1().map(|_| ())
    }

    /// Rejoins the exact retained rows; native provenance stays with the caller.
    pub(crate) fn require_same_v1(
        &self,
        controller: HistoricalLedgerRowsDataV2<'_>,
        source: &LifecycleHistoricalReadOriginalV1,
    ) -> Result<(), JournalError> {
        self.entries_v1()?;
        if self.controller != Some(controller_commitment(controller, &self.entries)?)
            || self.source != Some(source.projection_ready_v1()?.0.root())
        {
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(crate) fn entries_v1(
        &self,
    ) -> Result<impl Iterator<Item = &CompletedStopHistoryDataV1>, JournalError> {
        if self.reentered || !matches!(self.returned, Some(Ok(()))) || self.failure().is_some() {
            return Err(CLOSED);
        }
        Ok(self.entries.iter().filter_map(|entry| entry.data.as_ref()))
    }

    pub(crate) fn require_scope_v1(
        &self,
        scope: &HostStoppedNamespaceDataV4,
    ) -> Result<CompletedStopHistoryDataV1, JournalError> {
        self.entries_v1()?;
        let mut selected = None;
        for entry in &self.entries {
            let candidate = if let Some(data) = entry.data {
                (data.historical_scope_v1() == scope).then_some(data)
            } else if let Some((operation, project, sandbox, fence, dispatch, record)) =
                entry.ordinary
            {
                (scope.stop_v4() == dispatch && require_source_fence(scope, fence).is_ok())
                    .then_some(CompletedStopHistoryDataV1 {
                        completion: None,
                        scope: *scope,
                        operation,
                        record,
                        project,
                        sandbox,
                        source_fence: fence,
                    })
            } else {
                None
            };
            if let Some(data) = candidate {
                if selected.replace(data).is_some() {
                    return Err(CLOSED);
                }
            }
        }
        selected.ok_or(CLOSED)
    }

    /// Reports completed logical Stop history before a fresh physical census.
    /// This grants no absence, retained-resource population or native permission.
    pub(crate) fn has_completed_stops_v1(&self) -> Result<bool, JournalError> {
        self.entries_v1()?;
        Ok(self
            .entries
            .iter()
            .any(|entry| entry.data.is_some() || entry.ordinary.is_some()))
    }

    /// Classifies only the exact public operations proved by this retained owner.
    pub(crate) fn operation_is_completed_v1(
        &self,
        operation: OperationId,
    ) -> Result<bool, JournalError> {
        self.entries_v1()?;
        Ok(self.entries.iter().any(|entry| {
            entry
                .data
                .is_some_and(|data| data.operation_v1() == operation)
                || entry.ordinary.is_some_and(|data| data.0 == operation)
        }))
    }

    /// Borrows the finite logical family without nominating a historical scope.
    pub(crate) fn completed_operations_v1(
        &self,
    ) -> Result<impl Iterator<Item = (OperationId, ProjectId, SandboxId)> + '_, JournalError> {
        self.entries_v1()?;
        Ok(self.entries.iter().filter_map(|entry| {
            entry
                .data
                .map(|data| (data.operation_v1(), data.project_v1(), data.sandbox_v1()))
                .or_else(|| entry.ordinary.map(|data| (data.0, data.1, data.2)))
        }))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entries
            .iter()
            .find_map(Entry::failure)
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref() as _)
            })
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn require_source_fence(
    scope: &HostStoppedNamespaceDataV4,
    source: crate::lifecycle::LiveRuntimeFenceV1,
) -> Result<(), JournalError> {
    let fence = scope.fence_v4();
    let desired = source.desired();
    // Runtime admission captures the original manifest generation/digest.
    // These are distinct from a later public desired-Stopped generation.
    if fence.sandbox_id() != source.sandbox().as_bytes()
        || fence.incarnation_id() != source.incarnation().as_bytes()
        || fence.assignment_epoch() != source.assignment_epoch().get()
        || fence.desired_generation() != desired.expected_generation().get()
        || fence.desired_generation() != desired.resource_revision().get()
        || fence.assignment_digest() != desired.resource_state().digest().as_bytes()
    {
        return Err(CLOSED);
    }
    Ok(())
}

fn row<'rows>(
    rows: HistoricalLedgerRowsDataV2<'rows>,
    namespace: RecordNamespace,
    key: &[u8],
) -> Result<&'rows [u8], JournalError> {
    rows.all_records()
        .find(|(actual, name, _)| *actual == namespace && *name == key)
        .map(|(_, _, value)| value)
        .ok_or(CLOSED)
}

fn require_receipt(
    state: &EffectState,
    operation: OperationId,
    source: ObjectDigest,
) -> Result<(), Cause> {
    let EffectState::Applied { receipt, .. } = state else {
        return Err(CLOSED.into());
    };
    let LifecycleEffectReceiptDataV1::Ordinary {
        operation: receipt_id,
        source: receipt_source,
    } = decode_lifecycle_effect_receipt_v1(receipt.as_bytes(), [0; 16])?
    else {
        return Err(CLOSED.into());
    };
    if receipt_id != operation || receipt_source != source {
        return Err(CLOSED.into());
    }
    Ok(())
}

fn controller_commitment(
    rows: HistoricalLedgerRowsDataV2<'_>,
    entries: &[Entry],
) -> Result<[u8; 32], JournalError> {
    let mut hash = Sha256::new().chain_update(b"aos.sandbox.completed-stop.controller-rows.v1\0");
    // Genuine maintenance snapshots may advance other Controller families.
    // Rejoin the literal Stop completion rows; the actual enclosing native
    // owner separately validates every permitted successor and current policy.
    for entry in entries {
        let id = if let Some(data) = entry.data {
            data.operation_v1()
        } else if let Some(data) = entry.ordinary {
            data.0
        } else {
            continue;
        };
        let effect = effect_key(id, 0);
        for (namespace, key) in [
            (RecordNamespace::Operation, id.as_bytes().as_slice()),
            (RecordNamespace::Effect, effect.as_slice()),
        ] {
            let value = row(rows, namespace, key)?;
            hash.update((namespace as u16).to_be_bytes());
            hash.update((key.len() as u64).to_be_bytes());
            hash.update(key);
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn historical_launch_generation_and_assignment_digest_are_full_source_fence_fields() {
        use crate::lifecycle::{
            DesiredStateFenceV1, LifecycleResourceStateDigestV1,
            LiveRuntimeFenceV1,
        };
        use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1;
        use aos_sandbox_core::{
            AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, Revision,
        };
        let mut bytes = [1; 328];
        bytes[..8].copy_from_slice(b"AOSHNS04");
        bytes[8..24].copy_from_slice(&[6; 16]);
        bytes[40..56].copy_from_slice(&[2; 16]);
        bytes[56..64].copy_from_slice(&3_u64.to_le_bytes());
        bytes[64..72].copy_from_slice(&4_u64.to_le_bytes());
        bytes[72..104].copy_from_slice(&[5; 32]);
        bytes[104..136].copy_from_slice(&[7; 32]);
        bytes[136..168].copy_from_slice(&aos_sandbox_protocol::semantics::host::runtime_handle_v1(
            &[2; 16], 3, &[5; 32],
        ));
        // Canonical Launch and Stop requests have distinct signed identities.
        bytes[168..184].copy_from_slice(&[8; 16]);
        bytes[184..216].copy_from_slice(&[9; 32]);
        bytes[216..248].copy_from_slice(&[10; 32]);
        bytes[248..264].copy_from_slice(&[11; 16]);
        bytes[264..296].copy_from_slice(&[12; 32]);
        bytes[296..328].copy_from_slice(&[13; 32]);
        let scope = HostStoppedNamespaceDataV4::decode_v4(&bytes).unwrap();
        let mut duplicate_signature = bytes;
        duplicate_signature[296..328].copy_from_slice(&scope.launch_v4().2);
        assert!(HostStoppedNamespaceDataV4::decode_v4(&duplicate_signature).is_err());
        let sandbox = SandboxId::from_bytes([1; 16]);
        let source = |generation, digest| {
            LiveRuntimeFenceV1::new(
                sandbox,
                DesiredStateFenceV1::new(
                    LifecycleResourceV1::Sandbox(sandbox),
                    DesiredGeneration::new(generation),
                    Revision::new(generation),
                    LifecycleResourceStateDigestV1::from_stored(ObjectDigest::from_bytes(digest))
                        .unwrap(),
                )
                .unwrap(),
                IncarnationId::from_bytes([2; 16]),
                AssignmentEpoch::new(3),
                NamespaceGeneration::new(8),
            )
            .unwrap()
        };

        assert!(require_source_fence(&scope, source(4, [5; 32])).is_ok());
        // The current desired-Stopped generation can be seven; it cannot
        // substitute for the original manifest's Launch generation four.
        assert!(require_source_fence(&scope, source(7, [5; 32])).is_err());
        assert!(require_source_fence(&scope, source(4, [9; 32])).is_err());
    }

    #[test]
    fn applied_stop_must_name_the_exact_selected_a8_not_the_failed_operation_record() {
        use aos_sandbox_protocol::domain_ledger::effect_history::{
            EffectReceipt, encode_lifecycle_effect_receipt_v1,
        };
        let operation = OperationId::from_bytes([1; 16]);
        let completion = ObjectDigest::from_bytes([2; 32]);
        let old_failed_source = ObjectDigest::from_bytes([3; 32]);
        let state = |source| EffectState::Applied {
            attempt: 1,
            receipt: EffectReceipt::from_bytes_unchecked(
                encode_lifecycle_effect_receipt_v1(operation, source).to_vec(),
            ),
        };

        assert!(require_receipt(&state(completion), operation, completion).is_ok());
        assert!(require_receipt(&state(old_failed_source), operation, completion).is_err());
        assert!(
            require_receipt(
                &state(completion),
                OperationId::from_bytes([4; 16]),
                completion
            )
            .is_err()
        );
        assert!(require_receipt(&EffectState::Planned, operation, completion).is_err());
    }

    #[test]
    fn empty_valid_source_proves_no_stop_and_reentry_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let (source, _) = Journal::open(
            directory.path().join("source"),
            crate::JournalLimits::default(),
        )
        .unwrap();
        let mut replay = LifecycleHistoricalReadOriginalV1::new();
        replay.observe_projection_once_v1(&source).unwrap();
        let controller = BTreeMap::new();
        let index = BTreeMap::new();
        let rows = HistoricalLedgerRowsDataV2::new(&controller, &index);
        let mut original = CompletedStopHistoryOriginalV1::new();

        original.observe_once_v1(rows, &replay).unwrap();
        original.require_same_v1(rows, &replay).unwrap();
        assert!(!original.has_completed_stops_v1().unwrap());
        assert!(
            !original
                .operation_is_completed_v1(OperationId::from_bytes([1; 16]))
                .unwrap()
        );

        let changed = BTreeMap::from([((RecordNamespace::Operation, vec![1; 16]), vec![2; 8])]);
        // Unrelated Controller families remain the native caller's concern;
        // this empty logical proof still cannot classify even one Stop.
        original
            .require_same_v1(HistoricalLedgerRowsDataV2::new(&changed, &index), &replay)
            .unwrap();
        assert!(!original.has_completed_stops_v1().unwrap());
        assert!(original.observe_once_v1(rows, &replay).is_err());
        let cause = original.failure().unwrap().to_string();
        assert!(original.entries_v1().is_err());
        assert!(original.observe_once_v1(rows, &replay).is_err());
        assert_eq!(original.failure().unwrap().to_string(), cause);
    }
}
