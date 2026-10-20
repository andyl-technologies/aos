//! Produces the exact unaccepted operation and batch on real authorized C17.
//!
//! The same completed Cache query retains full Source/C rows and verified
//! metadata. This owner pays closure, lifecycle, encoder and decoder planes
//! before growth, and owns both kernel identity samples through their owed
//! clock posts. Output remains DATA until the actual Collection binds all six
//! originals and the Source pending consumer rechecks every native predecessor.

use super::*;
use aos_sandbox_core::{OperationId, ResourceDimension as D, ResourceVector, SandboxId};
use aos_sandbox_ledger_replay::delete_graph::{
    DeleteDependencyGraphDataV2, DeleteGraphSelectionDataV2, DeleteGraphSelectionErrorV2,
};
use aos_sandbox_protocol::domain_ledger::{
    delete_batch::{
        DeleteBatchCommitmentsDataV2, DeleteBatchDependencyDataV1, DeleteBatchEncodingDataV1,
        DeleteBatchOwnerCutDataV1, DeleteBatchOwnerCutDataV2, DeleteBatchViewV1,
        DeleteBatchWriteDataV1, LifecycleDeleteBatchV1, native_value_digest,
    },
    lifecycle_model::{LifecycleModelError, LifecycleResourceV1 as Resource},
    provisioning_resources::{
        ProvisioningCompanionRetirementDataV2, ProvisioningCompanionRetirementErrorV2,
        ProvisioningResourceRowKindV1 as CompanionKind,
    },
};
use crate::cache_residency::CacheDeleteInventoryOriginalV1;
use crate::lifecycle::{
    DeleteCandidateOperationErrorV2, LifecycleOperationV1, ResourceExpectationV1,
    authorized_delete_operation_data_v2, delete_candidate_projection_generation_data_v2,
};
use crate::JournalError;

#[derive(Debug, thiserror::Error)]
enum CandidateErrorV2 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Reservation(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Selection(#[from] DeleteGraphSelectionErrorV2),
    #[error(transparent)]
    GraphComparison(#[from] crate::lifecycle::delete_batch_comparison::DeleteGraphBatchComparisonErrorV2),
    #[error(transparent)]
    Operation(#[from] DeleteCandidateOperationErrorV2),
    #[error(transparent)]
    Public(#[from] crate::lifecycle::LifecyclePublicMutationAdmissionErrorV1),
    #[error(transparent)]
    Model(#[from] LifecycleModelError),
    #[error(transparent)]
    Companion(#[from] ProvisioningCompanionRetirementErrorV2),
    #[error("the bounded Delete candidate allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
}

#[derive(Clone, Copy)]
enum First {
    Begin(usize),
    Body,
    After(usize),
    Reentry,
}

// This first field runs before any native/error carrier can be destroyed.
// Successful pure DATA needs no permanent native-custody guard after all posts.
struct CandidateDispositionGuardV2 {
    armed: bool,
}

impl Drop for CandidateDispositionGuardV2 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

/// Retains an actual paid candidate and every entered identity/clock refusal.
///
/// No public constructor or adoption exists. A successful take returns only
/// canonical operation/batch DATA, without an acceptance or effect token.
#[doc(hidden)]
#[must_use = "retain an entered failed candidate with its actual Source/C17 originals"]
pub struct ControllerDeleteCandidateOriginalV2 {
    disposition: CandidateDispositionGuardV2,
    identities: [PlanningNonce; 2],
    begins: [Option<Result<(), JournalError>>; 2],
    body: Option<Result<(LifecycleOperationV1, LifecycleDeleteBatchV1), CandidateErrorV2>>,
    afters: [Option<Result<(), JournalError>>; 2],
    first: Option<First>,
    reentry: Option<JournalError>,
    taken: bool,
}

impl ControllerDeleteCandidateOriginalV2 {
    fn demand_v2(graph: &DeleteDependencyGraphDataV2) -> Result<ResourceVector, JournalError> {
        type LocalPlanes<'bytes> = (
            DeleteBatchEncodingDataV1<'bytes, 'bytes>,
            [DeleteBatchOwnerCutDataV2; 6],
            DeleteBatchCommitmentsDataV2,
            Vec<DeleteBatchWriteDataV1<'bytes>>,
            Vec<DeleteBatchDependencyDataV1>,
            Vec<[u8; aos_sandbox_protocol::domain_ledger::provisioning_resources::
                PROVISIONING_RESOURCE_KEY_BYTES_V1]>,
            Vec<ProvisioningCompanionRetirementDataV2>,
        );
        let resources = graph.projections.len()
            .checked_add(graph.companions.len().checked_mul(2).ok_or(JournalError::JournalTooLarge)?)
            .ok_or(JournalError::JournalTooLarge)?;
        let rows = resources.checked_mul(
            std::mem::size_of::<ResourceExpectationV1>()
                .checked_add(std::mem::size_of::<DeleteBatchWriteDataV1<'_>>())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u8>>()))
                .ok_or(JournalError::JournalTooLarge)?,
        ).and_then(|bytes| bytes.checked_mul(3)).ok_or(JournalError::JournalTooLarge)?;
        let edges = graph.edges.len().checked_mul(std::mem::size_of::<DeleteBatchDependencyDataV1>())
            .and_then(|bytes| bytes.checked_mul(3)).ok_or(JournalError::JournalTooLarge)?;
        let companions = graph.companions.len().checked_mul(
            std::mem::size_of::<ProvisioningCompanionRetirementDataV2>()
                .checked_add(2 * aos_sandbox_protocol::domain_ledger::provisioning_resources::
                    PROVISIONING_RESOURCE_KEY_BYTES_V1)
                .and_then(|bytes| bytes.checked_add(2 * aos_sandbox_protocol::domain_ledger::
                    provisioning_resources::PROVISIONING_RESOURCE_ROW_BYTES_V1))
                .ok_or(JournalError::JournalTooLarge)?,
        ).and_then(|bytes| bytes.checked_mul(3)).ok_or(JournalError::JournalTooLarge)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<LocalPlanes<'_>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                super::ControllerDeletePlanningRootCutDataV1>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(graph.selection_receiving_bytes_v2()?))
            .and_then(|bytes| bytes.checked_add(crate::lifecycle::delete_batch_comparison::
                delete_graph_batch_comparison_bytes_v2()?))
            .and_then(|bytes| bytes.checked_add(rows))
            .and_then(|bytes| bytes.checked_add(edges))
            .and_then(|bytes| bytes.checked_add(companions))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<LifecycleOperationV1>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::lifecycle::LifecycleStepV1>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let nonce = PlanningNonce::demand_v1()?;
        ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .checked_add(nonce).and_then(|demand| demand.checked_add(nonce))
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Borrows the selected first cause while both native identity owners live.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Begin(index) => self.identities[index].failure()
                .or_else(|| self.begins[index].as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::After(index) => self.identities[index].failure()
                .or_else(|| self.afters[index].as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    /// Moves the two prepared DATA values once after both independent posts.
    ///
    /// # Errors
    /// Refuses a failed, incomplete or repeated take without changing custody.
    pub fn take_prepared_once_v2(
        &mut self,
    ) -> Result<(LifecycleOperationV1, LifecycleDeleteBatchV1), JournalError> {
        if self.first.is_some() || self.taken
            || !self.afters.iter().all(|result| matches!(result, Some(Ok(()))))
            || !matches!(self.body, Some(Ok(_)))
        {
            self.disposition.armed = true;
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.taken = true;
        match self.body.take() {
            Some(Ok(data)) => Ok(data),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }
}

impl ControllerDeleteSourceAuthorizedScopeV1<'_, '_> {
    pub(crate) fn prepare_candidate_once_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        cache: &CacheDeleteInventoryOriginalV1<'_>,
        request_scope: crate::ControllerRequestScopeV1,
        owners: [DeleteBatchOwnerCutDataV2; 6],
        initial_six: [u8; 32],
    ) -> Result<ControllerDeleteCandidateOriginalV2, ResourceReservationErrorV1> {
        bank.require_delete_candidate_cache_v2(cache, self, controller, profile)?;
        let graph = cache.dependency_graph_data_v2()?;
        let demand = ControllerDeleteCandidateOriginalV2::demand_v2(graph)?;
        bank.reserve_delete_candidate_v2(self, controller, profile, demand)?;
        let mut original = ControllerDeleteCandidateOriginalV2 {
            disposition: CandidateDispositionGuardV2 { armed: true },
            identities: [PlanningNonce::new(&self.authorization), PlanningNonce::new(&self.authorization)],
            begins: std::array::from_fn(|_| None), body: None,
            afters: std::array::from_fn(|_| None), first: None, reentry: None, taken: false,
        };
        for index in 0..2 {
            if original.first.is_none() {
                original.begins[index] = Some(original.identities[index].begin_once());
                if !matches!(original.begins[index], Some(Ok(()))) {
                    original.first = Some(First::Begin(index));
                }
            }
        }
        if original.first.is_none() {
            original.body = Some(self.candidate_body_v2(
                bank, controller, profile, graph, request_scope, owners, initial_six,
                &original.identities,
            ));
            if !matches!(original.body, Some(Ok(_))) {
                original.first = Some(First::Body);
            }
        }
        // These destinations were paid before either primary. Refusal never
        // obtains another healthy debit or suppresses an independent after.
        for index in 0..2 {
            original.afters[index] = Some(original.identities[index].finish_once());
            if !matches!(original.afters[index], Some(Ok(()))) {
                original.first.get_or_insert(First::After(index));
            }
        }
        if original.first.is_none() {
            original.disposition.armed = false;
        }
        Ok(original)
    }

    fn candidate_body_v2(
        &mut self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        graph: &DeleteDependencyGraphDataV2,
        request_scope: crate::ControllerRequestScopeV1,
        owners: [DeleteBatchOwnerCutDataV2; 6],
        initial_six: [u8; 32],
        identities: &[PlanningNonce; 2],
    ) -> Result<(LifecycleOperationV1, LifecycleDeleteBatchV1), CandidateErrorV2> {
        use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
        let authorized = self.authorization.authorization();
        let DormantSandboxRequestKindV1::Delete(request) = authorized.request().request() else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        let sandbox: [u8; 16] = request.sandbox_id.as_slice().try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let selection = graph.select_dependent_closure_data_v2(
            SandboxId::from_bytes(sandbox), request.cascade,
        )?;
        let flags = u8::from(request.cascade) | (u8::from(request.force) << 1);
        let expected_graph: Option<[u8; 32]> = if request.expected_plan_digest.is_empty() {
            None
        } else {
            Some(request.expected_plan_digest.as_slice().try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?)
        };
        let caller = authorized.caller();
        let project = authorized.project();
        let request_digest = request_scope.public_request_digest(
            caller, project, self.authorization.input(),
        );
        let operation_id = OperationId::from_bytes(identities[0].coordinates()?.0);
        let transaction = identities[1].coordinates()?.0;
        if transaction == operation_id.into_bytes()
            || controller.get(aos_sandbox_core::RecordNamespace::Operation,
                operation_id.as_bytes()).is_some()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let operation = authorized_delete_operation_data_v2(
            &self.authorization, operation_id, graph, &selection,
        )?;
        let mut companions = Vec::new();
        companions.try_reserve_exact(graph.companions.len())?;
        for original in &graph.companions {
            let fields = original.fields_v1();
            if selection.resources.binary_search(&Resource::Other(fields.assignment)).is_ok() {
                companions.push(ProvisioningCompanionRetirementDataV2::from_data_v2(
                    *original, operation_id, transaction,
                )?);
            }
        }
        companions.sort_by_key(|descriptor| descriptor.original_v1().fields_v1().parent);

        // Companion keys are materialized only after their exact fixed recipe
        // was paid. Public keys/values remain borrowed from the complete graph.
        let mut companion_keys = Vec::new();
        companion_keys.try_reserve_exact(companions.len().checked_mul(2)
            .ok_or(JournalError::JournalTooLarge)?)?;
        for descriptor in &companions {
            let original = descriptor.original_v1();
            for kind in [CompanionKind::Assignment, CompanionKind::Reservation] {
                companion_keys.push(original.key_v1(kind));
            }
        }
        let mut writes = Vec::new();
        writes.try_reserve_exact(selection.resources.len())?;
        for row in &graph.projections {
            if selection.resources.binary_search(&row.resource).is_ok() {
                writes.push(DeleteBatchWriteDataV1 {
                    resource: row.resource, key: &row.key,
                    before_generation: delete_candidate_projection_generation_data_v2(&row.record)?,
                    before_digest: native_value_digest(&row.original),
                });
            }
        }
        for (index, descriptor) in companions.iter().enumerate() {
            let original = descriptor.original_v1();
            let fields = original.fields_v1();
            for (offset, kind, resource) in [
                (0, CompanionKind::Assignment, fields.assignment),
                (1, CompanionKind::Reservation, fields.reservation),
            ] {
                writes.push(DeleteBatchWriteDataV1 {
                    resource: Resource::Other(resource), key: &companion_keys[index * 2 + offset],
                    before_generation: 1, before_digest: native_value_digest(&original.encode_v1(kind)),
                });
            }
        }
        writes.sort_by(|left, right| left.key.cmp(right.key));
        let mut dependencies = Vec::new();
        dependencies.try_reserve_exact(selection.dependencies.len())?;
        for relation in &selection.dependencies {
            dependencies.push(DeleteBatchDependencyDataV1 {
                dependent: relation.edge.dependent(), dependency: relation.edge.dependency(),
                class: relation.class.code_v2(),
            });
        }
        let (controller_next, source_next) = bank.delete_candidate_boundaries_v2(
            self, controller, profile,
        )?;
        let base = self.planning_base_cuts_v2(bank, controller, profile)?;
        let input = DeleteBatchEncodingDataV1 {
            project: graph.project, operation: operation_id, transaction,
            root: Resource::Sandbox(selection.root), flags,
            before_sequence: controller_next, authority_epoch: 0,
            commitments: [request_digest, [0; 32], [0; 32], [0; 32], [0; 32]],
            owners: owners.map(|owner| DeleteBatchOwnerCutDataV1 {
                sequence: 0, count: owner.count, digest: owner.digest,
            }),
            writes: &writes, reads: &[], collections: &[],
            dependencies: &dependencies, postorder: &selection.postorder,
        };
        let length = input.encoded_length_with_companions_v2(companions.len())?;
        let bytes = length.checked_mul(3)
            .and_then(|bytes| bytes.checked_add(DeleteBatchViewV1::decode_receiving_bytes_v1(length)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        bank.reserve_delete_candidate_v2(self, controller, profile,
            ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        let batch = LifecycleDeleteBatchV1::from_encoding_with_native_cuts_v2(
            &input, DeleteBatchCommitmentsDataV2 {
                authorization: base.authorization, source: base.source,
                controller: base.controller, initial_six,
            }, source_next, owners, &companions,
        )?;
        crate::lifecycle::delete_batch_comparison::require_delete_graph_batch_data_v2(
            graph, &selection, batch.view()?,
        )?;
        let graph_plan = batch.view()?.graph_plan();
        if expected_graph.is_some_and(|expected| expected != graph_plan) {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok((operation, batch))
    }
}
