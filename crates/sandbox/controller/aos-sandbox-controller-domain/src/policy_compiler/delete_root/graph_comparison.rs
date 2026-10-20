//! Retains Root's paid request, closure and complete batch comparison results.
//!
//! The graph comes only from this flight's completed native object reader. The
//! request comes from the independently verified authorization witness. Neither
//! the received batch nor its claimed selection can substitute for these owners.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector, SandboxId};
use aos_sandbox_ledger_replay::delete_graph::{DeleteGraphSelectionDataV2, DeleteGraphSelectionErrorV2};
use aos_sandbox_protocol::{
    domain_ledger::delete_batch::DeleteBatchViewV1,
    public_api::{
        mutation::{ResolvedPublicMutationRequestV1, PublicMutationResolutionErrorV1},
        projection::PublicProjectionResourceV1,
        request::DormantSandboxRequestKindV1,
    },
};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::journal::JournalError;
use crate::lifecycle::delete_batch_comparison::{
    DeleteGraphBatchComparisonErrorV2, delete_graph_batch_comparison_bytes_v2,
    require_delete_graph_batch_data_v2,
};
use std::error::Error;

#[derive(Clone, Copy)]
enum First { Geometry, Funding, Request, Selection, Comparison, Reentry }

#[derive(Debug, thiserror::Error)]
enum ComparisonErrorV2 {
    #[error(transparent)]
    Original(#[from] RootDeleteErrorV1),
    #[error(transparent)]
    Model(#[from] aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError),
    #[error(transparent)]
    Graph(#[from] DeleteGraphBatchComparisonErrorV2),
    #[error("the Root-owned canonical request, current version or selected graph differs")]
    Changed,
}

#[derive(Default)]
pub(crate) struct RootDeleteGraphComparisonOriginalV2 {
    demand: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    request: Option<Result<ResolvedPublicMutationRequestV1, PublicMutationResolutionErrorV1>>,
    selection: Option<Result<DeleteGraphSelectionDataV2, DeleteGraphSelectionErrorV2>>,
    compared: Option<Result<(), ComparisonErrorV2>>,
    first: Option<First>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteGraphComparisonOriginalV2 {
    fn demand_v2(
        graph: &RootDeleteGraphObjectsOriginalV2,
        body: &body::RootDeleteBatchReceivingV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
    ) -> Result<ResourceVector, JournalError> {
        let graph = graph.verified_graph_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let batch = body.bytes_for_graph_comparison_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let input = controller.verified_authorized_input_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(graph.selection_receiving_bytes_v2()?))
            .and_then(|bytes| bytes.checked_add(delete_graph_batch_comparison_bytes_v2()?))
            .and_then(|bytes| bytes.checked_add(DeleteBatchViewV1::decode_receiving_bytes_v1(batch.len())?))
            .and_then(|bytes| bytes.checked_add(crate::public_mutation_compiler::delete_admission::geometry::
                delete_decode_bytes_v1(input.len())?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.first.is_some() || self.funding.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        graph_original: &RootDeleteGraphObjectsOriginalV2,
        body: &body::RootDeleteBatchReceivingV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.demand = Some(Self::demand_v2(graph_original, body, controller));
        if !matches!(self.demand, Some(Ok(_))) {
            self.first = Some(First::Geometry);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.funding = Some(flight.admit_delete_graph_comparison_v2(graph_original, self));
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.request = Some(ResolvedPublicMutationRequestV1::decode_delete(
            controller.verified_authorized_input_v2()?));
        if !matches!(self.request, Some(Ok(_))) {
            self.first = Some(First::Request);
            return Err(RootDeleteErrorV1::Opening);
        }
        let graph = graph_original.verified_graph_v2()?;
        let request = self.request.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)?;
        let DormantSandboxRequestKindV1::Delete(request) = request.request() else {
            self.first = Some(First::Request);
            return Err(RootDeleteErrorV1::Opening);
        };
        let sandbox = request.sandbox_id.as_slice().try_into()
            .map(SandboxId::from_bytes).map_err(|_| RootDeleteErrorV1::Original)?;
        self.selection = Some(graph.select_dependent_closure_data_v2(sandbox, request.cascade));
        if !matches!(self.selection, Some(Ok(_))) {
            self.first = Some(First::Selection);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.compared = Some((|| {
            let selection = self.selection.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ComparisonErrorV2::Changed)?;
            let batch = DeleteBatchViewV1::decode(body.bytes_for_graph_comparison_v2()?)?;
            let original = graph.projections.iter().find(|row| {
                row.resource == aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(sandbox)
            }).ok_or(ComparisonErrorV2::Changed)?;
            let PublicProjectionResourceV1::Sandbox(original) = original.record.resource() else {
                return Err(ComparisonErrorV2::Changed);
            };
            let mutation = request.mutation.as_option().ok_or(ComparisonErrorV2::Changed)?;
            if mutation.expected_resource_version.as_slice() != original.resource_version.as_slice()
                || batch.flags() != (u8::from(request.cascade) | (u8::from(request.force) << 1))
                || (!request.expected_plan_digest.is_empty()
                    && request.expected_plan_digest.as_slice() != batch.graph_plan().as_slice())
            {
                return Err(ComparisonErrorV2::Changed);
            }
            require_delete_graph_batch_data_v2(graph, selection, batch)?;
            Ok(())
        })());
        if !matches!(self.compared, Some(Ok(()))) {
            self.first = Some(First::Comparison);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        Ok(())
    }

    pub(super) fn selected_root_v2(&self) -> Result<aos_sandbox_model::SandboxId, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        self.selection.as_ref().and_then(|value| value.as_ref().ok())
            .map(|selection| selection.root).ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn selection_data_v2(&self) -> Result<&DeleteGraphSelectionDataV2, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        self.selection.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(crate) fn require_completed_v2(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete && self.first.is_none() && matches!(self.compared, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootDeleteErrorV1::Original)
        }
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(First::Funding))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry => cause(&self.demand),
            First::Funding => cause(&self.funding),
            First::Request => cause(&self.request),
            First::Selection => cause(&self.selection),
            First::Comparison => cause(&self.compared),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
