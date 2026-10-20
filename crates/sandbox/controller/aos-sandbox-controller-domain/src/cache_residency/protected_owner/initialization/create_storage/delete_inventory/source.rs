//! Keeps the two genuine Delete Cache predecessors on one local query engine.
//!
//! Planning borrows the actual authorized pair and obtains entropy/horizon from
//! its same retained decision. Preaccept borrows the intrinsic pending fence
//! and live verified Root challenge. Neither entrance accepts a nonce, scalar
//! admission, J/U loan, decoded challenge or historical inventory as authority.

use super::*;
use crate::public_mutation_compiler::delete_admission::{
    ControllerDeleteSourceAuthorizedScopeV1, DeleteAuthorizationBindingV1, PlanningNonce,
};
use crate::journal::{SourceDeleteSemanticScopeV1, SourceDeletePendingFenceV1};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerDeletePreacceptTurnOriginalV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;

pub(super) enum CacheQuerySourceV1<'query, 'fence, 'journal, 'original, 'authorization> {
    Planning {
        source: &'query mut SourceDeleteSemanticScopeV1<'journal, 'original>,
        authorization: &'query DeleteAuthorizationBindingV1<'authorization>,
        nonce: PlanningNonce,
    },
    Preaccept {
        fence: SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>,
        challenge: &'query crate::normal_root::RootDeleteChallengeLoanV1<'query>,
    },
}

impl<'query, 'scope, 'original> CacheQuerySourceV1<'query, 'query, 'scope, 'original, 'scope> {
    // The actual pair alone performs this split. A foreign authorization cannot
    // be joined to the Source borrower through this private constructor.
    pub(super) fn planning(
        pair: &'query mut ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
    ) -> Self {
        let (authorization, source) = pair.planning_parts_v1();
        let nonce = PlanningNonce::new(authorization);
        Self::Planning { source, authorization, nonce }
    }
}

impl CacheQuerySourceV1<'_, '_, '_, '_, '_> {
    pub(super) fn metadata_graph_receiving_demand_v2(&self, controller: &Journal) -> Result<ResourceVector, JournalError> {
        match self {
            Self::Planning { source, .. } => source.metadata_graph_receiving_demand_v2(controller),
            Self::Preaccept { fence, .. } => fence.metadata_graph_receiving_demand_v2(controller),
        }
    }

    pub(super) fn metadata_graph_requests_v2(&self, controller: &Journal)
        -> Result<(aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2,
            Vec<crate::journal::SourceDeleteMetadataRequestDataV2>),
            crate::journal::SourceDeleteMetadataRequestErrorV2>
    {
        match self {
            Self::Planning { source, authorization, .. } => source.metadata_graph_requests_v2(
                controller, authorization.authorization().project()),
            Self::Preaccept { fence, challenge } => fence.metadata_graph_requests_v2(
                controller, aos_sandbox_model::ProjectId::from_bytes(challenge.open_v2().project)),
        }
    }

    pub(super) fn dependency_graph_receiving_demand_v2(&self, controller: &Journal,
        metadata_links: usize,
    ) -> Result<ResourceVector, JournalError> {
        match self {
            Self::Planning { source, .. } => source.dependency_graph_receiving_demand_v2(controller, metadata_links),
            Self::Preaccept { fence, .. } => fence.dependency_graph_receiving_demand_v2(controller, metadata_links),
        }
    }

    pub(super) fn finish_dependency_graph_metadata_data_v2<'metadata>(&self,
        base: aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2,
        controller: &Journal,
        metadata: &[aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2<'metadata>],
    ) -> Result<crate::journal::DeleteDependencyGraphDataV2, crate::journal::SourceDeleteGraphErrorV2> {
        match self {
            Self::Planning { source, .. } => source.finish_dependency_graph_metadata_data_v2(
                base, controller, metadata),
            Self::Preaccept { fence, .. } => fence.finish_dependency_graph_metadata_data_v2(
                base, controller, metadata),
        }
    }

    pub(super) fn finish_outer_failure_once_v1(&mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        match self {
            Self::Planning { source, .. } => source.finish_native_once_v1(controller, launch, profile),
            Self::Preaccept { fence, .. } => fence.finish_failed_outer_scope_once_v1(controller, launch, profile),
        }
    }

    pub(super) fn reserve_additional_v1(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ResourceVector,
    ) -> Result<(), JournalError> {
        match self {
            // These named Source ports use the same genuine D17 private turn
            // and monotone requirement engine. They supply no Root proof.
            Self::Planning { source, .. } => source.reserve_planning_root_additional_v1(
                controller, launch, profile, additional),
            Self::Preaccept { fence, .. } => fence.reserve_preaccept_additional_v1(
                controller, launch, profile, additional),
        }
    }

    pub(super) fn prepare_turn_v1<'profile>(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerDeletePreacceptTurnOriginalV1<'profile>, JournalError> {
        match self {
            Self::Planning { source, .. } => source.prepare_planning_root_turn_v1(controller, launch, profile),
            Self::Preaccept { fence, .. } => fence.prepare_preaccept_turn_v1(
                controller, launch, profile, ResourceVector::ZERO),
        }
    }

    pub(super) fn begin_nonce_once_v1(&mut self) -> Result<(), JournalError> {
        match self {
            Self::Planning { nonce, .. } => nonce.begin_once(),
            Self::Preaccept { .. } => Ok(()),
        }
    }

    pub(super) fn finish_nonce_once_v1(&mut self) -> Result<(), JournalError> {
        match self {
            Self::Planning { nonce, .. } => nonce.finish_once(),
            Self::Preaccept { .. } => Ok(()),
        }
    }

    pub(super) fn coordinates_v1(&self) -> Result<([u8; 16], u64), JournalError> {
        match self {
            Self::Planning { nonce, .. } => nonce.coordinates(),
            Self::Preaccept { challenge, .. } => Ok((*challenge.nonce_v1(), challenge.cutoff_v1())),
        }
    }

    pub(super) fn intake_failure_view_v1<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        match self {
            Self::Planning { source, .. } => source.planning_root_intake_failure_view_v1(profile),
            Self::Preaccept { fence, .. } => fence.intake_failure_view_v1(profile),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Planning { nonce, .. } => nonce.failure(),
            Self::Preaccept { .. } => None,
        }
    }
}
