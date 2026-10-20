//! Lends only the same actual D flight's Root original to its named challenge.

mod source_predecessor;
mod graph;

use super::RootPolicyAcceptedFlightV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::policy_compiler::delete_root::{
    RootDeleteChallengeOriginalsV1, RootDeletePendingReceivingV1,
};

impl RootPolicyAcceptedFlightV1<'_, '_> {
    // The constructor and Option return each move the complete L/U guard.
    // Price this distinct Delete view at the fixed Root entry, including its
    // negative diagnostic path before later purpose admission can succeed.
    pub(in crate::normal_root) fn financial_failure_view_demand_v1()
        -> Option<aos_sandbox_core::ResourceVector>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        type View<'a> = RootDeleteFundingFailureViewV1<'a>;
        let bytes = std::mem::size_of::<View<'_>>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Option<View<'_>>>().checked_mul(2)?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::MetadataEntries, 4))
    }

    pub(crate) fn delete_exchange_financial_failure_view_v1(
        &self,
    ) -> Option<impl std::fmt::Display + '_> {
        // Diagnostics borrow the same actual original without healthy reentry.
        let guard = self.listener.startup.lock_receiving_v1().ok()?;
        guard.original_v1().delete_exchange_financial_failure_v1()?;
        Some(RootDeleteFundingFailureViewV1(guard))
    }

    pub(crate) fn admit_delete_opening_once_v1(
        &self,
        owner: &RootDeletePendingReceivingV1<'_, '_, '_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let startup = self
            .delete_cut_startup_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_opening_once_v1(owner);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn admit_delete_challenge_once_v1(
        &self,
        owner: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let startup = self
            .delete_cut_startup_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_challenge_once_v1(owner);
        receiving.finish_returned_v1(returned)
    }
}

struct RootDeleteFundingFailureViewV1<'original>(
    crate::normal_root::RootReceivingGuardV1<'original>,
);

impl std::fmt::Display for RootDeleteFundingFailureViewV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.original_v1().delete_exchange_financial_failure_v1() {
            Some(cause) => std::fmt::Display::fmt(cause, f),
            None => f.write_str("Delete Root financial failure is unavailable"),
        }
    }
}

macro_rules! chunk_arm_port {
    ($method:ident, $cut:ident, $owner:ty, $posts:ty) => {
        impl RootPolicyAcceptedFlightV1<'_, '_> {
            pub(crate) fn $method(&self, owner: &$owner, posts: &mut $posts)
                -> Result<(), crate::normal_root::NormalRootStartupErrorV1>
            {
                let startup = self.$cut()?;
                let mut receiving = startup.lock_receiving_v1().map_err(|_| crate::normal_root::NormalRootStartupErrorV1::Service)?;
                let returned = receiving.original_mut_v1().$method(startup, owner, posts);
                receiving.finish_returned_v1(returned)
            }
        }
    };
}

chunk_arm_port!(arm_delete_chunk_posts_once_v1, delete_cut_startup_v1,
    RootDeleteChallengeOriginalsV1, crate::controller_resource_reservation::RootDeleteChunkPostsV1);
chunk_arm_port!(arm_apply_chunk_posts_once_v1, apply_cut_startup_v1,
    crate::policy_compiler::storage_apply_root::RootStorageApplyOpeningOriginalV1,
    crate::controller_resource_reservation::RootApplyChunkPostsV1);


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_controller_current_v1(&self,
        challenge: &RootDeleteChallengeOriginalsV1,
        owner: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let startup = self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_controller_current_v1(challenge, owner);
        receiving.finish_returned_v1(returned)
    }
}


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn require_delete_controller_funding_original_v3(&self,
        owner: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let startup = self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().require_delete_controller_funding_original_v3(owner);
        receiving.finish_returned_v1(returned)
    }
}

chunk_arm_port!(arm_delete_planning_chunk_posts_once_v1, delete_cut_startup_v1,
    crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1,
    crate::controller_resource_reservation::RootDeleteChunkPostsV1);

// These closed entries name only actual planning originals, never a request
// vector, account, parsed claim or completion flag.
macro_rules! planning_receiving_port {
    ($method:ident, $owner:ty) => {
        impl RootPolicyAcceptedFlightV1<'_, '_> {
            pub(crate) fn $method(&self, owner: &$owner) -> Result<(),ResourceReservationErrorV1> {
                let startup = self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
                let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
                let returned = receiving.original_mut_v1().$method(owner);
                receiving.finish_returned_v1(returned)
            }
        }
    };
}

planning_receiving_port!(admit_delete_planning_opening_once_v1, crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1);
planning_receiving_port!(admit_delete_planning_challenge_once_v1, crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1);
planning_receiving_port!(admit_delete_planning_read_once_v1, crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1);
planning_receiving_port!(require_delete_planning_funding_original_v3, crate::policy_compiler::delete_root::RootDeletePlanningDispatchOriginalV1);

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_source_current_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if source.is_final_read_v2() {
            controller.retained_receiving_demand_v1()?;
            let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
                source.receiving_demand_v1()?,
            );
            self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            return self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
                .and_then(|mut receiving| receiving.admit_delete_fresh_source_fixed_once_v2(demand))
                .map_err(|_| ResourceReservationErrorV1::Conflict);
        }
        let startup = self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_source_current_v1(challenge, controller, source);
        receiving.finish_returned_v1(returned)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_floor_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        floor: &crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if floor.is_final_read_v2() {
            challenge.retained_receiving_demand_v1()?;
            controller.retained_receiving_demand_v1()?;
            source.retained_receiving_demand_v1()?;
            let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
                floor.receiving_demand_v1()?,
            );
            self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            return self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
                .and_then(|mut receiving| receiving.admit_delete_fresh_floor_once_v2(demand))
                .map_err(|_| ResourceReservationErrorV1::Conflict);
        }
        let startup = self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_floor_v1(challenge, controller, source, floor);
        receiving.finish_returned_v1(returned)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_transfer_namespace_v1(&mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        floor: &crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
        namespace: &crate::policy_compiler::delete_root::RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if namespace.is_final_read_v2() {
            challenge.retained_receiving_demand_v1()?;
            controller.retained_receiving_demand_v1()?;
            source.retained_receiving_demand_v1()?;
            floor.retained_receiving_demand_v1()?;
            let bootstrap = namespace.final_admission_is_bootstrap_v2()?;
            let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
                namespace.receiving_demand_v1()?,
            );
            self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            return self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
                .and_then(|mut receiving| {
                    if bootstrap { receiving.admit_delete_fresh_transfer_trust_once_v2(demand) }
                    else { receiving.admit_delete_fresh_transfer_once_v2(demand) }
                }).map_err(|_| ResourceReservationErrorV1::Conflict);
        }
        let startup = self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = startup.lock_receiving_v1().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let returned = receiving.original_mut_v1().admit_delete_transfer_namespace_v1(challenge, controller, source, floor, namespace);
        receiving.finish_returned_v1(returned)
    }
}


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_fresh_controller_current_v2(
        &mut self,
        challenge: &RootDeleteChallengeOriginalsV1,
        owner: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        challenge.retained_receiving_demand_v1()?;
        let phase = owner.fresh_admission_phase_v2()?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v1()?,
        );
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        // The existing peer owns the cumulative stage invoice. Initial C,
        // Source, Cache, graph and signed models remain in that same resident
        // sum. No highwater is treated as capacity for this new read.
        self.delete_peer_mut_v1()
            .and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_fresh_controller_once_v2(phase, demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_fresh_frame_once_v2(
        &mut self,
        owner: &RootDeletePendingReceivingV1<'_, '_, '_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.fresh_frame_receiving_demand_v2()?,
        );
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_fresh_frame_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_fresh_transfer_observation_once_v2(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeleteFreshInventoryOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.transfer_observation_receiving_demand_v2()?,
        );
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_fresh_transfer_observation_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_resource_policy_once_v2(&mut self,
        graph: &crate::policy_compiler::delete_root::RootDeleteGraphObjectsOriginalV2,
        comparison: &crate::policy_compiler::delete_root::RootDeleteGraphComparisonOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        graph.verified_graph_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        comparison.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_resource_policy_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_cleanup_inputs_once_v2(&mut self,
        policy: &crate::policy_compiler::delete_root::RootDeleteResourcePolicyOriginalV2,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        graph: &crate::policy_compiler::delete_root::RootDeleteGraphComparisonOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteCleanupInputsOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        use crate::policy_compiler::delete_root::CleanupInputsPhaseV2;
        policy.verified_sources_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        controller.current_assignment_rows_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        graph.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let phase = owner.admission_phase_v2()?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let mut receiving = self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        match phase {
            CleanupInputsPhaseV2::Trust => receiving.admit_delete_resource_trust_once_v2(demand),
            CleanupInputsPhaseV2::Assignment => receiving.admit_delete_resource_assignment_once_v2(demand),
        }.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn delete_cleanup_enrolled_node_v2(&mut self)
        -> Result<[u8; 16], crate::normal_root::NormalRootStartupErrorV1> {
        self.delete_cut_startup_v1()?;
        self.delete_peer_mut_v1()?.stage_receiving_v1()?.enrolled_node_v1()
    }
}


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_resource_preparation_once_v2(&mut self,
        inputs: &crate::policy_compiler::delete_root::RootDeleteCleanupInputsOriginalV2,
        selected: &crate::policy_compiler::delete_root::RootDeleteResourceSelectionOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteResourcePreparationOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        inputs.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        selected.require_selected_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_resource_preparation_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

chunk_arm_port!(arm_host_launch_chunk_posts_once_v2, host_launch_cut_startup_v1,
    crate::policy_compiler::host_launch_root::RootHostLaunchOpeningOriginalV2,
    crate::controller_resource_reservation::RootHostLaunchChunkPostsV2);

chunk_arm_port!(arm_maintenance_storage_chunk_posts_once_v2, maintenance_storage_cut_startup_v2,
    crate::policy_compiler::host_launch_root::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2,
    crate::controller_resource_reservation::RootMaintenanceStorageChunkPostsV2);

chunk_arm_port!(arm_start_assignment_inputs_chunk_posts_once_v2,
    start_assignment_inputs_cut_startup_v2,
    crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2,
    crate::controller_resource_reservation::RootStartAssignmentInputsChunkPostsV2);


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_resource_draft_once_v2(&mut self,
        prepared: &crate::policy_compiler::delete_root::RootDeleteResourcePreparationOriginalV2,
        fresh: &crate::policy_compiler::delete_root::RootDeleteFreshInventoryOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteResourceDraftOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        prepared.preparation_data_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        fresh.require_inputs_complete_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_resource_draft_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_resource_signature_once_v2(&mut self,
        draft: &crate::policy_compiler::delete_root::RootDeleteResourceDraftOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteResourceSignatureOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        draft.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_resource_signature_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_resource_policy_confirmation_once_v2(&mut self,
        signature: &crate::policy_compiler::delete_root::RootDeleteResourceSignatureOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        signature.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v2()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_resource_policy_confirmation_once_v2(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}


impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_preparatory_approval_once_v3(&mut self,
        signature: &crate::policy_compiler::delete_root::RootDeleteResourceSignatureOriginalV2,
        confirmation: &crate::policy_compiler::delete_root::RootDeleteResourcePolicyOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeletePreparatoryApprovalOriginalV3,
    ) -> Result<(), ResourceReservationErrorV1> {
        signature.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        confirmation.require_confirmation_complete_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(
            owner.receiving_demand_v3()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_preparatory_approval_once_v3(demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn admit_delete_preparation_current_once_v3(&mut self,
        approval: &crate::policy_compiler::delete_root::RootDeletePreparatoryApprovalOriginalV3,
        owner: &crate::policy_compiler::delete_root::RootDeletePreparationCurrentOriginalV3,
    ) -> Result<(), ResourceReservationErrorV1> {
        approval.require_completed_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let phase = owner.admission_phase_v3()?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(owner.receiving_demand_v3()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_preparation_current_once_v3(phase, demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn admit_delete_cleanup_current_once_v4(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeleteCleanupCurrentOriginalV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        let phase = owner.admission_phase_v4()?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(owner.receiving_demand_v4()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_cleanup_current_once_v4(phase, demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn admit_delete_completion_once_v4(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeleteCompletionCurrentOriginalV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        let phase = owner.admission_phase_v4()?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(owner.receiving_demand_v4()?);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_completion_once_v4(phase, demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn admit_delete_apply_issuer_once_v3(&mut self,
        current: &crate::policy_compiler::delete_root::RootDeletePreparationCurrentOriginalV3,
        owner: crate::policy_compiler::delete_root::ApplyStageOwnerV3<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.admit_delete_resource_continuation_once_v4(
            crate::policy_compiler::delete_root::RootDeleteResourceContinuationV4::apply_v4(current), owner)
    }

    pub(crate) fn admit_delete_resource_continuation_once_v4(&mut self,
        current: crate::policy_compiler::delete_root::RootDeleteResourceContinuationV4<'_>,
        owner: crate::policy_compiler::delete_root::ApplyStageOwnerV3<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        current.require_completed_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let (phase, demand) = owner.receiving_v3()?;
        let demand = demand.checked_add(current.receiving_demand_v4()?)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(demand);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_resource_continuation_once_v4(current.purpose_v4(), phase, demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn admit_delete_mount_spec_once_v4(&mut self,
        current: crate::policy_compiler::delete_root::RootDeleteResourceContinuationV4<'_>,
        assignment: &crate::policy_compiler::delete_root::RootDeleteCleanupInputsOriginalV2,
        owner: &crate::policy_compiler::delete_root::RootDeleteMountSpecOriginalV4,
    ) -> Result<(), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3 as Purpose;
        if current.purpose_v4() != Purpose::MountReap62 { return Err(ResourceReservationErrorV1::Conflict); }
        current.require_completed_v3().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        assignment.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let phase = owner.admission_phase_v4()?;
        let demand = owner.receiving_demand_v4()?.checked_add(current.receiving_demand_v4()?)?;
        let demand = crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(demand);
        self.delete_cut_startup_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.delete_peer_mut_v1().and_then(|peer| peer.stage_receiving_v1())
            .and_then(|mut receiving| receiving.admit_delete_mount_spec_once_v4(phase, demand))
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

chunk_arm_port!(arm_execution_no_apply_chunk_posts_once_v2, execution_no_apply_cut_startup_v2,
    crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2, crate::controller_resource_reservation::RootExecutionNoApplyChunkPostsV2);

chunk_arm_port!(arm_stop_cleanup_chunk_posts_once_v1, stop_cleanup_cut_startup_v1,
    crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1, crate::controller_resource_reservation::RootStopCleanupChunkPostsV1);
