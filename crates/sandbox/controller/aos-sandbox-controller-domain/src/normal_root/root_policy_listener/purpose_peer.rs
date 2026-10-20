//! Shares the accepted-flight ports for the finite sealed Root peer purposes.
//!
//! The private macro changes only names, concrete variant and concrete peer
//! type. Native admission, subject reads, comparison and independently owed
//! final posts have one source body; no callback or erased purpose is accepted.

use std::error::Error;
use super::{RootPolicyAcceptedFlightV1, NormalRootStartupErrorV1, ProductionNormalRootStartupV1};

// Exactly one purpose is materialized. A failed selected variant remains
// resident and excludes every sibling purpose and the initial-controller path.
pub(super) enum RootAcceptedPurposePeerV1<'startup> {
    Delete(crate::normal_root::RootDeleteControllerPeerReceivingV1<'startup>),
    Environment(crate::normal_root::RootEnvironmentControllerPeerReceivingV1<'startup>),
    Apply(crate::normal_root::RootApplyControllerPeerReceivingV1<'startup>),
    HostLaunch(crate::normal_root::RootHostLaunchControllerPeerReceivingV1<'startup>),
    ExecutionNoApply(crate::normal_root::RootExecutionNoApplyControllerPeerReceivingV2<'startup>),
    StopCleanup(crate::normal_root::RootStopCleanupControllerPeerReceivingV1<'startup>),
    MaintenanceStorage(crate::normal_root::RootMaintenanceStorageControllerPeerReceivingV2<'startup>),
    FinalityRecover(crate::normal_root::RootFinalityRecoverControllerPeerReceivingV1<'startup>),
    StartAssignmentInputs(crate::normal_root::RootStartAssignmentInputsControllerPeerReceivingV2<'startup>),
}

impl RootAcceptedPurposePeerV1<'_> {
    pub(super) fn primary_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Delete(peer) => peer.primary_failure_v1(),
            Self::Environment(peer) => peer.primary_failure_v1(),
            Self::Apply(peer) => peer.primary_failure_v1(),
            Self::HostLaunch(peer) => peer.primary_failure_v1(),
            Self::ExecutionNoApply(peer) => peer.primary_failure_v1(),
            Self::StopCleanup(peer) => peer.primary_failure_v1(),
            Self::MaintenanceStorage(peer) => peer.primary_failure_v1(),
            Self::FinalityRecover(peer) => peer.primary_failure_v1(),
            Self::StartAssignmentInputs(peer) => peer.primary_failure_v1(),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Delete(peer) => peer.failure(),
            Self::Environment(peer) => peer.failure(),
            Self::Apply(peer) => peer.failure(),
            Self::HostLaunch(peer) => peer.failure(),
            Self::ExecutionNoApply(peer) => peer.failure(),
            Self::StopCleanup(peer) => peer.failure(),
            Self::MaintenanceStorage(peer) => peer.failure(),
            Self::FinalityRecover(peer) => peer.failure(),
            Self::StartAssignmentInputs(peer) => peer.failure(),
        }
    }
}

macro_rules! purpose_peer_ports {
    ($variant:ident, $peer:ident,
        $admit_controller_peer_once_v1:ident,
        $cut_startup_v1:ident,
        $enable_subject_reporting_once_v1:ident,
        $receive_subject_chunk_into_v1:ident,
        $observe_chunk_subject_into_v1:ident,
        $finish_controller_peer_posts_once_v1:ident,
        $settle_controller_peer_positive_once_v1:ident,
        $controller_property_failure_view_v1:ident,
        $peer_v1:ident,
        $peer_mut_v1:ident
    ) => {
        impl<'listener, 'startup> RootPolicyAcceptedFlightV1<'listener, 'startup> {
            /// Enters only the selected purpose peer owner on this same accepted flight.
            /// This neither reuses InitialController nor grants a lifecycle phase.
            pub(crate) fn $admit_controller_peer_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
                if self.purpose_peer.is_some() || self.purpose_admission.is_some() || self.controller_admission.is_some()
                    || self.closed.is_some() || !self.transferred
                {
                    self.closed.get_or_insert(NormalRootStartupErrorV1::Service);
                    return Err(NormalRootStartupErrorV1::Service);
                }
                self.purpose_peer = Some(RootAcceptedPurposePeerV1::$variant(
                    crate::normal_root::$peer::new(self.listener.startup),
                ));
                self.purpose_admission = Some((|| {
                    let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or(NormalRootStartupErrorV1::Service)?;
                    match self.purpose_peer.as_mut() {
                        Some(RootAcceptedPurposePeerV1::$variant(peer)) => peer.capture_once_v1(native),
                        _ => Err(NormalRootStartupErrorV1::Service),
                    }
                })());
                if matches!(self.purpose_admission, Some(Ok(()))) { Ok(()) }
                else { Err(NormalRootStartupErrorV1::Service) }
            }

            pub(crate) fn $cut_startup_v1(&self) -> Result<&'startup ProductionNormalRootStartupV1, NormalRootStartupErrorV1> {
                if self.closed.is_some() || !matches!(self.purpose_admission, Some(Ok(()))) {
                    return Err(NormalRootStartupErrorV1::Service);
                }
                self.$peer_v1()?.require_initial_v1()?;
                Ok(self.listener.startup)
            }

            pub(crate) fn $enable_subject_reporting_once_v1(
                &mut self,
            ) -> Result<(), aos_sandbox_linux::seqpacket::SeqpacketError> {
                use aos_sandbox_linux::seqpacket::SeqpacketError as Error;
                self.$cut_startup_v1().map_err(|_| Error::Closed)?;
                self.native.as_mut().and_then(|result| result.as_mut().ok())
                    .ok_or(Error::Closed)?.enable_subject_reporting()
            }

            pub(crate) fn $receive_subject_chunk_into_v1(
                &mut self,
                buffer: &mut aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1,
                geometry: &aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
            ) -> Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1> {
                use aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1 as Error;
                self.$cut_startup_v1().map_err(|_| Error::Order)?;
                let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                    .ok_or(Error::Order)?;
                buffer.receive_next_with_geometry_once(native, geometry)
            }

            pub(crate) fn $observe_chunk_subject_into_v1(&self,
                buffer: &aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1,
                sample: &mut crate::normal_root::RootControllerChunkSubjectSampleV1,
            ) -> Result<(), NormalRootStartupErrorV1> {
                let peer = self.$peer_v1()?.peer_v1()?;
                let native = self.current_cut_native()?;
                let chunk = buffer.pending_chunk().map_err(|_| NormalRootStartupErrorV1::Service)?;
                sample.capture_once(peer.native_original_v1(), native, chunk).map_err(Into::into)
            }

            pub(crate) fn $finish_controller_peer_posts_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
                // The actual accepted native stream survives a failed protocol body.
                // These already-prepaid posts do not call a healthy-cut accessor.
                let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(NormalRootStartupErrorV1::Service)?;
                match self.purpose_peer.as_mut() {
                    Some(RootAcceptedPurposePeerV1::$variant(peer)) => peer.finish_posts_once_v1(native),
                    _ => Err(NormalRootStartupErrorV1::Service),
                }
            }

            pub(crate) fn $settle_controller_peer_positive_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
                self.$peer_mut_v1()?.settle_positive_once_v1()
            }

            pub(crate) fn $controller_property_failure_view_v1(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
                self.$peer_v1().ok()?.property_failure_view_v1()
            }

            fn $peer_v1(&self) -> Result<&crate::normal_root::$peer<'startup>, NormalRootStartupErrorV1> {
                match self.purpose_peer.as_ref() {
                    Some(RootAcceptedPurposePeerV1::$variant(peer)) => Ok(peer),
                    _ => Err(NormalRootStartupErrorV1::Service),
                }
            }

            pub(super) fn $peer_mut_v1(&mut self) -> Result<&mut crate::normal_root::$peer<'startup>, NormalRootStartupErrorV1> {
                match self.purpose_peer.as_mut() {
                    Some(RootAcceptedPurposePeerV1::$variant(peer)) => Ok(peer),
                    _ => Err(NormalRootStartupErrorV1::Service),
                }
            }

        }
    };
}

purpose_peer_ports!(
    Delete, RootDeleteControllerPeerReceivingV1,
    admit_delete_controller_peer_once_v1,
    delete_cut_startup_v1,
    enable_delete_subject_reporting_once_v1,
    receive_delete_subject_chunk_into_v1,
    observe_delete_chunk_subject_into_v1,
    finish_delete_controller_peer_posts_once_v1,
    settle_delete_controller_peer_positive_once_v1,
    delete_controller_property_failure_view_v1,
    delete_peer_v1,
    delete_peer_mut_v1
);

purpose_peer_ports!(
    Environment, RootEnvironmentControllerPeerReceivingV1,
    admit_environment_controller_peer_once_v1,
    environment_cut_startup_v1,
    enable_environment_subject_reporting_once_v1,
    receive_environment_subject_chunk_into_v1,
    observe_environment_chunk_subject_into_v1,
    finish_environment_controller_peer_posts_once_v1,
    settle_environment_controller_peer_positive_once_v1,
    environment_controller_property_failure_view_v1,
    environment_peer_v1,
    environment_peer_mut_v1
);

purpose_peer_ports!(
    Apply, RootApplyControllerPeerReceivingV1,
    admit_apply_controller_peer_once_v1,
    apply_cut_startup_v1,
    enable_apply_subject_reporting_once_v1,
    receive_apply_subject_chunk_into_v1,
    observe_apply_chunk_subject_into_v1,
    finish_apply_controller_peer_posts_once_v1,
    settle_apply_controller_peer_positive_once_v1,
    apply_controller_property_failure_view_v1,
    apply_peer_v1,
    apply_peer_mut_v1
);

purpose_peer_ports!(
    HostLaunch, RootHostLaunchControllerPeerReceivingV1,
    admit_host_launch_controller_peer_once_v1,
    host_launch_cut_startup_v1,
    enable_host_launch_subject_reporting_once_v1,
    receive_host_launch_subject_chunk_into_v1,
    observe_host_launch_chunk_subject_into_v1,
    finish_host_launch_controller_peer_posts_once_v1,
    settle_host_launch_controller_peer_positive_once_v1,
    host_launch_controller_property_failure_view_v1,
    host_launch_peer_v1,
    host_launch_peer_mut_v1
);

impl<'listener, 'startup> RootPolicyAcceptedFlightV1<'listener, 'startup> {
    pub(crate) fn environment_stage_receiving_v1(&mut self) -> Result<crate::normal_root::RootEnvironmentStageReceivingV1<'_, 'startup>, NormalRootStartupErrorV1> {
        self.environment_cut_startup_v1()?;
        self.environment_peer_mut_v1()?.stage_receiving_v1()
    }

    pub(crate) fn apply_stage_receiving_v1(&mut self) -> Result<crate::normal_root::RootApplyStageReceivingV1<'_, 'startup>, NormalRootStartupErrorV1> {
        self.apply_cut_startup_v1()?;
        self.apply_peer_mut_v1()?.stage_receiving_v1()
    }

    pub(crate) fn host_launch_stage_receiving_v1(&mut self) -> Result<crate::normal_root::RootHostLaunchStageReceivingV1<'_, 'startup>, NormalRootStartupErrorV1> {
        self.host_launch_cut_startup_v1()?;
        self.host_launch_peer_mut_v1()?.stage_receiving_v1()
    }

}

// The macro selects only a sealed actual peer variant and concrete owner.
// Native currentness, cutoff and already-owed observation have one source.
macro_rules! continuation_chunk_post_port {
    ($method:ident, $variant:ident, $owner:ty) => {
        impl RootPolicyAcceptedFlightV1<'_, '_> {
            pub(crate) fn $method(&self,
                post: &mut crate::normal_root::RootHistoryPeerPostV1, owner: &$owner,
            ) -> Result<(), NormalRootStartupErrorV1> {
                let native = self.native.as_ref().and_then(|result| result.as_ref().ok());
                let peer = match self.purpose_peer.as_ref() {
                    Some(RootAcceptedPurposePeerV1::$variant(peer)) => peer.peer_v1().ok(),
                    _ => None,
                };
                // These prearmed posts remain owed after protocol refusal.
                // No healthy admission accessor can suppress their native IO.
                let cutoff = owner.current_cutoff_v1().map_err(|_| NormalRootStartupErrorV1::Service)?;
                post.observe_continuation_once_v1(self.listener.startup, native, peer, cutoff)
            }
        }
    };
}

continuation_chunk_post_port!(observe_delete_chunk_post_once_v1, Delete,
    crate::policy_compiler::delete_root::RootDeleteChallengeOriginalsV1);
continuation_chunk_post_port!(observe_apply_chunk_post_once_v1, Apply,
    crate::policy_compiler::storage_apply_root::RootStorageApplyOpeningOriginalV1);


continuation_chunk_post_port!(observe_delete_planning_chunk_post_once_v1, Delete,
    crate::policy_compiler::delete_root::RootDeletePlanningChallengeOriginalV1);

impl<'startup> RootPolicyAcceptedFlightV1<'_, 'startup> {
    pub(crate) fn delete_cache_stage_receiving_v2(&mut self,
        challenge: &crate::policy_compiler::delete_root::RootDeleteChallengeOriginalsV1,
        controller: &crate::policy_compiler::delete_root::RootDeleteControllerCurrentOriginalV1,
        source: &crate::policy_compiler::delete_root::RootDeleteSourceCurrentOriginalV1,
        floor: &crate::policy_compiler::delete_root::RootDeleteFloorOriginalV1,
        transfer: &crate::policy_compiler::delete_root::RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<crate::normal_root::RootDeleteCacheStageReceivingV2<'_, 'startup>, NormalRootStartupErrorV1> {
        self.delete_cut_startup_v1()?;
        self.delete_peer_mut_v1()?.cache_stage_receiving_v2(challenge, controller, source, floor, transfer)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn retire_delete_cache_resident_once_v2(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.delete_cut_startup_v1()?;
        self.delete_peer_mut_v1()?.retire_delete_cache_resident_once_v2(owner)
    }
}

impl RootPolicyAcceptedFlightV1<'_, '_> {
    pub(crate) fn delete_cache_retirement_failure_v2(&self)
        -> Option<&(dyn Error + 'static)>
    {
        match self.purpose_peer.as_ref()? {
            RootAcceptedPurposePeerV1::Delete(peer) => peer.delete_cache_retirement_failure_v2(),
            _ => None,
        }
    }
}

continuation_chunk_post_port!(observe_host_launch_chunk_post_once_v2, HostLaunch,
    crate::policy_compiler::host_launch_root::RootHostLaunchOpeningOriginalV2);

continuation_chunk_post_port!(observe_maintenance_storage_chunk_post_once_v2, MaintenanceStorage,
    crate::policy_compiler::host_launch_root::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2);

purpose_peer_ports!(
    FinalityRecover, RootFinalityRecoverControllerPeerReceivingV1,
    admit_finality_recover_controller_peer_once_v1,
    finality_recover_cut_startup_v1,
    enable_finality_recover_subject_reporting_once_v1,
    receive_finality_recover_subject_chunk_into_v1,
    observe_finality_recover_chunk_subject_into_v1,
    finish_finality_recover_controller_peer_posts_once_v1,
    settle_finality_recover_controller_peer_positive_once_v1,
    finality_recover_controller_property_failure_view_v1,
    finality_recover_peer_v1,
    finality_recover_peer_mut_v1
);

impl<'listener, 'startup> RootPolicyAcceptedFlightV1<'listener, 'startup> {
    pub(crate) fn finality_recover_stage_receiving_v1(&mut self)
        -> Result<crate::normal_root::RootFinalityRecoverStageReceivingV1<'_, 'startup>, NormalRootStartupErrorV1> {
        self.finality_recover_cut_startup_v1()?;
        self.finality_recover_peer_mut_v1()?.finality_recover_stage_receiving_v1()
    }
}

purpose_peer_ports!(
    StartAssignmentInputs, RootStartAssignmentInputsControllerPeerReceivingV2,
    admit_start_assignment_inputs_controller_peer_once_v2,
    start_assignment_inputs_cut_startup_v2,
    enable_start_assignment_inputs_subject_reporting_once_v2,
    receive_start_assignment_inputs_subject_chunk_into_v2,
    observe_start_assignment_inputs_chunk_subject_into_v2,
    finish_start_assignment_inputs_controller_peer_posts_once_v2,
    settle_start_assignment_inputs_controller_peer_positive_once_v2,
    start_assignment_inputs_controller_property_failure_view_v2,
    start_assignment_inputs_peer_v2,
    start_assignment_inputs_peer_mut_v2
);

impl<'listener, 'startup> RootPolicyAcceptedFlightV1<'listener, 'startup> {
    pub(crate) fn start_assignment_inputs_stage_receiving_v2(&mut self)
        -> Result<crate::normal_root::RootStartAssignmentInputsStageReceivingV2<'_, 'startup>,
            NormalRootStartupErrorV1>
    {
        self.start_assignment_inputs_cut_startup_v2()?;
        self.start_assignment_inputs_peer_mut_v2()?.start_assignment_inputs_stage_receiving_v2()
    }
}

continuation_chunk_post_port!(observe_start_assignment_inputs_chunk_post_once_v2,
    StartAssignmentInputs,
    crate::policy_compiler::start_assignment_inputs_root::opening::RootStartAssignmentInputsOpeningOriginalV2);

// This port constructs its own actual peer and uses the common native/PID1
// capture/post engine. It cannot borrow the HostLaunch or InitialController peer.
purpose_peer_ports!(
    MaintenanceStorage, RootMaintenanceStorageControllerPeerReceivingV2,
    admit_maintenance_storage_controller_peer_once_v2,
    maintenance_storage_cut_startup_v2,
    enable_maintenance_storage_subject_reporting_once_v2,
    receive_maintenance_storage_subject_chunk_into_v2,
    observe_maintenance_storage_chunk_subject_into_v2,
    finish_maintenance_storage_controller_peer_posts_once_v2,
    settle_maintenance_storage_controller_peer_positive_once_v2,
    maintenance_storage_controller_property_failure_view_v2,
    maintenance_storage_peer_v2,
    maintenance_storage_peer_mut_v2
);

impl<'startup> RootPolicyAcceptedFlightV1<'_, 'startup> {
    pub(crate) fn maintenance_storage_stage_receiving_v2(&mut self)
        -> Result<crate::normal_root::RootMaintenanceStorageStageReceivingV2<'_, 'startup>, NormalRootStartupErrorV1>
    {
        self.maintenance_storage_peer_mut_v2()?.stage_receiving_v1()
    }
}

// This concrete peer reuses the sole native Controller/PID1/posts body.
purpose_peer_ports!(
    ExecutionNoApply, RootExecutionNoApplyControllerPeerReceivingV2,
    admit_execution_no_apply_controller_peer_once_v2,
    execution_no_apply_cut_startup_v2,
    enable_execution_no_apply_subject_reporting_once_v2,
    receive_execution_no_apply_subject_chunk_into_v2,
    observe_execution_no_apply_chunk_subject_into_v2,
    finish_execution_no_apply_controller_peer_posts_once_v2,
    settle_execution_no_apply_controller_peer_positive_once_v2,
    execution_no_apply_controller_property_failure_view_v2,
    execution_no_apply_peer_v2,
    execution_no_apply_peer_mut_v2
);

impl<'startup> RootPolicyAcceptedFlightV1<'_, 'startup> {
    pub(crate) fn execution_no_apply_stage_receiving_v2(&mut self)
        -> Result<crate::normal_root::RootExecutionNoApplyStageReceivingV2<'_, 'startup>, NormalRootStartupErrorV1>
    {
        self.execution_no_apply_peer_mut_v2()?.execution_no_apply_stage_receiving_v2()
    }

    /// Uses this same Execution peer's genuine native/PID1 currentness body.
    pub(crate) fn observe_execution_no_apply_floor_peer_once_v2(&self,
        stream: &aos_sandbox_linux::unix_stream::RetainedUnixStream,
        sample: &mut crate::normal_root::RootControllerPeerCurrentSampleV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.execution_no_apply_peer_v2()?.peer_v1()?
            .observe_prearmed_current_into_v1(stream, sample)
    }
}

continuation_chunk_post_port!(observe_execution_no_apply_chunk_post_once_v2, ExecutionNoApply,
    crate::policy_compiler::execution_no_apply_root::transport::RootExecutionNoApplyOpeningOriginalV2);

purpose_peer_ports!(
    StopCleanup, RootStopCleanupControllerPeerReceivingV1,
    admit_stop_cleanup_controller_peer_once_v1,
    stop_cleanup_cut_startup_v1,
    enable_stop_cleanup_subject_reporting_once_v1,
    receive_stop_cleanup_subject_chunk_into_v1,
    observe_stop_cleanup_chunk_subject_into_v1,
    finish_stop_cleanup_controller_peer_posts_once_v1,
    settle_stop_cleanup_controller_peer_positive_once_v1,
    stop_cleanup_controller_property_failure_view_v1,
    stop_cleanup_peer_v1,
    stop_cleanup_peer_mut_v1
);

impl<'startup> RootPolicyAcceptedFlightV1<'_, 'startup> {
    pub(crate) fn stop_cleanup_stage_receiving_v1(&mut self)
        -> Result<crate::normal_root::RootStopCleanupStageReceivingV1<'_, 'startup>, NormalRootStartupErrorV1> {
        self.stop_cleanup_peer_mut_v1()?.stage_receiving_v1()
    }
}

continuation_chunk_post_port!(observe_stop_cleanup_chunk_post_once_v1, StopCleanup,
    crate::policy_compiler::stop_cleanup_root::transport::RootStopCleanupOpeningOriginalV1);
