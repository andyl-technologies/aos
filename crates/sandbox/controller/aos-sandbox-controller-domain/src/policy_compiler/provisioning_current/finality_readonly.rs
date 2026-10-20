//! Captures distinct final Controller, Session and Source cuts for Apply.
//!
//! The initial readers remain resident. No final receipt can rearm them or
//! replace native proof with supplied names. Every reached fixed target is
//! paid before construction, then captured, audited and fully replayed by the
//! same rooted reader. The final semantic comparator runs while all three
//! actual native owners and their independent late posts remain held.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::{JournalError, RootReadonlyJournalModelOriginalsV1 as Model};
use crate::normal_root::{NormalRootStartupErrorV1, RootStopCleanupStageReceivingV1, RootApplyStageReceivingV1, RootFinalityRecoverStageReceivingV1, RootStartAssignmentInputsStageReceivingV2, RootHostLaunchStageReceivingV1, RootMaintenanceStorageStageReceivingV2, RootExecutionNoApplyStageReceivingV2};
use crate::policy_compiler::create_storage_current::controller_readonly::native_read::{
    RootFixedNativeReadOriginalsV1 as Reader, RootFixedNativeReadbackV1,
};
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;

type Cause = Box<dyn Error>;

// This finite target is private mechanical DATA. Each branch derives its own
// fixed recipe and same R stage; callers cannot select paths or native limits.
#[derive(Clone, Copy)]
enum TargetV1 { Controller, Session, Source }

impl TargetV1 {
    fn construct_v1(self, stage: &RootCreateFinalityReadStageV1<'_, '_, '_>) -> Reader {
        match self { Self::Controller => Reader::controller_current_v1(),
            Self::Session => match stage {
                RootCreateFinalityReadStageV1::StopCleanup(_) | RootCreateFinalityReadStageV1::StopCleanupFinal(_) | RootCreateFinalityReadStageV1::ExecutionNoApply(_) | RootCreateFinalityReadStageV1::ExecutionNoApplyFinal(_) | RootCreateFinalityReadStageV1::ExecutionNoApplyAcquisition(_) => Reader::host_session_v2(),
                RootCreateFinalityReadStageV1::PreparationSession(_, kind) => match kind {
                    StartPreparationSessionKindV2::HostNetworkCatalog => Reader::network_session_v2(),
                    StartPreparationSessionKindV2::HostMountCatalog
                        | StartPreparationSessionKindV2::MountBefore62 => Reader::mount_session_v2(),
                },
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Host) => Reader::host_session_v2(),
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Network) => Reader::network_session_v2(),
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Mount) => Reader::mount_session_v2(),
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::StorageGuestRoot) => Reader::default(),
                _ => Reader::default(),
            },
            Self::Source => Reader::source_current_v1() }
    }

    fn fixed_demand_v1(self, stage: &RootCreateFinalityReadStageV1<'_, '_, '_>) -> Result<ResourceVector, JournalError> {
        match self { Self::Controller => Reader::controller_current_fixed_demand_v1(),
            Self::Session => match stage {
                RootCreateFinalityReadStageV1::StopCleanup(_) | RootCreateFinalityReadStageV1::StopCleanupFinal(_) | RootCreateFinalityReadStageV1::ExecutionNoApply(_) | RootCreateFinalityReadStageV1::ExecutionNoApplyFinal(_) | RootCreateFinalityReadStageV1::ExecutionNoApplyAcquisition(_) => Reader::host_session_fixed_demand_v2(),
                RootCreateFinalityReadStageV1::PreparationSession(_, kind) => match kind {
                    StartPreparationSessionKindV2::HostNetworkCatalog => Reader::network_session_fixed_demand_v2(),
                    StartPreparationSessionKindV2::HostMountCatalog
                        | StartPreparationSessionKindV2::MountBefore62 => Reader::mount_session_fixed_demand_v2(),
                },
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Host) => Reader::host_session_fixed_demand_v2(),
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Network) => Reader::network_session_fixed_demand_v2(),
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Mount) => Reader::mount_session_fixed_demand_v2(),
                RootCreateFinalityReadStageV1::HostResource(_, crate::policy_compiler::host_launch_root::kind::ResourceKindV2::StorageGuestRoot) => Reader::fixed_demand_v1(),
                _ => Reader::fixed_demand_v1(),
            },
            Self::Source => Reader::source_current_fixed_demand_v1() }
    }

    fn admit_fixed_v1(self, stage: &mut RootCreateFinalityReadStageV1<'_, '_, '_>,
        demand: ResourceVector) -> Result<(), NormalRootStartupErrorV1> {
        stage.admit_once_v1(self, ReadPlaneV1::Fixed, demand)
    }

    fn admit_native_v1(self, stage: &mut RootCreateFinalityReadStageV1<'_, '_, '_>,
        demand: ResourceVector) -> Result<(), NormalRootStartupErrorV1> {
        stage.admit_once_v1(self, ReadPlaneV1::Native, demand)
    }

    fn admit_semantic_v1(self, stage: &mut RootCreateFinalityReadStageV1<'_, '_, '_>,
        demand: ResourceVector) -> Result<(), NormalRootStartupErrorV1> {
        stage.admit_once_v1(self, ReadPlaneV1::Semantic, demand)
    }

}


#[derive(Clone, Copy)]
enum ReadPlaneV1 { Fixed, Native, Semantic }

// Both variants borrow a genuine already-entered same-R purpose. No callback,
// raw parts, supplied vector or sibling-purpose cast can populate this selector.
pub(crate) enum RootCreateFinalityReadStageV1<'call, 'flight, 'startup> {
    StopCleanup(&'call mut RootStopCleanupStageReceivingV1<'flight, 'startup>),
    StopCleanupFinal(&'call mut RootStopCleanupStageReceivingV1<'flight, 'startup>),
    ExecutionNoApply(&'call mut RootExecutionNoApplyStageReceivingV2<'flight, 'startup>),
    ExecutionNoApplyFinal(&'call mut RootExecutionNoApplyStageReceivingV2<'flight, 'startup>),
    ExecutionNoApplyAcquisition(&'call mut RootExecutionNoApplyStageReceivingV2<'flight, 'startup>),
    Apply(&'call mut RootApplyStageReceivingV1<'flight, 'startup>),
    MaintenanceInitial(&'call mut RootMaintenanceStorageStageReceivingV2<'flight, 'startup>),
    MaintenanceFinal(&'call mut RootMaintenanceStorageStageReceivingV2<'flight, 'startup>),
    Recover(&'call mut RootFinalityRecoverStageReceivingV1<'flight, 'startup>),
    HostResource(&'call mut RootHostLaunchStageReceivingV1<'flight, 'startup>, crate::policy_compiler::host_launch_root::kind::ResourceKindV2),
    StartInputs(&'call mut RootStartAssignmentInputsStageReceivingV2<'flight, 'startup>),
    PreparationSession(&'call mut RootHostLaunchStageReceivingV1<'flight, 'startup>, StartPreparationSessionKindV2),
}

impl RootCreateFinalityReadStageV1<'_, '_, '_> {
    fn admit_once_v1(&mut self, target: TargetV1, plane: ReadPlaneV1,
        demand: ResourceVector) -> Result<(), NormalRootStartupErrorV1> {
        let demand = RootContinuationDemandV1::from_demand_v1(demand);
        match (self, target, plane) {
            (Self::StopCleanup(stage), target, plane) => {
                use crate::controller_resource_reservation::RootStopCleanupStageV1 as P;
                stage.admit_stop_cleanup_once_v1(match (target, plane) {
                    (TargetV1::Controller, ReadPlaneV1::Fixed) => P::ControllerFixed,
                    (TargetV1::Controller, ReadPlaneV1::Native) => P::ControllerNative,
                    (TargetV1::Controller, ReadPlaneV1::Semantic) => P::ControllerSemantic,
                    (TargetV1::Session, ReadPlaneV1::Fixed) => P::HostFixed,
                    (TargetV1::Session, ReadPlaneV1::Native) => P::HostNative,
                    (TargetV1::Session, ReadPlaneV1::Semantic) => P::HostSemantic,
                    (TargetV1::Source, ReadPlaneV1::Fixed) => P::SourceFixed,
                    (TargetV1::Source, ReadPlaneV1::Native) => P::SourceNative,
                    (TargetV1::Source, ReadPlaneV1::Semantic) => P::SourceSemantic,
                }, demand)
            }
            (Self::StopCleanupFinal(stage), TargetV1::Session, plane) => {
                use crate::controller_resource_reservation::RootStopCleanupStageV1 as P;
                stage.admit_stop_cleanup_once_v1(match plane {
                    ReadPlaneV1::Fixed => P::FinalHostFixed,
                    ReadPlaneV1::Native => P::FinalHostNative,
                    ReadPlaneV1::Semantic => P::FinalHostSemantic,
                }, demand)
            }
            (Self::StopCleanupFinal(_), _, _) => Err(NormalRootStartupErrorV1::Service),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::ControllerFixed, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::ControllerNative, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::ControllerSemantic, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::HostSessionFixed, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::HostSessionNative, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::HostSessionSemantic, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::SourceFixed, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::SourceNative, demand),
            (Self::ExecutionNoApplyAcquisition(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_acquisition_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::SourceSemantic, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::ControllerFixed, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::ControllerNative, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::ControllerSemantic, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::HostSessionFixed, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::HostSessionNative, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::HostSessionSemantic, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::SourceFixed, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::SourceNative, demand),
            (Self::ExecutionNoApplyFinal(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_final_read_once_v2(crate::controller_resource_reservation::RootExecutionNoApplyReadPhaseV2::SourceSemantic, demand),
            (Self::ExecutionNoApply(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_controller_fixed_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_execution_no_apply_controller_native_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_controller_semantic_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_host_session_fixed_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_execution_no_apply_host_session_native_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_host_session_semantic_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_execution_no_apply_source_fixed_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_execution_no_apply_source_native_once_v2(demand),
            (Self::ExecutionNoApply(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_execution_no_apply_source_semantic_once_v2(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_controller_fixed_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_controller_native_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_controller_semantic_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_storage_fixed_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_storage_native_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_storage_semantic_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_source_fixed_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_source_native_once_v1(demand),
            (Self::MaintenanceInitial(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_source_semantic_once_v1(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_maintenance_final_controller_fixed_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_maintenance_final_controller_native_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_maintenance_final_controller_semantic_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_maintenance_final_session_fixed_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_maintenance_final_session_native_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_maintenance_final_session_semantic_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_maintenance_final_source_fixed_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_maintenance_final_source_native_once_v2(demand),
            (Self::MaintenanceFinal(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_maintenance_final_source_semantic_once_v2(demand),
            (Self::Apply(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_apply_final_controller_fixed_once_v1(demand),
            (Self::Apply(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_apply_final_controller_native_once_v1(demand),
            (Self::Apply(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_apply_final_controller_semantic_once_v1(demand),
            (Self::Apply(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_apply_final_storage_fixed_once_v1(demand),
            (Self::Apply(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_apply_final_storage_native_once_v1(demand),
            (Self::Apply(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_apply_final_storage_semantic_once_v1(demand),
            (Self::Apply(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_apply_final_source_fixed_once_v1(demand),
            (Self::Apply(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_apply_final_source_native_once_v1(demand),
            (Self::Apply(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_apply_final_source_semantic_once_v1(demand),
            (Self::Recover(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_finality_recover_controller_fixed_once_v1(demand),
            (Self::Recover(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_finality_recover_controller_native_once_v1(demand),
            (Self::Recover(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_finality_recover_controller_semantic_once_v1(demand),
            (Self::Recover(stage), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_finality_recover_session_fixed_once_v1(demand),
            (Self::Recover(stage), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_finality_recover_session_native_once_v1(demand),
            (Self::Recover(stage), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_finality_recover_session_semantic_once_v1(demand),
            (Self::Recover(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_finality_recover_source_fixed_once_v1(demand),
            (Self::Recover(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_finality_recover_source_native_once_v1(demand),
            (Self::Recover(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_finality_recover_source_semantic_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_host_final_controller_fixed_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_host_final_controller_native_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_host_final_controller_semantic_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Session, ReadPlaneV1::Fixed) => stage.admit_host_final_session_fixed_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Session, ReadPlaneV1::Native) => stage.admit_host_final_session_native_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Session, ReadPlaneV1::Semantic) => stage.admit_host_final_session_semantic_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_host_final_source_fixed_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_host_final_source_native_once_v1(demand),
            (Self::HostResource(stage, _), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_host_final_source_semantic_once_v1(demand),
            (Self::StartInputs(stage), TargetV1::Controller, ReadPlaneV1::Fixed) => stage.admit_start_assignment_inputs_controller_fixed_once_v2(demand),
            (Self::StartInputs(stage), TargetV1::Controller, ReadPlaneV1::Native) => stage.admit_start_assignment_inputs_controller_native_once_v2(demand),
            (Self::StartInputs(stage), TargetV1::Controller, ReadPlaneV1::Semantic) => stage.admit_start_assignment_inputs_controller_semantic_once_v2(demand),
            (Self::StartInputs(stage), TargetV1::Source, ReadPlaneV1::Fixed) => stage.admit_start_assignment_inputs_source_fixed_once_v2(demand),
            (Self::StartInputs(stage), TargetV1::Source, ReadPlaneV1::Native) => stage.admit_start_assignment_inputs_source_native_once_v2(demand),
            (Self::StartInputs(stage), TargetV1::Source, ReadPlaneV1::Semantic) => stage.admit_start_assignment_inputs_source_semantic_once_v2(demand),
            (Self::StartInputs(_), TargetV1::Session, _) => Err(NormalRootStartupErrorV1::Service),
            (Self::PreparationSession(stage, kind), TargetV1::Session, plane) => {
                kind.admit_once_v2(stage, plane, demand)
            }
            (Self::PreparationSession(_, _), _, _) => Err(NormalRootStartupErrorV1::Service),

        }
    }

    fn controller_identity_v1(&self) -> (u32, u32) {
        match self {
            Self::StopCleanup(stage) | Self::StopCleanupFinal(stage) => stage.controller_identity_v1(),
            Self::ExecutionNoApply(stage) | Self::ExecutionNoApplyFinal(stage) | Self::ExecutionNoApplyAcquisition(stage) => stage.controller_identity_v1(),
            Self::Apply(stage) => stage.controller_identity_v1(),
            Self::MaintenanceInitial(stage) | Self::MaintenanceFinal(stage) => stage.controller_identity_v1(),
            Self::Recover(stage) => stage.controller_identity_v1(),
            Self::StartInputs(stage) => stage.controller_identity_v1(),
            Self::HostResource(stage, _) => stage.controller_identity_v1(),
            Self::PreparationSession(stage, _) => stage.controller_identity_v1(),
        }
    }

    fn session_receiving_demand_v1(&self, prefix: usize) -> Result<ResourceVector, JournalError> {
        match self {
            Self::StopCleanup(_) | Self::StopCleanupFinal(_) | Self::ExecutionNoApply(_) | Self::ExecutionNoApplyFinal(_) | Self::ExecutionNoApplyAcquisition(_) => crate::policy_compiler::host_launch_root::session::
                RootStartResourceFinalSessionOriginalV2::receiving_demand_v2(prefix,
                    crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Host),
            Self::MaintenanceInitial(_) | Self::MaintenanceFinal(_) => crate::policy_compiler::host_launch_root::session::
                RootStartResourceFinalSessionOriginalV2::receiving_demand_v2(prefix,
                    crate::policy_compiler::host_launch_root::kind::ResourceKindV2::StorageGuestRoot),
            Self::Apply(_) => crate::policy_compiler::storage_apply_root::session::
                RootApplyFinalSessionOriginalV1::receiving_demand_v1(prefix),
            Self::Recover(_) => super::create_finality::session::
                CreateFinalitySessionOriginalV1::receiving_demand_v1(prefix),
            Self::StartInputs(_) => Err(JournalError::ProtectedBoundary),
            Self::PreparationSession(_, kind) => crate::policy_compiler::host_launch_root::session::
                RootStartResourceFinalSessionOriginalV2::receiving_demand_v2(prefix, kind.resource_kind_v2()),
            Self::HostResource(_, kind) => crate::policy_compiler::host_launch_root::session::
                RootStartResourceFinalSessionOriginalV2::receiving_demand_v2(prefix, *kind),
        }
    }
}

#[derive(Clone, Copy)]
enum TargetFailureV1 { Native, Model, Funding, ExternalClock, Primary }

struct FinalTargetOriginalV1 {
    first: Option<TargetFailureV1>,
    target: TargetV1,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    semantic_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Reader>>,
    model: Option<Box<Model>>,
    native_data: Option<NativeCutDataV1>,
    primary: Option<Result<(), Cause>>,
    posts: Option<Result<(), JournalError>>,
}

#[derive(Clone, Copy)]
pub(crate) struct NativeCutDataV1 {
    pub(crate) names: aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
    pub(crate) next: u64,
    pub(crate) end: u64,
}

impl NativeCutDataV1 {
    pub(crate) fn matches_encoded_data_v3(self, encoded: &[u8]) -> bool {
        encoded.len() == 64
            && self.names.to_bytes().as_slice() == &encoded[..48]
            && self.next.to_be_bytes().as_slice() == &encoded[48..56]
            && self.end.to_be_bytes().as_slice() == &encoded[56..]
    }
}

impl FinalTargetOriginalV1 {
    fn new(target: TargetV1) -> Self {
        Self { first: None, target, funding: None, native_funding: None, semantic_funding: None, native: None, model: None, native_data: None, primary: None, posts: None }
    }

    fn observe_once_v1(&mut self, stage: &mut RootCreateFinalityReadStageV1<'_, '_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        if self.funding.is_some() { return Err(JournalError::ProtectedBoundary); }
        let bytes = size_of::<Reader>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(3 * size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(3 * size_of::<RootCreateFinalityReadStageV1<'static, 'static, 'static>>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let wrapper = match stage {
            RootCreateFinalityReadStageV1::PreparationSession(_, _) =>
                size_of::<RootStartPreparationSessionReadOriginalV2>().checked_mul(3)
                    .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?,
            _ => 0,
        };
        let demand = self.target.fixed_demand_v1(stage)?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, bytes.checked_add(wrapper)
                .ok_or(JournalError::JournalTooLarge)?)).map_err(JournalError::ReceivingAccounting)?;
        self.funding = Some(self.target.admit_fixed_v1(stage, demand));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.native = Some(Box::new(self.target.construct_v1(stage)));
        self.primary = Some(self.observe_inner_v1(stage, clock));
        if matches!(self.primary, Some(Err(_))) {
            self.first = Some(if self.native.as_ref().and_then(|native| native.failure()).is_some() {
                TargetFailureV1::Native
            } else if self.model.as_ref().and_then(|model| model.failure()).is_some() {
                TargetFailureV1::Model
            } else if self.funding_failed_v1() { TargetFailureV1::Funding }
            else if clock.failure().is_some() { TargetFailureV1::ExternalClock }
            else { TargetFailureV1::Primary });
        }
        if matches!(self.primary, Some(Ok(()))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    fn observe_inner_v1(&mut self, stage: &mut RootCreateFinalityReadStageV1<'_, '_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), Cause> {
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        clock.check_next_once_v1()?;
        native.capture_once(stage.controller_identity_v1().0);
        native.require_captured_v1()?;
        self.native_funding = Some(self.target.admit_native_v1(stage, native.replay_demand_v1()?));
        if !matches!(self.native_funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        clock.check_next_once_v1()?;
        let semantic = if matches!(self.target, TargetV1::Session) {
            // SessionSchema's complete codec/index geometry is already in
            // replay_demand_v1; it has no separate full-cold audit/model.
            stage.session_receiving_demand_v1(
                usize::try_from(native.captured_extent_v1()?.native_bytes)
                    .map_err(|_| JournalError::JournalTooLarge)?)?
        } else {
            native.audit_once();
            native.additional_semantic_demand_v1()?.checked_add(Model::receiving_demand_v1(native)?)?
        };
        self.semantic_funding = Some(self.target.admit_semantic_v1(stage, semantic));
        if !matches!(self.semantic_funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        clock.check_next_once_v1()?;
        native.replay_once();
        let data = native.replay_native_v1()?;
        self.native_data = Some(NativeCutDataV1 { names: data.names, next: data.next, end: data.end });
        if !matches!(self.target, TargetV1::Session) {
            native.finish_post_once();
            native.terminal_native_v1()?;
            self.model = Some(Box::new(Model::new()));
            self.model.as_mut().ok_or(JournalError::ProtectedBoundary)?.adopt_once(native);
            self.model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v1()?;
        }
        Ok(())
    }

    fn finish_posts_once_v1(&mut self) {
        if self.posts.is_some() { return; }
        if let Some(native) = self.native.as_mut() { native.finish_post_once(); }
        if let Some(model) = self.model.as_mut() { model.finish_parent_post_once_v1(); }
        self.posts = Some((|| {
            if !matches!(self.primary, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
            if let Some(model) = self.model.as_ref() { model.require_parent_post_v1()?; }
            else { self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.terminal_native_v1()?; }
            Ok(())
        })());
    }

    fn body_complete_v1(&self) -> Result<(), JournalError> {
        if matches!(self.primary, Some(Ok(()))) && self.posts.is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    fn funding_failed_v1(&self) -> bool {
        matches!(self.funding, Some(Err(_))) || matches!(self.native_funding, Some(Err(_)))
            || matches!(self.semantic_funding, Some(Err(_)))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if matches!(self.first, Some(TargetFailureV1::ExternalClock)) { return None; }
        let selected = match self.first {
            Some(TargetFailureV1::Native) => self.native.as_ref().and_then(|native| native.failure()),
            Some(TargetFailureV1::Model) => self.model.as_ref().and_then(|model| model.failure()),
            Some(TargetFailureV1::Funding) => self.native_funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
                .or_else(|| self.semantic_funding.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(TargetFailureV1::ExternalClock) => None,
            Some(TargetFailureV1::Primary) => self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            None => None,
        };
        self.funding.as_ref()?.as_ref().err().map(|cause| cause as _)
            .or(selected)
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.model.as_ref().and_then(|model| model.failure()))
            .or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.posts.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[derive(Clone, Copy)]
enum ReadonlySelectionV2 {
    FullFinality,
    StartInputs,
    MaintenanceInitial,
    MaintenanceFinal,
    ExecutionNoApply,
    ExecutionNoApplyFinal,
    ExecutionNoApplyAcquisition,
}

/// Lends comparison operations over the same Execution purpose's paid C model.
/// The owner retains all three native readers and their independently owed posts.
/// No raw Journal, writer, current Host lease or Root floor is returned.
pub(crate) struct RootExecutionNoApplyCurrentDataV2<'held> {
    owner: &'held RootCreateFinalityReadonlyOriginalV1,
}

impl RootExecutionNoApplyCurrentDataV2<'_> {
    /// Recomputes the final global C cut from this same actual native capture.
    pub(crate) fn global_controller_cut_data_v2(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::
            RootExecutionNoApplyControllerCutDataV2, JournalError> {
        let journal=self.controller_model_v2()?.journal_v1()?;
        // Replay moved this exact prefix/index into the canonical Model. Only
        // native names/NEXT/end were copied before that same-owner transfer.
        let native=self.owner.controller.native_data.ok_or(JournalError::ProtectedBoundary)?;
        if journal.snapshot_sequence()!=native.next{return Err(JournalError::ProtectedBoundary);}
        aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::
            RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
                native.names,native.next,native.end,journal.all_records())
            .map_err(|_|JournalError::ProtectedBoundary)
    }

    pub(crate) fn host_current_lease_demand_data_v2(&self) -> Result<ResourceVector, JournalError> {
        self.controller_model_v2()?;
        let native = self.owner.session_v1()?;
        let prefix = usize::try_from(native.end)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let entries = native.state.keys().filter(|(namespace, _)|
            *namespace == crate::journal::RecordNamespace::BrokerSessionTraffic).count();
        crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyHostLeaseOriginalV2::
            receiving_demand_v2(prefix, entries)
    }

    pub(crate) fn observe_host_current_lease_data_v2(&self,
        original: &mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &mut crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyHostTrustOriginalV2,
        controller: (u32, u32),
    ) -> Result<(), JournalError> {
        self.controller_model_v2()?;
        original.observe_native_data_v2(self.owner.session_v1()?, trust, controller)
    }

    fn controller_model_v2(&self) -> Result<&Model, JournalError> {
        if !matches!(self.owner.selection, ReadonlySelectionV2::ExecutionNoApply | ReadonlySelectionV2::ExecutionNoApplyFinal | ReadonlySelectionV2::ExecutionNoApplyAcquisition) {
            return Err(JournalError::ProtectedBoundary);
        }
        for target in [&self.owner.controller,&self.owner.session,&self.owner.source] {
            if target.posts.is_none() {
                target.body_complete_v1()?;
            } else {
                // This distinct Execution DATA phase borrows the same actual
                // model after its independently owed original post completed.
                if !matches!(target.primary,Some(Ok(()))) || !matches!(target.posts,Some(Ok(())))
                    || target.first.is_some() || target.failure().is_some() {
                    return Err(JournalError::ProtectedBoundary);
                }
                if let Some(model)=target.model.as_ref(){model.require_parent_post_v1()?;}
                else{target.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.terminal_native_v1()?;}
            }
        }
        self.owner.controller.model.as_deref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn planning_demand_v2(&self) -> Result<ResourceVector,
        crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyModelsErrorV2> {
        let journal = self.controller_model_v2()?.journal_v1()?;
        Ok(crate::reconciler::ClosedCreateFailurePlanDataV2::receiving_demand_data_v2(journal)?)
    }

    pub(crate) fn plan_rows_data_v2(&self,
        marker: aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2,
        terminal_archive: aos_sandbox_model::ObjectDigest,
        signed_terminal: aos_sandbox_model::ObjectDigest,
        wall_seconds: i64,
    ) -> Result<crate::reconciler::ClosedCreateFailurePlanDataV2,
        crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyModelsErrorV2> {
        Ok(crate::reconciler::plan_closed_create_failure_rows_data_v2(
            self.controller_model_v2()?.journal_v1()?, marker, terminal_archive,
            signed_terminal, wall_seconds)?)
    }
}

/// Borrows only DATA from the actual Maintenance Root's captured Source model.
/// The native reader and its independently owed parent post remain resident.
#[derive(Clone, Copy)]
pub(crate) struct RootMaintenanceSourceDataV2<'held> {
    owner: &'held RootCreateFinalityReadonlyOriginalV1,
}

/// Keeps current Maintenance C/Source comparison access inside their real reader.
/// No raw Journal, writer, callback or caller-supplied row map is returned.
#[derive(Clone, Copy)]
pub(crate) struct RootMaintenanceCurrentDataV2<'held> {
    owner: &'held RootCreateFinalityReadonlyOriginalV1,
}

impl RootMaintenanceCurrentDataV2<'_> {
    fn controller_model_v2(&self) -> Result<&Model, JournalError> {
        self.owner.maintenance_source_data_v2()?;
        self.owner.controller.body_complete_v1()?;
        self.owner.controller.model.as_deref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_initial_cut_data_v3(&self) -> Result<(), JournalError> {
        if !matches!(self.owner.selection, ReadonlySelectionV2::MaintenanceInitial) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.controller_model_v2().map(|_| ())
    }

    pub(crate) fn require_final_cut_data_v3(&self) -> Result<(), JournalError> {
        if !matches!(self.owner.selection, ReadonlySelectionV2::MaintenanceFinal) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.controller_model_v2().map(|_| ())
    }

    pub(crate) fn require_opening_native_data_v3(&self,
        stage: &RootMaintenanceStorageStageReceivingV2<'_, '_>,
        query: aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageQueryDataV2,
        subject: aos_sandbox_protocol::domain_ledger::provisioning_root::maintenance_storage::MaintenanceStorageSubjectDataV2<'_>,
    ) -> Result<(), Box<dyn Error>> {
        self.require_initial_cut_data_v3()?;
        let (controller, source) = self.owner.cuts_v1()?;
        let session = self.owner.session_v1()?;
        if (controller.next, controller.end) != (query.controller_next, query.controller_end)
            || !source.matches_encoded_data_v3(subject.source_native)
            || !(NativeCutDataV1 { names: session.names, next: session.next, end: session.end })
                .matches_encoded_data_v3(subject.session_native) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        crate::policy_compiler::root_resource_opening::require_controller_baseline_account_data_v3(
            self.controller_model_v2()?.raw_state_v1()?, subject.controller_account,
            stage.enrolled_node_v1()?, stage.controller_baseline_partition_v1()?)
    }

    pub(crate) fn compiler_geometry_v2(&self,
        signed: &crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1,
    ) -> Result<ResourceVector, JournalError> {
        let state = self.controller_model_v2()?.raw_state_v1()?;
        let source = self.owner.maintenance_source_data_v2()?;
        let width = state.iter().chain(source.state_data_v2()?.iter()).try_fold(
            0_u64, |sum, ((_, key), value)| {
                sum.checked_add(u64::try_from(key.len()).ok()?)?
                    .checked_add(u64::try_from(value.len()).ok()?)
            }).ok_or(JournalError::JournalTooLarge)?;
        super::current_compiler_complete_receiving_demand_v1(width, state, signed)
    }

    pub(crate) fn reservation_data_v2(&self, bytes: &[u8])
        -> Result<crate::guest_root_publication::GuestRootPublicationReservationV1, Box<dyn Error>> {
        Ok(crate::guest_root_publication::current_guest_root_reservation_data_v2(
            self.controller_model_v2()?.journal_v1()?, bytes)?)
    }

    pub(crate) fn reserved_workspace_data_v2<'inventory>(&self,
        manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        inventory: &'inventory aos_sandbox_protocol::ValidatedStorageInventory,
        reservation: &[u8], enrolled_node: aos_sandbox_model::NodeId,
    ) -> Result<crate::guest_root_publication::ReservedGuestRootWorkspaceDataV2<'inventory>, Box<dyn Error>> {
        Ok(crate::guest_root_publication::reserved_guest_root_workspace_data_v2(
            self.controller_model_v2()?.journal_v1()?, manifest, inventory, reservation, enrolled_node)?)
    }

    pub(crate) fn assignment_data_v2(&self, sandbox: aos_sandbox_model::SandboxId)
        -> Result<super::current_cleanup_assignment::CurrentCleanupAssignmentDataV2, Box<dyn Error>> {
        let journal = self.controller_model_v2()?.journal_v1()?;
        super::current_cleanup_assignment::current_cleanup_assignment_rows_data_v2(
            journal.historical_read_view_v1().rows_data_v2(), sandbox)
            .map_err(|cause| cause as Box<dyn Error>)
    }

    pub(crate) fn specification_data_v2(&self, descriptor: &aos_sandbox_model::ObjectDescriptor)
        -> Result<crate::sandbox_spec_state::DurableSandboxSpecV1, Box<dyn Error>> {
        crate::sandbox_spec_state::get(self.controller_model_v2()?.journal_v1()?, descriptor)?
            .ok_or_else(|| Box::new(JournalError::ProtectedBoundary) as Box<dyn Error>)
    }
}

impl RootMaintenanceSourceDataV2<'_> {
    pub(crate) fn state_data_v2(&self) -> Result<&aos_sandbox_ledger_replay::cache_current::State, JournalError> {
        if !matches!(self.owner.selection, ReadonlySelectionV2::MaintenanceInitial
            | ReadonlySelectionV2::MaintenanceFinal) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.owner.source.body_complete_v1()?;
        self.owner.source.model.as_ref().ok_or(JournalError::ProtectedBoundary)?.raw_state_v1()
    }
}

pub(crate) struct RootCreateFinalityReadonlyOriginalV1 {
    selection: ReadonlySelectionV2,
    first: Option<TargetV1>,
    controller: FinalTargetOriginalV1,
    session: FinalTargetOriginalV1,
    source: FinalTargetOriginalV1,
}

/// Retains Stop's independent final Host cut after its permitted child progress.
///
/// This uses the same fixed/native/schema target as the initial reader. The
/// original initial cut remains resident; no old logical head is reset or
/// treated as unchanged after actual signed Host1/Host3 progression.
pub(crate) struct RootStopCleanupFinalHostOriginalV1 {
    session: FinalTargetOriginalV1,
}

impl RootStopCleanupFinalHostOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { session: FinalTargetOriginalV1::new(TargetV1::Session) }
    }

    pub(crate) fn observe_once_v1(&mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.session.observe_once_v1(&mut RootCreateFinalityReadStageV1::StopCleanupFinal(stage), clock)
    }

    pub(crate) fn session_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.session.body_complete_v1()?;
        self.session.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.replay_native_v1()
    }

    pub(crate) fn finish_posts_once_v1(&mut self) {
        self.session.finish_posts_once_v1();
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if matches!(self.session.primary, Some(Ok(())))
            && matches!(self.session.posts, Some(Ok(())))
            && self.session.first.is_none() && self.session.failure().is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.session.failure()
    }
}

impl RootCreateFinalityReadonlyOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { selection: ReadonlySelectionV2::FullFinality, first: None,
            controller: FinalTargetOriginalV1::new(TargetV1::Controller),
            session: FinalTargetOriginalV1::new(TargetV1::Session), source: FinalTargetOriginalV1::new(TargetV1::Source) }
    }

    pub(crate) fn observe_once_v1(&mut self, stage: &mut RootCreateFinalityReadStageV1<'_, '_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        if let Err(cause) = self.controller.observe_once_v1(stage, clock) {
            self.first = Some(TargetV1::Controller);
            return Err(cause);
        }
        if let Err(cause) = self.session.observe_once_v1(stage, clock) {
            self.first = Some(TargetV1::Session);
            return Err(cause);
        }
        if let Err(cause) = self.source.observe_once_v1(stage, clock) {
            self.first = Some(TargetV1::Source);
            return Err(cause);
        }
        Ok(())
    }

    /// Captures actual current C, Host Session and Source on the distinct paid purpose.
    /// The same targets own native capture, full replay and independently owed posts.
    pub(crate) fn observe_execution_no_apply_once_v2(
        &mut self, stage: &mut RootExecutionNoApplyStageReceivingV2<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.selection = ReadonlySelectionV2::ExecutionNoApply;
        self.observe_once_v1(&mut RootCreateFinalityReadStageV1::ExecutionNoApply(stage), clock)
    }

    /// Captures independent final C, Host Session and Source after real ACK.
    pub(crate) fn observe_execution_no_apply_final_once_v2(
        &mut self, stage: &mut RootExecutionNoApplyStageReceivingV2<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.selection = ReadonlySelectionV2::ExecutionNoApplyFinal;
        self.observe_once_v1(&mut RootCreateFinalityReadStageV1::ExecutionNoApplyFinal(stage), clock)
    }

    /// Captures genuine current C/Host/Source before any fresh cleanup acquisition.
    /// Its clocks belong to the newly verified Root/Controller purpose, never
    /// the historical64 cutoff. This reader alone supplies no cleanup authority.
    pub(crate) fn observe_execution_no_apply_acquisition_once_v2(
        &mut self, stage: &mut RootExecutionNoApplyStageReceivingV2<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.selection = ReadonlySelectionV2::ExecutionNoApplyAcquisition;
        self.observe_once_v1(&mut RootCreateFinalityReadStageV1::ExecutionNoApplyAcquisition(stage), clock)
    }

    pub(crate) fn execution_no_apply_current_data_v2(&self)
        -> Result<RootExecutionNoApplyCurrentDataV2<'_>, JournalError> {
        let data = RootExecutionNoApplyCurrentDataV2 { owner: self };
        data.controller_model_v2()?;
        Ok(data)
    }

    /// Requires the distinct initial acquisition reader, without a floor or ACK grant.
    pub(crate) fn require_execution_no_apply_acquisition_v2(&self) -> Result<(), JournalError> {
        if !matches!(self.selection, ReadonlySelectionV2::ExecutionNoApplyAcquisition) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.execution_no_apply_current_data_v2().map(|_| ())
    }

    /// Requires the distinct actual final reader rather than its earlier snapshot.
    pub(crate) fn require_execution_no_apply_final_v2(&self) -> Result<(), JournalError> {
        if !matches!(self.selection, ReadonlySelectionV2::ExecutionNoApplyFinal) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.execution_no_apply_current_data_v2().map(|_| ())
    }

    /// Captures current C, full Storage Session and Source on this actual purpose.
    /// Initial and final cuts keep separate native owners and finite R slots.
    pub(crate) fn observe_maintenance_storage_initial_once_v2(
        &mut self, stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.selection = ReadonlySelectionV2::MaintenanceInitial;
        self.observe_once_v1(&mut RootCreateFinalityReadStageV1::MaintenanceInitial(stage), clock)
    }

    pub(crate) fn observe_maintenance_storage_final_once_v2(
        &mut self, stage: &mut RootMaintenanceStorageStageReceivingV2<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.selection = ReadonlySelectionV2::MaintenanceFinal;
        self.observe_once_v1(&mut RootCreateFinalityReadStageV1::MaintenanceFinal(stage), clock)
    }

    pub(crate) fn maintenance_source_data_v2(&self) -> Result<RootMaintenanceSourceDataV2<'_>, JournalError> {
        let data = RootMaintenanceSourceDataV2 { owner: self };
        data.state_data_v2()?;
        Ok(data)
    }

    pub(crate) fn maintenance_current_data_v2(&self) -> Result<RootMaintenanceCurrentDataV2<'_>, JournalError> {
        let data = RootMaintenanceCurrentDataV2 { owner: self };
        data.controller_model_v2()?;
        Ok(data)
    }

    /// Captures only current C and Source for the genuine read-only Start purpose.
    /// All capture/audit/replay/post bodies are the same finite target engine.
    pub(crate) fn observe_start_inputs_once_v2(
        &mut self,
        stage: &mut RootStartAssignmentInputsStageReceivingV2<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.selection = ReadonlySelectionV2::StartInputs;
        let mut stage = RootCreateFinalityReadStageV1::StartInputs(stage);
        if let Err(cause) = self.controller.observe_once_v1(&mut stage, clock) {
            self.first = Some(TargetV1::Controller);
            return Err(cause);
        }
        if let Err(cause) = self.source.observe_once_v1(&mut stage, clock) {
            self.first = Some(TargetV1::Source);
            return Err(cause);
        }
        Ok(())
    }

    pub(crate) fn controller_v1(&mut self) -> Result<&mut crate::journal::Journal, JournalError> {
        self.controller.body_complete_v1()?;
        self.controller.model.as_mut().ok_or(JournalError::ProtectedBoundary)?.journal_mut_v1()
    }

    pub(crate) fn journals_v1(&mut self)
        -> Result<(&mut crate::journal::Journal, &mut crate::journal::Journal), JournalError>
    {
        self.controller.body_complete_v1()?;
        self.source.body_complete_v1()?;
        let controller = self.controller.model.as_mut().ok_or(JournalError::ProtectedBoundary)?.journal_mut_v1()?;
        let source = self.source.model.as_mut().ok_or(JournalError::ProtectedBoundary)?.journal_mut_v1()?;
        Ok((controller, source))
    }

    pub(crate) fn source_v1(&mut self) -> Result<&mut crate::journal::Journal, JournalError> {
        self.source.body_complete_v1()?;
        self.source.model.as_mut().ok_or(JournalError::ProtectedBoundary)?.journal_mut_v1()
    }

    /// Borrows the same immutable adopted C model after its paid late post.
    /// This performs no observation or reentry and supplies no writer grant.
    pub(crate) fn completed_controller_v1(&mut self) -> Result<&mut crate::journal::Journal, JournalError> {
        self.require_complete_v1()?;
        let model = self.controller.model.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        model.require_parent_post_v1()?;
        model.journal_mut_v1()
    }

    pub(crate) fn session_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.session.body_complete_v1()?;
        self.session.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.replay_native_v1()
    }

    pub(crate) fn cuts_v1(&self) -> Result<(NativeCutDataV1, NativeCutDataV1), JournalError> {
        self.controller.body_complete_v1()?;
        self.source.body_complete_v1()?;
        Ok((self.controller.native_data.ok_or(JournalError::ProtectedBoundary)?,
            self.source.native_data.ok_or(JournalError::ProtectedBoundary)?))
    }

    pub(crate) fn finish_posts_once_v1(&mut self) {
        self.controller.finish_posts_once_v1();
        if !matches!(self.selection, ReadonlySelectionV2::StartInputs) {
            self.session.finish_posts_once_v1();
        }
        self.source.finish_posts_once_v1();
    }

    /// Closes only the initial Host observation before permitted child progress.
    /// The unchanged C/Source model and its parent posts remain owned until the
    /// enclosing Stop exchange finishes. A final independent Host reader then
    /// authenticates the actual Host1/Host3 successor instead of resetting this
    /// historical head or demanding it remain current across the real child.
    pub(crate) fn finish_stop_initial_host_posts_once_v1(&mut self) -> Result<(), JournalError> {
        self.session.finish_posts_once_v1();
        if matches!(self.session.primary, Some(Ok(())))
            && matches!(self.session.posts, Some(Ok(())))
            && self.session.first.is_none() && self.session.failure().is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        let session_complete = matches!(self.selection, ReadonlySelectionV2::StartInputs)
            || matches!(self.session.posts, Some(Ok(())));
        if matches!(self.controller.posts, Some(Ok(())))
            && matches!(self.source.posts, Some(Ok(()))) && session_complete
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn selected_funding_failed_v1(&self) -> bool {
        match self.first {
            Some(TargetV1::Controller) => self.controller.funding_failed_v1(),
            Some(TargetV1::Session) => self.session.funding_failed_v1(),
            Some(TargetV1::Source) => self.source.funding_failed_v1(),
            None => false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(TargetV1::Controller) => self.controller.failure(),
            Some(TargetV1::Session) => self.session.failure(),
            Some(TargetV1::Source) => self.source.failure(),
            None => None,
        };
        if self.first.is_some() { selected } else {
            self.controller.failure().or_else(|| self.session.failure()).or_else(|| self.source.failure())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_source_body_keeps_its_identity_ahead_of_later_controller_post() {
        let mut readers = RootCreateFinalityReadonlyOriginalV1::new();
        readers.controller.funding = Some(Ok(()));
        readers.controller.primary = Some(Ok(()));
        readers.source.funding = Some(Ok(()));
        readers.source.primary = Some(Err(Box::new(std::io::Error::other("Source semantic refusal"))));
        readers.source.first = Some(TargetFailureV1::Primary);
        readers.first = Some(TargetV1::Source);
        let original = readers.failure().unwrap() as *const (dyn Error + 'static);

        readers.controller.posts = Some(Err(JournalError::ProtectedBoundary));
        readers.source.posts = Some(Err(JournalError::JournalTooLarge));

        assert!(std::ptr::eq(readers.failure().unwrap(), original));
        assert_eq!(readers.failure().unwrap().downcast_ref::<std::io::Error>().unwrap().to_string(),
            "Source semantic refusal");
    }

    #[test]
    fn post_only_failure_remains_visible_after_successful_bodies() {
        let mut readers = RootCreateFinalityReadonlyOriginalV1::new();
        readers.controller.funding = Some(Ok(()));
        readers.controller.primary = Some(Ok(()));
        readers.controller.posts = Some(Err(JournalError::JournalTooLarge));

        assert!(matches!(readers.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::JournalTooLarge)));
    }
}

/// Selects one closed preparatory reader under the same actual Host Root stage.
#[derive(Clone, Copy)]
pub(in crate::policy_compiler) enum StartPreparationSessionKindV2 {
    MountBefore62,
    HostNetworkCatalog,
    HostMountCatalog,
}

impl StartPreparationSessionKindV2 {
    fn resource_kind_v2(self) -> crate::policy_compiler::host_launch_root::kind::ResourceKindV2 {
        use crate::policy_compiler::host_launch_root::kind::ResourceKindV2;
        match self {
            Self::HostNetworkCatalog => ResourceKindV2::Network,
            Self::HostMountCatalog | Self::MountBefore62 => ResourceKindV2::Mount,
        }
    }

    fn admit_once_v2(self, stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        plane: ReadPlaneV1, demand: RootContinuationDemandV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        match (self, plane) {
            (Self::HostNetworkCatalog, ReadPlaneV1::Fixed) => stage.admit_host_catalog_network_fixed_once_v2(demand),
            (Self::HostNetworkCatalog, ReadPlaneV1::Native) => stage.admit_host_catalog_network_native_once_v2(demand),
            (Self::HostNetworkCatalog, ReadPlaneV1::Semantic) => stage.admit_host_catalog_network_semantic_once_v2(demand),
            (Self::HostMountCatalog, ReadPlaneV1::Fixed) => stage.admit_host_catalog_mount_fixed_once_v2(demand),
            (Self::HostMountCatalog, ReadPlaneV1::Native) => stage.admit_host_catalog_mount_native_once_v2(demand),
            (Self::HostMountCatalog, ReadPlaneV1::Semantic) => stage.admit_host_catalog_mount_semantic_once_v2(demand),
            (Self::MountBefore62, ReadPlaneV1::Fixed) => stage.admit_mount_before62_fixed_once_v2(demand),
            (Self::MountBefore62, ReadPlaneV1::Native) => stage.admit_mount_before62_native_once_v2(demand),
            (Self::MountBefore62, ReadPlaneV1::Semantic) => stage.admit_mount_before62_semantic_once_v2(demand),
        }
    }
}

/// Owns one real preparatory Session capture through the existing native engine.
///
/// Construction fixes its path and finite stage destinations. Session data is
/// lent only from that original replay; independent native posts remain owed
/// after any reached capture, funding, clock, replay or comparison refusal.
pub(in crate::policy_compiler) struct RootStartPreparationSessionReadOriginalV2 {
    target: FinalTargetOriginalV1,
    kind: StartPreparationSessionKindV2,
}

impl RootStartPreparationSessionReadOriginalV2 {
    pub(in crate::policy_compiler) fn new(kind: StartPreparationSessionKindV2) -> Self {
        Self {
            target: FinalTargetOriginalV1::new(TargetV1::Session),
            kind,
        }
    }

    pub(in crate::policy_compiler) fn observe_once_v2(&mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.target.observe_once_v1(
            &mut RootCreateFinalityReadStageV1::PreparationSession(stage, self.kind), clock,
        )
    }

    pub(in crate::policy_compiler) fn session_v2(&self)
        -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        if !matches!(self.target.primary, Some(Ok(())))
            || self.target.posts.as_ref().is_some_and(Result::is_err)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.target.native.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .replay_native_v1()
    }

    pub(in crate::policy_compiler) fn finish_posts_once_v2(&mut self) {
        self.target.finish_posts_once_v1();
    }

    pub(in crate::policy_compiler) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if matches!(self.target.posts, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(in crate::policy_compiler) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.target.failure()
    }
}
