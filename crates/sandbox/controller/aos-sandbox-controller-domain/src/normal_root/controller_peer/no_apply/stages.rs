//! Holds the real native NoApply peer across short upper receiving intervals.
//!
//! No standalone stage ledger, completion flag or supplied financial handle is
//! retained here. Native Policy owns307 and each actual returned stage cause.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    RootExecutionNoApplyReadPhaseV2 as Phase, RootNoApplyControllerPeerOriginalV2 as Peer,
    RootNoApplyStageDataV2 as Stage,
};
use std::mem::size_of;

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};

pub(crate) struct RootExecutionNoApplyStageReceivingV2<'flight, 'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    peer: &'flight mut Peer<'startup>,
}

impl<'flight, 'startup> RootExecutionNoApplyStageReceivingV2<'flight, 'startup> {
    pub(super) fn new_v2(
        startup: &'startup ProductionNormalRootStartupV1,
        peer: &'flight mut Peer<'startup>,
    ) -> Self {
        Self { startup, peer }
    }

    pub(super) fn construction_control_bytes_v2() -> Option<usize> {
        // Every finite stage entry delegates immediately to the same private
        // admit call. Their single largest co-resident entry has a phase.
        let entry = size_of::<(&mut Self, Phase, RootContinuationDemandV1)>()
            .max(size_of::<(&mut Self, RootContinuationDemandV1)>());
        let construction = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(size_of::<Result<Self, Error>>().checked_mul(2)?)?
            .checked_add(
                size_of::<(&ProductionNormalRootStartupV1, &mut Peer<'static>)>().checked_mul(2)?,
            )?;
        let admission = entry
            .checked_add(size_of::<Result<(), Error>>())?
            .checked_mul(2)?
            .checked_add(
                size_of::<(&mut Self, Stage, RootContinuationDemandV1)>()
                    .checked_add(size_of::<Result<(), Error>>())?
                    .checked_mul(2)?,
            )?;

        // These read-only entries have different real return shapes; none
        // donates a larger unrelated owner's header to another operation.
        let queries = size_of::<&Self>()
            .checked_add(size_of::<
                Result<(ResourceVector, ResourceVector, ResourceVector), Error>,
            >())?
            .checked_mul(2)?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<(u32, u32)>())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<Result<[u8; 16], Error>>())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(&Self, ResourceVector)>()
                    .checked_add(size_of::<Result<(), Error>>())?
                    .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<&Self>()
                    .checked_add(size_of::<Option<&(dyn std::error::Error + 'static)>>())?
                    .checked_mul(2)?,
            )?;
        construction.checked_add(admission)?.checked_add(queries)
    }

    pub(crate) fn controller_baseline_partition_v1(
        &self,
    ) -> Result<(ResourceVector, ResourceVector, ResourceVector), Error> {
        self.peer.require_initial_v2().map_err(|_| Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving
            .original_mut_v1()
            .current_controller_baseline_partition_data_v1();
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn controller_identity_v1(&self) -> (u32, u32) {
        let identities = self.startup.native.fields().profile.identities;
        (identities[0], identities[1])
    }

    pub(crate) fn enrolled_node_v1(&self) -> Result<[u8; 16], Error> {
        self.peer.require_initial_v2().map_err(|_| Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving
            .original_mut_v1()
            .native_no_apply_node_data_v2(self.peer);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_execution_transport_prepaid_v2(
        &self,
        required: ResourceVector,
    ) -> Result<(), Error> {
        self.peer
            .require_transport_prepaid_v2(required)
            .map_err(Into::into)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.peer.continuation_failure_v2()
    }

    fn admit_once(&mut self, stage: Stage, demand: RootContinuationDemandV1) -> Result<(), Error> {
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving
            .original_mut_v1()
            .admit_native_no_apply_stage_v2(self.peer, stage, demand);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn admit_execution_no_apply_acquisition_trust_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::AcquisitionTrust, demand)
    }

    pub(crate) fn admit_execution_no_apply_acquisition_models_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::AcquisitionModels, demand)
    }

    pub(crate) fn admit_execution_no_apply_acquisition_sign_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::AcquisitionSign, demand)
    }

    pub(crate) fn admit_execution_no_apply_ack_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Ack, demand)
    }

    pub(crate) fn admit_execution_no_apply_host_trust_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::HostTrust, demand)
    }

    pub(crate) fn admit_execution_no_apply_floor_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Floor, demand)
    }

    pub(crate) fn admit_execution_no_apply_host_current_lease_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::HostCurrentLease, demand)
    }

    pub(crate) fn admit_execution_no_apply_models_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Models, demand)
    }

    pub(crate) fn admit_execution_no_apply_acquisition_read_once_v2(
        &mut self,
        phase: Phase,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::AcquisitionRead(phase), demand)
    }

    pub(crate) fn admit_execution_no_apply_final_read_once_v2(
        &mut self,
        phase: Phase,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::FinalRead(phase), demand)
    }

    pub(crate) fn admit_execution_no_apply_controller_fixed_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::ControllerFixed), demand)
    }

    pub(crate) fn admit_execution_no_apply_controller_native_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::ControllerNative), demand)
    }

    pub(crate) fn admit_execution_no_apply_controller_semantic_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::ControllerSemantic), demand)
    }

    pub(crate) fn admit_execution_no_apply_host_session_fixed_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::HostSessionFixed), demand)
    }

    pub(crate) fn admit_execution_no_apply_host_session_native_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::HostSessionNative), demand)
    }

    pub(crate) fn admit_execution_no_apply_host_session_semantic_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::HostSessionSemantic), demand)
    }

    pub(crate) fn admit_execution_no_apply_source_fixed_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::SourceFixed), demand)
    }

    pub(crate) fn admit_execution_no_apply_source_native_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::SourceNative), demand)
    }

    pub(crate) fn admit_execution_no_apply_source_semantic_once_v2(
        &mut self,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(Stage::Read(Phase::SourceSemantic), demand)
    }
}
