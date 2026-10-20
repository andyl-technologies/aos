//! Joins completed Create to the same Controller's next native purpose.
//!
//! This private Bank adapter selects no account and cannot renew J or U. Its
//! native staged original uses the same C baseline, writer, confirmed launch
//! and profile while the original completed intake stays with the caller.

mod source;
mod completion;
mod network_endpoint;

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1;
use aos_sandbox_model::ResourceVector;

use crate::controller_resource_reservation::create_intake::provisioning::CreateStorageCompletedIntakeOriginalV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::Journal;

use super::super::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};

impl ControllerResourceBankOpeningV1 {
    /// Starts the separate purpose only from the actual completed intake.
    ///
    /// The installed caller retains this whole result before inspecting entry.
    /// The lower original retains admission errors and owns its independently
    /// owed native post; a coarse error must never discard that original.
    pub(crate) fn begin_create_provisioning_receiving_v1(
        &self,
        completed: &CreateStorageCompletedIntakeOriginalV1<'_>,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<ControllerCreateProvisioningReceivingV1, ResourceReservationErrorV1> {
        completed.require_current_v1()?;
        completed.require_original_owners_v1(controller, source, profile)?;
        self.begin_provisioning_native_v1(controller, profile, complete)
    }

    // Both closed upper contexts select the same native Bank/name/profile body.
    // A fresh Start cannot call this helper without its completed predecessor.
    fn begin_provisioning_native_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<ControllerCreateProvisioningReceivingV1, ResourceReservationErrorV1> {
        self.require_operation_intake_entry_v1(controller, profile)?;
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;

        launch.require_controller_baseline_precharge_v1(
            controller.controller_coordinator_for_bank_read_v1()?)?;
        Ok(controller.controller_coordinator_for_bank_v1()?
            .begin_create_provisioning_receiving_v1(
                launch, profile.lower_original_v1(), complete,
            ))
    }

    pub(crate) fn begin_accepted_start_native_v1(
        &self,
        predecessor: &crate::controller_resource_reservation::create_intake::provisioning::StartNativeEntryPredecessorV1<'_>,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<ControllerCreateProvisioningReceivingV1, ResourceReservationErrorV1> {
        predecessor.require_bank_v1(self, controller, profile)?;
        self.begin_provisioning_native_v1(controller, profile, complete)
    }

    /// Rejoins the same fixed writer and profile during the retained purpose.
    pub(crate) fn require_create_provisioning_current_v1(
        &self,
        original: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.require_current_v1(
            controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }

    /// Borrows the current baseline head after the same native C23 join.
    ///
    /// Owner23 is a subdivision of this C, not a new bank claim. The native
    /// original owns the paid fixed-name/profile/launch observations; this
    /// projection performs only the existing complete materialized bank fold.
    pub(crate) fn provisioning_controller_head_v1<'journal>(
        &self,
        original: &ControllerCreateProvisioningReceivingV1,
        controller: &'journal Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&'journal [u8], ResourceReservationErrorV1> {
        self.require_create_provisioning_current_v1(original, controller, profile)?;
        self.baseline_controller_head_data_v3(controller)
    }

    // Every caller first rejoins its own actual native receiving purpose.
    // The enrolled baseline fold and account selection are shared DATA work.
    pub(super) fn baseline_controller_head_data_v3<'journal>(
        &self,
        controller: &'journal Journal,
    ) -> Result<&'journal [u8], ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::resource_bank as bank;

        let enrolled = self.observed.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let state = controller.controller_resource_state_v1()?;
        if bank::validate(state)? != Some(enrolled.identity) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank::head_bytes(state, enrolled.identity.account_id(b"controller"))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Compares an actual initial Storage receiver with this same Bank original.
    pub(crate) fn require_provisioning_initial_storage_original_v1(
        &self,
        initial: &super::super::initial_session::ControllerInitialBrokerSessionReceivingV1,
        profile: &std::sync::Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        initial.require_provisioning_owner_v1(&self.original, profile)
    }

    /// Rejoins the same positively completed native original without new IO.
    pub(crate) fn require_completed_provisioning_original_v1(
        &self,
        original: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.require_completed_original_v1(
            controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }

    /// Raises only this original purpose's monotone representation requirement.
    pub(crate) fn require_create_provisioning_complete_v1(
        &self,
        original: &mut ControllerCreateProvisioningReceivingV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.require_complete_representation_v1(
            controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(), complete,
        ).map_err(Into::into)
    }

    /// Begins the next turn only through this original's positive disposition.
    pub(crate) fn begin_next_create_provisioning_turn_v1(
        &self,
        completed: &CreateStorageCompletedIntakeOriginalV1<'_>,
        original: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        completed.require_original_owners_v1(controller, source, profile)?;
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.begin_next_native_turn_v1(
            controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(), complete,
        ).map_err(Into::into)
    }

    pub(crate) fn begin_next_start_provisioning_turn_v1(&self,
        original:&mut ControllerCreateProvisioningReceivingV1,controller:&mut Journal,
        profile:&ProductionControllerNormalRootProfileV1,complete:ResourceVector,
    )->Result<(),ResourceReservationErrorV1> {
        let launch=self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.begin_next_native_turn_v1(controller.controller_coordinator_for_bank_v1()?,
            launch,profile.lower_original_v1(),complete).map_err(Into::into)
    }

    pub(crate) fn current_start_provisioning_node_v1(&self,
        original:&ControllerCreateProvisioningReceivingV1,controller:&Journal,
        profile:&ProductionControllerNormalRootProfileV1,
    )->Result<aos_sandbox_model::NodeId,ResourceReservationErrorV1> {
        self.require_create_provisioning_current_v1(original,controller,profile)?;
        let enrollment=self.observed.as_ref().and_then(|value|value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(aos_sandbox_model::NodeId::from_bytes(enrollment.identity.native_fields().node))
    }

    /// Runs the independently prepaid native post after every entered body.
    pub(crate) fn finish_create_provisioning_native_once_v1(
        &self,
        original: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        // No healthy-entry or semantic-success gate may suppress this post.
        let launch = self.launch.as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        original.finish_native_once(
            controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }
}
