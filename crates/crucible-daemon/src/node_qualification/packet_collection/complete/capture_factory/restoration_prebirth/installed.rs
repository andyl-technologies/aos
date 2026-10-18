//! Keeps selected scheduler, publication and installation inside the actual capsule.
//!
//! Only narrow phase methods cross the module boundary. Neither the ordinary
//! runtime nor its mutable native nodes, prepared publisher or graph escapes.

use super::*;
use crucible::node_adapters::cnp::PacketCompleteOriginalHostSdk;
use crucible::node_admission::{
    OriginalRestoredInitialSchedulingAdmission, OriginalRestoredSchedulingObservationAdmission,
};
use crucible::node_contract::RuntimePollFailure;
use crucible::node_scheduling::ValidatedSchedulingObservation;
use crucible_node_contract::Id;
use crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;

use crucible::node_admission::CompleteOriginalRestorationWindow;
use crucible::node_contract::{ActivationRecord, OriginalLineageRestoration, RuntimeError};

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn construct_original_complete_scope(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        window.construct_original_complete_scope(plan, &*self.runtime_data()?, activation)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_complete_context<
        'a,
    >(
        &self,
        window: &'a Rc<CompleteOriginalRestorationWindow>,
        plan: &'a InstalledConformancePlan,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        window.prepare_original_complete_context(plan, &*self.runtime_data()?)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_complete_scheduler(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime_data()?
            .prepare_original_installed_scheduler(window, plan, context)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn initialize_original_complete_coordinator17_before_activation(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime_data()?
            .initialize_original_installed_coordinator17_before_activation_data(
                window, plan, context,
            )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn arm_original_complete_restoration(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime_mut_data()?
            .arm_original_installed_restoration(window, plan, context)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retain_original_complete_coordinator(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        self.publication
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .with_original_publisher_data(
                window.original_coordinator_construction_data()?,
                |publisher| {
                    runtime.retain_original_installed_coordinator(window, plan, context, publisher)
                },
            )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn publish_original_complete_restoration(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .get_mut();
        let publication = self
            .publication
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        publication.with_original_publisher_data(
            window.original_coordinator_construction_data()?,
            |publisher| {
                runtime.publish_original_installed_restoration(window, plan, context, publisher)
            },
        )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn install_original_complete_restoration(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime_mut_data()?
            .install_original_installed_restoration(window, plan, context)
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn activate_original_complete_restoration_worlds(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime_mut_data()?
            .activate_original_installed_restoration_worlds(window, plan, context)
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_complete_restored_scheduling(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        node: &Id,
    ) -> Result<OriginalRestoredSchedulingObservationAdmission, RuntimeError> {
        self.runtime_data()?
            .prepare_original_installed_restored_scheduling(
                window,
                plan,
                sdks,
                launches,
                canonical_launch5,
                node,
            )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn observe_original_complete_restored_scheduling(
        &mut self,
        admission: &mut OriginalRestoredSchedulingObservationAdmission,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        node: &Id,
    ) -> Result<ValidatedSchedulingObservation, RuntimePollFailure> {
        self.runtime_mut_data()
            .map_err(RuntimePollFailure::Admission)?
            .observe_original_installed_restored_scheduling(
                admission,
                launch,
                canonical_launch5,
                node,
            )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_complete_initial_scheduling(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        node: &Id,
    ) -> Result<OriginalRestoredInitialSchedulingAdmission, RuntimeError> {
        self.runtime_data()?
            .prepare_original_installed_initial_scheduling(
                window,
                plan,
                sdks,
                launches,
                canonical_launch5,
                node,
            )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn observe_original_complete_initial_scheduling(
        &mut self,
        admission: &mut OriginalRestoredInitialSchedulingAdmission,
        node: &Id,
    ) -> Result<(), RuntimePollFailure> {
        self.runtime_mut_data()
            .map_err(RuntimePollFailure::Admission)?
            .observe_original_installed_initial_scheduling(admission, node)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn seed_original_complete_restored_suffix(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        node: &Id,
    ) -> Result<(), RuntimeError> {
        self.runtime_data()?
            .seed_original_installed_restored_suffix(window, plan, node)
    }
}
