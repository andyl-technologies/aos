//! Keeps selected scheduler, publication and installation inside the actual capsule.
//!
//! Only narrow phase methods cross the module boundary. Neither the ordinary
//! runtime nor its mutable native nodes, prepared publisher or graph escapes.

use super::*;
use crucible::node_admission::CompleteOriginalRestorationWindow;
use crucible::node_contract::{ActivationRecord, OriginalLineageRestoration, RuntimeError};

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn construct_original_complete_scope(
        &self, window: &Rc<CompleteOriginalRestorationWindow>, plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        window.construct_original_complete_scope(plan,
            self.runtime.as_ref().ok_or(RuntimeError::OwnerUnavailable)?, activation)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_complete_context<'a>(
        &self, window: &'a Rc<CompleteOriginalRestorationWindow>, plan: &'a InstalledConformancePlan,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        window.prepare_original_complete_context(plan,
            self.runtime.as_ref().ok_or(RuntimeError::OwnerUnavailable)?)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_complete_scheduler(
        &self, window: &Rc<CompleteOriginalRestorationWindow>, plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime.as_ref().ok_or(RuntimeError::OwnerUnavailable)?
            .prepare_original_installed_scheduler(window, plan, context)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn arm_original_complete_restoration(
        &mut self, window: &Rc<CompleteOriginalRestorationWindow>, plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime.as_mut().ok_or(RuntimeError::OwnerUnavailable)?
            .arm_original_installed_restoration(window, plan, context)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retain_original_complete_coordinator(
        &self, window: &Rc<CompleteOriginalRestorationWindow>, plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        let runtime = self.runtime.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        self.publication.as_ref().ok_or(RuntimeError::OwnerUnavailable)?
            .with_original_publisher_data(window.original_coordinator_construction_data()?, |publisher| {
                runtime.retain_original_installed_coordinator(window, plan, context, publisher)
            })
    }

    pub(in crate::node_qualification::packet_collection::complete) fn publish_original_complete_restoration(
        &mut self, window: &Rc<CompleteOriginalRestorationWindow>, plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        let runtime = self.runtime.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let publication = self.publication.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        publication.with_original_publisher_data(window.original_coordinator_construction_data()?, |publisher| {
            runtime.publish_original_installed_restoration(window, plan, context, publisher)
        })
    }

    pub(in crate::node_qualification::packet_collection::complete) fn install_original_complete_restoration(
        &mut self, window: &Rc<CompleteOriginalRestorationWindow>, plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.runtime.as_mut().ok_or(RuntimeError::OwnerUnavailable)?
            .install_original_installed_restoration(window, plan, context)
    }
}
