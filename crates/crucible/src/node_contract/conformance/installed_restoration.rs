//! Keeps the actual selected restoration runtime within its installed window.
//!
//! These forwarding loans expose no ordinary graph/runtime and never reinterpret
//! an initial-only observer as restored authority. Current backing is walked
//! from actual populated nodes, ledgers, scheduler and publication roots.

use super::*;
use crate::node_admission::{CompleteOriginalRestorationWindow, InstalledConformancePlan};
use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
use std::mem::size_of;

impl ConformanceRuntime {
    pub(crate) fn authenticate_original_installed_runtime_data(
        &self,
        window: &CompleteOriginalRestorationWindow,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &InstalledConformancePlan,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_complete_original_restoration_origin()?;
        if !self.graph.plan().is_same_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.authenticate_original_installed_runtime_identity_data(
            &self.runtime,
            archive,
            plan,
            target,
        )
    }

    pub(crate) fn original_installed_restoration_retained_storage_precredit_data(
        &self,
        window: &CompleteOriginalRestorationWindow,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &InstalledConformancePlan,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_installed_runtime_data(window, archive, plan, target)?;
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.add(
            self.runtime
                .original_retained_requested_storage_precredit_data(maximum)?,
        )?;
        if counter.rc(&self.graph)? {
            self.graph
                .charge_original_retained_storage_precredit_data(&mut counter)?;
        }
        if let Some(source) = &self.exact_inputs
            && counter.rc(source)?
        {
            counter.add(
                source.retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
                    archive, maximum,
                )?,
            )?;
        }
        if let Some(activation) = &self.activation {
            let facts = activation.retained_requested_storage_data(maximum)?;
            counter.views(
                facts.independent_bytes(),
                facts
                    .shared_allocations()
                    .map(|root| (root.identity(), root.requested_bytes())),
            )?;
        }
        self.authenticate_original_installed_runtime_data(window, archive, plan, target)?;
        Ok(counter.bytes())
    }

    pub(crate) fn original_installed_restoration_descriptor_views_precredit_data(
        &self,
        window: &CompleteOriginalRestorationWindow,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &InstalledConformancePlan,
        target: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_original_installed_runtime_data(window, archive, plan, target)?;
        let descriptors = self
            .runtime
            .original_inactive_descriptor_views_precredit_data()?;
        self.authenticate_original_installed_runtime_data(window, archive, plan, target)?;
        Ok(descriptors)
    }
}

impl ConformanceRuntime {
    /// Retains the genuine paused scheduler under the admitted complete context.
    ///
    /// # Errors
    /// Refuses another window/runtime/plan/context, repeated preparation, changed
    /// source scheduling or unresolved original queues and input custody.
    pub fn prepare_original_installed_scheduler(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        window.authenticate_original_context_owner_data(context)?;
        context.validate_current(&self.runtime)?;
        let (archive, _) = window.original_installed_context_inputs_data()?;
        window.retain_original_paused_scheduler_data(self, plan, || {
            self.runtime.prepare_original_lineage_scheduler(
                &self.graph.graph,
                context,
                archive.original_host_record_data()?.scheduling.clone(),
            )
        })
    }

    /// Arms actual selected owners after complete four-owner context admission.
    ///
    /// # Errors
    /// Refuses a missing whole observation, another installed context or failed
    /// Source-signed activation phase. Actual partial native attempts remain owned.
    pub fn arm_original_installed_restoration(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        window.authenticate_original_context_owner_data(context)?;
        window.authenticate_original_common_construction_data(self, plan)?;
        self.runtime.arm_original_lineage_restoration(context)?;
        context.validate_current(&self.runtime)
    }

    /// Retains the actual original coordinator before the durable publication call.
    ///
    /// # Errors
    /// Refuses missing authentic readiness, changed four-owner context, an
    /// unadmitted constructor, duplicate handoff or a failing concrete publisher.
    pub fn retain_original_installed_coordinator(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), RuntimeError> {
        window.authenticate_original_context_owner_data(context)?;
        window.authenticate_original_common_construction_data(self, plan)?;
        context.validate_current(&self.runtime)?;
        window.with_original_paused_scheduler_data(|scheduler| {
            window.retain_original_selected_coordinator_data(
                plan,
                self.graph.world(),
                context,
                scheduler,
                self.runtime.prepared_node_records()?,
                publisher,
            )
        })?;
        context.validate_current(&self.runtime)
    }

    /// Publishes the same complete original readiness without initial-route reuse.
    ///
    /// # Errors
    /// Refuses foreign context, missing whole observation, repeated publication,
    /// changed native/source custody or unavailable durable complete publication.
    /// Uncertain original publication stays in the actual runtime barrier.
    pub fn publish_original_installed_restoration(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<(), RuntimeError> {
        window.authenticate_original_context_owner_data(context)?;
        window.authenticate_original_common_construction_data(self, plan)?;
        context.validate_current(&self.runtime)?;
        if self.activation.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        window.authenticate_original_publisher_member_data(plan, publisher)?;
        self.activation = Some(self.runtime.activate_collection(&self.graph, publisher)?);
        window.authenticate_original_publisher_member_data(plan, publisher)?;
        window.retain_original_published_world_data(
            plan,
            self,
            self.activation.as_ref().ok_or(RuntimeError::NotActivated)?,
        )?;
        context.validate_current(&self.runtime)
    }

    /// Installs actual Runtime7 ledgers and paused scheduling after publication.
    ///
    /// # Errors
    /// Refuses a foreign context/activation, missing whole observation, repeated
    /// installation or failed selected native custody. Existing common containment
    /// retains the runtime and all original operation and input journal owners.
    pub fn install_original_installed_restoration(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        window.authenticate_original_context_owner_data(context)?;
        let activation = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        let scheduling = window.duplicate_original_paused_scheduler_for_install_data(self, plan)?;
        self.runtime.install_complete_original_lineage_restoration(
            &self.graph.graph,
            context,
            activation,
            scheduling,
        )?;
        context.validate_current(&self.runtime)
    }
}
