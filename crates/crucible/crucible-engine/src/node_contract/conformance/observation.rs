//! Borrows actual wrapper fields and the same runtime for complete observation.
//!
//! A split borrower retains genuine immutable wrapper-field loans while its
//! caller lends the actual NodeRuntime mutably to a writer. A callback must
//! release all owner loans before lending it to the complete owning census.
//! Process pointers are compared as identity DATA and are never dereferenced.

use super::*;
use crate::node_admission::{CompleteOriginalRestorationWindow, InstalledConformancePlan};
use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
use std::mem::size_of;

/// Borrows genuine wrapper fields and a current shared loan of its same runtime.
///
/// This view grants no operation, native claim, allocation, currentness, or
/// observation credit. Its private constructors retain original wrapper and
/// runtime identities. A split view cannot reconstruct a whole wrapper loan.
#[derive(Clone, Copy)]
pub struct ConformanceRuntimeObservation<'a> {
    fields: ConformanceRuntimeObservationFields<'a>,
    runtime: &'a NodeRuntime,
    whole_owner: Option<&'a ConformanceRuntime>,
}

/// Keeps actual non-runtime field loans across a separate mutable runtime loan.
#[derive(Clone, Copy)]
pub(crate) struct ConformanceRuntimeObservationFields<'a> {
    owner_identity: *const ConformanceRuntime,
    runtime_identity: *const NodeRuntime,
    graph: &'a Rc<ConformanceGraph>,
    activation: &'a Option<WorldActivation>,
    quantized: &'a bool,
    exact_inputs: &'a Option<Rc<super::super::HostSchedulingSource>>,
    origin: &'a CollectionOrigin,
}

impl ConformanceRuntime {
    /// Borrows the actual wrapper for a complete retained-state observation.
    ///
    /// No allocation, state copy, permission or currentness check occurs here.
    pub fn observation_data(&self) -> ConformanceRuntimeObservation<'_> {
        ConformanceRuntimeObservation {
            fields: ConformanceRuntimeObservationFields {
                owner_identity: std::ptr::from_ref(self),
                runtime_identity: std::ptr::from_ref(&self.runtime),
                graph: &self.graph,
                activation: &self.activation,
                quantized: &self.quantized,
                exact_inputs: &self.exact_inputs,
                origin: &self.origin,
            },
            runtime: &self.runtime,
            whole_owner: Some(self),
        }
    }

    /// Separates genuine other-field loans from the actual mutable runtime.
    pub(crate) fn split_observation_runtime_data(
        &mut self,
    ) -> (ConformanceRuntimeObservationFields<'_>, &mut NodeRuntime) {
        let owner_identity = std::ptr::from_ref(&*self);
        let runtime_identity = std::ptr::from_ref(&self.runtime);
        let Self {
            graph,
            runtime,
            activation,
            quantized,
            exact_inputs,
            origin,
        } = self;
        (
            ConformanceRuntimeObservationFields {
                owner_identity,
                runtime_identity,
                graph,
                activation,
                quantized,
                exact_inputs,
                origin,
            },
            runtime,
        )
    }
}

impl ConformanceRuntimeObservationFields<'_> {
    /// Borrows the original immutable collecting graph handle without cloning.
    pub(crate) fn graph_data(&self) -> &Rc<ConformanceGraph> {
        self.graph
    }

    /// Borrows the actual current activation field without substituting a DTO.
    pub(crate) fn activation_data(&self) -> Option<&WorldActivation> {
        self.activation.as_ref()
    }

    /// Borrows the actual installed Host scheduling source field.
    pub(crate) fn exact_inputs_data(&self) -> Option<&Rc<super::super::HostSchedulingSource>> {
        self.exact_inputs.as_ref()
    }

    /// Lends a full observation view only from the original actual runtime.
    ///
    /// # Errors
    /// Refuses another runtime allocation. The observer separately repeats all
    /// original plan, authority, policy, currentness and owner-census predicates.
    pub(crate) fn with_runtime_data<'a>(
        &'a self,
        runtime: &'a NodeRuntime,
    ) -> Result<ConformanceRuntimeObservation<'a>, RuntimeError> {
        if !std::ptr::eq(self.runtime_identity, runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(ConformanceRuntimeObservation {
            fields: *self,
            runtime,
            whole_owner: None,
        })
    }
}

impl<'a> ConformanceRuntimeObservation<'a> {
    /// Reports the original wrapper's actual quantized operating-mode field.
    pub fn is_quantized_data(&self) -> bool {
        *self.fields.quantized
    }

    /// Compares the genuine original wrapper allocation as identity DATA only.
    ///
    /// Equality creates no authority and does not dereference the pointer.
    pub fn is_original_runtime_data(&self, original: *const ConformanceRuntime) -> bool {
        !original.is_null()
            && self.fields.owner_identity == original
            && std::ptr::eq(self.fields.runtime_identity, self.runtime)
    }

    /// Borrows only a whole wrapper that the original caller actually lent.
    ///
    /// Split writer observations never contain such a loan. This method cannot
    /// recreate one from a pointer, runtime, DTO or historical state.
    ///
    /// # Errors
    /// Refuses a split observation with no genuine original whole-owner loan.
    pub fn original_whole_owner_data(&self) -> Result<&'a ConformanceRuntime, RuntimeError> {
        self.whole_owner.ok_or(RuntimeError::OutstandingObligations)
    }

    /// Authenticates the actual complete-restoration origin and runtime identity.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn authenticate_complete_original_restoration_origin(
        &self,
    ) -> Result<(), RuntimeError> {
        if *self.fields.origin != CollectionOrigin::CompleteRestoration
            || !std::ptr::eq(self.fields.runtime_identity, self.runtime)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Names the actual fixed borrowed views added to the complete observer.
    pub(crate) const fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<ConformanceRuntimeObservationFields<'static>>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<(
                &crucible_node_format::WorldBinding,
                &super::super::HostSchedulingSource,
            )>()
            + size_of::<
                Result<
                    (
                        &crucible_node_format::WorldBinding,
                        &super::super::HostSchedulingSource,
                    ),
                    RuntimeError,
                >,
            >()
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Repeats the original installed Window, plan and actual runtime predicates.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn authenticate_original_installed_runtime_data(
        &self,
        window: &CompleteOriginalRestorationWindow,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &InstalledConformancePlan,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_complete_original_restoration_origin()?;
        if !self.fields.graph.plan().is_same_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        window.authenticate_original_installed_runtime_identity_data(
            self.runtime,
            archive,
            plan,
            target,
        )
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Counts the actual installed wrapper and all original retained child owners.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
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
        counter.add(size_of::<ConformanceRuntime>())?;
        counter.add(
            self.runtime
                .original_retained_requested_storage_precredit_data(maximum)?,
        )?;
        if counter.rc(self.fields.graph)? {
            self.fields
                .graph
                .charge_original_retained_storage_precredit_data(&mut counter)?;
        }
        if let Some(source) = self.fields.exact_inputs
            && counter.rc(source)?
        {
            counter.add(
                source.retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
                    archive, maximum,
                )?,
            )?;
        }
        if let Some(activation) = self.fields.activation {
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
}

impl ConformanceRuntimeObservation<'_> {
    /// Counts actual installed node and custody descriptor views.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
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

impl ConformanceRuntimeObservation<'_> {
    /// Authenticates cold target custody through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn authenticate_original_restoration_target_data(
        &self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.original_whole_owner_data()?
            .authenticate_original_restoration_target_data(source, plan, activation)
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Quotes cold group scratch through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn original_restoration_group_counter_scratch_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<usize, RuntimeError> {
        self.original_whole_owner_data()?
            .original_restoration_group_counter_scratch_data(inputs, plan)
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Quotes a cold native node through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn quote_original_restoration_node_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
        maximum: usize,
    ) -> Result<crate::node_admission::OriginalRestorationNodeConstructionData, RuntimeError> {
        self.original_whole_owner_data()?
            .quote_original_restoration_node_data(inputs, plan, maximum)
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Quotes the cold native group through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn quote_original_restoration_group_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
        maximum: usize,
    ) -> Result<[crate::node_admission::OriginalRestorationNodeConstructionData; 3], RuntimeError>
    {
        self.original_whole_owner_data()?
            .quote_original_restoration_group_data(inputs, plan, maximum)
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Borrows cold member identity through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn original_restoration_live_member_identity_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<super::OriginalRestorationRuntimeMemberIdentity, RuntimeError> {
        self.original_whole_owner_data()?
            .original_restoration_live_member_identity_data(archive, plan, activation)
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Quotes cold signer construction through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn quote_original_restoration_signer_node_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationConstructionInputs<'_>,
        plan: &crate::node_admission::InstalledConformancePlan,
        cold: &crate::node_adapters::cnp::OriginalRestorationColdGroup,
        activation_request_ids: &[Id; 2],
        observation_request_id: Option<&Id>,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum_record_bytes: usize,
        observed_other_retained_bytes: usize,
        maximum: usize,
    ) -> Result<crate::node_admission::OriginalRestorationNodeConstructionData, RuntimeError> {
        self.original_whole_owner_data()?
            .quote_original_restoration_signer_node_data(
                inputs,
                plan,
                cold,
                activation_request_ids,
                observation_request_id,
                coordinator,
                maximum_record_bytes,
                observed_other_retained_bytes,
                maximum,
            )
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Counts cold target storage through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn original_restoration_retained_storage_precredit_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original_whole_owner_data()?
            .original_restoration_retained_storage_precredit_data(
                archive, plan, activation, maximum,
            )
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Counts cold target descriptors through its genuine whole-owner loan.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn original_restoration_descriptor_views_precredit_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.original_whole_owner_data()?
            .original_restoration_descriptor_views_precredit_data(archive, plan, activation)
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Counts the actual retained Producer grant under the same restoration origin.
    ///
    /// # Errors
    /// Preserves the defining owner's authority, currentness, storage and policy
    /// refusals. Cold-only operations additionally refuse split writer views.
    pub(crate) fn original_restored_producer_grant_requested_storage_data(
        &self,
        grant: &crate::node_scheduling::ExecutionAdmission,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_complete_original_restoration_origin()?;
        self.runtime
            .original_restored_producer_grant_requested_storage_data(grant, maximum)
    }
}

impl<'a> From<&'a ConformanceRuntime> for ConformanceRuntimeObservation<'a> {
    fn from(runtime: &'a ConformanceRuntime) -> Self {
        runtime.observation_data()
    }
}

impl<'a> ConformanceRuntimeObservation<'a> {
    /// Borrows the actual World and Host fields under the original restoration plan.
    ///
    /// # Errors
    /// Refuses a foreign origin/runtime, another installed plan or an absent
    /// actual Host source. This read grants no restoration or activation rights.
    pub(crate) fn original_restoration_coordinator_sources_data(
        &self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<
        (
            &'a crucible_node_format::WorldBinding,
            &'a super::super::HostSchedulingSource,
        ),
        RuntimeError,
    > {
        self.authenticate_complete_original_restoration_origin()?;
        if !self.fields.graph.plan().is_same_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let host = self
            .fields
            .exact_inputs
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        Ok((self.fields.graph.world(), host.as_ref()))
    }
}

impl ConformanceRuntimeObservation<'_> {
    /// Quotes cold common installation through the actual borrowed graph and runtime.
    ///
    /// # Errors
    /// Preserves the defining origin, plan, availability and construction
    /// refusals. Cold installation additionally requires an inactive owner.
    pub(crate) fn original_runtime_restoration_installation_construction_data(
        &self,
        record: &crate::node_contract::OriginalLineageRuntimeRecord,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        target: &ActivationRecord,
        content: &crate::node_state::VerifiedStateContent,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum: usize,
    ) -> Result<
        crate::node_contract::OriginalRuntimeRestorationInstallationConstructionData,
        RuntimeError,
    > {
        self.authenticate_complete_original_restoration_origin()?;
        if self.fields.activation.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let data = self
            .runtime
            .original_runtime_restoration_installation_construction_data(
                &self.fields.graph.graph,
                record,
                scheduling,
                target,
                content,
                coordinator,
                maximum,
            )?;
        self.authenticate_complete_original_restoration_origin()?;
        Ok(data)
    }
}
