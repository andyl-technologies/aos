//! Retains one real publisher and admits its once-only slot construction.

use super::*;

impl OriginalRestorationConstructionScope<'_> {
    /// Borrows the actual once-retained candidate and its independently quoted row.
    ///
    /// The concrete holder must compare this pointer and every row field against
    /// its own original publisher. This DATA comparison grants no backend right.
    pub fn original_restored_producer_publication_candidate_data(
        &self,
    ) -> Option<(
        *const (),
        &OriginalRestoredProducerPublicationConstructionData,
    )> {
        self.window
            .and_then(|window| window.producer_publication.get())
            .map(|candidate| (candidate.publisher, &candidate.row))
    }
}

impl OriginalRestorationMemberScope<'_> {
    /// Reports the once-retained candidate identity without opening its owner.
    ///
    /// The concrete holder compares its own stable recorded publisher address.
    /// Absence identifies the earlier cold phase and creates no selected rights.
    pub fn original_restored_producer_publication_candidate_data(&self) -> Option<*const ()> {
        self.window
            .producer_publication
            .get()
            .map(|candidate| candidate.publisher)
    }

    /// Compares the original target publisher registered before Prepare.
    ///
    /// The holder independently authenticates its capsule, actual plan, Source
    /// roster and retained future row; a matching pointer is never a grant.
    pub fn is_original_restored_producer_publisher_data(&self, publisher: *const ()) -> bool {
        !publisher.is_null()
            && self
                .window
                .producer_publication
                .get()
                .is_some_and(|candidate| candidate.publisher == publisher)
    }
}

impl CompleteOriginalRestorationWindow {
    /// Retains the actual target publisher candidate after cold construction.
    ///
    /// The concrete holder has already retained its original inputs and fixed
    /// future quote during the cold census. Later full observation authenticates
    /// this candidate and every independent current/prospective owner again.
    /// This method alone issues neither action nor publication authority.
    ///
    /// # Errors
    /// Refuses another plan/runtime/target, repeated or late binding, null
    /// identity, unsupported Producer roster, or capacity/memory/scratch excess.
    pub fn retain_original_restored_producer_publication_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        target: &ActivationRecord,
        publisher: *const (),
        row: OriginalRestoredProducerPublicationConstructionData,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.stage.get() != WindowStage::ColdComplete
            || self.phase_in_flight.get()
            || self.context_started.get()
            || publisher.is_null()
            || self.producer_publication.get().is_some()
            || self.original_activation_slot != target as *const _
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.authenticate_original_restoration_target_data(&self.archive, plan, target)?;
        let mut selected = None;
        for (index, source) in self.sources.iter().enumerate() {
            if source.role() == crate::node_adapters::cnp::PacketCompleteSourceRole::Producer {
                if selected.replace(index).is_some() {
                    return Err(RuntimeError::UnsupportedFacet);
                }
            }
        }
        let selected = selected.ok_or(RuntimeError::UnsupportedFacet)?;
        let capacity = row.maximum_slots_data();
        if capacity == 0
            || capacity > runtime.original_restored_producer_operation_limit_data()?
            || capacity > self.sources[selected].installation().maximum_operations
            || capacity
                > self.sources[selected].original_restored_producer_native_original_limit_data()?
            || row.requested_bytes_data() > self.policy.maximum_requested_bytes
            || row.counter_scratch_bytes_data() > self.policy.declared_observer_scratch_bytes
            || row.maximum_simultaneous_transient_descriptors_data()
                > self.policy.maximum_owned_descriptors
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.producer_publication
            .set(ProducerPublicationIdentity {
                publisher,
                row,
                selected,
                construction_started: Cell::new(false),
                constructing: Cell::new(false),
                constructed: Cell::new(false),
            })
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        self.whole_observation.require_observation();
        Ok(())
    }
}

/// Borrows one whole-census admission for constructing actual publisher slots.
///
/// It supplies no backend, native or operation permission. Only the concrete
/// registered publisher may consume this once allocation phase before Prepare.
pub struct OriginalRestoredProducerPublisherConstructionScope<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    plan: &'a InstalledConformancePlan,
    runtime: &'a ConformanceRuntime,
    target: &'a ActivationRecord,
    candidate: &'a ProducerPublicationIdentity,
}

impl OriginalRestoredProducerPublisherConstructionScope<'_> {
    /// Borrows the fixed complete construction row retained before admission.
    pub fn construction_data(&self) -> &OriginalRestoredProducerPublicationConstructionData {
        &self.candidate.row
    }

    /// Returns the exact finite slot population admitted for this lifecycle.
    pub fn funded_capacity_data(&self) -> usize {
        self.candidate.row.maximum_slots_data()
    }

    /// Compares the actual target capsule's retained Window allocation.
    pub fn is_original_window_data(&self, window: &Rc<CompleteOriginalRestorationWindow>) -> bool {
        std::ptr::eq(self.window, window.as_ref())
    }

    /// Compares the actual candidate recorded before the complete census.
    pub fn original_publisher_data(&self, publisher: *const ()) -> bool {
        !publisher.is_null() && publisher == self.candidate.publisher
    }

    /// Rechecks this same once-in-flight allocation scope and unstarted targets.
    ///
    /// # Errors
    /// Refuses changed plan/runtime/target, a failed or completed constructor,
    /// changed current member, or any already-started Prepare phase.
    pub fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        if !self.candidate.construction_started.get()
            || !self.candidate.constructing.get()
            || self.candidate.constructed.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.window
            .authenticate_producer_publisher_construction_identity_data(
                self.plan,
                self.runtime,
                self.target,
                self.candidate.publisher,
            )
    }
}

pub(super) struct PublisherConstructionGuard<'a>(&'a CompleteOriginalRestorationWindow);

impl Drop for PublisherConstructionGuard<'_> {
    fn drop(&mut self) {
        if let Some(candidate) = self.0.producer_publication.get() {
            candidate.constructing.set(false);
        }
        self.0.whole_observation.require_observation();
    }
}

impl CompleteOriginalRestorationWindow {
    fn authenticate_producer_publisher_construction_identity_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        target: &ActivationRecord,
        publisher: *const (),
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.stage.get() != WindowStage::TransactionAdmitted
            || self.phase_in_flight.get()
            || self.original_activation_slot != target as *const _
            || !self
                .plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .is_same_original_plan_data(plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let candidate = self
            .producer_publication
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if publisher.is_null() || candidate.publisher != publisher {
            return Err(RuntimeError::ForeignAuthority);
        }
        for target in &self.targets {
            target
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticate_original_before_prepare_data()?;
        }
        runtime.authenticate_original_restoration_target_data(&self.archive, plan, target)?;
        self.authenticate_original_runtime_member_current_data(&target.world_binding_hash)?;
        let member = OriginalRestorationMemberScope {
            plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        self.authenticate_original_runtime_member_current_data(&target.world_binding_hash)
    }

    /// Lends a genuine once-only publisher allocation phase after whole admission.
    ///
    /// Every target still precedes Prepare. The old and newly requested banks
    /// stay independently committed, including failed reserve/resize capacity.
    /// Another whole owner observation is mandatory before transaction effects.
    ///
    /// # Errors
    /// Refuses foreign or spent scope, incomplete whole admission, started
    /// targets, changed original members, or the concrete constructor's failure.
    pub fn with_original_admitted_restored_producer_publication_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        target: &ActivationRecord,
        publisher: *const (),
        construct: impl FnOnce(
            &OriginalRestoredProducerPublisherConstructionScope<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.whole_observation.authenticate_dispatch_data()?;
        self.authenticate_producer_publisher_construction_identity_data(
            plan, runtime, target, publisher,
        )?;
        let candidate = self
            .producer_publication
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if candidate.construction_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        candidate.constructing.set(true);
        let _guard = PublisherConstructionGuard(self);
        let scope = OriginalRestoredProducerPublisherConstructionScope {
            window: self,
            plan,
            runtime,
            target,
            candidate,
        };
        scope.authenticate_current_data()?;
        construct(&scope)?;
        scope.authenticate_current_data()?;
        candidate.constructed.set(true);
        Ok(())
    }

    pub(in crate::node_admission::conformance::restoration_construction::window) fn authenticate_producer_publication_before_prepare_data(
        &self,
        phase: &OriginalRestorationTransactionPhase,
    ) -> Result<(), RuntimeError> {
        if matches!(phase, OriginalRestorationTransactionPhase::Prepare)
            && let Some(candidate) = self.producer_publication.get()
            && (!candidate.constructed.get() || candidate.constructing.get())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}
