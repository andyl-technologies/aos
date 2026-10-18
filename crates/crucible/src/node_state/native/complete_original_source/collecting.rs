//! Separates verified historical code from one fresh collecting target plan.
//!
//! Historical source validation creates an explicit unbound collecting source.
//! Its four tickets construct actual fresh owners before the source binds once
//! to their genuine graph. An absent or failed target plan is never interpreted
//! as the ordinary restoration route.

use super::*;
use crate::node_admission::{
    ConformanceGraph, InstalledConformancePlan, WeakInstalledConformancePlan,
};
use crate::node_contract::HostSchedulingSource;

pub(super) enum CompleteOriginalSourcePurpose {
    Ordinary,
    Collecting {
        validation_plan: WeakInstalledConformancePlan,
        target: RefCell<CollectingTargetPhase>,
    },
}

pub(super) enum CollectingTargetPhase {
    Unbound,
    Binding,
    Bound(WeakInstalledConformancePlan),
    Failed,
}

impl CollectingTargetPhase {
    fn authenticate_ticket_phase(&self) -> Result<(), RuntimeError> {
        if matches!(self, Self::Unbound) {
            Ok(())
        } else {
            Err(RuntimeError::OutstandingObligations)
        }
    }

    fn begin(&mut self) -> Result<(), RuntimeError> {
        self.authenticate_ticket_phase()?;
        *self = Self::Binding;
        Ok(())
    }

    fn bound_plan(&self) -> Result<InstalledConformancePlan, RuntimeError> {
        match self {
            Self::Bound(plan) => plan.upgrade().map_err(|_| RuntimeError::ForeignAuthority),
            Self::Unbound | Self::Binding | Self::Failed => Err(RuntimeError::ForeignAuthority),
        }
    }
}

impl CompleteOriginalSourcePurpose {
    pub(super) fn new(plan: Option<InstalledConformancePlan>) -> Self {
        match plan {
            None => Self::Ordinary,
            Some(validation_plan) => Self::Collecting {
                validation_plan: validation_plan.downgrade(),
                target: RefCell::new(CollectingTargetPhase::Unbound),
            },
        }
    }

    pub(super) fn retained_plan_storage(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self::Collecting {
            validation_plan,
            target,
        } = self
        else {
            return Ok(0);
        };
        // Weak owners retain backing without owning the Plan/authority child
        // heaps. Strong factory/runtime owners count those separately. Actual
        // repeated allocations conservatively overcharge here, never refund.
        let mut bytes = validation_plan.retained_allocation_bytes();
        let phase = target
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if let CollectingTargetPhase::Bound(plan) = &*phase {
            bytes = bytes
                .checked_add(plan.retained_allocation_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(bytes)
    }

    pub(super) fn bound_plan(&self) -> Result<Option<InstalledConformancePlan>, RuntimeError> {
        match self {
            Self::Ordinary => Ok(None),
            Self::Collecting { target, .. } => target
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .bound_plan()
                .map(Some),
        }
    }
}

impl CompleteOriginalSource {
    pub(crate) fn original_target_plan_counter_scratch_data() -> usize {
        std::mem::size_of::<std::cell::Ref<'static, CollectingTargetPhase>>()
            + std::mem::size_of::<Option<InstalledConformancePlan>>()
            + std::mem::size_of::<InstalledConformancePlan>()
            // An already-bound archive borrows the real same-runtime slot.
            + std::mem::size_of::<std::cell::Ref<'static, Option<Rc<()>>>>()
    }

    pub(super) fn authenticate_ticket_phase(&self) -> Result<(), RuntimeError> {
        self.authenticate_birth()?;
        match &self.purpose {
            CompleteOriginalSourcePurpose::Ordinary => Ok(()),
            CompleteOriginalSourcePurpose::Collecting { target, .. } => target
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .authenticate_ticket_phase(),
        }
    }

    pub(crate) fn bind_collecting_target(
        self: &Rc<Self>,
        graph: &ConformanceGraph,
        host: &Rc<HostSchedulingSource>,
    ) -> Result<(), RuntimeError> {
        // Origin authentication precedes all RefCell access and callback loans.
        self.authenticate_birth()?;
        let CompleteOriginalSourcePurpose::Collecting {
            validation_plan,
            target,
        } = &self.purpose
        else {
            return Err(RuntimeError::ForeignAuthority);
        };
        target
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?
            .begin()?;

        // Drop the mutable phase loan before calling an installed authority.
        // Any reentrant or refused attempt remains Binding/Failed, never Unbound.
        let checked = (|| {
            if self.target_started.get()
                || self
                    .target
                    .try_borrow()
                    .map_err(|_| RuntimeError::OutstandingObligations)?
                    .is_some()
                || !self.host_issued.get()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            let owners = self.archive.owners();
            let issued = self.native_issued.get();
            let host_owner = &self.host.selection_data().owner.owner.id;
            if owners.len() != issued.len()
                || owners.iter().filter(|row| &row.owner == host_owner).count() != 1
                || owners
                    .iter()
                    .enumerate()
                    .any(|(index, row)| issued[index] != (&row.owner != host_owner))
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            let validation_plan = validation_plan
                .upgrade()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            if validation_plan.same_authority(graph.plan()) {
                return Err(RuntimeError::ForeignAuthority);
            }
            validation_plan
                .reauthenticate()
                .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
            graph
                .reauthenticate()
                .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
            let historical = validation_plan.evidence();
            let fresh = graph.plan().evidence();
            if historical.plan_ref != fresh.plan_ref
                || historical.plan_bytes != fresh.plan_bytes
                || historical.refused_ref != fresh.refused_ref
                || historical.refused_bytes != fresh.refused_bytes
                || historical.world != fresh.world
                || historical.sources != fresh.sources
                || graph.graph.world_binding_hash() != &self.archive.manifest().world_binding_hash
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            // Full evidence equality above is compatibility data. These actual
            // fresh graph/host checks authenticate its distinct owning authority.
            host.authenticate_complete_archive_source(self)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            graph
                .authenticate_exact_input_scope(host)
                .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
            self.authenticate_birth()
        })();
        let mut phase = target
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        match checked {
            Ok(()) => {
                *phase = CollectingTargetPhase::Bound(graph.plan().downgrade());
                Ok(())
            }
            Err(error) => {
                *phase = CollectingTargetPhase::Failed;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_collecting_phase_never_becomes_an_ordinary_context() {
        let phase = CollectingTargetPhase::Unbound;
        assert!(phase.authenticate_ticket_phase().is_ok());
        assert!(matches!(
            phase.bound_plan(),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(matches!(
            CompleteOriginalSourcePurpose::new(None).bound_plan(),
            Ok(None)
        ));
    }

    #[test]
    fn first_collecting_binding_attempt_spends_ticket_phase_before_callbacks() {
        let mut phase = CollectingTargetPhase::Unbound;
        assert!(phase.begin().is_ok());
        assert!(matches!(
            phase.begin(),
            Err(RuntimeError::OutstandingObligations)
        ));
        assert!(phase.authenticate_ticket_phase().is_err());
        assert!(phase.bound_plan().is_err());
    }

    #[test]
    fn failed_collecting_binding_cannot_renew_tickets_or_target_context() {
        let mut phase = CollectingTargetPhase::Failed;
        assert!(phase.begin().is_err());
        assert!(phase.authenticate_ticket_phase().is_err());
        assert!(phase.bound_plan().is_err());
    }
}
