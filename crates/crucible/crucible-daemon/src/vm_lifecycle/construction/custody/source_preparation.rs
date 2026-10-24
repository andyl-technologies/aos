//! Keeps initial capture in the original Main carrier until its pure export.
//!
//! The actual Source Loop Box is allocated once, after its World debit and
//! before capture IO. Refusal leaves the whole preparer and all partial disk,
//! template and continuation owners in this same preborn carrier.

use super::*;
use crate::vm_lifecycle::{
    ProductionVmHotForkSourcePreparationHistory, SourcePreparationBoundary, SourceWorldPreparation,
};

impl ProductionVmConstructionCustody {
    pub(crate) fn prepare_hot_fork_source_world(
        &mut self,
        boundary: SourcePreparationBoundary<'_>,
    ) -> Result<(bool, ProductionVmHotForkSourcePreparationHistory), LifecycleApiError> {
        if self.first.is_some()
            || self.physically_closed.load(Ordering::Acquire)
            || self.reservation.is_some()
            || self.return_destination.is_some()
        {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        let phase = self
            .phase
            .get_mut()
            .map_err(|_| LifecycleApiError::ConstructionCustodyUnavailable)?;
        if !matches!(phase, Phase::Complete(_)) {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        let Phase::Complete(lifecycle) = std::mem::replace(phase, Phase::Empty) else {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        };
        // This is the one already-priced Source Loop Box, not another carrier.
        *phase = Phase::SourcePreparation(SourceWorldPreparation::new(
            Box::new(lifecycle),
            BTreeMap::new(),
            false,
        ));
        let Phase::SourcePreparation(preparation) = phase else {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        };
        let complete = preparation.run_in_main(boundary).is_ok();
        let history = preparation.take_history();
        Ok((complete, history))
    }

    /// Observes only the fixed phase needed for the next pure ownership move.
    pub(crate) fn source_preparation_is_complete(&mut self) -> bool {
        if self.first.is_some()
            || self.physically_closed.load(Ordering::Acquire)
            || self.reservation.is_some()
            || self.return_destination.is_some()
        {
            return false;
        }
        matches!(self.phase.get_mut(), Ok(Phase::SourcePreparation(preparation)) if preparation.is_complete())
    }

    /// Issues only the actual same-body destination inside the admitted commit.
    fn prepare_captured_source_return(&mut self) -> Result<(), LifecycleApiError> {
        if !self.source_preparation_is_complete() {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        }
        let phase = self
            .phase
            .get_mut()
            .map_err(|_| LifecycleApiError::ConstructionCustodyUnavailable)?;
        let Phase::SourcePreparation(preparation) = phase else {
            return Err(LifecycleApiError::ConstructionCustodyUnavailable);
        };
        preparation
            .lifecycle_for_return()?
            .prepare_source_body_return(&mut self.reservation, &mut self.return_destination)
    }

    /// Moves a complete Source and reattaches its same original empty carrier.
    pub(crate) fn into_prepared_source_with_return(
        mut self: Box<Self>,
    ) -> Result<ProductionVmHotForkSourceWorld, Box<Self>> {
        if !self.source_preparation_is_complete() {
            return Err(self);
        }
        if let Err(first) = self.prepare_captured_source_return() {
            self.first.get_or_insert(first);
            return Err(self.cancel_capture_return());
        }
        let source = match self.phase.get_mut() {
            Ok(phase) => match std::mem::replace(phase, Phase::Empty) {
                Phase::SourcePreparation(preparation) => match preparation.into_world() {
                    Ok(source) => Some(source),
                    Err(preparation) => {
                        *phase = Phase::SourcePreparation(preparation);
                        None
                    }
                },
                other => {
                    *phase = other;
                    None
                }
            },
            Err(_) => None,
        };
        match source {
            Some(mut source) => {
                // Completeness validated this exact nonoptional body above.
                let Some(lifecycle) = source.lifecycle.as_mut() else {
                    match self.phase.get_mut() {
                        Ok(phase) => *phase = Phase::Source(source),
                        Err(poisoned) => *poisoned.into_inner() = Phase::Source(source),
                    }
                    return Err(self.cancel_capture_return());
                };
                match self.attach_exported_lifecycle(lifecycle) {
                    Ok(()) => Ok(source),
                    Err(mut custody) => {
                        // The whole checked Source remains retained if a fixed
                        // transfer invariant is violated; no owner is dropped.
                        match custody.phase.get_mut() {
                            Ok(phase) => *phase = Phase::Source(source),
                            Err(poisoned) => *poisoned.into_inner() = Phase::Source(source),
                        }
                        Err(custody.cancel_capture_return())
                    }
                }
            }
            None => Err(self.cancel_capture_return()),
        }
    }

    fn cancel_capture_return(mut self: Box<Self>) -> Box<Self> {
        if let Err(first) = self.cancel_prepared_body_return() {
            self.first.get_or_insert(first);
        }
        self
    }
}
