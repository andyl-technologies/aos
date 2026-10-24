//! Captures the complete Source before exporting its actual World body.
//!
//! Preparation, disk custody and every received template token remain in the
//! original Main-paid carrier. Only a fully checked Source crosses the final
//! pure work commit; refusal returns a selector to that same retained body.

use super::*;
use crate::vm_lifecycle::{ProductionVmHotForkSourceWorld, SourcePreparationBoundary};

impl<F> PendingSourceConstruction<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: crate::QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Closes a completed no-entry request without consuming its real proof.
    pub(crate) fn close_unentered_request(&mut self) {
        self.service.prepared_selector().request_retirement();
    }

    pub(crate) fn prepare_hot_fork_source_world(
        &mut self,
        boundary: SourcePreparationBoundary<'_>,
    ) -> Result<ProductionVmHotForkSourceWorld, ()> {
        if !self.carrier_active
            || self.transferred
            || self.body_cleanup_complete
            || self.body_disposed
            || self.post_body_taken
            || self.history.first.is_some()
            || self.history.preparation.is_some()
        {
            return Err(());
        }
        let prepared = match self.construction_custody.as_mut() {
            Some(custody) => custody.prepare_hot_fork_source_world(boundary),
            None => Err(LifecycleApiError::ConstructionCustodyUnavailable),
        };
        match prepared {
            Ok((complete, history)) => {
                if !history.is_empty() {
                    self.history.preparation = Some(history);
                }
                if !complete {
                    return Err(());
                }
            }
            Err(first) => {
                self.record_construction_first(
                    crate::QemuAttemptProductionVmLifecycleError::Lifecycle(first),
                );
                return Err(());
            }
        }
        if !self
            .construction_custody
            .as_mut()
            .is_some_and(|custody| custody.source_preparation_is_complete())
        {
            self.record_unavailable();
            return Err(());
        }
        let service = self.service.clone();
        match service.commit_work(|| {
            // The admitted pure cut takes the same carrier before issuing its
            // destination, so Main never retains a strong return edge to itself.
            let Some(custody) = self.construction_custody.take() else {
                self.record_unavailable();
                return Err(());
            };
            match custody.into_prepared_source_with_return() {
                Ok(source) => {
                    self.carrier_active = false;
                    self.transferred = true;
                    Ok(source)
                }
                Err(custody) => {
                    self.construction_custody = Some(custody);
                    self.record_unavailable();
                    Err(())
                }
            }
        }) {
            Ok(result) => result,
            Err(first) => {
                self.history
                    .first
                    .get_or_insert(prepared::SourcePreparationFirst::Role(first));
                Err(())
            }
        }
    }
}
