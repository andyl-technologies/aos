//! Retains the actual current17 cold source load before prebirth exists.
//!
//! The caller owns both pending and completed slots. No private factory cache
//! is mutably held while its validation callback observes the same factory.
//! A refused decoder or completed Source therefore stays in its original slot.

use super::*;
use crucible::node_state::CompleteRestoredSettledSourceLoadAttempt;

impl PacketCompleteArchiveCodeFactory {
    /// Loads the distinct signed17 family into caller-retained cold owners.
    ///
    /// The actual code graph, selected-load receipt, complete immutable closure
    /// and all-owner callback remain mandatory. A successful Source contains no
    /// current target, native registration, ticket issuance or Ready grant.
    /// The caller independently admits its own surrounding retained setup.
    ///
    /// # Errors
    /// Refuses another code graph/actor, occupied output, failed or spent decode,
    /// incomplete lineage, unsupported owner format or finite storage excess.
    /// Every initialized load owner and any completed output remain retained.
    pub fn prepare_restored_settled_restoration_source_into(
        self: &Rc<Self>,
        graph: &Rc<CompleteArchiveCodeGraph>,
        archive: &mut Option<NativeArchiveRecord>,
        limits: HostSchedulingContinuationLimits,
        additional_retained_bytes: usize,
        pending: &mut Option<CompleteRestoredSettledSourceLoadAttempt>,
        output: &mut Option<CollectingCompleteRestorationSource>,
    ) -> Result<(), StateError> {
        self.authenticate_code_owner()?;
        let selected = self.original_code_graph()?;
        if !Rc::ptr_eq(&selected, graph) {
            return Err(refused("restored17 load crossed its actual code graph"));
        }
        if archive.is_none() {
            return Err(refused("restored17 selected signed archive absent"));
        }
        // This is the factory's independent ceiling. Core additionally enforces
        // the actual selected archive's bound without widening either one.
        let maximum = self
            .inner
            .limits
            .state
            .maximum_total_content_bytes
            .min(self.inner.limits.native.maximum_total_record_bytes)
            .min(
                usize::try_from(self.inner.limits.state.maximum_native_memory_bytes)
                    .map_err(error)?,
            );
        let scratch = Self::retained_requested_storage_scratch_bytes()?;
        // The wrapper/graph observer and full factory observer overlap some
        // roots conservatively. Neither is a completed Source decode allowance.
        let retained = self
            .retained_requested_storage_data(maximum)?
            .checked_add(self.cold_additional_requested_storage_data(graph, maximum)?)
            .and_then(|n| n.checked_add(additional_retained_bytes))
            .and_then(|n| n.checked_add(scratch))
            .filter(|n| *n <= maximum)
            .ok_or_else(|| refused("restored17 caller/factory storage exhausted"))?;
        let result = ConformanceRuntime::prepare_complete_restored_settled_archive_code_source_into(
            graph.as_ref(),
            archive,
            self.as_ref(),
            limits,
            retained,
            pending,
            output,
        );
        // A real completed Source is already in output before either fence. An
        // Err callback also receives the same code-owner/graph postconditions.
        self.authenticate_code_owner()?;
        if !Rc::ptr_eq(&self.original_code_graph()?, graph) {
            return Err(refused("restored17 code graph changed during validation"));
        }
        result
    }
}
