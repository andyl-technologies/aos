//! Observes administrative bridge backing without checking frontier or MAC rights.

use super::super::capacities::fields_layout_data;
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use std::mem::size_of;

impl CaptureAdminBridge {
    /// Checks the original creator and actual containing Source before rows.
    ///
    /// # Errors
    /// Refuses another process, thread or Source allocation.
    pub(in super::super) fn check_capacity_creator_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Observes every actual bridge field without validating completion rights.
    ///
    /// # Errors
    /// Refuses foreign original creators, exhausted rows, unsupported children
    /// or checked capacity geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        source: &PacketCompleteSemanticSource,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_capacity_creator_data(source)?;
        let Self {
            process,
            thread,
            source: original,
            controller,
            world,
            measurement,
            model,
            native_after,
            capture_request,
            capture_id,
            capture_operation,
            prefix_frontier,
            frontier,
            signature,
        } = self;
        census.observe_inline_data(process)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(original)?;
        census.observe_inline_data(controller)?;
        census.observe_inline_data(prefix_frontier)?;
        census.observe_inline_data(frontier)?;
        census.observe_inline_data(signature)?;

        census.observe(world)?;
        census.observe(measurement)?;
        census.observe(model)?;
        census.observe(native_after)?;
        census.observe(capture_request)?;
        census.observe(capture_id)?;
        census.observe(capture_operation)?;
        self.check_capacity_creator_data(source)
    }

    /// Names the actual borrowed fields and original-creator controls.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                process,
                thread,
                source,
                controller,
                world,
                measurement,
                model,
                native_after,
                capture_request,
                capture_id,
                capture_operation,
                prefix_frontier,
                frontier,
                signature,
            } = owner;
            (
                process,
                thread,
                source,
                controller,
                world,
                measurement,
                model,
                native_after,
                capture_request,
                capture_id,
                capture_operation,
                prefix_frontier,
                frontier,
                signature,
            )
        }) + size_of::<&Self>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
