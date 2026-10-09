//! Original settled tuple and lexical native custody for slot publication.
//!
//! This GPL leaf owns preparation immediately before the actual permissive
//! NodeSlot writer and release immediately after its coherent close, including
//! refusal and unwind. It creates no native phase or paired-clamp authority.
//! The ordinary plugin and GPL-only configured bridge fixture share this code.

use crucible_protocol::native_console::NativeConsoleError;
use crucible_shmem::{
    NodeBoundaryPublication, NodeBoundaryPublicationError, NodeSlot, NodeSlotSnapshot,
    SchedulerAdvancePublication,
};

/// Original shared tuple retained after fault-command settlement succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) struct SettledConsoleControl {
    pub(in crate::runtime) request: u32,
    pub(in crate::runtime) command_frontier: u64,
    pub(in crate::runtime) capture_request: u32,
    pub(in crate::runtime) advance: u64,
    pub(in crate::runtime) raw: u64,
}

/// Native-prepared and committed disposition; observation never accepts a prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) enum ConsoleControlDisposition {
    Accepted,
    Observed,
}

/// Bounded native preparation; pending carries no mutation or ACK permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) enum ConsoleControlPreparation {
    Pending,
    Prepared(ConsoleControlDisposition),
}

/// Private native adapter contract, never a shared-memory callback table.
///
/// Preparation must authenticate the original native closed owner and immutable
/// resources. Acceptance additionally owns full AUTH; observation owns only its
/// already accepted, drained prefix and never mutates the acceptance frontier.
/// Commit may perform
/// bounded BQL-protected identity/lexical checks, but no wait, allocation, IO or
/// re-admission. Every refusal precedes accepted state/frontier mutation; after
/// that point the complete frontier/accepted-prefix suffix must be infallible.
pub(in crate::runtime) trait NativeConsoleControlOwner {
    /// Reconciles loaded canonical custody under the actual stopped Restore owner.
    ///
    /// Returns `false` on a bounded unavailable observation before acceptance
    /// or either original restore/control ACK. Missing owner refuses; the
    /// default preserves that refusal for external fixture implementations.
    ///
    /// # Errors
    ///
    /// Refuses absent whole-loader, resource, closed-control or full-body custody.
    fn restore_prefix(
        &mut self,
        _generation: u32,
        _raw: u64,
        _logical: u64,
    ) -> Result<bool, NativeConsoleError> {
        Err(NativeConsoleError::Binding)
    }

    /// Prepares typed custody, or returns an effect-free pending observation.
    ///
    /// # Errors
    ///
    /// Refuses missing owner, changed original AUTH, tuple or prefix custody.
    fn prepare(
        &mut self,
        settled: SettledConsoleControl,
        logical: u64,
    ) -> Result<ConsoleControlPreparation, NativeConsoleError>;

    /// Checks the still-valid prepared owner before its infallible commit suffix.
    ///
    /// # Errors
    ///
    /// Refuses before any frontier or accepted-prefix mutation.
    fn commit(
        &mut self,
        fields: NodeBoundaryPublication,
        advance: SchedulerAdvancePublication,
    ) -> Result<ConsoleControlDisposition, NativeConsoleError>;

    /// Releases actual native custody after the original writer closes.
    ///
    /// Preparation failure must already have released any partial custody.
    /// This infallible release precedes original ACK, checkpoint and error work.
    fn clear(&mut self);
}

/// One invocation's prepared effect; successful commitment is required for ACK.
pub(super) struct ConsoleControlEffect<'a> {
    owner: &'a mut dyn NativeConsoleControlOwner,
    settled: Option<SettledConsoleControl>,
    prepared: Option<ConsoleControlDisposition>,
    committed: Option<ConsoleControlDisposition>,
    pending: bool,
}

impl<'a> ConsoleControlEffect<'a> {
    pub(super) fn new(owner: &'a mut dyn NativeConsoleControlOwner) -> Self {
        Self {
            owner,
            settled: None,
            prepared: None,
            committed: None,
            pending: false,
        }
    }

    /// Applies the stopped loaded prefix before its original physical restore ACK.
    ///
    /// # Errors
    ///
    /// Refuses missing genuine native Restore custody. Busy observations retain
    /// the same pending request without capture, frontier or ACK effects.
    pub(super) fn restore_prefix(
        &mut self,
        generation: u32,
        raw: u64,
        logical: u64,
    ) -> Result<bool, NativeConsoleError> {
        let restored = self.owner.restore_prefix(generation, raw, logical)?;
        if !restored {
            self.pending = true;
        }
        Ok(restored)
    }

    pub(super) fn retain_pending(&mut self) {
        self.pending = true;
    }

    /// Retains an original successfully settled shared callback tuple.
    ///
    /// # Errors
    ///
    /// Refuses reuse or a malformed original publication.
    pub(super) fn bind_settled(
        &mut self,
        snapshot: NodeSlotSnapshot,
        raw: u64,
    ) -> Result<(), NativeConsoleError> {
        if self.settled.is_some()
            || snapshot.control_boundary_ack & 1 != 0
            || snapshot.advance_publication_sequence & 1 != 0
        {
            return Err(NativeConsoleError::Sequence);
        }
        let settled = SettledConsoleControl {
            request: snapshot.control_boundary_ack,
            command_frontier: snapshot.control_boundary_fault_command_frontier,
            capture_request: snapshot.control_boundary_capture_request,
            advance: snapshot.advance_publication_sequence,
            raw,
        };
        self.settled = Some(settled);
        Ok(())
    }

    /// Publishes the original pause fields while borrowing native custody.
    ///
    /// Returns `false` on effect-free native contention before opening the
    /// writer. The original even request remains pending without an ACK.
    ///
    /// # Errors
    ///
    /// Returns the original slot validation or native-owner refusal.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic after coherent writer-close and native release.
    pub(super) fn publish_pause(
        &mut self,
        slot: &NodeSlot,
        logical: u64,
        raw: u64,
        advance: SchedulerAdvancePublication,
    ) -> Result<bool, NodeBoundaryPublicationError<NativeConsoleError>> {
        let Some(prepared) = self.prepare_publication(logical)? else {
            return Ok(false);
        };
        slot.publish_pause_quiesced_with_effect(logical, raw, |fields| {
            prepared.effect.commit(fields, advance)
        })?;
        Ok(true)
    }

    /// Publishes the ordinary writer's original same-read advance receipt.
    ///
    /// Returns `false` on effect-free native contention before opening the
    /// writer. The original even request remains pending without an ACK.
    ///
    /// # Errors
    ///
    /// Returns the original slot validation or native-owner refusal.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic after coherent writer-close and native release.
    pub(super) fn publish_ordinary(
        &mut self,
        slot: &NodeSlot,
        logical: u64,
        raw: u64,
    ) -> Result<bool, NodeBoundaryPublicationError<NativeConsoleError>> {
        let Some(prepared) = self.prepare_publication(logical)? else {
            return Ok(false);
        };
        slot.publish_control_boundary_with_effect(logical, raw, |fields| {
            prepared.effect.commit_ordinary(fields)
        })?;
        Ok(true)
    }

    fn prepare_publication(
        &mut self,
        logical: u64,
    ) -> Result<
        Option<PreparedConsolePublication<'_, 'a>>,
        NodeBoundaryPublicationError<NativeConsoleError>,
    > {
        let settled = self.settled.ok_or(NodeBoundaryPublicationError::Effect(
            NativeConsoleError::Binding,
        ))?;
        let prepared = self
            .owner
            .prepare(settled, logical)
            .map_err(NodeBoundaryPublicationError::Effect)?;
        match prepared {
            ConsoleControlPreparation::Pending => {
                self.pending = true;
                Ok(None)
            }
            ConsoleControlPreparation::Prepared(disposition) => {
                self.prepared = Some(disposition);
                Ok(Some(PreparedConsolePublication { effect: self }))
            }
        }
    }

    /// Invokes one prepared effect inside its actual original boundary writer.
    ///
    /// # Errors
    ///
    /// Refuses a changed original tuple or native owner before accepted mutation.
    pub(super) fn commit(
        &mut self,
        fields: NodeBoundaryPublication,
        advance: SchedulerAdvancePublication,
    ) -> Result<(), NativeConsoleError> {
        let settled = self.settled.ok_or(NativeConsoleError::Binding)?;
        if self.committed.is_some()
            || fields.raw() != settled.raw
            || advance.sequence() != settled.advance
            || fields.advance().is_some_and(|original| original != advance)
        {
            return Err(NativeConsoleError::Binding);
        }
        let prepared = self.prepared.ok_or(NativeConsoleError::Binding)?;
        let committed = self.owner.commit(fields, advance)?;
        if committed != prepared {
            return Err(NativeConsoleError::Binding);
        }
        // Keep the native disposition through original ACK/capture ordering.
        // Observed is never evidence of accepted-prefix retirement.
        self.committed = Some(committed);
        Ok(())
    }

    /// Uses the ordinary writer's own checked advance observation.
    ///
    /// # Errors
    ///
    /// Refuses a missing receipt or the original prepared owner's refusal.
    pub(super) fn commit_ordinary(
        &mut self,
        fields: NodeBoundaryPublication,
    ) -> Result<(), NativeConsoleError> {
        let advance = fields.advance().ok_or(NativeConsoleError::Binding)?;
        self.commit(fields, advance)
    }

    /// Requires an actual successful effect before the original odd ACK.
    ///
    /// # Errors
    ///
    /// Refuses branches that deferred or skipped boundary publication.
    pub(super) fn require_committed(
        &self,
    ) -> Result<ConsoleControlDisposition, NativeConsoleError> {
        self.committed.ok_or(NativeConsoleError::Binding)
    }

    #[cfg(test)]
    pub(super) fn committed_disposition(&self) -> Option<ConsoleControlDisposition> {
        self.committed
    }

    pub(super) fn is_pending(&self) -> bool {
        self.pending
    }

    pub(super) fn is_committed(&self) -> bool {
        self.committed.is_some()
    }
}

/// Its inner NodeSlot writer closes before this outer scope releases custody.
struct PreparedConsolePublication<'invocation, 'owner> {
    effect: &'invocation mut ConsoleControlEffect<'owner>,
}

impl Drop for PreparedConsolePublication<'_, '_> {
    fn drop(&mut self) {
        self.effect.owner.clear();
    }
}
