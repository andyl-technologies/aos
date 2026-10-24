//! Retains one original core-issued host closure for a distinct fresh target.
//!
//! Portable decoded records cannot construct this ticket. It retains the same
//! opaque producer bytes and birth custody, independently of native capture and
//! target readiness. Retirement does not erase immutable historical evidence.

use std::thread::{self, ThreadId};

use super::{
    HostSchedulingContinuationLimits, HostSchedulingContinuationRecord,
    HostSchedulingContinuationV2, HostSchedulingObservation, HostSchedulingRuntimeRecord,
};
use crate::node_contract::RuntimeError;
use crate::node_scheduling::InputPayload;
use crucible_node_format::{Position, U64};

/// Retains the single original bounded common closure without capture permission.
///
/// Only the actual attached runtime observation constructs this nonserializable
/// ticket. It grants no native capture, fresh child adoption or Ready authority.
/// The distinct host restore factory must consume it beneath the independently
/// authenticated complete-world native continuation context.
#[must_use = "retain the original closure through preparation and failure containment"]
pub struct HostSchedulingOriginalContinuationTicket {
    original: HostSchedulingContinuationV2,
    process: u32,
    thread: ThreadId,
}

impl HostSchedulingOriginalContinuationTicket {
    /// Borrows the complete original producer record as historical data.
    pub fn record(&self) -> &HostSchedulingContinuationRecord {
        self.original.record()
    }

    /// Borrows the exact original canonical bytes without allocating a copy.
    pub fn encoded(&self) -> &InputPayload {
        self.original.encoded()
    }

    pub(super) fn authenticate_birth(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl HostSchedulingObservation<'_> {
    /// Retains the complete actual Runtime7 closure for one fresh original target.
    ///
    /// The same original runtime and scheduler produce the bytes; no caller
    /// record, portable source label or alternate queue is accepted. Original
    /// body and canonical-record credits are charged by the existing producer
    /// before copying, then moved into this ticket without a second body copy.
    ///
    /// # Errors
    /// Refuses foreign, stale or busy original custody, unsupported legacy
    /// ledgers, changed cut or insufficient aggregate record/body credit.
    pub fn original_continuation_ticket(
        &self,
        cut: Position,
        ordinal: U64,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<HostSchedulingOriginalContinuationTicket, RuntimeError> {
        self.runtime
            .authenticate_host_scheduling_source(self.source)?;
        let original = self.continuation_v2(cut, ordinal, limits)?;
        if !matches!(
            original.record().runtime,
            HostSchedulingRuntimeRecord::OriginalLineage(_)
        ) {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.runtime
            .authenticate_host_scheduling_source(self.source)?;
        let ticket = HostSchedulingOriginalContinuationTicket {
            original,
            process: self.source.process,
            thread: self.source.owner_thread,
        };
        ticket.authenticate_birth()?;
        Ok(ticket)
    }
}
