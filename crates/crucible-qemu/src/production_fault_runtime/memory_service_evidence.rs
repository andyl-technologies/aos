//! Fixed-size diagnostics derived from authenticated memory-service events.
//!
//! This cache exposes only the last Applied occurrence in the deterministic
//! node/event traversal of the latest committed boundary. It is neither a
//! history nor a resumable continuation; the canonical event hashes retain
//! complete occurrence coverage independently.

use super::*;

/// Reports one authenticated Applied memory-service occurrence.
///
/// Ledger timing fields use simulator ticks. The observed absolute instruction
/// count is a separate counter and must not be compared with ledger ticks.
/// Host paging waits do not enter this record. Multiple rules or accesses may occur at one boundary; this record
/// identifies only the last occurrence in node/event traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuMemoryServiceOccurrence {
    /// Committed scheduler boundary containing the observation.
    pub boundary_ticks: u64,
    /// Raw absolute retired-instruction counter observed at the memory access.
    pub observed_absolute_icount: u64,
    /// Monotone native event sequence within the target node.
    pub event_sequence: u64,
    /// Native command sequence installing the active rule.
    pub rule_command_sequence: u64,
    /// Authenticated resolved action identity.
    pub action_hash: [u8; 32],
    /// Authenticated target identity, independent of host placement.
    pub target_hash: [u8; 32],
    /// Digest of the complete native occurrence payload.
    pub evidence_hash: [u8; 32],
    /// Service ledger availability before reserving this access.
    pub ready_before_ticks: u64,
    /// Service ledger availability after reserving this access.
    pub ready_after_ticks: u64,
    /// Fixed latency attributed to this rule's occurrence.
    pub fixed_latency_ticks: u64,
    /// Rate-derived demand for this access.
    pub demand_ticks: u64,
    /// Native service queue delay for this occurrence.
    pub queue_delay_ticks: u64,
    /// Native completion delay recorded for the transaction.
    pub completion_delay_ticks: u64,
    /// Materialized fixed latency configured on the active rule.
    pub configured_latency_ticks: u64,
    /// Configured byte rate, used only when flag bit zero is set.
    pub bytes_per_second: u64,
    /// Configured operation rate, used only when flag bit one is set.
    pub operations_per_second: u64,
    /// Closed rate-presence flags: byte rate bit zero, operation rate bit one.
    pub rate_flags: u32,
}

/// Bounds fixed memory-service diagnostics owned by one runtime and snapshot.
///
/// Includes both retained runtime slots, one snapshot copy, and two temporary
/// parsing/staging copies. It excludes unrelated runtime and process metadata.
pub const MEMORY_SERVICE_EVIDENCE_RESIDENT_BYTES: u64 =
    5 * std::mem::size_of::<Option<QemuMemoryServiceOccurrence>>() as u64;

const _: () = assert!(MEMORY_SERVICE_EVIDENCE_RESIDENT_BYTES <= 2048);

#[derive(Clone, Copy, Default)]
pub(super) struct MemoryServiceEvidence {
    committed: Option<QemuMemoryServiceOccurrence>,
    pending: Option<QemuMemoryServiceOccurrence>,
}

impl MemoryServiceEvidence {
    pub(super) fn begin_boundary(&mut self) {
        // A failed boundary never leaves the previous boundary's diagnostic
        // visible as if it belonged to the attempted boundary.
        self.committed = None;
        self.pending = None;
    }

    pub(super) fn stage(&mut self, occurrence: Option<QemuMemoryServiceOccurrence>) {
        if occurrence.is_some() {
            self.pending = occurrence;
        }
    }

    pub(super) fn commit_boundary(&mut self) {
        self.committed = self.pending.take();
    }
}

impl ProductionFaultRuntime {
    /// Returns the last Applied service occurrence at the committed boundary.
    ///
    /// Returns `None` after restore, an empty boundary, or a failed boundary.
    /// It does not drain events, advance guest execution, or update ledgers.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime has been poisoned by a failed effect.
    pub fn memory_service_occurrence(
        &self,
    ) -> Result<Option<QemuMemoryServiceOccurrence>, ProductionFaultRuntimeError> {
        self.require_usable()?;
        Ok(self.memory_service_evidence.committed)
    }
}

pub(super) fn parse_occurrence(
    event: &DequeuedFaultEvent,
    boundary: FaultCoordinate,
) -> Result<Option<QemuMemoryServiceOccurrence>, ProductionFaultRuntimeError> {
    if event.header.command_kind != crucible_shmem::FaultCommandKind::MemoryService
        || event.header.outcome != FaultEventOutcomeV1::Applied
    {
        return Ok(None);
    }
    let reject = || BackendError::Rejected {
        message: String::from("invalid native memory-service diagnostic evidence"),
    };
    let bytes = event.payload.as_slice();
    if bytes.len() != 576
        || bytes.get(..8) != Some(b"CRUCMEM2")
        || bytes.get(368..376) != Some(b"CRUCSVC3")
        || read_u32(bytes, 376) != Some(3)
        || bytes.get(304..336) != Some(event.header.before_hash.as_slice())
        || bytes.get(336..368) != Some(event.header.after_hash.as_slice())
        || read_u32(bytes, 468) != Some(FaultEventOutcomeV1::Applied as u32)
    {
        return Err(reject().into());
    }
    let tick = |offset| {
        read_u64(bytes, offset)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(reject)
    };
    let occurrence = QemuMemoryServiceOccurrence {
        boundary_ticks: boundary.virtual_ticks,
        observed_absolute_icount: event.header.observed_icount,
        event_sequence: event.header.event_sequence,
        rule_command_sequence: event.header.rule_command_sequence,
        action_hash: event.header.action_hash,
        target_hash: event.header.target_hash,
        evidence_hash: event.header.evidence_hash,
        ready_before_ticks: tick(392)?,
        ready_after_ticks: tick(400)?,
        fixed_latency_ticks: tick(408)?,
        demand_ticks: tick(416)?,
        queue_delay_ticks: tick(424)?,
        completion_delay_ticks: tick(432)?,
        configured_latency_ticks: tick(440)?,
        bytes_per_second: read_u64(bytes, 448).ok_or_else(reject)?,
        operations_per_second: read_u64(bytes, 456).ok_or_else(reject)?,
        rate_flags: read_u32(bytes, 464).ok_or_else(reject)?,
    };
    if occurrence.rate_flags & !3 != 0
        || occurrence.observed_absolute_icount > i64::MAX as u64
        || occurrence.boundary_ticks > i64::MAX as u64
        || occurrence.ready_after_ticks < occurrence.ready_before_ticks
        || occurrence
            .fixed_latency_ticks
            .checked_add(occurrence.queue_delay_ticks)
            != Some(occurrence.completion_delay_ticks)
    {
        return Err(reject().into());
    }
    Ok(Some(occurrence))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
#[path = "memory_service_evidence/tests.rs"]
mod tests;
