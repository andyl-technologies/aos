//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Independent, bounded host-pager control protocol.
//!
//! This channel is distinct from QMP and the deterministic execution stream.
//! Its descriptor is handed to one authenticated controller at setup. A fresh
//! secret session and exact arena incarnation are required after fork or restore.
//! A pager worker services this stream without acquiring QEMU execution locks.
//!
//! ```text
//! u32 body_length (big endian, at most 4096)
//! u32 schema_version = 1
//! u8 message_tag
//! bytes[32] session
//! u64 request_sequence (nonzero, strictly increasing)
//! Target { bytes[32] daemon, bytes[32] owner, bytes[32] node,
//!          u64 owner_generation, u64 arena_generation, u8 retained_template }
//! tag-specific fixed-width canonical body
//! ```

use std::io::{Read, Write};

mod admission;
pub use admission::{RamControlInventoryRegion, RamControlInventoryReport, RamControlResources};

/// Current independent pager control schema.
pub const RAM_CONTROL_VERSION: u32 = 1;
/// Maximum framed message body, checked before reading or allocating a body.
pub const RAM_CONTROL_MAX_BYTES: usize = 4096;
/// Fixed operation-class roster in canonical supervision order.
pub const RAM_CONTROL_BUDGET_COUNT: usize = 14;
/// Maximum canonical launch budget roster: schema plus fourteen bounded budgets.
pub const RAM_CONTROL_BUDGET_ROSTER_MAX_BYTES: usize = 4 + RAM_CONTROL_BUDGET_COUNT * 26;

/// Authenticated operational mapping owner; no field denotes a native pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlTarget {
    /// Daemon authority incarnation.
    pub daemon_epoch: [u8; 32],
    /// Execution or retained-template identity.
    pub owner_id: [u8; 32],
    /// Node or retained-template identity.
    pub node_id: [u8; 32],
    /// Process/controller ownership generation, never zero.
    pub owner_generation: u64,
    /// Mapping ownership generation, never zero.
    pub arena_generation: u64,
    /// Whether the owner is a retained shared template.
    pub retained_template: bool,
}

/// One fixed class's monotonic allowances, expressed in whole milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlBudget {
    /// Positive bounded polling slice.
    pub poll_ms: u64,
    /// Positive optional allowance since meaningful completion progress.
    pub progress_ms: Option<u64>,
    /// Positive optional allowance since the original operation start.
    pub total_ms: Option<u64>,
}

/// Host placement mode, independent of guest memory semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamControlMode {
    /// Best-effort managed placement under a separate sound peak reservation.
    Managed = 0,
    /// Preserve complete logical RAM in backing and reclaim cold mappings.
    DiskOriented = 1,
    /// Maintain qualified full residency and memory locks.
    ResidentRequired = 2,
}

/// Canonical host placement and operation-budget request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlPolicy {
    /// Requested placement mode.
    pub mode: RamControlMode,
    /// Desired guest-page working set.
    pub resident_target_bytes: u64,
    /// Cold-page eviction preference in the inclusive range zero to one hundred.
    pub eviction_preference: u8,
    /// Positive admitted writeback rate.
    pub writeback_bytes_per_second: u64,
    /// Positive admitted paging I/O concurrency.
    pub maximum_paging_io_in_flight: u32,
    /// Permits bounded, cancelable prefetch when increasing residency.
    pub prefetch_on_increase: bool,
    /// Fixed operation roster; index is the public operation-class tag.
    pub budgets: [RamControlBudget; RAM_CONTROL_BUDGET_COUNT],
}

/// Observed physical transition, separate from acceptance and application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamControlConvergence {
    /// Current physical placement meets the applied policy.
    Stable = 0,
    /// Worker has not completed the accepted application.
    Applying = 1,
    /// Preserving and reclaiming excess residency.
    Evicting = 2,
    /// Bounded prefetch is in progress.
    Prefetching = 3,
    /// A known operational dependency prevents convergence.
    Blocked = 4,
    /// An operation failed while authority remains retained.
    Failed = 5,
    /// Ambiguous ownership is retained for containment.
    Quarantined = 6,
}

/// Portable refusal/acceptance returned by the actual pager owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamControlDisposition {
    /// Request accepted; observed revisions determine actual application.
    Accepted = 0,
    /// Expected revision does not identify the current policy.
    RevisionConflict = 1,
    /// Authenticated target is no longer the mapping owner.
    NotCurrent = 2,
    /// Backend has not qualified the requested behavior.
    Unsupported = 3,
    /// Compulsory progress or preservation capacity was not admitted.
    AdmissionRefused = 4,
    /// Worker cannot currently provide the requested operation.
    Unavailable = 5,
    /// Cancellation was observed under retained authority.
    Canceled = 6,
}

/// Compulsory resident floor limits the requested target.
pub const RAM_LIMIT_COMPULSORY_FLOOR: u32 = 1;
/// Active native borrowers prevent safe reclamation.
pub const RAM_LIMIT_PINNED_BORROWER: u32 = 2;
/// Preservation capacity prevents further reclamation.
pub const RAM_LIMIT_BACKING_CAPACITY: u32 = 4;
/// Admitted I/O slots or staging capacity constrain convergence.
pub const RAM_LIMIT_IO_CAPACITY: u32 = 8;
/// Sound execution-peak admission constrains the applied policy.
pub const RAM_LIMIT_EXECUTION_PEAK: u32 = 16;
/// Observed external host pressure prevents the requested placement.
pub const RAM_LIMIT_HOST_PRESSURE: u32 = 32;
/// Closed limitation-bit vocabulary; all other bits are rejected.
pub const RAM_LIMIT_KNOWN_MASK: u32 = 63;

/// Bounded measurement snapshot from the independent worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlReply {
    /// Request disposition, independent of convergence.
    pub disposition: RamControlDisposition,
    /// Complete logical RAM bytes from the actual sealed native inventory.
    ///
    /// This includes admitted device RAM and never derives from the requested
    /// resident target. Zero means inventory authority is unavailable.
    pub logical_ram_bytes: u64,
    /// Actual pre-CPU report, when native inventory publication has completed.
    pub inventory: Option<RamControlInventoryReport>,
    /// One bounded region returned only for an inventory-region request.
    pub inventory_region: Option<RamControlInventoryRegion>,
    /// Latest accepted policy revision.
    pub requested_policy_revision: u64,
    /// Latest policy revision applied by the paging owner.
    pub applied_policy_revision: u64,
    /// Admitted reservation revision bound to the policy.
    pub reservation_revision: u64,
    /// Monotonically increasing measurement sequence.
    pub observation_sequence: u64,
    /// Effective guest-page residency target.
    pub effective_resident_target_bytes: u64,
    /// Compulsory resident working set.
    pub effective_floor_bytes: u64,
    /// Closed set of observed placement limitations.
    pub limitation_reasons: u32,
    /// Whether the five following physical counters are available.
    ///
    /// Unavailable counters are canonically zero, never reported as measurements.
    pub measurements_available: bool,
    /// Private resident guest-page bytes.
    pub private_resident_bytes: u64,
    /// Observed shared resident bytes; not a per-child reservation.
    pub shared_resident_bytes_observed: u64,
    /// Preserved authoritative backing bytes.
    pub preserved_backing_bytes: u64,
    /// Private modified bytes awaiting preservation.
    pub private_dirty_bytes: u64,
    /// Bytes currently claimed for writeback.
    pub writeback_pending_bytes: u64,
    /// Actual observed transition state.
    pub convergence: RamControlConvergence,
}

/// A request handled independently of replay, BQL, and guest execution locks.
// crucible-lint: allow rust-allow -- the closed fourteen-class roster stays inline so decoding needs no variant-sized allocation; every complete record is bounded to 4096 bytes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamControlRequest {
    /// Authenticate an already descriptor-bound controller session.
    Hello,
    /// Apply a policy after host-side reserve-before-apply admission.
    Apply {
        /// Revision that must still be current.
        expected_revision: u64,
        /// Newly admitted nonzero policy revision.
        policy_revision: u64,
        /// Admitted reservation revision (zero identifies initial admission).
        reservation_revision: u64,
        /// Complete normalized policy.
        policy: RamControlPolicy,
    },
    /// Return operational state even when a guest thread is fault-blocked.
    Status,
    /// Fetch one region from the actual immutable pre-CPU native report.
    InventoryRegion {
        /// Exact immutable report generation.
        topology_generation: u64,
        /// Requested bounded region ordinal.
        ordinal: u32,
    },
    /// Grants an exact host-ledger subset reclassification before CPU admission.
    GrantInventory {
        /// Exact immutable report generation.
        topology_generation: u64,
        /// Complete retained resource vector after host admission.
        resources: RamControlResources,
    },
    /// Stop claiming work for the selected nonzero operation generation.
    Cancel {
        /// Exact operation generation; never a guest address.
        operation_generation: u64,
    },
}

/// One portable bounded stream message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlFrame {
    /// Fresh secret setup session, never inherited into a child.
    pub session: [u8; 32],
    /// Nonzero strictly increasing per-session request sequence.
    pub sequence: u64,
    /// Exact operational mapping authority.
    pub target: RamControlTarget,
    /// Request or authenticated response.
    pub message: RamControlMessage,
}

/// Closed public message vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamControlMessage {
    /// Host request.
    Request(RamControlRequest),
    /// Pager reply bound to the complete canonical request.
    Reply {
        /// Domain-separated digest of the request frame body.
        request_digest: [u8; 32],
        /// Actual bounded worker observation.
        state: RamControlReply,
    },
}

/// Portable protocol, authentication, or stream failure.
#[derive(Debug, thiserror::Error)]
pub enum RamControlError {
    /// Message violates its fixed canonical encoding or value bounds.
    #[error("invalid RAM control frame")]
    InvalidFrame,
    /// Unsupported independently versioned schema.
    #[error("unsupported RAM control schema {0}")]
    UnsupportedVersion(u32),
    /// Controller/session/arena binding or monotonic sequence failed.
    #[error("RAM control authority or sequence mismatch")]
    AuthorityMismatch,
    /// Frame exceeded its fixed public bound.
    #[error("RAM control frame exceeds 4096 bytes")]
    TooLarge,
    /// Bounded stream transport failed.
    #[error("RAM control I/O: {0}")]
    Io(#[from] std::io::Error),
}

mod codec;
pub use codec::{
    decode_ram_control, decode_ram_control_budgets, encode_ram_control, encode_ram_control_budgets,
    ram_control_request_digest, read_ram_control, write_ram_control,
};

/// Services one authenticated stream until clean EOF or a protocol failure.
///
/// Call this on an independent GPL-side controller worker. The callback must
/// enqueue bounded work or read a bounded observation; it must not wait for the
/// guest replay token, BQL, disk I/O, or a lock held across those operations.
/// A descriptor-bound session is established by `Hello` before mutation.
///
/// # Errors
/// Returns transport/codec errors, a mismatched target/session, duplicate or
/// skipped request sequence, or a request sent before the authenticated hello.
pub fn serve_ram_control<S, F>(
    stream: &mut S,
    session: [u8; 32],
    target: RamControlTarget,
    mut dispatch: F,
) -> Result<(), RamControlError>
where
    S: Read + Write,
    F: FnMut(RamControlRequest) -> RamControlReply,
{
    let mut sequence = 0_u64;
    while serve_ram_control_once(stream, session, target, &mut sequence, &mut dispatch)? {}
    Ok(())
}

/// Services one complete record and retains the sequence at a clean boundary.
///
/// This primitive lets a native owner quiesce an independent control worker
/// without shutting down the parent's socket during fork. The owner preserves
/// `last_sequence` and the same stream when resuming the parent. Children receive
/// new streams/sessions and start with sequence zero. A failed record cannot be
/// resumed with a reset decoder or sequence; its authority remains quarantined.
/// Returns `false` only for clean EOF before a new record.
///
/// # Errors
/// Returns transport/codec failures, mismatched authority, a duplicate/skipped
/// sequence, or invalid hello ordering. Errors never authorize stream reuse.
pub fn serve_ram_control_once<S, F>(
    stream: &mut S,
    session: [u8; 32],
    target: RamControlTarget,
    last_sequence: &mut u64,
    dispatch: &mut F,
) -> Result<bool, RamControlError>
where
    S: Read + Write,
    F: FnMut(RamControlRequest) -> RamControlReply,
{
    let Some(frame) = read_ram_control(stream)? else {
        return Ok(false);
    };
    if session == [0; 32]
        || frame.session != session
        || frame.target != target
        || frame.sequence
            != last_sequence
                .checked_add(1)
                .ok_or(RamControlError::AuthorityMismatch)?
    {
        return Err(RamControlError::AuthorityMismatch);
    }
    let RamControlMessage::Request(request) = frame.message else {
        return Err(RamControlError::InvalidFrame);
    };
    if (*last_sequence == 0) != matches!(request, RamControlRequest::Hello) {
        return Err(RamControlError::AuthorityMismatch);
    }
    let response = RamControlFrame {
        session,
        sequence: frame.sequence,
        target,
        message: RamControlMessage::Reply {
            request_digest: ram_control_request_digest(&frame)?,
            state: dispatch(request),
        },
    };
    write_ram_control(stream, &response)?;
    *last_sequence = frame.sequence;
    Ok(true)
}

#[cfg(test)]
mod tests;
