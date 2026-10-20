//! Original staged RUN collection with immutable indexed histories and replay scratch.
//!
//! Every inbound identity has one constructor-preallocated slot. A separate
//! full parser buffer retains partial and conflicting frames. Exact repetitions
//! reuse no history slot and discard parser scratch only after complete byte
//! equality; all physical read attempts and bytes remain charged permanently.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use crucible_qemu_protocol::whole_control::{
    WHOLE_FRAME_HEADER_BYTES,
    body::{WholeAcknowledgement, WholeRequest, WholeResult},
    staged::{
        StagedControlProfile, StagedFrameKind,
        body::{StageCommit, StageInventory, StageReceipt},
        decode_frame_header, encode_frame_header,
        plan_ack::QueuePlanAcknowledgement,
        queue_plan::QueuePlan,
    },
};

use super::NativeRunControlCustody;
use super::whole_ingress::WholeIngressError;

struct FrameHistory {
    backing: Box<[u8]>,
    received: usize,
}

struct Parser {
    backing: Box<[u8]>,
    received: usize,
    expected: Option<usize>,
    kind: Option<StagedFrameKind>,
    allowed: u16,
}

struct ReplyHistory {
    backing: Box<[u8]>,
    extent: usize,
    written: usize,
}

struct CollectionState {
    profile: StagedControlProfile,
    frames: Box<[FrameHistory]>,
    replies: Box<[ReplyHistory]>,
    parser: Parser,
    read_attempts: u64,
    read_bytes: u64,
    write_attempts: u64,
    write_bytes: u64,
    retained_byte_count: u64,
    refusal: Option<WholeIngressError>,
}

/// Correlates a physically collected complete original or exact repetition.
pub(crate) struct CollectedStagedFrame {
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    pub(crate) kind: StagedFrameKind,
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    pub(crate) sequence: u64,
    pub(crate) repeated: bool,
}

/// Owns the same selected RUN actor and all original indexed inbound bodies.
pub(crate) struct SelectedStagedIngress {
    original: Arc<NativeRunControlCustody>,
    process: u32,
    state: Mutex<CollectionState>,
}

/// Retains original socket custody even if constructor allocation is refused.
pub(crate) struct StagedIngressPreparation {
    pub(crate) owner: Arc<SelectedStagedIngress>,
    pub(crate) status: Result<(), WholeIngressError>,
}

impl SelectedStagedIngress {
    pub(crate) fn prepare(
        original: Arc<NativeRunControlCustody>,
        profile: StagedControlProfile,
    ) -> StagedIngressPreparation {
        let mut state = CollectionState {
            profile,
            frames: Box::new([]),
            replies: Box::new([]),
            parser: Parser {
                backing: Box::new([]),
                received: 0,
                expected: None,
                kind: None,
                allowed: 0,
            },
            read_attempts: 0,
            read_bytes: 0,
            write_attempts: 0,
            write_bytes: 0,
            retained_byte_count: 0,
            refusal: None,
        };
        let status = (|| {
            let lifecycle = original
                .lifecycle
                .try_lock()
                .map_err(|_| WholeIngressError::Ownership)?;
            let mut stored = original
                .original
                .try_lock()
                .map_err(|_| WholeIngressError::Ownership)?;
            if stored.whole_selected {
                return Err(WholeIngressError::Selection);
            }
            stored.whole_selected = true;
            if lifecycle.state()
                != crucible_qemu_protocol::ControlLifecycleState::RunningViaSharedMemory
                || stored.received != 0
                || stored.terminal.is_some()
            {
                return Err(WholeIngressError::Selection);
            }
            state
                .profile
                .validate()
                .map_err(|_| WholeIngressError::Profile)?;
            if monotonic_ns()? >= state.profile.compute.deadline_monotonic_ns {
                return Err(WholeIngressError::Deadline);
            }

            let count = (state.profile.compute.operation_capacity as usize)
                .checked_add(state.profile.input_stage_limit as usize)
                .and_then(|count| count.checked_mul(2))
                .and_then(|count| count.checked_add(1))
                .ok_or(WholeIngressError::Allocation)?;
            let mut frames = Vec::new();
            frames
                .try_reserve_exact(count)
                .map_err(|_| WholeIngressError::Allocation)?;
            let mut bytes = count
                .checked_mul(std::mem::size_of::<FrameHistory>())
                .ok_or(WholeIngressError::Allocation)? as u64;
            let kinds = std::iter::once((StagedFrameKind::QueuePlanAcknowledgement, 1u32)).chain([
                (
                    StagedFrameKind::StageInventory,
                    state.profile.input_stage_limit,
                ),
                (
                    StagedFrameKind::StageCommit,
                    state.profile.input_stage_limit,
                ),
                (
                    StagedFrameKind::ExecutionRequest,
                    state.profile.compute.operation_capacity,
                ),
                (
                    StagedFrameKind::ExecutionAcknowledgement,
                    state.profile.compute.operation_capacity,
                ),
            ]);
            // Slots are ordered plan ACK, all stage bodies, all stage commits,
            // all compute bodies and all compute ACKs. Lookup is arithmetic.
            for (kind, count) in kinds {
                let body = match kind {
                    StagedFrameKind::StageInventory => state.profile.stage_body_byte_limit as usize,
                    StagedFrameKind::ExecutionRequest => {
                        state.profile.compute.body_byte_limit as usize
                    }
                    _ => 128,
                };
                let extent = body
                    .checked_add(WHOLE_FRAME_HEADER_BYTES)
                    .ok_or(WholeIngressError::Allocation)?;
                for _ in 0..count {
                    bytes = bytes
                        .checked_add(extent as u64)
                        .ok_or(WholeIngressError::Allocation)?;
                    if bytes > state.profile.compute.provider_history_byte_limit {
                        return Err(WholeIngressError::Allocation);
                    }
                    frames.push(FrameHistory {
                        backing: allocate(extent)?,
                        received: 0,
                    });
                }
            }
            state.frames = frames.into_boxed_slice();

            let mut replies = Vec::new();
            replies
                .try_reserve_exact(count)
                .map_err(|_| WholeIngressError::Allocation)?;
            bytes = bytes
                .checked_add((count * std::mem::size_of::<ReplyHistory>()) as u64)
                .ok_or(WholeIngressError::Allocation)?;
            for (body, count) in [
                (state.profile.compute.body_byte_limit as usize, 1),
                (256, state.profile.input_stage_limit),
                (128, state.profile.input_stage_limit),
                (
                    state.profile.compute.body_byte_limit as usize,
                    state.profile.compute.operation_capacity,
                ),
                (128, state.profile.compute.operation_capacity),
            ] {
                let extent = body
                    .checked_add(WHOLE_FRAME_HEADER_BYTES)
                    .ok_or(WholeIngressError::Allocation)?;
                for _ in 0..count {
                    bytes = bytes
                        .checked_add(extent as u64)
                        .ok_or(WholeIngressError::Allocation)?;
                    if bytes > state.profile.compute.provider_history_byte_limit {
                        return Err(WholeIngressError::Allocation);
                    }
                    replies.push(ReplyHistory {
                        backing: allocate(extent)?,
                        extent: 0,
                        written: 0,
                    });
                }
            }
            state.replies = replies.into_boxed_slice();
            let parser_extent = WHOLE_FRAME_HEADER_BYTES
                + state
                    .profile
                    .compute
                    .body_byte_limit
                    .max(state.profile.stage_body_byte_limit) as usize;
            bytes = bytes
                .checked_add(parser_extent as u64)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CollectionState>() as u64))
                .ok_or(WholeIngressError::Allocation)?;
            if bytes > state.profile.compute.provider_history_byte_limit {
                return Err(WholeIngressError::Allocation);
            }
            state.parser.backing = allocate(parser_extent)?;
            state.retained_byte_count = bytes;
            Ok(())
        })();
        state.refusal = status.err();
        StagedIngressPreparation {
            owner: Arc::new(Self {
                original,
                process: std::process::id(),
                state: Mutex::new(state),
            }),
            status,
        }
    }

    /// Performs one physical read under the original native parser phase.
    ///
    /// Changed parser phase, malformed new identities, changed repetitions,
    /// exhaustion and socket faults preserve every consumed original byte.
    pub(crate) fn collect(
        &self,
        allowed: &[StagedFrameKind],
    ) -> Result<Option<CollectedStagedFrame>, WholeIngressError> {
        if std::process::id() != self.process {
            return Err(WholeIngressError::Selection);
        }
        let lifecycle = self
            .original
            .lifecycle
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        let mut original = self
            .original
            .original
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        if let Some(refusal) = state.refusal {
            return Err(refusal);
        }
        if !original.whole_selected
            || lifecycle.state()
                != crucible_qemu_protocol::ControlLifecycleState::RunningViaSharedMemory
        {
            return state.refuse(WholeIngressError::Selection);
        }
        let mask = match allowed_mask(allowed) {
            Ok(mask) => mask,
            Err(error) => return state.refuse(error),
        };
        if state.parser.allowed != 0 && state.parser.allowed != mask {
            return state.refuse(WholeIngressError::Envelope);
        }
        let now = match monotonic_ns() {
            Ok(now) => now,
            Err(error) => return state.refuse(error),
        };
        if now >= state.profile.compute.deadline_monotonic_ns {
            return state.refuse(WholeIngressError::Deadline);
        }
        if state.read_attempts >= state.profile.compute.administrative_read_attempt_limit {
            return state.refuse(WholeIngressError::Attempts);
        }
        let remaining = state
            .profile
            .compute
            .administrative_read_byte_limit
            .saturating_sub(state.read_bytes);
        if remaining == 0 {
            return state.refuse(WholeIngressError::Bytes);
        }

        let target = state.parser.expected.unwrap_or(WHOLE_FRAME_HEADER_BYTES);
        let start = state.parser.received;
        let count = (target - start).min(usize::try_from(remaining).unwrap_or(usize::MAX));
        state.parser.allowed = mask;
        state.read_attempts += 1;
        let received = match original
            .socket
            .read(&mut state.parser.backing[start..start + count])
        {
            Ok(0) => return state.refuse(WholeIngressError::EndOfStream),
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return state.refuse(WholeIngressError::Socket),
        };
        state.read_bytes += received as u64;
        state.parser.received += received;
        if state.parser.received == WHOLE_FRAME_HEADER_BYTES && state.parser.expected.is_none() {
            let (kind, extent) = match decode_frame_header(
                &state.parser.backing[..WHOLE_FRAME_HEADER_BYTES],
                &state.profile,
            ) {
                Ok(decoded) => decoded,
                Err(_) => return state.refuse(WholeIngressError::Envelope),
            };
            if mask & (1 << kind as u32) == 0 {
                return state.refuse(WholeIngressError::Envelope);
            }
            state.parser.kind = Some(kind);
            state.parser.expected = Some(WHOLE_FRAME_HEADER_BYTES + extent);
        }
        if state.parser.expected != Some(state.parser.received) {
            return Ok(None);
        }

        let result = match state.retain_complete() {
            Ok(frame) => frame,
            Err(error) => return state.refuse(error),
        };
        // Clearing transient parser bytes is allowed only after complete equality
        // or copying all original bytes into their immutable indexed history.
        state.parser.backing.fill(0);
        state.parser.received = 0;
        state.parser.expected = None;
        state.parser.kind = None;
        state.parser.allowed = 0;
        Ok(Some(result))
    }

    /// Copies the same complete historical body without renewing any allowance.
    pub(crate) fn copy_complete(
        &self,
        kind: StagedFrameKind,
        sequence: u64,
        destination: &mut [u8],
    ) -> Result<usize, WholeIngressError> {
        if std::process::id() != self.process {
            return Err(WholeIngressError::Selection);
        }
        let state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        let index = state.index(kind, sequence)?;
        let frame = &state.frames[index];
        if frame.received == 0 {
            return Err(WholeIngressError::History);
        }
        let body = &frame.backing[WHOLE_FRAME_HEADER_BYTES..frame.received];
        if destination.len() < body.len() {
            return Err(WholeIngressError::Capacity);
        }
        destination[..body.len()].copy_from_slice(body);
        Ok(body.len())
    }

    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
        )
    )]
    pub(crate) fn retained_byte_count(&self) -> Result<u64, WholeIngressError> {
        if std::process::id() != self.process {
            return Err(WholeIngressError::Selection);
        }
        let state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        Ok(state.retained_byte_count)
    }

    /// Retains the complete original reply before one bounded physical write.
    ///
    /// The caller supplies bytes from the same native journal. This collector
    /// checks portable shape and scope but creates no native receipt authority.
    /// Retry continues the original partial reply without replacing its backing.
    pub(crate) fn send_original(
        &self,
        kind: StagedFrameKind,
        sequence: u64,
        body: &[u8],
    ) -> Result<bool, WholeIngressError> {
        if std::process::id() != self.process {
            return Err(WholeIngressError::Selection);
        }
        let lifecycle = self
            .original
            .lifecycle
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        let mut original = self
            .original
            .original
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        if let Some(error) = state.refusal {
            return Err(error);
        }
        if !original.whole_selected
            || lifecycle.state()
                != crucible_qemu_protocol::ControlLifecycleState::RunningViaSharedMemory
        {
            return state.refuse(WholeIngressError::Selection);
        }
        let index = match state.reply_index(kind, sequence) {
            Ok(index) => index,
            Err(error) => return state.refuse(error),
        };
        let header = match encode_frame_header(kind, body.len(), &state.profile) {
            Ok(header) => header,
            Err(_) => return state.refuse(WholeIngressError::Envelope),
        };
        if !reply_matches(kind, sequence, body, state.profile.compute.scope) {
            return state.refuse(WholeIngressError::Correlation);
        }
        let reply = &mut state.replies[index];
        let extent = WHOLE_FRAME_HEADER_BYTES + body.len();
        if reply.extent == 0 {
            reply.backing[..WHOLE_FRAME_HEADER_BYTES].copy_from_slice(&header);
            reply.backing[WHOLE_FRAME_HEADER_BYTES..extent].copy_from_slice(body);
            reply.extent = extent;
        } else if reply.extent != extent
            || reply.backing[..WHOLE_FRAME_HEADER_BYTES] != header
            || reply.backing[WHOLE_FRAME_HEADER_BYTES..extent] != *body
        {
            return state.refuse(WholeIngressError::Correlation);
        }
        if reply.written == reply.extent {
            return Ok(true);
        }
        let now = match monotonic_ns() {
            Ok(now) => now,
            Err(error) => return state.refuse(error),
        };
        if now >= state.profile.compute.deadline_monotonic_ns {
            return state.refuse(WholeIngressError::Deadline);
        }
        if state.write_attempts >= state.profile.compute.administrative_write_attempt_limit {
            return state.refuse(WholeIngressError::Attempts);
        }
        let remaining = state
            .profile
            .compute
            .administrative_write_byte_limit
            .saturating_sub(state.write_bytes);
        if remaining == 0 {
            return state.refuse(WholeIngressError::Bytes);
        }
        let reply = &state.replies[index];
        let start = reply.written;
        let count = (reply.extent - start).min(usize::try_from(remaining).unwrap_or(usize::MAX));
        state.write_attempts += 1;
        let written = match original
            .socket
            .write(&state.replies[index].backing[start..start + count])
        {
            Ok(0) => return state.refuse(WholeIngressError::EndOfStream),
            Ok(written) => written,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(false);
            }
            Err(_) => return state.refuse(WholeIngressError::Socket),
        };
        state.write_bytes += written as u64;
        state.replies[index].written += written;
        Ok(state.replies[index].written == state.replies[index].extent)
    }
}

impl CollectionState {
    fn reply_index(
        &self,
        kind: StagedFrameKind,
        sequence: u64,
    ) -> Result<usize, WholeIngressError> {
        let stages = u64::from(self.profile.input_stage_limit);
        let computes = u64::from(self.profile.compute.operation_capacity);
        let index = match kind {
            StagedFrameKind::QueuePlan if sequence == 0 => 0,
            StagedFrameKind::StageReceipt if (1..=stages).contains(&sequence) => sequence,
            StagedFrameKind::StageCommitAcknowledgement if (1..=stages).contains(&sequence) => {
                stages + sequence
            }
            StagedFrameKind::ExecutionResult if (1..=computes).contains(&sequence) => {
                2 * stages + sequence
            }
            StagedFrameKind::ExecutionAcknowledgement if (1..=computes).contains(&sequence) => {
                2 * stages + computes + sequence
            }
            _ => return Err(WholeIngressError::History),
        };
        usize::try_from(index).map_err(|_| WholeIngressError::History)
    }
    fn index(&self, kind: StagedFrameKind, sequence: u64) -> Result<usize, WholeIngressError> {
        let stages = u64::from(self.profile.input_stage_limit);
        let computes = u64::from(self.profile.compute.operation_capacity);
        let index = match kind {
            StagedFrameKind::QueuePlanAcknowledgement if sequence == 0 => 0,
            StagedFrameKind::StageInventory if (1..=stages).contains(&sequence) => sequence,
            StagedFrameKind::StageCommit if (1..=stages).contains(&sequence) => stages + sequence,
            StagedFrameKind::ExecutionRequest if (1..=computes).contains(&sequence) => {
                2 * stages + sequence
            }
            StagedFrameKind::ExecutionAcknowledgement if (1..=computes).contains(&sequence) => {
                2 * stages + computes + sequence
            }
            _ => return Err(WholeIngressError::History),
        };
        usize::try_from(index).map_err(|_| WholeIngressError::History)
    }

    fn retain_complete(&mut self) -> Result<CollectedStagedFrame, WholeIngressError> {
        let kind = self.parser.kind.ok_or(WholeIngressError::Envelope)?;
        let body = &self.parser.backing[WHOLE_FRAME_HEADER_BYTES..self.parser.received];
        let (scope, sequence) = match kind {
            StagedFrameKind::QueuePlanAcknowledgement => {
                let ack = QueuePlanAcknowledgement::decode(body)
                    .map_err(|_| WholeIngressError::Correlation)?;
                (ack.scope, 0)
            }
            StagedFrameKind::StageInventory => {
                let stage =
                    StageInventory::decode(body).map_err(|_| WholeIngressError::Correlation)?;
                (stage.scope, stage.stage_sequence)
            }
            StagedFrameKind::StageCommit => {
                let commit =
                    StageCommit::decode(body).map_err(|_| WholeIngressError::Correlation)?;
                (commit.scope, commit.stage_sequence)
            }
            StagedFrameKind::ExecutionRequest => {
                let request = WholeRequest::decode_staged(body)
                    .map_err(|_| WholeIngressError::Correlation)?;
                (request.scope, request.sequence)
            }
            StagedFrameKind::ExecutionAcknowledgement => {
                let ack = WholeAcknowledgement::decode(body)
                    .map_err(|_| WholeIngressError::Correlation)?;
                (ack.scope, ack.sequence)
            }
            _ => return Err(WholeIngressError::Envelope),
        };
        if scope != self.profile.compute.scope {
            return Err(WholeIngressError::Correlation);
        }
        let index = self.index(kind, sequence)?;
        let original = &mut self.frames[index];
        let repeated = original.received != 0;
        if repeated {
            if original.received != self.parser.received
                || original.backing[..original.received]
                    != self.parser.backing[..self.parser.received]
            {
                return Err(WholeIngressError::Correlation);
            }
        } else {
            original.backing[..self.parser.received]
                .copy_from_slice(&self.parser.backing[..self.parser.received]);
            original.received = self.parser.received;
        }
        Ok(CollectedStagedFrame {
            kind,
            sequence,
            repeated,
        })
    }

    fn refuse<T>(&mut self, error: WholeIngressError) -> Result<T, WholeIngressError> {
        Err(*self.refusal.get_or_insert(error))
    }
}

fn reply_matches(kind: StagedFrameKind, sequence: u64, body: &[u8], scope: [u8; 32]) -> bool {
    match kind {
        StagedFrameKind::QueuePlan => {
            QueuePlan::decode(body).is_ok_and(|plan| plan.scope == scope && sequence == 0)
        }
        StagedFrameKind::StageReceipt => StageReceipt::decode(body)
            .is_ok_and(|receipt| receipt.scope == scope && receipt.stage_sequence == sequence),
        StagedFrameKind::StageCommitAcknowledgement => StageCommit::decode(body)
            .is_ok_and(|commit| commit.scope == scope && commit.stage_sequence == sequence),
        StagedFrameKind::ExecutionResult => WholeResult::decode(body)
            .is_ok_and(|result| result.scope == scope && result.sequence == sequence),
        StagedFrameKind::ExecutionAcknowledgement => WholeAcknowledgement::decode(body)
            .is_ok_and(|ack| ack.scope == scope && ack.sequence == sequence),
        _ => false,
    }
}

fn allowed_mask(kinds: &[StagedFrameKind]) -> Result<u16, WholeIngressError> {
    if kinds.is_empty() || kinds.len() > 5 {
        return Err(WholeIngressError::Envelope);
    }
    let mut mask = 0u16;
    for kind in kinds {
        if !matches!(
            kind,
            StagedFrameKind::QueuePlanAcknowledgement
                | StagedFrameKind::StageInventory
                | StagedFrameKind::StageCommit
                | StagedFrameKind::ExecutionRequest
                | StagedFrameKind::ExecutionAcknowledgement
        ) || mask & (1 << *kind as u32) != 0
        {
            return Err(WholeIngressError::Envelope);
        }
        mask |= 1 << *kind as u32;
    }
    Ok(mask)
}

fn allocate(extent: usize) -> Result<Box<[u8]>, WholeIngressError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(extent)
        .map_err(|_| WholeIngressError::Allocation)?;
    bytes.resize(extent, 0);
    Ok(bytes.into_boxed_slice())
}

fn monotonic_ns() -> Result<u64, WholeIngressError> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The writable timespec remains live through this synchronous call.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } != 0 {
        return Err(WholeIngressError::Clock);
    }
    u64::try_from(clock.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(clock.tv_nsec)
                .ok()
                .and_then(|ns| seconds.checked_add(ns))
        })
        .ok_or(WholeIngressError::Clock)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Physical socket custody controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_qemu_protocol::whole_control::{WholeControlProfile, staged::encode_frame_header};
    use std::io::Write;

    const STAGE: &[u8] = include_bytes!(
        "../../../../protocol/crucible-qemu-protocol/src/whole_control/testdata/native-stage.bin"
    );

    fn profile() -> StagedControlProfile {
        StagedControlProfile {
            compute: WholeControlProfile {
                scope: StageInventory::decode(STAGE).unwrap().scope,
                operation_capacity: 2,
                body_byte_limit: 1024,
                native_history_byte_limit: 1_000_000,
                provider_history_byte_limit: 1_000_000,
                administrative_read_attempt_limit: 100,
                administrative_read_byte_limit: 100_000,
                administrative_write_attempt_limit: 100,
                administrative_write_byte_limit: 100_000,
                deadline_monotonic_ns: monotonic_ns().unwrap() + 10_000_000_000,
                cpu_retirement_limit: 100,
                event_step_limit: 100,
                input_byte_limit: 100,
                input_record_limit: 10,
                output_byte_limit: 100,
                output_record_limit: 10,
            },
            input_stage_limit: 3,
            stage_body_byte_limit: 1024,
        }
    }

    fn frame(body: &[u8], profile: &StagedControlProfile) -> Vec<u8> {
        let mut frame = encode_frame_header(StagedFrameKind::StageInventory, body.len(), profile)
            .unwrap()
            .to_vec();
        frame.extend_from_slice(body);
        frame
    }

    fn collect_complete(owner: &SelectedStagedIngress) -> CollectedStagedFrame {
        assert!(
            owner
                .collect(&[StagedFrameKind::StageInventory])
                .unwrap()
                .is_none()
        );
        owner
            .collect(&[StagedFrameKind::StageInventory])
            .unwrap()
            .unwrap()
    }

    #[test]
    fn same_original_socket_retains_partial_stage_and_fences_legacy_reader() {
        let (mut peer, lifecycle) = super::super::test_running_pair();
        let custody = NativeRunControlCustody::prepare(lifecycle).owner;
        let profile = profile();
        let prepared = SelectedStagedIngress::prepare(Arc::clone(&custody), profile.clone());
        assert_eq!(prepared.status, Ok(()));
        let frame = frame(STAGE, &profile);
        peer.write_all(&frame[..11]).unwrap();

        assert!(
            prepared
                .owner
                .collect(&[StagedFrameKind::StageInventory])
                .unwrap()
                .is_none()
        );
        assert!(custody.receive_step().is_err());
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(state.parser.received, 11);
        assert_eq!(&state.parser.backing[..11], &frame[..11]);
        assert_eq!(state.frames.len(), 11);
        drop(state);

        peer.write_all(&frame[11..]).unwrap();
        assert!(!collect_complete(&prepared.owner).repeated);
        let mut retained = [0; 1024];
        let extent = prepared
            .owner
            .copy_complete(StagedFrameKind::StageInventory, 1, &mut retained)
            .unwrap();
        assert_eq!(&retained[..extent], STAGE);
    }

    #[test]
    fn exact_replay_keeps_one_original_slot_and_charges_every_physical_byte() {
        let (mut peer, lifecycle) = super::super::test_running_pair();
        let profile = profile();
        let prepared = SelectedStagedIngress::prepare(
            NativeRunControlCustody::prepare(lifecycle).owner,
            profile.clone(),
        );
        assert_eq!(prepared.status, Ok(()));
        let frame = frame(STAGE, &profile);
        peer.write_all(&frame).unwrap();
        assert!(!collect_complete(&prepared.owner).repeated);
        let original = prepared.owner.state.lock().unwrap().frames[1]
            .backing
            .as_ptr();

        peer.write_all(&frame).unwrap();
        assert!(collect_complete(&prepared.owner).repeated);
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(state.frames[1].backing.as_ptr(), original);
        assert_eq!(state.read_bytes, 2 * frame.len() as u64);
        assert_eq!(state.read_attempts, 4);
        assert_eq!(
            state
                .frames
                .iter()
                .filter(|frame| frame.received != 0)
                .count(),
            1
        );
    }

    #[test]
    fn changed_replay_retains_original_and_conflicting_complete_parser() {
        let (mut peer, lifecycle) = super::super::test_running_pair();
        let profile = profile();
        let prepared = SelectedStagedIngress::prepare(
            NativeRunControlCustody::prepare(lifecycle).owner,
            profile.clone(),
        );
        let frame = frame(STAGE, &profile);
        peer.write_all(&frame).unwrap();
        collect_complete(&prepared.owner);
        let mut changed = frame.clone();
        // Change an otherwise well-formed opaque host inventory commitment.
        changed[WHOLE_FRAME_HEADER_BYTES + 88] ^= 1;
        peer.write_all(&changed).unwrap();

        assert!(
            prepared
                .owner
                .collect(&[StagedFrameKind::StageInventory])
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            prepared.owner.collect(&[StagedFrameKind::StageInventory]),
            Err(WholeIngressError::Correlation)
        ));
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(&state.frames[1].backing[..frame.len()], &frame);
        assert_eq!(&state.parser.backing[..changed.len()], &changed);
        assert_eq!(state.parser.received, changed.len());
    }

    #[test]
    fn changed_phase_retains_partial_header_and_refuses_before_next_io() {
        let (mut peer, lifecycle) = super::super::test_running_pair();
        let profile = profile();
        let prepared = SelectedStagedIngress::prepare(
            NativeRunControlCustody::prepare(lifecycle).owner,
            profile.clone(),
        );
        let frame = frame(STAGE, &profile);
        peer.write_all(&frame[..7]).unwrap();
        assert!(
            prepared
                .owner
                .collect(&[StagedFrameKind::StageInventory])
                .unwrap()
                .is_none()
        );
        peer.write_all(&frame[7..]).unwrap();

        assert!(matches!(
            prepared.owner.collect(&[StagedFrameKind::ExecutionRequest]),
            Err(WholeIngressError::Envelope)
        ));
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(state.read_bytes, 7);
        assert_eq!(state.read_attempts, 1);
        assert_eq!(&state.parser.backing[..7], &frame[..7]);
    }

    #[test]
    fn empty_socket_attempts_are_nonrenewing_and_failed_setup_remains_selected() {
        let (_peer, lifecycle) = super::super::test_running_pair();
        let custody = NativeRunControlCustody::prepare(lifecycle).owner;
        let mut profile = profile();
        profile.compute.administrative_read_attempt_limit = 26;
        let prepared = SelectedStagedIngress::prepare(Arc::clone(&custody), profile.clone());
        assert_eq!(prepared.status, Ok(()));
        for _ in 0..26 {
            assert!(
                prepared
                    .owner
                    .collect(&[StagedFrameKind::StageInventory])
                    .unwrap()
                    .is_none()
            );
        }
        assert!(matches!(
            prepared.owner.collect(&[StagedFrameKind::StageInventory]),
            Err(WholeIngressError::Attempts)
        ));
        assert!(matches!(
            prepared.owner.collect(&[StagedFrameKind::StageInventory]),
            Err(WholeIngressError::Attempts)
        ));
        assert!(custody.receive_step().is_err());
        assert_eq!(prepared.owner.state.lock().unwrap().read_attempts, 26);
        assert!(matches!(
            SelectedStagedIngress::prepare(custody, profile).status,
            Err(WholeIngressError::Selection)
        ));
    }

    #[test]
    fn reply_budget_exhaustion_retains_full_original_and_exact_physical_prefix() {
        use crucible_qemu_protocol::whole_control::{
            inventory::WholeQueueRole, staged::queue_plan::QueueRole,
        };
        use std::io::Read;

        let (mut peer, lifecycle) = super::super::test_running_pair();
        let mut profile = profile();
        profile.compute.administrative_write_byte_limit = 2488 + 24 + 256;
        profile.compute.body_byte_limit = 4096;
        let prepared = SelectedStagedIngress::prepare(
            NativeRunControlCustody::prepare(lifecycle).owner,
            profile.clone(),
        );
        assert_eq!(prepared.status, Ok(()));
        // Admit the current constructor floor, then spend real earlier reply
        // bytes. The residual budget still forces the original physical prefix.
        // Native issuance is modeled by this immutable codec receipt fixture.
        let receipt = include_bytes!(
            "../../../../protocol/crucible-qemu-protocol/src/whole_control/testdata/native-stage-receipt.bin"
        );
        assert!(
            prepared
                .owner
                .send_original(StagedFrameKind::StageReceipt, 1, receipt)
                .unwrap()
        );
        let mut prior_reply = [0; 24 + 256];
        peer.read_exact(&mut prior_reply).unwrap();
        assert_eq!(&prior_reply[24..], receipt);
        let original = include_bytes!(
            "../../../../protocol/crucible-qemu-protocol/src/whole_control/testdata/native-queue-plan.bin"
        );
        let identifier = "n".repeat(128);
        let mut plan = original[..128].to_vec();
        for (index, role) in [
            WholeQueueRole::PacketDelivery,
            WholeQueueRole::BlockCompletion,
            WholeQueueRole::ReadonlyNinePCompletion,
            WholeQueueRole::PacketPublication,
            WholeQueueRole::BlockRequest,
            WholeQueueRole::ReadonlyNinePRequest,
        ]
        .into_iter()
        .enumerate()
        {
            let role = QueueRole {
                role,
                ring_index: index as u32,
                source_slot: 0,
                target_slot: 1,
                capacity: 1,
                generation: 1,
                header_offset: 128 + index as u64 * 128,
                entries_offset: 4096 + index as u64 * 4640,
                transport_epoch: 0,
                producer_frontier: 0,
                node: &identifier,
                port: &identifier,
                lane: &identifier,
            };
            let mut row = vec![0; 464];
            role.encode_into(&mut row).unwrap();
            plan.extend_from_slice(&row);
        }
        let extent = plan.len() as u32;
        plan[12..16].copy_from_slice(&extent.to_be_bytes());
        plan[72..80].copy_from_slice(&65536u64.to_be_bytes());
        plan[80..84].copy_from_slice(&6u32.to_be_bytes());
        assert!(QueuePlan::decode(&plan).is_ok());
        // The actual socket gets only the remaining selected administrative
        // bytes. The complete source reply remains in its original history.
        assert!(
            !prepared
                .owner
                .send_original(StagedFrameKind::QueuePlan, 0, &plan)
                .unwrap()
        );
        let mut prefix = vec![0; 2488];
        peer.read_exact(&mut prefix).unwrap();
        assert_eq!(
            prepared
                .owner
                .send_original(StagedFrameKind::QueuePlan, 0, &plan),
            Err(WholeIngressError::Bytes)
        );
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(state.write_attempts, 2);
        assert_eq!(state.write_bytes, 2488 + 24 + 256);
        assert_eq!(state.replies[0].written, 2488);
        assert_eq!(state.replies[0].extent, 24 + plan.len());
        assert_eq!(&state.replies[0].backing[..2488], &prefix);
        assert_eq!(&state.replies[0].backing[24..24 + plan.len()], &plan);
    }
}
