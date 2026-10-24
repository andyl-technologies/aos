//! Staged administrative collection on the same original selected RUN actor.
//!
//! The constructor owns all full and partial frame histories before activation.
//! Native callbacks choose the next allowed grammar symbol; collection grants
//! neither queue effects, original source eligibility nor native ACK consumption.

use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use crucible_qemu_protocol::whole_control::{
    WHOLE_FRAME_HEADER_BYTES,
    staged::{StagedControlProfile, StagedFrameKind, decode_frame_header},
};

use super::NativeRunControlCustody;
use super::whole_ingress::WholeIngressError;

struct FrameHistory {
    backing: Vec<u8>,
    received: usize,
    expected_extent: Option<usize>,
    expected_kind: Option<StagedFrameKind>,
}

struct CollectionState {
    profile: StagedControlProfile,
    frames: Vec<FrameHistory>,
    completed: usize,
    read_attempts: u64,
    read_bytes: u64,
    retained_byte_count: u64,
    refusal: Option<WholeIngressError>,
}

/// Retains the same original RUN actor and every independently indexed frame.
pub(crate) struct SelectedStagedIngress {
    original: Arc<NativeRunControlCustody>,
    process: u32,
    state: Mutex<CollectionState>,
}

/// Retains the original selected reader before publishing a constructor failure.
pub(crate) struct StagedIngressPreparation {
    pub(crate) owner: Arc<SelectedStagedIngress>,
    pub(crate) status: Result<(), WholeIngressError>,
}

impl SelectedStagedIngress {
    /// Selects the original reader and preallocates all finite inbound history.
    ///
    /// Selection fences legacy reads before allocation and any I/O. Input
    /// stage and compute counts are independent; no slot is renewed after ACK.
    pub(crate) fn prepare(
        original: Arc<NativeRunControlCustody>,
        profile: StagedControlProfile,
    ) -> StagedIngressPreparation {
        let mut state = CollectionState {
            profile,
            frames: Vec::new(),
            completed: 0,
            read_attempts: 0,
            read_bytes: 0,
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

            let computes = state.profile.compute.operation_capacity as usize;
            let stages = state.profile.input_stage_limit as usize;
            let count = computes
                .checked_add(stages)
                .and_then(|count| count.checked_mul(2))
                .and_then(|count| count.checked_add(1))
                .ok_or(WholeIngressError::Allocation)?;
            let body = state
                .profile
                .compute
                .body_byte_limit
                .max(state.profile.stage_body_byte_limit) as usize;
            let extent = body
                .checked_add(WHOLE_FRAME_HEADER_BYTES)
                .ok_or(WholeIngressError::Allocation)?;
            let backing = count
                .checked_mul(extent)
                .and_then(|bytes| {
                    count
                        .checked_mul(std::mem::size_of::<FrameHistory>())
                        .and_then(|metadata| bytes.checked_add(metadata))
                })
                .ok_or(WholeIngressError::Allocation)?;
            if backing as u64 > state.profile.compute.provider_history_byte_limit {
                return Err(WholeIngressError::Allocation);
            }
            state.retained_byte_count = backing as u64;
            state
                .frames
                .try_reserve_exact(count)
                .map_err(|_| WholeIngressError::Allocation)?;
            for _ in 0..count {
                let mut backing = Vec::new();
                backing
                    .try_reserve_exact(extent)
                    .map_err(|_| WholeIngressError::Allocation)?;
                backing.resize(extent, 0);
                state.frames.push(FrameHistory {
                    backing,
                    received: 0,
                    expected_extent: None,
                    expected_kind: None,
                });
            }
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

    /// Performs one bounded read for the native controller's next grammar symbol.
    ///
    /// The original deadline, read attempts and actual received byte allowance
    /// are nonrenewing. Every partial body remains in its original history.
    pub(crate) fn collect(
        &self,
        expected_kind: StagedFrameKind,
    ) -> Result<Option<usize>, WholeIngressError> {
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
        if !matches!(
            expected_kind,
            StagedFrameKind::QueuePlanAcknowledgement
                | StagedFrameKind::StageInventory
                | StagedFrameKind::StageCommit
                | StagedFrameKind::ExecutionRequest
                | StagedFrameKind::ExecutionAcknowledgement
        ) {
            return state.refuse(WholeIngressError::Envelope);
        }
        let index = state.completed;
        if index == state.frames.len() {
            return state.refuse(WholeIngressError::History);
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

        let frame = &state.frames[index];
        if frame
            .expected_kind
            .is_some_and(|kind| kind != expected_kind)
        {
            return state.refuse(WholeIngressError::Envelope);
        }
        let target = frame.expected_extent.unwrap_or(WHOLE_FRAME_HEADER_BYTES);
        let start = frame.received;
        let available = (target - start).min(usize::try_from(remaining).unwrap_or(usize::MAX));
        state.frames[index].expected_kind = Some(expected_kind);
        state.read_attempts += 1;
        let received = match original
            .socket
            .read(&mut state.frames[index].backing[start..start + available])
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
        state.frames[index].received += received;

        let frame = &state.frames[index];
        if frame.received == WHOLE_FRAME_HEADER_BYTES && frame.expected_extent.is_none() {
            let (kind, extent) = match decode_frame_header(
                &frame.backing[..WHOLE_FRAME_HEADER_BYTES],
                &state.profile,
            ) {
                Ok(decoded) => decoded,
                Err(_) => return state.refuse(WholeIngressError::Envelope),
            };
            if kind != expected_kind {
                return state.refuse(WholeIngressError::Envelope);
            }
            state.frames[index].expected_extent = Some(WHOLE_FRAME_HEADER_BYTES + extent);
        }
        if state.frames[index].expected_extent != Some(state.frames[index].received) {
            return Ok(None);
        }
        state.completed += 1;
        Ok(Some(index))
    }

    /// Copies one complete original historical body into source-owned backing.
    ///
    /// Later refusal does not discard already collected bodies. The native
    /// provider independently validates the same original identity and journal.
    pub(crate) fn copy_complete(
        &self,
        index: usize,
        destination: &mut [u8],
    ) -> Result<(StagedFrameKind, usize), WholeIngressError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        if index >= state.completed {
            return Err(WholeIngressError::History);
        }
        let frame = &state.frames[index];
        let body = &frame.backing[WHOLE_FRAME_HEADER_BYTES..frame.received];
        if body.len() > destination.len() {
            return Err(WholeIngressError::Capacity);
        }
        destination[..body.len()].copy_from_slice(body);
        Ok((
            frame.expected_kind.ok_or(WholeIngressError::Envelope)?,
            body.len(),
        ))
    }

    /// Reports actual owned parser and inbound-history storage for total geometry.
    pub(crate) fn retained_byte_count(&self) -> Result<u64, WholeIngressError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        Ok(state.retained_byte_count)
    }
}

impl CollectionState {
    fn refuse<T>(&mut self, error: WholeIngressError) -> Result<T, WholeIngressError> {
        Err(*self.refusal.get_or_insert(error))
    }
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
