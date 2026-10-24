//! Preallocated administrative history on the original selected RUN socket.
//!
//! Selection fences the ordinary parser before I/O and retains every complete
//! or partial frame in constructor-owned storage. Encoded inventories do not
//! spend guest payload credit here; native service charges that separately.
//! Socket collection supplies no native grant, stopped proof or ACK consumption.

use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use crucible_qemu_protocol::whole_control::body::{WholeAcknowledgement, WholeRequest};
use crucible_qemu_protocol::whole_control::{
    WHOLE_FRAME_HEADER_BYTES, WholeControlProfile, WholeFrameKind, decode_whole_frame_header,
};

use super::NativeRunControlCustody;

/// Retains the first refusal without discarding original consumed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WholeIngressError {
    Ownership,
    Selection,
    Profile,
    Allocation,
    Clock,
    Deadline,
    Attempts,
    Bytes,
    Envelope,
    Correlation,
    EndOfStream,
    Socket,
    History,
    Capacity,
}

struct FrameHistory {
    backing: Vec<u8>,
    received: usize,
    expected: Option<usize>,
    kind: Option<WholeFrameKind>,
}

struct CollectionState {
    profile: WholeControlProfile,
    frames: Vec<FrameHistory>,
    complete: usize,
    attempts: u64,
    bytes: u64,
    refusal: Option<WholeIngressError>,
}

/// Owns the same socket actor and never-recycled request/ACK frame history.
pub(crate) struct SelectedWholeIngress {
    original: Arc<NativeRunControlCustody>,
    process: u32,
    state: Mutex<CollectionState>,
}

/// Preserves selected original ownership before reporting preparation status.
pub(crate) struct WholeIngressPreparation {
    pub(crate) owner: Arc<SelectedWholeIngress>,
    pub(crate) status: Result<(), WholeIngressError>,
}

impl SelectedWholeIngress {
    /// Preallocates two entire administrative frames for each selected operation.
    ///
    /// The authentic constructor must already retain native worker and ring
    /// holds. Selection occurs before allocation, so a failure cannot revert
    /// to the ordinary reader or consume an unretained socket prefix.
    pub(crate) fn prepare(
        original: Arc<NativeRunControlCustody>,
        profile: WholeControlProfile,
    ) -> WholeIngressPreparation {
        let mut state = CollectionState {
            profile,
            frames: Vec::new(),
            complete: 0,
            attempts: 0,
            bytes: 0,
            refusal: None,
        };
        let status = (|| {
            // All ordinary and selected reads acquire these locks in this order.
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
            if monotonic_ns()? >= state.profile.deadline_monotonic_ns {
                return Err(WholeIngressError::Deadline);
            }

            let count = (state.profile.operation_capacity as usize)
                .checked_mul(2)
                .ok_or(WholeIngressError::Allocation)?;
            let extent = WHOLE_FRAME_HEADER_BYTES
                .checked_add(state.profile.body_byte_limit as usize)
                .ok_or(WholeIngressError::Allocation)?;
            let total = count
                .checked_mul(extent)
                .and_then(|bytes| {
                    count
                        .checked_mul(std::mem::size_of::<FrameHistory>())
                        .and_then(|metadata| bytes.checked_add(metadata))
                })
                .ok_or(WholeIngressError::Allocation)?;
            if total as u64 > state.profile.provider_history_byte_limit {
                return Err(WholeIngressError::Allocation);
            }
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
                    expected: None,
                    kind: None,
                });
            }
            Ok(())
        })();
        state.refusal = status.err();
        WholeIngressPreparation {
            owner: Arc::new(Self {
                original,
                process: std::process::id(),
                state: Mutex::new(state),
            }),
            status,
        }
    }

    /// Performs at most one physical read under nonrenewing administrative credit.
    ///
    /// # Errors
    /// Retains every consumed byte and the first terminal deadline, quota,
    /// framing, correlation or socket refusal. Busy locks consume no credit.
    pub(crate) fn collect(&self) -> Result<bool, WholeIngressError> {
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
        if state.complete == state.frames.len() {
            return state.refuse(WholeIngressError::History);
        }
        let now = match monotonic_ns() {
            Ok(now) => now,
            Err(error) => return state.refuse(error),
        };
        if now >= state.profile.deadline_monotonic_ns {
            return state.refuse(WholeIngressError::Deadline);
        }
        if state.attempts >= state.profile.administrative_read_attempt_limit {
            return state.refuse(WholeIngressError::Attempts);
        }
        let remaining = state
            .profile
            .administrative_read_byte_limit
            .saturating_sub(state.bytes);
        if remaining == 0 {
            return state.refuse(WholeIngressError::Bytes);
        }

        let index = state.complete;
        let frame = &state.frames[index];
        let target = frame.expected.unwrap_or(WHOLE_FRAME_HEADER_BYTES);
        let start = frame.received;
        let available = target - start;
        let count = available.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        state.attempts += 1;
        let received = match original
            .socket
            .read(&mut state.frames[index].backing[start..start + count])
        {
            Ok(0) => return state.refuse(WholeIngressError::EndOfStream),
            Ok(received) => received,
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
        state.frames[index].received += received;
        state.bytes += received as u64;

        let frame = &state.frames[index];
        if frame.received == WHOLE_FRAME_HEADER_BYTES && frame.expected.is_none() {
            let decoded = decode_whole_frame_header(
                &frame.backing[..WHOLE_FRAME_HEADER_BYTES],
                state.profile.body_byte_limit,
            );
            let (kind, extent) = match decoded {
                Ok(decoded) => decoded,
                Err(_) => return state.refuse(WholeIngressError::Envelope),
            };
            let expected = if index.is_multiple_of(2) {
                WholeFrameKind::Request
            } else {
                WholeFrameKind::Acknowledgement
            };
            if kind != expected {
                return state.refuse(WholeIngressError::Envelope);
            }
            state.frames[index].kind = Some(kind);
            state.frames[index].expected = Some(WHOLE_FRAME_HEADER_BYTES + extent);
        }
        if state.frames[index].expected != Some(state.frames[index].received) {
            return Ok(false);
        }
        if state.validate_complete(index).is_err() {
            return state.refuse(WholeIngressError::Correlation);
        }
        state.complete += 1;
        Ok(true)
    }

    /// Copies one immutable completed original without spending or refunding credit.
    ///
    /// # Errors
    /// Refuses a nonhistorical index, insufficient destination or busy ownership.
    /// Historical bytes remain recoverable after a later sticky refusal.
    pub(crate) fn copy_complete(
        &self,
        index: usize,
        destination: &mut [u8],
    ) -> Result<(WholeFrameKind, usize), WholeIngressError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| WholeIngressError::Ownership)?;
        if index >= state.complete {
            return Err(WholeIngressError::History);
        }
        let frame = &state.frames[index];
        let body = &frame.backing[WHOLE_FRAME_HEADER_BYTES..frame.received];
        if destination.len() < body.len() {
            return Err(WholeIngressError::Capacity);
        }
        let kind = frame.kind.ok_or(WholeIngressError::Envelope)?;
        destination[..body.len()].copy_from_slice(body);
        Ok((kind, body.len()))
    }
}

impl CollectionState {
    fn refuse<T>(&mut self, error: WholeIngressError) -> Result<T, WholeIngressError> {
        Err(*self.refusal.get_or_insert(error))
    }

    fn validate_complete(&self, index: usize) -> Result<(), WholeIngressError> {
        let frame = &self.frames[index];
        let body = &frame.backing[WHOLE_FRAME_HEADER_BYTES..frame.received];
        let sequence = index as u64 / 2 + 1;
        if index.is_multiple_of(2) {
            let request = WholeRequest::decode(body).map_err(|_| WholeIngressError::Correlation)?;
            if request.scope != self.profile.scope || request.sequence != sequence {
                return Err(WholeIngressError::Correlation);
            }
        } else {
            let acknowledgement =
                WholeAcknowledgement::decode(body).map_err(|_| WholeIngressError::Correlation)?;
            let request_frame = &self.frames[index - 1];
            let request = WholeRequest::decode(
                &request_frame.backing[WHOLE_FRAME_HEADER_BYTES..request_frame.received],
            )
            .map_err(|_| WholeIngressError::Correlation)?;
            if acknowledgement.scope != request.scope
                || acknowledgement.epoch != request.epoch
                || acknowledgement.sequence != sequence
            {
                return Err(WholeIngressError::Correlation);
            }
        }
        Ok(())
    }
}

fn monotonic_ns() -> Result<u64, WholeIngressError> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The writable timespec lives through this synchronous call; the
    // monotonic clock shares the original host deadline's time domain.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(WholeIngressError::Clock);
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|nanos| seconds.checked_add(nanos))
        })
        .ok_or(WholeIngressError::Clock)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Actual socket controls panic on unmet custody invariants.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crucible_qemu_protocol::whole_control::body::WholeOperationQuota;
    use crucible_qemu_protocol::whole_control::encode_whole_frame_header;
    use std::io::Write;

    fn profile() -> WholeControlProfile {
        WholeControlProfile {
            scope: [1; 32],
            operation_capacity: 16,
            body_byte_limit: 512,
            native_history_byte_limit: 1_000_000,
            provider_history_byte_limit: 1_000_000,
            administrative_read_attempt_limit: 100,
            administrative_read_byte_limit: 100_000,
            administrative_write_attempt_limit: 100,
            administrative_write_byte_limit: 100_000,
            deadline_monotonic_ns: monotonic_ns().unwrap() + 10_000_000_000,
            cpu_retirement_limit: 16,
            event_step_limit: 16,
            input_byte_limit: 0,
            input_record_limit: 0,
            output_byte_limit: 0,
            output_record_limit: 0,
        }
    }

    fn request_frame(sequence: u64) -> Vec<u8> {
        let input = [0; 8];
        let request = WholeRequest {
            scope: [1; 32],
            epoch: 1,
            sequence,
            grant_digest: [2; 32],
            binding_digest: [3; 32],
            start_ps: 0,
            limit_ps: 50,
            quota: WholeOperationQuota {
                input_bytes: 0,
                input_records: 0,
                output_bytes: 0,
                output_records: 0,
                cpu_retirements: 1,
                event_steps: 1,
            },
            input_inventory: &input,
        };
        let mut body = vec![0; 264];
        request.encode_into(&mut body).unwrap();
        let mut frame = encode_whole_frame_header(WholeFrameKind::Request, body.len(), 512)
            .unwrap()
            .to_vec();
        frame.extend(body);
        frame
    }

    #[test]
    fn same_socket_selection_retains_partial_frame_and_fences_legacy_before_io() {
        let (mut peer, lifecycle) = super::super::test_running_pair();
        let custody = NativeRunControlCustody::prepare(lifecycle).owner;
        let prepared = SelectedWholeIngress::prepare(Arc::clone(&custody), profile());
        assert_eq!(prepared.status, Ok(()));
        assert_eq!(prepared.owner.state.lock().unwrap().frames.len(), 32);
        let frame = request_frame(1);
        peer.write_all(&frame[..11]).unwrap();

        assert!(!prepared.owner.collect().unwrap());
        assert!(custody.receive_step().is_err());
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(state.frames[0].received, 11);
        assert_eq!(&state.frames[0].backing[..11], &frame[..11]);
        drop(state);

        peer.write_all(&frame[11..]).unwrap();
        assert!(!prepared.owner.collect().unwrap());
        assert!(prepared.owner.collect().unwrap());
        let mut body = [0; 512];
        assert_eq!(
            prepared.owner.copy_complete(0, &mut body).unwrap(),
            (WholeFrameKind::Request, 264)
        );
        assert_eq!(&body[..264], &frame[WHOLE_FRAME_HEADER_BYTES..]);
    }

    #[test]
    fn failed_constructor_is_sticky_before_ordinary_reader_can_consume() {
        let (mut peer, lifecycle) = super::super::test_running_pair();
        let custody = NativeRunControlCustody::prepare(lifecycle).owner;
        let mut selected = profile();
        selected.body_byte_limit = 0;
        let prepared = SelectedWholeIngress::prepare(Arc::clone(&custody), selected);
        assert_eq!(prepared.status, Err(WholeIngressError::Profile));
        peer.write_all(&request_frame(1)).unwrap();
        assert!(custody.receive_step().is_err());
        assert_eq!(custody.snapshot().unwrap().received, 0);
        assert_eq!(prepared.owner.collect(), Err(WholeIngressError::Profile));
    }

    #[test]
    fn empty_socket_attempts_are_never_refunded_or_renewed() {
        let (_peer, lifecycle) = super::super::test_running_pair();
        let custody = NativeRunControlCustody::prepare(lifecycle).owner;
        let mut selected = profile();
        selected.administrative_read_attempt_limit = 32;
        let prepared = SelectedWholeIngress::prepare(custody, selected);
        assert_eq!(prepared.status, Ok(()));
        for _ in 0..32 {
            assert!(!prepared.owner.collect().unwrap());
        }
        assert_eq!(prepared.owner.collect(), Err(WholeIngressError::Attempts));
        assert_eq!(prepared.owner.collect(), Err(WholeIngressError::Attempts));
        let state = prepared.owner.state.lock().unwrap();
        assert_eq!(state.attempts, 32);
        assert_eq!(state.bytes, 0);
        assert_eq!(state.frames.len(), 32);
    }
}
