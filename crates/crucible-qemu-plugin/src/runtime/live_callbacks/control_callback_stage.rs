//! Opt-in positions within an originally admitted control callback.
//!
//! `CRUCIBLE_CONTROL_CALLBACK_WITNESS=1` and a canonical decimal
//! `CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN` enable four stage records for
//! even shared tokens at or above that minimum. Settings are read at construction.
//! The minimum selects diagnostics only; it never filters control work.
//!
//! Each token epoch in one PID permits one record per phase. Serialized callbacks
//! at that token emit at most four records, without exhausting later requests.
//! Token reuse after another epoch or child identity rebind permits fresh records. Each row,
//! including its newline, is bounded by 256 bytes. Total stream volume grows
//! with qualifying requests; the existing capture ceiling remains authoritative.
//! Records are observations, not proof that an invocation is currently active.
//!
//! Mapping identity is copied at original runtime construction and refreshed at
//! the authenticated, barrier-held child rebind before worker startup. Token and raw
//! count come from the original admitted callback and its existing snapshot;
//! observing stages adds no mapped reads, clocks, queries or canonical locks.
//!
//! ```text
//! CRUCIBLE-CONTROL-STAGE-V1 phase=settle-return pid=42 callback=9 token=4400 raw=7 dev=1 ino=8 slot=0 gen=2 result=true
//! ```

use std::ffi::OsStr;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState, PluginShmemOrdering};

const TOKEN_VALID: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ControlStageIdentity {
    backing: crucible_shmem::SetupRegionBackingIdentity,
    slot: u32,
    generation: u64,
}

/// Holds only the cached diagnostic setting and per-token phase deduplication.
pub(super) struct ControlCallbackStages {
    minimum_token: Option<u32>,
    token_and_phases: AtomicU64,
}

impl ControlCallbackStages {
    pub(super) fn from_setting(value: Option<&OsStr>) -> Self {
        Self {
            minimum_token: value.and_then(|value| {
                let text = value.to_str()?;
                if text.is_empty()
                    || !text.bytes().all(|byte| byte.is_ascii_digit())
                    || (text.len() > 1 && text.starts_with('0'))
                {
                    return None;
                }
                text.parse().ok()
            }),
            token_and_phases: AtomicU64::new(0),
        }
    }

    pub(super) fn reset(&self) {
        self.token_and_phases.store(0, Ordering::Relaxed);
    }

    fn permits(&self, token: u32) -> bool {
        token & 1 == 0 && self.minimum_token.is_some_and(|minimum| token >= minimum)
    }

    fn record(
        &self,
        invocation: StageInvocation,
        phase: StagePhase,
        result: StageResult,
    ) -> Option<StageRecord> {
        let phase_bit = 1 << (phase as u8 + 1);
        let mut observed = self.token_and_phases.load(Ordering::Relaxed);
        loop {
            let same_epoch =
                observed & TOKEN_VALID != 0 && (observed >> 32) as u32 == invocation.token;
            if same_epoch && observed & phase_bit != 0 {
                return None;
            }
            let epoch = if same_epoch {
                observed
            } else {
                (u64::from(invocation.token) << 32) | TOKEN_VALID
            };
            match self.token_and_phases.compare_exchange_weak(
                observed,
                epoch | phase_bit,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(StageRecord {
                        invocation,
                        phase,
                        result,
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn observe_work<E>(
        &self,
        invocation: Option<StageInvocation>,
        enter: StagePhase,
        returned: StagePhase,
        emit: &mut impl FnMut(StageRecord),
        work: impl FnOnce() -> Result<bool, E>,
    ) -> Result<bool, E> {
        if let Some(invocation) = invocation
            && let Some(record) = self.record(invocation, enter, StageResult::Unavailable)
        {
            emit(record);
        }

        let result = work();

        if let Some(invocation) = invocation {
            let outcome = match &result {
                Ok(true) => StageResult::True,
                Ok(false) => StageResult::False,
                Err(_) => StageResult::Error,
            };
            if let Some(record) = self.record(invocation, returned, outcome) {
                emit(record);
            }
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StageInvocation {
    pid: u32,
    callback: u64,
    token: u32,
    raw: u64,
    identity: Option<ControlStageIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagePhase {
    SettleEnter,
    SettleReturn,
    PauseEnter,
    PauseReturn,
}

impl StagePhase {
    fn label(self) -> &'static str {
        match self {
            Self::SettleEnter => "settle-enter",
            Self::SettleReturn => "settle-return",
            Self::PauseEnter => "pause-enter",
            Self::PauseReturn => "pause-return",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageResult {
    Unavailable,
    True,
    False,
    Error,
}

impl StageResult {
    fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::True => "true",
            Self::False => "false",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StageRecord {
    invocation: StageInvocation,
    phase: StagePhase,
    result: StageResult,
}

impl StageRecord {
    pub(super) fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        let mut bytes = [0_u8; 256];
        let mut cursor = io::Cursor::new(bytes.as_mut_slice());
        let invocation = self.invocation;
        write!(
            cursor,
            "CRUCIBLE-CONTROL-STAGE-V1 phase={} pid={} callback={} token={} raw={}",
            self.phase.label(),
            invocation.pid,
            invocation.callback,
            invocation.token,
            invocation.raw,
        )?;
        match invocation.identity {
            Some(identity) => write!(
                cursor,
                " dev={} ino={} slot={} gen={}",
                identity.backing.device(),
                identity.backing.inode(),
                identity.slot,
                identity.generation,
            )?,
            None => write!(
                cursor,
                " dev=unavailable ino=unavailable slot=unavailable gen=unavailable"
            )?,
        }
        writeln!(cursor, " result={}", self.result.label())?;
        let length = cursor.position() as usize;
        writer.write_all(&bytes[..length])
    }
}

impl super::ControlCallbackWitness {
    pub(super) fn stage_invocation(
        &self,
        callback: Option<u64>,
        token: u32,
        raw: u64,
        identity: Option<ControlStageIdentity>,
    ) -> Option<StageInvocation> {
        if !self.is_enabled() || !self.stages.permits(token) {
            return None;
        }
        Some(StageInvocation {
            pid: self.process_id.load(Ordering::Relaxed),
            callback: callback?,
            token,
            raw,
            identity,
        })
    }
}

impl LiveVcpuTimeCallbackState {
    /// Copies original mapping identity before callback registration.
    pub(in crate::runtime) fn attach_control_stage_identity(
        mut self,
        backing: crucible_shmem::SetupRegionBackingIdentity,
        slot: u32,
        generation: u64,
    ) -> Self {
        self.rebind_control_stage_identity(backing, slot, generation);
        self
    }

    /// Refreshes only diagnostic identity at the original held child rebind.
    pub(in crate::runtime) fn rebind_control_stage_identity(
        &mut self,
        backing: crucible_shmem::SetupRegionBackingIdentity,
        slot: u32,
        generation: u64,
    ) {
        if self.control_callback_witness.is_enabled() {
            self.control_stage_identity = Some(ControlStageIdentity {
                backing,
                slot,
                generation,
            });
            self.control_callback_witness.stages.reset();
        }
    }

    #[cfg(test)]
    pub(super) fn on_control_boundary(
        &self,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.on_control_boundary_with_stages(raw_icount, None, &mut |_| {})
    }

    // The original admitted control work remains here in its original order.
    pub(super) fn on_control_boundary_with_stages(
        &self,
        raw_icount: u64,
        callback: Option<u64>,
        emit: &mut impl FnMut(StageRecord),
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        // A stopped boundary permits the host to save VMState. RX poison is not
        // serialized, so no checkpoint may acknowledge ambiguous ownership.
        self.require_network_rx_commit_certain()?;

        // A drained wake is an exact host-control opportunity, not a vCPU
        // lifecycle transition. Publish before the release acknowledgement so
        // a host acquire-load of the odd successor orders every boundary field.
        // Halt tracking and idle publication remain owned by the real
        // idle/resume callbacks.
        let control_boundary = self.slot.get().snapshot();
        if control_boundary.control_boundary_ack & 1 != 0 {
            let _fault_pump_drained = self.pump_fault_commands(raw_icount)?;
            return Ok(());
        }

        let control_request = control_boundary.control_boundary_ack;
        let fault_command_frontier = control_boundary.control_boundary_fault_command_frontier;
        let fingerprint_capture_request = match control_boundary.control_boundary_capture_request {
            0 => None,
            request => Some(request),
        };
        let observed_capture_request = self
            .fingerprint
            .as_ref()
            .and_then(|fingerprint| fingerprint.slot.get().pending_capture_request_v1());
        if observed_capture_request != fingerprint_capture_request {
            return Err(
                LiveVcpuTimeCallbackError::ControlBoundaryCaptureRequestMismatch {
                    bound: fingerprint_capture_request,
                    observed: observed_capture_request,
                },
            );
        }

        // The host binds this request to an immutable producer frontier. Submit
        // exactly those commands, commit all mutations due at this coordinate,
        // and publish every resulting record before observing machine state.
        // Any backpressure or concurrent producer advance leaves the request
        // outstanding without a capture, pause, or acknowledgement.
        let invocation = self.control_callback_witness.stage_invocation(
            callback,
            control_request,
            raw_icount,
            self.control_stage_identity,
        );
        let settled = self.control_callback_witness.stages.observe_work(
            invocation,
            StagePhase::SettleEnter,
            StagePhase::SettleReturn,
            emit,
            || {
                self.settle_fault_commands_at_control_boundary(
                    raw_icount,
                    control_request,
                    fault_command_frontier,
                )
            },
        )?;
        if !settled {
            return Ok(());
        }
        let paused = self.control_callback_witness.stages.observe_work(
            invocation,
            StagePhase::PauseEnter,
            StagePhase::PauseReturn,
            emit,
            || {
                self.publish_pause_for_boundary(
                    raw_icount,
                    true,
                    true,
                    fingerprint_capture_request,
                    "control-boundary",
                )
            },
        )?;
        if !paused {
            self.preserve_network_output_stop(raw_icount, "control-boundary")?;
            let current_icount = self.logical_icount_for_raw(raw_icount)?;
            let (ceiling_icount, _) = self.scheduler_advance()?;
            if current_icount > ceiling_icount {
                return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                    current_icount,
                    ceiling_icount,
                });
            }
            if self.fingerprint.is_some()
                && let Some(capture_request) = fingerprint_capture_request
            {
                // The main-loop callback holds the BQL after every vCPU has
                // quiesced, making cross-vCPU register capture safe even when
                // the serialized RR owner is intentionally absent at idle.
                self.publish_fingerprint_sample(
                    current_icount,
                    "requested-control-boundary",
                    capture_request,
                )?;
            }
            PluginShmemOrdering::publish_control_boundary(
                self.slot.get(),
                current_icount,
                raw_icount,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::PublishIcount { source })?;
            self.last_raw_icount.store(raw_icount, Ordering::Release);
            self.last_icount.store(current_icount, Ordering::Release);

            // Returning from the all-halted callback for an ordinary control
            // boundary ends that invocation without a real vCPU resume. Re-arm
            // the plugin-side all-halted edge so the RR loop can enter a fresh
            // idle wait and consume the next scheduler ceiling. A checkpoint
            // pause deliberately remains armed until QEMU is resumed through
            // the lifecycle control path.
            self.all_halted_idle_handled.store(false, Ordering::Release);
        }
        PluginShmemOrdering::acknowledge_control_boundary(self.slot.get());
        self.control_boundary_dispatch_generation
            .store(u32::MAX, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
