//! Bounded, opt-in caller notices around original native checkpoint admission.
//!
//! The existing control callback witness opt-in enables these advisory rows.
//! Each caller/phase retains its last raw/token epoch, so duplicate stop requests
//! do not flood the stream and later requests retain their own notices. Fork
//! changes reset the diagnostic cache. Initial setup and barrier-held child
//! rebind install region identity before callbacks resume; native return uses the captured call
//! rather than a later slot or region. Neither notice grants stopped ownership.
//!
//! ```text
//! CRUCIBLE-CHECKPOINT-STOP-V1 phase=before-request pid=42 device=1 inode=2 length=4096 slot=0 generation=2 caller=selectable-sim-publication raw_icount=7 logical_ps=350 token=2 status=unavailable
//! ```

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

use super::{LiveVcpuTimeCallbackState, PluginShmemOrdering};

const CALLER_LABELS: [&str; 15] = [
    "selectable-sim-publication",
    "campaign-marker-sim-publication",
    "network-output",
    "vcpu-idle-wait",
    "vcpu-idle",
    "vcpu-resume",
    "sim-publication",
    "progress-publication",
    "block-wait",
    "control-boundary",
    "max-advance",
    "block-poll",
    "ninep-poll",
    "ninep-burst-done",
    "accelerator-poll",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    ClaimedBeforePause,
    BeforeRequest,
    AfterRequest,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::ClaimedBeforePause => "claimed-before-pause",
            Self::BeforeRequest => "before-request",
            Self::AfterRequest => "after-request",
        }
    }
}

#[derive(Clone, Copy)]
struct Identity {
    backing: crucible_shmem::SetupRegionBackingIdentity,
    slot: u32,
    generation: u64,
}

/// Original process-private diagnostic binding; it never participates in admission.
pub(super) struct StopCallerWitness {
    enabled: bool,
    identity: Option<Identity>,
    process_id: AtomicU32,
    epochs: [Epoch; 45],
}

#[derive(Default)]
struct Epoch {
    emitted: AtomicBool,
    raw: AtomicU64,
    token: AtomicU32,
    status: AtomicI64,
}

impl StopCallerWitness {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            identity: None,
            process_id: AtomicU32::new(0),
            epochs: std::array::from_fn(|_| Epoch::default()),
        }
    }

    fn capture(
        &self,
        caller: &'static str,
        read: impl FnOnce() -> (u64, u64, u32),
    ) -> Option<Notice> {
        if !self.enabled {
            return None;
        }
        let caller = CALLER_LABELS.iter().position(|label| *label == caller)?;
        let (raw, logical, token) = read();
        Some(Notice {
            phase: Phase::BeforeRequest,
            process_id: std::process::id(),
            identity: self.identity,
            caller,
            raw,
            logical,
            token,
            status: None,
        })
    }

    fn emit(&self, notice: Notice) {
        if self.process_id.swap(notice.process_id, Ordering::Relaxed) != notice.process_id {
            for epoch in &self.epochs {
                epoch.emitted.store(false, Ordering::Relaxed);
            }
        }
        let epoch = &self.epochs[notice.caller * 3 + notice.phase as usize];
        let first = !epoch.emitted.swap(true, Ordering::Relaxed);
        let raw_changed = epoch.raw.swap(notice.raw, Ordering::Relaxed) != notice.raw;
        let token_changed = epoch.token.swap(notice.token, Ordering::Relaxed) != notice.token;
        let status_changed = epoch
            .status
            .swap(notice.status.map_or(i64::MAX, i64::from), Ordering::Relaxed)
            != notice.status.map_or(i64::MAX, i64::from);
        if first || raw_changed || token_changed || status_changed {
            #[cfg(test)]
            {
                tests::retain(notice);
            }
            #[cfg(not(test))]
            {
                // crucible-lint: allow direct-diagnostic -- fixed-size opted-in
                // caller rows remain advisory and cannot change the stop result.
                let _write_result = notice.write_to(&mut io::stderr().lock());
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Notice {
    phase: Phase,
    process_id: u32,
    identity: Option<Identity>,
    caller: usize,
    raw: u64,
    logical: u64,
    token: u32,
    status: Option<i32>,
}

impl Notice {
    fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        let mut bytes = [0_u8; 512];
        let mut cursor = io::Cursor::new(bytes.as_mut_slice());
        write!(
            cursor,
            "CRUCIBLE-CHECKPOINT-STOP-V1 phase={} pid={}",
            self.phase.label(),
            self.process_id
        )?;
        match self.identity {
            Some(identity) => write!(
                cursor,
                " device={} inode={} length={} slot={} generation={}",
                identity.backing.device(),
                identity.backing.inode(),
                identity.backing.length(),
                identity.slot,
                identity.generation
            )?,
            None => write!(
                cursor,
                " device=unavailable inode=unavailable length=unavailable slot=unavailable generation=unavailable"
            )?,
        }
        write!(
            cursor,
            " caller={} raw_icount={} logical_ps={} token={} status=",
            CALLER_LABELS[self.caller], self.raw, self.logical, self.token
        )?;
        match self.status {
            Some(status) => write!(cursor, "{status}")?,
            None => write!(cursor, "unavailable")?,
        }
        writeln!(cursor)?;
        let length = cursor.position() as usize;
        writer.write_all(&bytes[..length])
    }
}

impl LiveVcpuTimeCallbackState {
    /// Binds already-validated setup identity before this callback state is published.
    pub(in crate::runtime) fn attach_stop_caller_identity(
        mut self,
        backing: crucible_shmem::SetupRegionBackingIdentity,
        slot: u32,
        generation: u64,
    ) -> Self {
        self.rebind_stop_caller_identity(backing, slot, generation);
        self
    }

    /// Refreshes advisory identity under the original child initialization barrier.
    pub(in crate::runtime) fn rebind_stop_caller_identity(
        &mut self,
        backing: crucible_shmem::SetupRegionBackingIdentity,
        slot: u32,
        generation: u64,
    ) {
        if !self.stop_caller_witness.enabled {
            return;
        }
        self.stop_caller_witness.identity = Some(Identity {
            backing,
            slot,
            generation,
        });
        // Child adoption retains this state in place. A new private binding
        // must emit even when PID and the original request coordinates match.
        for epoch in &mut self.stop_caller_witness.epochs {
            *epoch.emitted.get_mut() = false;
        }
    }

    pub(super) fn capture_stop_caller(
        &self,
        caller: &'static str,
        original: Option<(u64, u64)>,
    ) -> Option<Notice> {
        self.stop_caller_witness.capture(caller, || {
            let (raw, logical) = original.unwrap_or_else(|| {
                (
                    self.last_raw_icount.load(Ordering::Acquire),
                    self.last_icount.load(Ordering::Acquire),
                )
            });
            (
                raw,
                logical,
                PluginShmemOrdering::control_boundary_token(self.slot.get()),
            )
        })
    }

    pub(super) fn notice_claimed_stop(&self, caller: &'static str, raw: u64, logical: u64) {
        if let Some(mut notice) = self.stop_caller_witness.capture(caller, || {
            (
                raw,
                logical,
                PluginShmemOrdering::control_boundary_token(self.slot.get()),
            )
        }) {
            notice.phase = Phase::ClaimedBeforePause;
            self.stop_caller_witness.emit(notice);
        }
    }

    pub(super) fn notice_stop_before(&self, notice: Option<Notice>) {
        if let Some(notice) = notice {
            self.stop_caller_witness.emit(notice);
        }
    }

    pub(super) fn notice_stop_after(&self, notice: Option<Notice>, status: i32) {
        if let Some(mut notice) = notice {
            notice.phase = Phase::AfterRequest;
            notice.status = Some(status);
            self.stop_caller_witness.emit(notice);
        }
    }
}

#[cfg(test)]
mod tests;
