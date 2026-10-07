//! SPDX-License-Identifier: GPL-2.0-only
//! Bounded advisory observations armed by a genuine pending selection.
//!
//! This independent stream admits at most 24 rows of 512 bytes per process,
//! further limited by the existing aggregate allowance. It does not share the
//! control, device or idle stream's budget. Missing providers, capture, capacity
//! or PID identity leave the original request and callback result untouched.
//! Native data crosses only a GPL-local function call, never process IPC.
//! The optional native tuple contains stop generation, stop state, runstate,
//! observed CPU, lifecycle flags and the original prepare/flush return code.
//! These fields are sampled independently and are not a coherent snapshot.
//! Row exhaustion suppresses capture, not completed-reply lifecycle cleanup.
//! `request_vcpu` retains the target of the actual catalog request separately.
//!
//! ```text
//! CRUCIBLE-SELECTABLE-RESUME-V1 phase=rust-entry pid=42 sequence=2 request_vcpu=0 vcpu=0 raw=Some(3) ps=None read=Some(0) write=Some(1) native=None
//! ```

use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use super::super::live_callbacks::device_wait_witness::capture::destination;

const MAX_ROWS: usize = 24;
const MAX_ROW_BYTES: usize = 512;
const PROVIDER: &[u8] = b"qemu_plugin_crucible_set_selectable_resume_observer\0";

type NativeObserver = extern "C" fn(u32, u64, u32, u32, u32, u32, i32);
type SetObserver = extern "C" fn(Option<NativeObserver>);

static WITNESS: OnceLock<Witness> = OnceLock::new();

/// Identifies an original native or Rust callback seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) enum Phase {
    Pending,
    ProviderUnavailable,
    PrepareStartEnter,
    PrepareStartReturn,
    Stopped,
    ResumePending,
    ResumeConsumed,
    NativeEntry,
    NativeReturn,
    RustEntry,
    PauseReturn,
    NetworkReturn,
    IdleControlReturn,
    IdleError,
    ReplyEnter,
    ReplyDequeued,
    ReplyCompleted,
    ReplyReturn,
    ControlReturn,
    AlreadyRunningReturn,
    RunningReturn,
}

impl Phase {
    const fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::PrepareStartEnter => "prepare-start-enter",
            Self::PrepareStartReturn => "prepare-start-return",
            Self::Stopped => "stopped",
            Self::ResumePending => "resume-pending",
            Self::ResumeConsumed => "resume-consumed",
            Self::NativeEntry => "native-entry",
            Self::NativeReturn => "native-return",
            Self::RustEntry => "rust-entry",
            Self::PauseReturn => "pause-return",
            Self::NetworkReturn => "network-return",
            Self::IdleControlReturn => "idle-control-return",
            Self::IdleError => "idle-error",
            Self::ReplyEnter => "reply-enter",
            Self::ReplyDequeued => "reply-dequeued",
            Self::ReplyCompleted => "reply-completed",
            Self::ReplyReturn => "reply-return",
            Self::ControlReturn => "control-return",
            Self::AlreadyRunningReturn => "already-running-return",
            Self::RunningReturn => "running-return",
        }
    }

    const fn native(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::PrepareStartEnter),
            2 => Some(Self::PrepareStartReturn),
            3 => Some(Self::Stopped),
            4 => Some(Self::ResumePending),
            5 => Some(Self::ResumeConsumed),
            6 => Some(Self::NativeEntry),
            7 => Some(Self::NativeReturn),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeState {
    generation: u64,
    stop_state: u32,
    runstate: u32,
    cpu: u32,
    flags: u32,
    result: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    phase: Phase,
    pid: u32,
    sequence: u64,
    request_vcpu: u32,
    vcpu: u32,
    raw: Option<u64>,
    ps: Option<u64>,
    indices: Option<(u64, u64)>,
    native: Option<NativeState>,
}

impl Record {
    fn capture_to(self, source: &impl AsFd) {
        let Some(_errno) = ErrnoGuard::preserve() else {
            return;
        };
        let mut bytes = [0_u8; MAX_ROW_BYTES];
        let mut writer = io::Cursor::new(bytes.as_mut_slice());
        if self.write_to(&mut writer).is_err() {
            return;
        }
        let length = writer.position() as usize;
        if let Ok(destination) = destination(source) {
            let _ = (&destination).write(&bytes[..length]);
        }
    }

    fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        writeln!(
            writer,
            "CRUCIBLE-SELECTABLE-RESUME-V1 phase={} pid={} sequence={} request_vcpu={} vcpu={} raw={:?} ps={:?} read={:?} write={:?} native={:?}",
            self.phase.name(),
            self.pid,
            self.sequence,
            self.request_vcpu,
            self.vcpu,
            self.raw,
            self.ps,
            self.indices.map(|indices| indices.0),
            self.indices.map(|indices| indices.1),
            self.native.map(|state| (
                state.generation,
                state.stop_state,
                state.runstate,
                state.cpu,
                state.flags,
                state.result
            )),
        )
    }
}

// This callback-local guard never crosses a thread or native boundary. Targets
// without a reviewed errno accessor drop this optional capture instead.
struct ErrnoGuard {
    slot: NonNull<libc::c_int>,
    saved: libc::c_int,
}

impl ErrnoGuard {
    fn preserve() -> Option<Self> {
        #[cfg(target_os = "linux")]
        // SAFETY: libc returns this thread's errno slot, live for the thread.
        let slot = unsafe { libc::__errno_location() };
        #[cfg(target_vendor = "apple")]
        // SAFETY: libc returns this thread's errno slot, live for the thread.
        let slot = unsafe { libc::__error() };
        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        let slot = std::ptr::null_mut();

        let slot = NonNull::new(slot)?;
        // SAFETY: the non-null thread-local slot is read on its owning thread.
        let saved = unsafe { *slot.as_ptr() };
        Some(Self { slot, saved })
    }
}

impl Drop for ErrnoGuard {
    fn drop(&mut self) {
        // SAFETY: this lexical guard stays on the originating thread and the
        // libc errno slot remains live until after the guard is dropped.
        unsafe { *self.slot.as_ptr() = self.saved };
    }
}

struct Inventory {
    active: Option<(u64, u32)>,
    completed: bool,
    rows: [Option<Record>; MAX_ROWS],
    count: usize,
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            active: None,
            completed: false,
            rows: [None; MAX_ROWS],
            count: 0,
        }
    }
}

struct Witness {
    budget: usize,
    pid: u32,
    provider: Option<SetObserver>,
    inventory: Mutex<Inventory>,
}

impl Witness {
    fn from_env() -> Self {
        let budget = budget(
            std::env::var_os("CRUCIBLE_OUT_RESUME_RUNTIME_TRACE").as_deref(),
            std::env::var_os("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS").as_deref(),
        );
        let provider = if budget == 0 { None } else { provider() };
        Self {
            budget,
            pid: std::process::id(),
            provider,
            inventory: Mutex::default(),
        }
    }

    fn record(
        &self,
        phase: Phase,
        vcpu: u32,
        raw: Option<u64>,
        ps: Option<u64>,
        indices: Option<(u64, u64)>,
        native: Option<NativeState>,
    ) {
        if self.budget == 0 || self.pid != std::process::id() {
            return;
        }
        let Some(record) = self.retain(phase, vcpu, raw, ps, indices, native) else {
            return;
        };

        // Charge before touching a sink. Capture refusal cannot affect any
        // catalog, native admission, callback result or observer allowance.
        record.capture_to(&io::stderr());
    }

    fn reply_completed(&self) {
        if self.budget == 0 || self.pid != std::process::id() {
            return;
        }
        if let Ok(mut inventory) = self.inventory.try_lock()
            && inventory.active.is_some()
        {
            inventory.completed = true;
        }
    }

    fn finish_rust_return(&self, phase: Phase) {
        if self.provider.is_none()
            && matches!(
                phase,
                Phase::ControlReturn | Phase::AlreadyRunningReturn | Phase::RunningReturn
            )
        {
            self.close_completed();
        }
    }

    fn close_completed(&self) {
        if self.budget == 0 || self.pid != std::process::id() {
            return;
        }
        {
            let Ok(mut inventory) = self.inventory.try_lock() else {
                return;
            };
            if !inventory.completed || inventory.active.is_none() {
                return;
            }
            inventory.active = None;
            inventory.completed = false;
        }
        if let Some(provider) = self.provider {
            provider(None);
        }
    }

    fn retain(
        &self,
        phase: Phase,
        vcpu: u32,
        raw: Option<u64>,
        ps: Option<u64>,
        indices: Option<(u64, u64)>,
        native: Option<NativeState>,
    ) -> Option<Record> {
        if self.budget == 0 || self.pid != std::process::id() {
            return None;
        }
        let Ok(mut inventory) = self.inventory.try_lock() else {
            return None;
        };
        let (sequence, request_vcpu) = inventory.active?;
        let record = Record {
            phase,
            pid: self.pid,
            sequence,
            request_vcpu,
            vcpu,
            raw,
            ps,
            indices,
            native,
        };
        if inventory.count == self.budget
            || inventory.rows[..inventory.count].contains(&Some(record))
        {
            return None;
        }
        let index = inventory.count;
        inventory.rows[index] = Some(record);
        inventory.count += 1;
        Some(record)
    }
}

fn budget(runtime: Option<&OsStr>, aggregate: Option<&OsStr>) -> usize {
    if runtime != Some(OsStr::new("1")) {
        return 0;
    }
    aggregate
        .and_then(OsStr::to_str)
        .and_then(|text| {
            text.parse::<usize>()
                .ok()
                .filter(|value| (1..=256).contains(value) && value.to_string() == text)
        })
        .map_or(0, |value| value.min(MAX_ROWS))
}

fn provider() -> Option<SetObserver> {
    // SAFETY: this static NUL-terminated optional symbol is a GPL-local function
    // whose exact scalar callback signature matches the reviewed native draft.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, PROVIDER.as_ptr().cast()) };
    if address.is_null() {
        return None;
    }
    // SAFETY: the non-null symbol has the function-pointer ABI declared above;
    // it carries no native object or function pointer through process IPC.
    Some(unsafe { std::mem::transmute::<*mut libc::c_void, SetObserver>(address) })
}

/// Prepares optional settings and symbol lookup before guest execution.
pub(super) fn initialize() {
    let _ = WITNESS.get_or_init(Witness::from_env);
}

/// Arms only after the original catalog accepted an actual request.
pub(super) fn arm(sequence: u64, vcpu: u32, raw: u64, ps: u64) {
    let Some(witness) = WITNESS.get() else {
        return;
    };
    if witness.budget == 0 || witness.pid != std::process::id() {
        return;
    }
    {
        let Ok(mut inventory) = witness.inventory.try_lock() else {
            return;
        };
        if inventory.count == witness.budget {
            return;
        }
        inventory.active = Some((sequence, vcpu));
        inventory.completed = false;
    }
    witness.record(Phase::Pending, vcpu, Some(raw), Some(ps), None, None);
    if let Some(provider) = witness.provider {
        provider(Some(native_observation));
    } else {
        witness.record(Phase::ProviderUnavailable, vcpu, None, None, None, None);
    }
}

pub(super) fn is_armed() -> bool {
    WITNESS.get().is_some_and(|witness| {
        witness.budget != 0
            && witness.pid == std::process::id()
            && witness.inventory.try_lock().is_ok_and(|inventory| {
                inventory.active.is_some() && inventory.count < witness.budget
            })
    })
}

/// Tracks original completion even when no further row can be retained.
pub(super) fn reply_completed() {
    if let Some(witness) = WITNESS.get() {
        witness.reply_completed();
    }
}

/// Closes an unavailable-provider window without reading diagnostic indices.
pub(super) fn finish_unrecorded_rust_return(phase: Phase) {
    if let Some(witness) = WITNESS.get() {
        witness.finish_rust_return(phase);
    }
}

pub(super) fn observe(
    phase: Phase,
    vcpu: u32,
    raw: Option<u64>,
    ps: Option<u64>,
    indices: Option<(u64, u64)>,
) {
    if let Some(witness) = WITNESS.get() {
        witness.record(phase, vcpu, raw, ps, indices, None);
        witness.finish_rust_return(phase);
    }
}

extern "C" fn native_observation(
    phase: u32,
    generation: u64,
    stop_state: u32,
    runstate: u32,
    cpu: u32,
    flags: u32,
    result: i32,
) {
    let Some(phase) = Phase::native(phase) else {
        return;
    };
    if let Some(witness) = WITNESS.get() {
        witness.record(
            phase,
            cpu,
            None,
            None,
            None,
            Some(NativeState {
                generation,
                stop_state,
                runstate,
                cpu,
                flags,
                result,
            }),
        );
        if phase == Phase::NativeReturn {
            witness.close_completed();
        }
    }
}

#[cfg(test)]
mod tests;
