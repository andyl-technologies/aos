//! Bounded, opt-in observations of native control callback delivery and admission.
//!
//! `CRUCIBLE_CONTROL_CALLBACK_WITNESS=1` enables stderr records. An observed
//! token epoch in one process permits at most ten records: entry, admission,
//! four rejection reasons, and four exit outcomes. QEMU serializes this native
//! main-loop control callback under the BQL. Token reuse after another epoch or
//! a fork may emit new records for the same numeric token. Repeated callbacks
//! at a stalled token do not exhaust the budget for a later request. Hot-fork
//! copies this diagnostic state, but a PID change clears its token epoch before
//! callback entry. This state is neither canonical nor part of the shared-memory
//! ABI.
//!
//! Entry and rejection use only the last admitted token, explicitly labelled
//! cached (initially unavailable). Reading shared memory before admission could
//! race teardown unmapping. Admission and exit read only the ACK atomic, never
//! a slot snapshot. The current PID distinguishes fork children and guests in
//! merged stderr. Records carry no host-clock measurement or payload state.
//!
//! Fixed observations also retain the last callback and last admitted
//! outcome independently of row deduplication. Original ordered teardown emits
//! two bounded summaries using its immutable region identity after callback
//! draining. Rejected callbacks can still update observations, so snapshots use
//! one nonblocking lock attempt and never assume all writers have stopped.
//!
//! ```text
//! CRUCIBLE-CONTROL-CALLBACK-V1 phase=exit reason=pending pid=42 raw_icount=7 token_kind=observed token_before=2 token_after=2
//! ```

use std::io::{self, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::super::callback_quiescence::LiveCallbackQuiescenceSnapshot;
use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState, PluginShmemOrdering};

const TOKEN_VALID: u64 = 1;

/// Diagnostic state independent of callback admission and canonical replay state.
pub(in crate::runtime) struct ControlCallbackWitness {
    enabled: bool,
    pub(super) stages: super::control_callback_stage::ControlCallbackStages,
    pub(super) process_id: AtomicU32,
    token_and_events: AtomicU64,
    callback_sequence: AtomicU64,
    last_callback: LastObservation,
    last_admitted: LastObservation,
}

impl ControlCallbackWitness {
    /// Returns whether the original opt-in enabled callback diagnostics.
    pub(in crate::runtime) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn from_env() -> Self {
        let mut witness =
            Self::from_setting(std::env::var_os("CRUCIBLE_CONTROL_CALLBACK_WITNESS").as_deref());
        if witness.enabled {
            witness.stages = super::control_callback_stage::ControlCallbackStages::from_setting(
                std::env::var_os("CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN").as_deref(),
            );
        }
        witness
    }

    fn from_setting(value: Option<&std::ffi::OsStr>) -> Self {
        Self::new(value == Some(std::ffi::OsStr::new("1")))
    }

    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            stages: super::control_callback_stage::ControlCallbackStages::from_setting(None),
            process_id: AtomicU32::new(if enabled { std::process::id() } else { 0 }),
            token_and_events: AtomicU64::new(0),
            callback_sequence: AtomicU64::new(0),
            last_callback: LastObservation::default(),
            last_admitted: LastObservation::default(),
        }
    }

    fn entry_record(&self, raw_icount: u64) -> Option<Record> {
        if !self.enabled {
            return None;
        }
        let process_id = std::process::id();
        if self.process_id.swap(process_id, Ordering::Relaxed) != process_id {
            // A fork child must witness its first callback even if the parent's
            // copied token/phase budget had already been exhausted.
            self.token_and_events.store(0, Ordering::Relaxed);
            self.stages.reset();
            self.callback_sequence.store(0, Ordering::Relaxed);
            self.last_callback.clear();
            self.last_admitted.clear();
        }
        self.record(Event::Entry, raw_icount, None)
    }

    fn observe_token(&self, token: u32) {
        let mut observed = self.token_and_events.load(Ordering::Relaxed);
        loop {
            if observed & TOKEN_VALID != 0 && (observed >> 32) as u32 == token {
                return;
            }
            let next = (u64::from(token) << 32) | TOKEN_VALID;
            match self.token_and_events.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => observed = actual,
            }
        }
    }

    fn record(&self, event: Event, raw_icount: u64, token_after: Option<u32>) -> Option<Record> {
        if !self.enabled {
            return None;
        }
        let event_bit = 1_u64 << (event as u8 + 1);
        let previous = self.token_and_events.fetch_or(event_bit, Ordering::Relaxed);
        if previous & event_bit != 0 {
            return None;
        }
        Some(Record {
            event,
            process_id: self.process_id.load(Ordering::Relaxed),
            raw_icount,
            token_before: (previous & TOKEN_VALID != 0).then_some((previous >> 32) as u32),
            token_after,
        })
    }

    fn retain_observation(
        &self,
        callback: u64,
        event: Event,
        raw_icount: u64,
        tokens: (Option<u32>, Option<u32>),
        rejection_mask: u32,
    ) {
        if !self.enabled {
            return;
        }
        let observation = Observation {
            callback,
            event,
            raw_icount,
            token_before: tokens.0,
            token_after: tokens.1,
            rejection_mask,
        };
        self.last_callback.store(observation);
        if matches!(
            event,
            Event::Admitted
                | Event::Pending
                | Event::Acknowledged
                | Event::NoRequest
                | Event::Error
        ) {
            self.last_admitted.store(observation);
        }
    }

    /// Emits two fixed-size final observations after original callback draining.
    ///
    /// # Errors
    /// Returns an error if a bounded row cannot be encoded or the diagnostic sink fails.
    pub(in crate::runtime) fn write_final_to(
        &self,
        writer: &mut impl Write,
        identity: crucible_shmem::SetupRegionBackingIdentity,
        slot: u32,
        generation: u64,
        teardown: &str,
        final_token: u32,
    ) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let process_id = std::process::id();
        let inherited = self.process_id.load(Ordering::Relaxed) != process_id;
        for (kind, observation) in [
            ("last-callback", &self.last_callback),
            ("last-admitted", &self.last_admitted),
        ] {
            let mut bytes = [0_u8; 512];
            let mut cursor = io::Cursor::new(bytes.as_mut_slice());
            write!(
                cursor,
                "CRUCIBLE-CONTROL-LAST-V1 kind={kind} phase=after-drain teardown={teardown} pid={} device={} inode={} length={} slot={slot} generation={generation} final_token={final_token}",
                process_id,
                identity.device(),
                identity.inode(),
                identity.length()
            )?;
            // A child without callbacks must not claim copied parent observations.
            match (!inherited).then(|| observation.snapshot()).flatten() {
                Some(observation) => {
                    let (phase, reason, token_kind) = observation.event.labels();
                    write!(
                        cursor,
                        " callback={} raw_icount={} callback_phase={phase} reason={reason} rejection_mask={} token_kind={token_kind} token_before=",
                        observation.callback, observation.raw_icount, observation.rejection_mask
                    )?;
                    write_token(&mut cursor, observation.token_before)?;
                    write!(cursor, " token_after=")?;
                    write_token(&mut cursor, observation.token_after)?;
                }
                None => write!(cursor, " observation=unavailable")?,
            }
            writeln!(cursor)?;
            let length = cursor.position() as usize;
            writer.write_all(&bytes[..length])?;
        }
        Ok(())
    }
}

/// Fixed storage with nonblocking access and sticky loss on contention or poison.
#[derive(Default)]
struct LastObservation {
    observation: Mutex<Option<Observation>>,
    lost: AtomicBool,
}

#[derive(Clone, Copy)]
struct Observation {
    callback: u64,
    event: Event,
    raw_icount: u64,
    token_before: Option<u32>,
    token_after: Option<u32>,
    rejection_mask: u32,
}

impl LastObservation {
    fn clear(&self) {
        match self.observation.try_lock() {
            Ok(mut observation) => {
                *observation = None;
                self.lost.store(false, Ordering::Relaxed);
            }
            Err(_) => self.lost.store(true, Ordering::Relaxed),
        }
    }

    fn store(&self, value: Observation) {
        match self.observation.try_lock() {
            Ok(mut observation) => *observation = Some(value),
            Err(_) => self.lost.store(true, Ordering::Relaxed),
        }
    }

    fn snapshot(&self) -> Option<Observation> {
        // No wait is permitted, including for a copied lock held at fork.
        if self.lost.load(Ordering::Relaxed) {
            return None;
        }
        match self.observation.try_lock() {
            Ok(observation) if !self.lost.load(Ordering::Relaxed) => *observation,
            Ok(_) => None,
            Err(_) => {
                self.lost.store(true, Ordering::Relaxed);
                None
            }
        }
    }
}

/// Exact admission rejection supplied by the original guard observation.
pub(super) enum Rejection {
    Admission(LiveCallbackQuiescenceSnapshot),
    SharedShutdown,
}

impl Rejection {
    fn mask(&self) -> u32 {
        match self {
            Self::SharedShutdown => 4,
            Self::Admission(snapshot) => {
                u32::from(snapshot.hot_fork_held) | (u32::from(snapshot.teardown_closed) << 1)
            }
        }
    }

    fn event(self) -> Event {
        match self {
            Self::SharedShutdown => Event::SharedShutdown,
            Self::Admission(snapshot) if snapshot.teardown_closed && snapshot.hot_fork_held => {
                Event::TeardownAndHotFork
            }
            Self::Admission(snapshot) if snapshot.teardown_closed => Event::Teardown,
            Self::Admission(_) => Event::HotFork,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Entry,
    Admitted,
    HotFork,
    Teardown,
    TeardownAndHotFork,
    SharedShutdown,
    Pending,
    Acknowledged,
    NoRequest,
    Error,
}

impl Event {
    fn labels(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Entry => ("entry", "native-delivery", "cached"),
            Self::Admitted => ("admitted", "guard-open", "observed"),
            Self::HotFork => ("rejected", "hot-fork-held", "cached"),
            Self::Teardown => ("rejected", "teardown-closed", "cached"),
            Self::TeardownAndHotFork => ("rejected", "teardown-and-hot-fork", "cached"),
            Self::SharedShutdown => ("rejected", "shared-shutdown", "cached"),
            Self::Pending => ("exit", "pending", "observed"),
            Self::Acknowledged => ("exit", "acknowledged", "observed"),
            Self::NoRequest => ("exit", "no-request", "observed"),
            Self::Error => ("exit", "error", "observed"),
        }
    }
}

pub(super) struct Record {
    event: Event,
    process_id: u32,
    raw_icount: u64,
    token_before: Option<u32>,
    token_after: Option<u32>,
}

impl Record {
    fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        // One compact write avoids interleaved fragments when several QEMU
        // processes share stderr. Overflow is treated like any failed sink.
        let mut bytes = [0_u8; 256];
        let mut cursor = io::Cursor::new(bytes.as_mut_slice());
        self.write_fields_to(&mut cursor)?;
        let length = cursor.position() as usize;
        writer.write_all(&bytes[..length])
    }

    fn write_fields_to(&self, writer: &mut impl Write) -> io::Result<()> {
        let (phase, reason, token_kind) = self.event.labels();
        write!(
            writer,
            "CRUCIBLE-CONTROL-CALLBACK-V1 phase={phase} reason={reason} pid={} raw_icount={} token_kind={token_kind} token_before=",
            self.process_id, self.raw_icount
        )?;
        write_token(writer, self.token_before)?;
        write!(writer, " token_after=")?;
        write_token(writer, self.token_after)?;
        writeln!(writer)
    }
}

fn write_token(writer: &mut impl Write, token: Option<u32>) -> io::Result<()> {
    match token {
        Some(token) => write!(writer, "{token}"),
        None => write!(writer, "unavailable"),
    }
}

impl LiveVcpuTimeCallbackState {
    pub(super) fn control_callback_with_witness(&self, raw_icount: u64) {
        self.run_control_callback_with_stages(
            raw_icount,
            |record| {
                // crucible-lint: allow direct-diagnostic -- bounded opt-in records
                // diagnose callbacks rejected before shared memory can be read.
                let _write_result = record.write_to(&mut io::stderr().lock());
            },
            |record| {
                // crucible-lint: allow direct-diagnostic -- bounded opt-in stage
                // writes must not change the original callback outcome.
                let _write_result = record.write_to(&mut io::stderr().lock());
            },
            |error| super::abort_live_callback(error),
        );
    }

    #[cfg(test)]
    fn run_control_callback(
        &self,
        raw_icount: u64,
        emit: impl FnMut(Record),
        on_error: impl FnOnce(LiveVcpuTimeCallbackError),
    ) {
        self.run_control_callback_with_stages(raw_icount, emit, |_| {}, on_error);
    }

    pub(super) fn run_control_callback_with_stages(
        &self,
        raw_icount: u64,
        mut emit: impl FnMut(Record),
        mut emit_stage: impl FnMut(super::control_callback_stage::StageRecord),
        on_error: impl FnOnce(LiveVcpuTimeCallbackError),
    ) {
        let witness = &self.control_callback_witness;
        let entry = witness.entry_record(raw_icount);
        let callback = if witness.enabled {
            witness
                .callback_sequence
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
        } else {
            0
        };
        let cached_token = witness
            .enabled
            .then(|| {
                let cached = witness.token_and_events.load(Ordering::Relaxed);
                (cached & TOKEN_VALID != 0).then_some((cached >> 32) as u32)
            })
            .flatten();
        witness.retain_observation(callback, Event::Entry, raw_icount, (cached_token, None), 0);
        if let Some(record) = entry {
            emit(record);
        }
        let Some(_in_flight) = self.callback_guard_with_rejection(|rejection| {
            let mask = rejection.mask();
            let event = rejection.event();
            witness.retain_observation(callback, event, raw_icount, (cached_token, None), mask);
            if let Some(record) = witness.record(event, raw_icount, None) {
                emit(record);
            }
        }) else {
            return;
        };

        // Disabled diagnostics add no shared-memory reads, snapshots, or writes.
        let token_before = witness.enabled.then(|| {
            let token = PluginShmemOrdering::control_boundary_token(self.slot.get());
            witness.observe_token(token);
            witness.retain_observation(
                callback,
                Event::Admitted,
                raw_icount,
                (Some(token), Some(token)),
                0,
            );
            if let Some(record) = witness.record(Event::Admitted, raw_icount, Some(token)) {
                emit(record);
            }
            token
        });

        let result = self.on_control_boundary_with_stages(
            raw_icount,
            witness.enabled.then_some(callback),
            &mut emit_stage,
        );
        if let Some(token_before) = token_before {
            let token_after = PluginShmemOrdering::control_boundary_token(self.slot.get());
            let event = if result.is_err() {
                Event::Error
            } else if token_before & 1 != 0 {
                Event::NoRequest
            } else if token_after == token_before.wrapping_add(1) {
                Event::Acknowledged
            } else {
                Event::Pending
            };
            witness.retain_observation(
                callback,
                event,
                raw_icount,
                (Some(token_before), Some(token_after)),
                0,
            );
            if let Some(record) = witness.record(event, raw_icount, Some(token_after)) {
                emit(record);
            }
        }
        if let Err(error) = result {
            // Keep the admitted guard alive through the original fatal handler.
            on_error(error);
        }
    }
}

#[cfg(test)]
mod tests;
