//! Capped pending-return notices before an indeterminate process is quarantined.
//!
//! Valid aggregate diagnostics plus the existing minimum-token setting permit
//! at most 16 rows per binding. Only admitted even requests that return pending
//! spend this independent cap; successful callbacks spend nothing. A matching
//! retained settlement gives positive evidence of that branch, never native wake
//! delivery. Missing, filtered, capped, or dropped rows are inconclusive.
//!
//! Each admitted notice briefly pins the sink without a global stdio lock. Regular
//! files share the original cursor and retain filesystem latency semantics.
//! Nonregular destinations, failed duplication, contention and write errors
//! drop advisory data. This discriminator targets fresh ThinReplay file captures.
//! No retry, worker, queue, clock read or canonical bridge borrow is introduced.
//! A PID change drops notices rather than writing into an inherited parent sink.
//! The opt-in can perturb host performance; it never extends a canonical guard.
//!
//! ```text
//! CRUCIBLE-CONTROL-PENDING-V1 phase=return pid=42 callback=7 raw=8 token=54008 device=1 inode=2 length=4096 slot=0 generation=2 frontier=6 capture=0 reason=pump-active
//! ```

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::sync::Mutex;

use super::super::control_callback_stage::ControlStageIdentity;
use super::settlement::SettlementContext;

const MAX_ROWS: u8 = 16;
const REASONS: [&str; 8] = [
    "entered",
    "pump-active",
    "frontier-pending",
    "publication-backpressure",
    "frontier-unsettled",
    "settled",
    "error",
    "unavailable",
];

pub(super) struct PendingNotices {
    minimum: Option<u32>,
    inventory: Mutex<Inventory>,
    pub(super) owner_pid: u32,
    #[cfg(test)]
    pub(super) destination: Option<Mutex<File>>,
}

impl PendingNotices {
    pub(super) fn disabled() -> Self {
        Self::new(None)
    }

    pub(super) fn new(minimum: Option<u32>) -> Self {
        Self {
            minimum,
            inventory: Mutex::new(Inventory::default()),
            owner_pid: if minimum.is_some() {
                std::process::id()
            } else {
                0
            },
            #[cfg(test)]
            destination: None,
        }
    }

    pub(super) fn from_settings(aggregate: Option<&OsStr>, minimum: Option<&OsStr>) -> Self {
        let admitted = aggregate
            .and_then(OsStr::to_str)
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|budget| (1..=256).contains(&budget));
        let minimum = admitted
            .then(|| {
                minimum.and_then(OsStr::to_str).and_then(|text| {
                    text.parse::<u32>()
                        .ok()
                        .filter(|parsed| parsed.to_string() == text)
                })
            })
            .flatten();
        Self::new(minimum)
    }

    fn reset(&self) {
        if let Ok(mut inventory) = self.inventory.try_lock() {
            *inventory = Inventory::default();
        }
    }

    fn record(&self, record: PendingRecord) -> Option<PendingRecord> {
        if record.token & 1 != 0 || !self.minimum.is_some_and(|minimum| record.token >= minimum) {
            return None;
        }
        // This fixed inventory remembers every admitted pair, including token
        // reordering. Contention/poison loses only advisory observations.
        let mut inventory = self.inventory.try_lock().ok()?;
        let pair = (record.token, record.reason);
        if inventory.pairs[..inventory.count].contains(&Some(pair))
            || inventory.count == usize::from(MAX_ROWS)
        {
            return None;
        }
        let index = inventory.count;
        inventory.pairs[index] = Some(pair);
        inventory.count += 1;
        Some(record)
    }

    fn owns_sink(&self) -> bool {
        self.minimum.is_some() && self.owner_pid == std::process::id()
    }

    fn emit(&self, record: PendingRecord) {
        if !self.owns_sink() {
            return;
        }
        let Some(record) = self.record(record) else {
            return;
        };
        #[cfg(test)]
        if let Some(source) = &self.destination {
            let Ok(source) = source.try_lock() else {
                return;
            };
            self.write_to_source(record, &*source);
            return;
        }
        self.write_to_source(record, &io::stderr());
    }

    fn write_to_source(&self, record: PendingRecord, source: &impl AsFd) {
        let Ok(destination) = destination(source) else {
            return;
        };
        let mut bytes = [0_u8; 512];
        let mut cursor = io::Cursor::new(bytes.as_mut_slice());
        if record.write_to(&mut cursor).is_ok() {
            let length = cursor.position() as usize;
            // One write invocation; regular capture retains filesystem latency.
            // Short/error writes lose only advisory bytes. No retries or queue.
            let _ = (&destination).write(&bytes[..length]);
        }
    }
}

/// Pins only an existing regular capture, preserving its original cursor.
pub(super) fn destination(source: &impl AsFd) -> io::Result<File> {
    let pinned = File::from(source.as_fd().try_clone_to_owned()?);
    if pinned.metadata()?.is_file() {
        Ok(pinned)
    } else {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[derive(Default)]
struct Inventory {
    pairs: [Option<(u32, usize)>; MAX_ROWS as usize],
    count: usize,
}

#[derive(Clone, Copy)]
struct PendingRecord {
    pid: u32,
    callback: u64,
    raw: u64,
    token: u32,
    identity: Option<ControlStageIdentity>,
    settlement: Option<SettlementContext>,
    reason: usize,
}

impl PendingRecord {
    fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        write!(
            writer,
            "CRUCIBLE-CONTROL-PENDING-V1 phase=return pid={} callback={} raw={} token={}",
            self.pid, self.callback, self.raw, self.token
        )?;
        if let Some(identity) = self.identity {
            let (backing, slot, generation) = identity.parts();
            write!(
                writer,
                " device={} inode={} length={} slot={slot} generation={generation}",
                backing.device(),
                backing.inode(),
                backing.length()
            )?;
        } else {
            write!(
                writer,
                " device=unavailable inode=unavailable length=unavailable slot=unavailable generation=unavailable"
            )?;
        }
        if let Some(context) = self.settlement {
            write!(
                writer,
                " frontier={} capture={}",
                context.frontier,
                context.capture.unwrap_or(0)
            )?;
        } else {
            write!(writer, " frontier=unavailable capture=unavailable")?;
        }
        writeln!(writer, " reason={}", REASONS[self.reason])
    }
}

impl super::ControlCallbackWitness {
    pub(in crate::runtime::live_callbacks) fn reset_pending(&self) {
        self.pending.reset();
    }

    pub(super) fn report_pending(
        &self,
        callback: u64,
        raw: u64,
        token: u32,
        identity: Option<ControlStageIdentity>,
    ) {
        if !self.pending.owns_sink() {
            return;
        }
        // A later/nested callback must never lend its settlement to this return.
        let observed = self.settlement.snapshot().filter(|(context, _)| {
            context.callback == callback && context.raw == raw && context.token == token
        });
        let settlement = observed.map(|(context, _)| context);
        let label = observed.map_or("unavailable", |(_, reason)| reason.label());
        let reason = REASONS
            .iter()
            .position(|candidate| *candidate == label)
            .unwrap_or(7);
        self.pending.emit(PendingRecord {
            pid: std::process::id(),
            callback,
            raw,
            token,
            identity,
            settlement,
            reason,
        });
    }
}

#[cfg(test)]
mod tests;
