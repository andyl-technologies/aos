//! Diagnostic comparison of the plugin's due test with QEMU's timer clock.
//!
//! When every vCPU is halted and the next virtual timer is due at or before
//! the plugin's logical coordinate, the idle callback returns so QEMU's round
//! robin can run that timer. QEMU decides expiry against `QEMU_CLOCK_VIRTUAL`,
//! not against the plugin's coordinate. If the two disagree, QEMU never runs
//! the timer, the vCPU halts again at the same point, and the host sees the
//! same pause twice. This trace reads QEMU's clock terms through a read-only
//! export and prints them when QEMU disagrees, when the same already-due
//! point repeats, or when an inbound frame or device completion is due at the
//! current coordinate:
//!
//! ```text
//! CRUCIBLE-CLOCK-DOMAIN-V1 pid=4242 reason=qemu-not-due cause=timer count=1 run=1 plugin_ps=587001000000 deadline_ps=587001000000 raw=1213 virtual_ps=587000999950 qemu_deadline_ps=587001000000 qemu_raw=1213 sim_tick_bias=586940350000 icount_bias_ps=0 warp_start=-1
//! ```
//!
//! Each reason prints on its 1st, 2nd, 4th, 8th, ... occurrence over the whole
//! run. A long flight passes those counts early, so each reason also counts
//! its consecutive occurrences at one coordinate and prints the 2nd, 4th,
//! 8th, ... of that run: a node that keeps returning to the same point, the
//! shape of a stall, prints there however late it happens, while isolated
//! occurrences at new coordinates stay quiet. When the export is missing or
//! refuses a read, the row still prints the plugin's side and replaces QEMU's
//! terms with `qemu=unavailable`. The rows are diagnostic only and never feed
//! a guest-visible value or a scheduling choice.

use std::ffi::c_void;
use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::IdleWakeCause;

/// NUL-terminated name of QEMU's read-only clock diagnostic export.
const QEMU_PLUGIN_CRUCIBLE_CLOCK_DIAGNOSTIC_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_clock_diagnostic\0";

/// Mirror of `struct qemu_plugin_crucible_clock_diagnostic`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct QemuClockDiagnostic {
    virtual_ps: i64,
    deadline_ps: i64,
    raw_icount: i64,
    sim_tick_bias: i64,
    icount_bias_ps: i64,
    warp_start: i64,
}

type QemuClockDiagnosticFn = extern "C" fn(*mut QemuClockDiagnostic) -> i32;

/// Why an already-due idle pass was traced.
#[derive(Clone, Copy, Debug)]
enum Reason {
    /// QEMU's virtual clock has not reached the deadline the plugin found due.
    QemuNotDue,
    /// The same already-due coordinate and deadline returned again.
    Repeated,
    /// An inbound frame or device completion woke the node at its current
    /// coordinate, so the idle pass asks QEMU for a zero-length advance.
    DueNowOther,
}

impl Reason {
    const fn index(self) -> usize {
        match self {
            Self::QemuNotDue => 0,
            Self::Repeated => 1,
            Self::DueNowOther => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::QemuNotDue => "qemu-not-due",
            Self::Repeated => "repeated",
            Self::DueNowOther => "due-now",
        }
    }
}

static COUNTS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Coordinate of each reason's latest occurrence and the length of its run
/// of consecutive occurrences there.
static LAST_COORDINATES: [AtomicU64; 3] = [const { AtomicU64::new(u64::MAX) }; 3];
static RUNS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Last already-due `(coordinate, deadline)` pair. Only the all-halted idle
/// callback writes it, so the two words never interleave with another writer.
static LAST_ALREADY_DUE: [AtomicU64; 2] = [AtomicU64::new(u64::MAX), AtomicU64::new(u64::MAX)];

/// Records one already-due idle pass and prints QEMU's clock terms when due.
pub(super) fn note_already_due(plugin_ps: u64, deadline_ps: Option<u64>, raw: u64) {
    let read = read_qemu_clock();
    let deadline = deadline_ps.unwrap_or(u64::MAX);
    let previous_ps = LAST_ALREADY_DUE[0].swap(plugin_ps, Ordering::Relaxed);
    let previous_deadline = LAST_ALREADY_DUE[1].swap(deadline, Ordering::Relaxed);
    let repeated = previous_ps == plugin_ps && previous_deadline == deadline;
    let qemu_not_due = read.is_some_and(|read| {
        deadline_ps.is_some_and(|deadline| {
            u64::try_from(read.virtual_ps).map_or(true, |virtual_ps| virtual_ps < deadline)
        })
    });

    for (reason, hit) in [
        (Reason::QemuNotDue, qemu_not_due),
        (Reason::Repeated, repeated),
    ] {
        if hit {
            print_row(reason, "timer", plugin_ps, deadline_ps, raw, read);
        }
    }
}

/// Records an idle pass whose non-timer wake is the current coordinate.
pub(super) fn note_due_now(
    cause: IdleWakeCause,
    plugin_ps: u64,
    deadline_ps: Option<u64>,
    raw: u64,
) {
    let cause = match cause {
        IdleWakeCause::InboundFrame => "inbound",
        IdleWakeCause::DeviceIoCompletion => "device",
        IdleWakeCause::TimerDeadline
        | IdleWakeCause::DeviceIoFreeze
        | IdleWakeCause::SchedulerCeiling => return,
    };
    print_row(
        Reason::DueNowOther,
        cause,
        plugin_ps,
        deadline_ps,
        raw,
        read_qemu_clock(),
    );
}

fn print_row(
    reason: Reason,
    cause: &str,
    plugin_ps: u64,
    deadline_ps: Option<u64>,
    raw: u64,
    read: Option<QemuClockDiagnostic>,
) {
    let index = reason.index();
    let count = COUNTS[index]
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let run = if LAST_COORDINATES[index].swap(plugin_ps, Ordering::Relaxed) == plugin_ps {
        RUNS[index]
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    } else {
        RUNS[index].store(1, Ordering::Relaxed);
        1
    };
    if !should_print(count, run) {
        return;
    }
    let deadline = deadline_ps.map_or_else(|| String::from("none"), |value| value.to_string());
    // A refused or missing export still prints the plugin's side, so a stall
    // names its cause even when QEMU's clock terms are unreadable.
    let qemu = read.map_or_else(
        || String::from("qemu=unavailable"),
        |read| {
            format!(
                "virtual_ps={} qemu_deadline_ps={} qemu_raw={} sim_tick_bias={} icount_bias_ps={} warp_start={}",
                read.virtual_ps,
                read.deadline_ps,
                read.raw_icount,
                read.sim_tick_bias,
                read.icount_bias_ps,
                read.warp_start,
            )
        },
    );
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-CLOCK-DOMAIN-V1 pid={} reason={} cause={cause} count={count} run={run} plugin_ps={plugin_ps} deadline_ps={deadline} raw={raw} {qemu}",
        std::process::id(),
        reason.name(),
    );
}

/// Selects power-of-two totals and power-of-two repeat runs at one coordinate.
const fn should_print(count: u64, run: u64) -> bool {
    count.is_power_of_two() || (run >= 2 && run.is_power_of_two())
}

fn read_qemu_clock() -> Option<QemuClockDiagnostic> {
    static EXPORT: OnceLock<Option<QemuClockDiagnosticFn>> = OnceLock::new();
    let export = (*EXPORT.get_or_init(resolve_clock_diagnostic))?;
    let mut read = QemuClockDiagnostic::default();
    (export(&raw mut read) == 0).then_some(read)
}

#[cfg(unix)]
fn resolve_clock_diagnostic() -> Option<QemuClockDiagnosticFn> {
    // SAFETY: The symbol name is a static NUL-terminated byte string. `dlsym`
    // returns either null or a process symbol address; a missing export only
    // disables this diagnostic.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_CRUCIBLE_CLOCK_DIAGNOSTIC_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: Non-null `symbol` was resolved for the patched QEMU export
    // `int qemu_plugin_crucible_clock_diagnostic(struct
    // qemu_plugin_crucible_clock_diagnostic *)`, whose struct layout
    // `QemuClockDiagnostic` mirrors field for field with `repr(C)`.
    Some(unsafe { std::mem::transmute::<*mut c_void, QemuClockDiagnosticFn>(symbol) })
}

#[cfg(not(unix))]
fn resolve_clock_diagnostic() -> Option<QemuClockDiagnosticFn> {
    None
}

#[cfg(test)]
mod tests {
    use super::should_print;

    #[test]
    fn a_late_repeat_at_one_coordinate_still_prints() {
        // Isolated occurrences past the early totals stay quiet.
        assert!(should_print(1, 1));
        assert!(should_print(64, 1));
        assert!(!should_print(65, 1));

        // The same coordinate returning prints on its 2nd, 4th, 8th visit.
        assert!(should_print(65, 2));
        assert!(!should_print(66, 3));
        assert!(should_print(67, 4));
        assert!(should_print(71, 8));
    }
}
