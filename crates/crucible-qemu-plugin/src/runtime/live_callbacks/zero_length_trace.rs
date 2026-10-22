//! Bounded live trace of budget queries that meet a zero-length advance.
//!
//! A vCPU that the host has advanced only to its current coordinate retires
//! nothing until the plugin answers that advance with a publication. If the
//! answer never comes, the vCPU keeps querying its zero budget while the host
//! waits, and neither side logs anything. This trace names the path each such
//! query took, so a stalled flight shows why the advance went unanswered.
//!
//! It is off unless the existing `CRUCIBLE_OUT_RESUME_RUNTIME_TRACE=1` opt-in
//! reaches QEMU. Each reason prints on its 1st, 2nd, 4th, 8th, ... occurrence,
//! so a spinning query costs a few dozen rows over billions of calls:
//!
//! ```text
//! CRUCIBLE-ZERO-LENGTH-QUERY-V1 pid=4242 reason=already-answered count=1024 sequence=30506 ceiling_ps=1853238670866 current_ps=1853238670866 raw=4416473812
//! ```
//!
//! The rows are diagnostic only and never feed a guest-visible value.

use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Why a budget query at a zero-length advance returned.
#[derive(Clone, Copy, Debug)]
pub(super) enum ZeroLengthQuery {
    /// A pause publication owned the boundary.
    Paused,
    /// A queued idle advance froze the budget at its request coordinate.
    IdlePending,
    /// An outer preemption enqueue owned the query.
    EnqueueActive,
    /// This advance had already been answered.
    AlreadyAnswered,
    /// The answer reached the boundary writer, which committed nothing.
    Declined,
    /// The answer published the boundary.
    Published,
}

impl ZeroLengthQuery {
    const COUNT: usize = 6;

    const fn index(self) -> usize {
        match self {
            Self::Paused => 0,
            Self::IdlePending => 1,
            Self::EnqueueActive => 2,
            Self::AlreadyAnswered => 3,
            Self::Declined => 4,
            Self::Published => 5,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Paused => "paused",
            Self::IdlePending => "idle-pending",
            Self::EnqueueActive => "enqueue-active",
            Self::AlreadyAnswered => "already-answered",
            Self::Declined => "declined",
            Self::Published => "published",
        }
    }
}

static COUNTS: [AtomicU64; ZeroLengthQuery::COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Reports whether the trace opt-in reached this QEMU process.
pub(super) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CRUCIBLE_OUT_RESUME_RUNTIME_TRACE").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    })
}

/// Records one query at a zero-length advance and prints it when due.
///
/// Callers pass the advance they observed; a query whose advance is not
/// zero-length (`ceiling != current`) records nothing.
pub(super) fn note(reason: ZeroLengthQuery, sequence: u64, ceiling: u64, current: u64, raw: u64) {
    if ceiling != current || !enabled() {
        return;
    }
    let count = COUNTS[reason.index()]
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if !count.is_power_of_two() {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-ZERO-LENGTH-QUERY-V1 pid={} reason={} count={count} sequence={sequence} ceiling_ps={ceiling} current_ps={current} raw={raw}",
        std::process::id(),
        reason.name(),
    );
}

/// A boundary or idle callback that met a zero-length advance and left the
/// slot's publication generation unchanged.
#[derive(Clone, Copy, Debug)]
pub(super) enum ZeroLengthBoundary {
    /// The boundary writer returned without publishing, for this reason.
    Unpublished(&'static str),
    /// The all-halted idle callback returned on this path.
    Idle(&'static str),
}

/// Unpublished-boundary reasons and idle paths, in counter order.
const BOUNDARY_PATHS: [&str; 12] = [
    "paused",
    "output-stop",
    "superseded",
    "idle-pending",
    "edge-held",
    "advance-pending",
    "idle-output-stop",
    "return-to-qemu",
    "rescan-in-qemu",
    "already-due",
    "advance-armed",
    "advance-deferred",
];

static BOUNDARY_COUNTS: [AtomicU64; BOUNDARY_PATHS.len()] =
    [const { AtomicU64::new(0) }; BOUNDARY_PATHS.len()];

/// Records one boundary or idle path at a zero-length advance and prints it
/// when due, naming the boundary that met it.
pub(super) fn note_boundary(
    path: ZeroLengthBoundary,
    boundary: &'static str,
    ceiling: u64,
    current: u64,
    raw: u64,
) {
    if ceiling != current || !enabled() {
        return;
    }
    let (family, name) = match path {
        ZeroLengthBoundary::Unpublished(name) => ("unpublished", name),
        ZeroLengthBoundary::Idle(name) => ("idle", name),
    };
    let Some(index) = BOUNDARY_PATHS.iter().position(|known| *known == name) else {
        return;
    };
    let count = BOUNDARY_COUNTS[index]
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if !count.is_power_of_two() {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-ZERO-LENGTH-QUERY-V1 pid={} reason={family}-{name} boundary={boundary} count={count} ceiling_ps={ceiling} current_ps={current} raw={raw}",
        std::process::id(),
    );
}
