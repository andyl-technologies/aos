//! Bounded live trace of guest TX that arrives while an idle advance is pending.
//!
//! A frame the device model hands over while the halted guest waits for an
//! armed idle advance is stamped with that advance's target. The same frame
//! handed over a moment earlier, before the advance is armed, takes the direct
//! path and is stamped with its own sample. Which path a frame takes depends on
//! when QEMU's main loop runs the device work, so two runs can stamp one frame
//! at different coordinates. Each row names the pending path, the advance's
//! start and target, and the raw sample, so a replay divergence shows whether a
//! frame took it. A completion row reports each buffered batch as it is
//! enqueued at the target.
//!
//! ```text
//! CRUCIBLE-NETWORK-TX-PATH-V1 pid=4242 path=pending start_ps=5611816250007 target_ps=5611855243868 raw=3884683996 buffered=1 count=1
//! CRUCIBLE-NETWORK-TX-PATH-V1 pid=4242 path=idle-completion start_ps=5611816250007 target_ps=5611855243868 raw=3884683996 buffered=5 count=2
//! ```
//!
//! A process prints at most [`MAXIMUM_ROWS`] rows. The rows are diagnostic
//! only and never feed a guest-visible value.

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Rows one process may print before the trace goes quiet.
const MAXIMUM_ROWS: u64 = 256;

static COUNT: AtomicU64 = AtomicU64::new(0);

/// Plugin path that handed a frame to the outbound ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TxPath {
    /// The frame arrived while an idle advance was pending and was buffered.
    Pending,
    /// The advance completed and enqueued its buffered frames at the target.
    IdleCompletion,
}

impl TxPath {
    const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::IdleCompletion => "idle-completion",
        }
    }
}

/// Coordinates one row reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TxPathSample {
    pub(super) path: TxPath,
    pub(super) start_icount: u64,
    pub(super) target_icount: u64,
    pub(super) raw_icount: u64,
    pub(super) buffered: usize,
}

/// Prints one row until the per-process allowance is spent.
pub(super) fn note(sample: TxPathSample) {
    let count = COUNT.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if count > MAXIMUM_ROWS {
        return;
    }
    let _ = writeln!(io_target(), "{}", row(std::process::id(), sample, count));
}

fn row(process_id: u32, sample: TxPathSample, count: u64) -> String {
    format!(
        "CRUCIBLE-NETWORK-TX-PATH-V1 pid={process_id} path={} start_ps={} target_ps={} raw={} buffered={} count={count}",
        sample.path.label(),
        sample.start_icount,
        sample.target_icount,
        sample.raw_icount,
        sample.buffered,
    )
}

#[cfg(not(test))]
fn io_target() -> std::io::StderrLock<'static> {
    std::io::stderr().lock()
}

#[cfg(test)]
fn io_target() -> std::io::Sink {
    std::io::sink()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pending_row_names_the_advance_start_and_target() {
        let sample = TxPathSample {
            path: TxPath::Pending,
            start_icount: 100,
            target_icount: 140,
            raw_icount: 25,
            buffered: 1,
        };

        assert_eq!(
            row(42, sample, 3),
            "CRUCIBLE-NETWORK-TX-PATH-V1 pid=42 path=pending start_ps=100 target_ps=140 raw=25 buffered=1 count=3"
        );
    }
}
