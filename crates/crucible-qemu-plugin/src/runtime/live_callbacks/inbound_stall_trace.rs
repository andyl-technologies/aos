//! Bounded live trace of zero-length advances that leave a due frame queued.
//!
//! A node that stops at a frame's delivery boundary must take that frame
//! before it can move again. When the host can only re-advance it to its
//! current coordinate and the frame is still at the ring head, every later
//! quantum pauses at the same point and the host reports a stall with no
//! consumed input. This trace names the plugin path that met each such
//! zero-length advance, together with the ring head and the plugin's idle and
//! delivery flags, so a stalled flight shows why the due frame stayed queued.
//!
//! A due head at one zero-length advance is ordinary: answering the advance
//! injects it. Only the same head at the same coordinate under a *later*
//! advance means the answer left it queued. The trace holds the first sample
//! for each coordinate and head, and prints it together with every repeat
//! from a later advance until a fixed per-process allowance is spent. It rides
//! the existing `CRUCIBLE_OUT_RESUME_RUNTIME_TRACE=1` opt-in:
//!
//! ```text
//! CRUCIBLE-INBOUND-STALL-V1 pid=4242 path=answer-published boundary=zero-length-advance raw=3884683996 sequence=901 current_ps=590811070150 ceiling_ps=590811070150 stop=ExactEvent head_delivery_ps=590811070121 head_src=4 head_seq=3 head_state=Pending head_attempts=0 head_last_attempt_ps=0 idle_pending=false idle_edge=true rx_active=false answered=true count=1
//! ```
//!
//! The rows are diagnostic only and never feed a guest-visible value.

use std::io::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_shmem::FrameEntry;

/// Rows one process may print before the trace goes quiet.
const MAXIMUM_ROWS: u64 = 64;

static COUNT: AtomicU64 = AtomicU64::new(0);

static REPEATS: Mutex<RepeatFilter> = Mutex::new(RepeatFilter::new());

/// Coordinate and ring head that one stall would keep meeting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StallKey {
    current: u64,
    head_delivery: u64,
    head_src: u32,
    head_seq: u32,
}

/// What [`RepeatFilter::observe`] decided for one sample.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// First sample for this key: keep its row until it repeats.
    Hold,
    /// A later advance met the same key: print the held row first, if any.
    Print { held: Option<String> },
    /// Another sample from the advance that was already held.
    Ignore,
}

/// Remembers the first sample per key until a later advance repeats it.
struct RepeatFilter {
    first: Option<(StallKey, u64, String)>,
}

impl RepeatFilter {
    const fn new() -> Self {
        Self { first: None }
    }

    fn observe(&mut self, key: StallKey, sequence: u64, row: String) -> Decision {
        match &mut self.first {
            Some((held_key, held_sequence, held_row)) if *held_key == key => {
                if *held_sequence == sequence {
                    return Decision::Ignore;
                }
                // Printing a held row once is enough; later repeats print alone.
                let held = (!held_row.is_empty()).then(|| std::mem::take(held_row));
                Decision::Print { held }
            }
            _ => {
                self.first = Some((key, sequence, row));
                Decision::Hold
            }
        }
    }
}

/// Plugin state sampled at one zero-length advance.
pub(super) struct InboundStallSample<'a> {
    pub(super) path: &'a str,
    pub(super) boundary: &'static str,
    pub(super) raw: u64,
    pub(super) sequence: u64,
    pub(super) current: u64,
    pub(super) ceiling: u64,
    pub(super) stop: &'a dyn std::fmt::Debug,
    pub(super) head: &'a FrameEntry,
    pub(super) idle_pending: bool,
    pub(super) idle_edge: bool,
    pub(super) rx_active: bool,
    pub(super) answered: bool,
}

/// Reports whether a ring head is due at a zero-length advance.
///
/// Only an advance that ends at the node's coordinate can stall on a queued
/// frame; any later ceiling still lets the node move and take it.
pub(super) const fn is_due_at_zero_length(current: u64, ceiling: u64, head_delivery: u64) -> bool {
    ceiling == current && head_delivery <= current
}

/// Holds a first sample and prints repeats from later advances.
///
/// Returns `true` when this sample confirmed a new stall, so the caller can
/// flush context that belongs next to its first rows. A contended filter
/// drops the sample rather than block a vCPU callback.
pub(super) fn note(sample: &InboundStallSample<'_>) -> bool {
    if COUNT.load(Ordering::Relaxed) >= MAXIMUM_ROWS {
        return false;
    }
    let key = StallKey {
        current: sample.current,
        head_delivery: sample.head.delivery_icount,
        head_src: sample.head.src_node,
        head_seq: sample.head.seq,
    };
    let row = render(std::process::id(), sample);
    let decision = match REPEATS.try_lock() {
        Ok(mut filter) => filter.observe(key, sample.sequence, row.clone()),
        Err(_) => return false,
    };
    let Decision::Print { held } = decision else {
        return false;
    };
    let confirmed = held.is_some();

    let mut stderr = std::io::stderr().lock();
    for row in held.iter().chain(std::iter::once(&row)) {
        let count = COUNT.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if count > MAXIMUM_ROWS {
            break;
        }
        let _ = writeln!(stderr, "{row} count={count}");
    }
    confirmed
}

fn render(pid: u32, sample: &InboundStallSample<'_>) -> String {
    let head = sample.head;
    let state = head.delivery_state().map_or_else(
        |error| format!("invalid({error})"),
        |state| format!("{state:?}"),
    );
    format!(
        "CRUCIBLE-INBOUND-STALL-V1 pid={pid} path={} boundary={} raw={} sequence={} current_ps={} ceiling_ps={} stop={:?} head_delivery_ps={} head_src={} head_seq={} head_state={state} head_attempts={} head_last_attempt_ps={} idle_pending={} idle_edge={} rx_active={} answered={}",
        sample.path,
        sample.boundary,
        sample.raw,
        sample.sequence,
        sample.current,
        sample.ceiling,
        sample.stop,
        head.delivery_icount,
        head.src_node,
        head.seq,
        head.delivery_attempts(),
        head.last_delivery_attempt_icount(),
        sample.idle_pending,
        sample.idle_edge,
        sample.rx_active,
        sample.answered,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_zero_length_advance_with_a_due_head_is_traced() {
        assert!(is_due_at_zero_length(150, 150, 121));
        assert!(is_due_at_zero_length(150, 150, 150));
        assert!(!is_due_at_zero_length(150, 150, 151));
        assert!(!is_due_at_zero_length(150, 200, 121));
    }

    #[test]
    fn a_due_head_prints_only_when_a_later_advance_meets_it_again() {
        let key = StallKey {
            current: 150,
            head_delivery: 121,
            head_src: 4,
            head_seq: 3,
        };
        let mut filter = RepeatFilter::new();

        assert_eq!(
            filter.observe(key, 9, String::from("first")),
            Decision::Hold
        );
        assert_eq!(
            filter.observe(key, 9, String::from("same")),
            Decision::Ignore
        );
        assert_eq!(
            filter.observe(key, 10, String::from("repeat")),
            Decision::Print {
                held: Some(String::from("first"))
            }
        );
        assert_eq!(
            filter.observe(key, 11, String::from("again")),
            Decision::Print { held: None }
        );

        let next = StallKey {
            current: 200,
            ..key
        };
        assert_eq!(
            filter.observe(next, 12, String::from("next")),
            Decision::Hold
        );
    }

    #[test]
    fn a_row_names_the_path_head_and_flags() {
        let head = FrameEntry::new(121, 4, 3, &[0_u8; 42])
            .unwrap_or_else(|error| panic!("fixture frame should be valid: {error}"));
        let stop = "ExactEvent";
        let sample = InboundStallSample {
            path: "idle-already-due",
            boundary: "vcpu-idle",
            raw: 7,
            sequence: 9,
            current: 150,
            ceiling: 150,
            stop: &stop,
            head: &head,
            idle_pending: false,
            idle_edge: true,
            rx_active: false,
            answered: true,
        };

        let row = render(42, &sample);

        assert!(row.starts_with("CRUCIBLE-INBOUND-STALL-V1 pid=42 path=idle-already-due"));
        assert!(row.contains(" head_delivery_ps=121 head_src=4 head_seq=3 head_state=Pending"));
        assert!(row.contains(" idle_pending=false idle_edge=true rx_active=false answered=true"));
    }
}
