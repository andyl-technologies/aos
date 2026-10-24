//! Fixed scalar intervals for existing supervised capture and transfer work.
//!
//! These measurements create no operation or resource authority. Missing clock
//! observations remain explicitly absent, and outputs borrow stack-only fields.

use std::io::Write;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(super) struct Interval {
    pub(super) elapsed_ns: Option<u64>,
    pub(super) incomplete_reason: Option<&'static str>,
}

impl Interval {
    pub(super) fn finish(start: Option<u64>) -> Self {
        Self::between(start, now())
    }

    fn between(start: Option<u64>, end: Option<u64>) -> Self {
        match start
            .zip(end)
            .and_then(|(start, end)| end.checked_sub(start))
        {
            Some(elapsed_ns) => Self {
                elapsed_ns: Some(elapsed_ns),
                incomplete_reason: None,
            },
            None => Self {
                elapsed_ns: None,
                incomplete_reason: Some("monotonic_interval_unavailable"),
            },
        }
    }
}

pub(super) fn now() -> Option<u64> {
    let clock = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(clock.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(clock.tv_nsec).ok()?)
}

/// Streams fixed scalar receipts without allocating a second encoded body.
pub(super) fn publish(label: &str, value: &impl serde::Serialize) {
    let mut output = std::io::stdout().lock();
    write!(output, "{label}=").expect("test measurement output");
    serde_json::to_writer(&mut output, value).expect("bounded scalar measurement output");
    writeln!(output).expect("test measurement newline");
}

#[test]
fn interval_distinguishes_unavailable_and_zero_without_wrap() {
    assert_eq!(Interval::between(Some(7), Some(7)).elapsed_ns, Some(0));
    for interval in [
        Interval::between(None, Some(8)),
        Interval::between(Some(9), Some(8)),
    ] {
        assert!(interval.elapsed_ns.is_none());
        assert!(interval.incomplete_reason.is_some());
    }
}
