//! Failure-only localization for the original clock-read flight.
//!
//! Console bytes are an incomplete, untimed host observation. A dead producer
//! can leave mapped publication in progress, so this helper never reads current
//! slot state. Its cached boundary predates the failure, not the timed-out step.

use std::io::{self, Write};

use crucible_qemu::QemuNode;

const CONSOLE_BYTES: usize = 4096;
const CONTEXT_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    Launch,
    Boot,
    Clock0,
    Idle,
    Timer,
    Clock1,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    Operation,
    Validation,
    Cleanup,
}

/// Retains only the closed run/stage labels of the original active operation.
pub(super) struct Context {
    hostile: bool,
    stage: Stage,
    phase: Phase,
}

impl Context {
    pub(super) const fn new(hostile: bool) -> Self {
        Self {
            hostile,
            stage: Stage::Launch,
            phase: Phase::Operation,
        }
    }

    pub(super) fn set(&mut self, stage: Stage, phase: Phase) {
        self.stage = stage;
        self.phase = phase;
    }

    pub(super) fn report(&self, node: Option<&mut QemuNode>) {
        let mut output = io::stderr();
        self.report_to(&mut output, node);
    }

    fn report_to(&self, output: &mut dyn Write, node: Option<&mut QemuNode>) {
        let label = self.label();
        let Some(node) = node else {
            let _ = writeln!(output, "{label} node=unavailable");
            return;
        };
        let pid = node.process_id();

        // Copy staged inner-QEMU bytes first. This neither drains observations
        // nor reads a socket, and contention returns unavailable immediately.
        let console = console_row(&label, pid, node.console_diagnostic_tail().as_deref());
        let _ = output.write_all(console.as_bytes());

        let accepted = node.completed_quantum_boundary().map(|boundary| {
            let calibration = boundary.calibration();
            let idle = boundary.idle_state();
            (
                calibration.logical_icount,
                calibration.raw_icount,
                idle.next_deadline.map(|deadline| deadline.retired),
            )
        });
        let row = context_row(&label, pid, accepted);
        // Fixed enum/numeric fields fit this bound. A future formatter change
        // cannot turn diagnostic retention into an unbounded output path.
        let _ = output.write_all(&row.as_bytes()[..row.len().min(CONTEXT_BYTES)]);
        let _ = output.write_all(b"\n");
    }

    fn label(&self) -> String {
        let run = if self.hostile { "hostile" } else { "reference" };
        format!(
            "CRUCIBLE-GUEST-CLOCK-FAILURE-V1 run={run} stage={:?} phase={:?}",
            self.stage, self.phase,
        )
    }
}

/// Observes a completed result without wrapping, replacing or retrying its error.
///
/// # Errors
///
/// Returns the unchanged original error after one advisory report attempt.
pub(super) fn retain_error<T, E>(result: Result<T, E>, report: impl FnOnce()) -> Result<T, E> {
    result.inspect_err(|_error| report())
}

fn context_row(label: &str, pid: u32, accepted: Option<(u64, u64, Option<u64>)>) -> String {
    format!(
        "{label} pid={pid} cached_accepted_ps_raw_deadline={accepted:?} \
         post_error_mapped=unavailable reason=producer_publication_may_be_incomplete"
    )
}

fn console_row(label: &str, pid: u32, bytes: Option<&[u8]>) -> String {
    let mut row = format!("{label} pid={pid} console_untimed=");
    if let Some(bytes) = bytes {
        let start = bytes.len().saturating_sub(CONSOLE_BYTES);
        for byte in &bytes[start..] {
            for escaped in std::ascii::escape_default(*byte) {
                row.push(char::from(escaped));
            }
        }
    } else {
        row.push_str("unavailable");
    }
    row.push('\n');
    row
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io;

    use super::*;

    #[test]
    fn original_error_identity_survives_one_operation_and_one_failed_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let calls = Cell::new(0);
        let reports = Cell::new(0);
        let error = Box::new(io::Error::other("original refusal"));
        let identity = std::ptr::from_ref(error.as_ref());
        let operation = || -> Result<(), Box<io::Error>> {
            calls.set(calls.get() + 1);
            Err(error)
        };
        let result = retain_error(operation(), || {
            reports.set(reports.get() + 1);
            let context = Context::new(false);
            context.report_to(&mut FailedSink, None);
        });
        let retained = match result {
            Err(retained) => retained,
            Ok(()) => return Err("diagnostic replaced original refusal".into()),
        };

        assert_eq!(std::ptr::from_ref(retained.as_ref()), identity);
        assert_eq!(calls.get(), 1);
        assert_eq!(reports.get(), 1);
        assert_eq!(retained.to_string(), "original refusal");

        let success = retain_error(Ok::<_, io::Error>(17), || {
            reports.set(reports.get() + 1);
        });
        assert_eq!(success?, 17);
        assert_eq!(reports.get(), 1);
        Ok(())
    }

    #[test]
    fn binary_console_is_capped_escaped_and_keeps_the_original_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut context = Context::new(true);
        context.set(Stage::Timer, Phase::Operation);
        let label = context.label();
        let bytes = [vec![b'x'; 100], vec![0xff; CONSOLE_BYTES]].concat();
        let row = console_row(&label, u32::MAX, Some(&bytes));

        assert_eq!(row.matches("\\xff").count(), CONSOLE_BYTES);
        assert!(!row.contains("xxxx"));
        assert!(row.starts_with(
            "CRUCIBLE-GUEST-CLOCK-FAILURE-V1 run=hostile stage=Timer phase=Operation"
        ));
        assert_eq!(row.lines().count(), 1);
        assert!(row.len() <= label.len() + 64 + 4 * CONSOLE_BYTES);
        assert!(console_row(&label, 9, Some(b"\n\r\0\\")).ends_with("\\n\\r\\x00\\\\\n"));
        assert!(console_row(&label, 9, None).ends_with("console_untimed=unavailable\n"));

        context.set(Stage::Boot, Phase::Validation);
        let mut output = Vec::new();
        context.report_to(&mut output, None);
        let row = String::from_utf8(output)?;
        assert!(row.contains("stage=Boot phase=Validation node=unavailable"));

        let row = context_row(&label, u32::MAX, Some((u64::MAX, u64::MAX, Some(u64::MAX))));
        assert!(row.len() < CONTEXT_BYTES);
        assert!(row.contains("cached_accepted_ps_raw_deadline=Some((18446744073709551615"));
        assert!(row.ends_with(
            "post_error_mapped=unavailable reason=producer_publication_may_be_incomplete"
        ));
        Ok(())
    }

    struct FailedSink;

    impl Write for FailedSink {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("diagnostic destination closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("diagnostic destination closed"))
        }
    }
}
