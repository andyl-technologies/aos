//! Failure-only context for the original retained network-output coordinate.
//!
//! The existing callback witness setting enables arm bookkeeping. Only the first
//! failed tuple in each process writes a row; PID changes after fork reserve a
//! fresh notice. No normal arm or admission writes a row. The original producer
//! frontier identifies the arm, while admission is the returned SDK status, not
//! a claim that native QEMU has stopped. Unavailable status includes a callback
//! nested before that return. Each arm owns an independent atomic status; its
//! observation never reacquires the original output-stop mutex. A delayed
//! return cannot overwrite a newer arm.
//!
//! ```text
//! CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 phase=vcpu-resume pid=42 arm_pid=42 origin=direct-tx original_ps=100 original_raw=2 observed_ps=150 observed_raw=3 write_frontier=1 admission=0
//! ```

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

const ADMISSION_UNAVAILABLE: i64 = i64::MAX;

use super::RetainedNetworkOutputStop;

#[derive(Clone, Copy)]
pub(in crate::runtime::live_callbacks) enum ArmOrigin {
    DirectTx,
    IdleAdvanceCompletion,
}

impl ArmOrigin {
    fn label(self) -> &'static str {
        match self {
            Self::DirectTx => "direct-tx",
            Self::IdleAdvanceCompletion => "idle-advance-completion",
        }
    }
}

/// Optional process-private observation; no field participates in admission.
pub(super) struct ArmContext {
    process_id: u32,
    origin: ArmOrigin,
    admission_status: AtomicI64,
}

impl ArmContext {
    pub(super) fn new(enabled: bool, origin: ArmOrigin) -> Option<Arc<Self>> {
        enabled.then(|| {
            Arc::new(Self {
                process_id: std::process::id(),
                origin,
                admission_status: AtomicI64::new(ADMISSION_UNAVAILABLE),
            })
        })
    }

    pub(super) fn observe_admission(&self, status: i32) {
        self.admission_status
            .store(i64::from(status), Ordering::Relaxed);
    }

    fn admission_label(&self) -> String {
        let status = self.admission_status.load(Ordering::Relaxed);
        if status == ADMISSION_UNAVAILABLE {
            "unavailable".to_owned()
        } else {
            status.to_string()
        }
    }
}

struct FailureReporter(AtomicU32);

impl FailureReporter {
    const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    fn emit(
        &self,
        writer: &mut impl Write,
        process_id: u32,
        stop: &RetainedNetworkOutputStop,
        logical_icount: u64,
        raw_icount: u64,
        phase: &'static str,
    ) {
        let Some(context) = stop.context.as_ref() else {
            return;
        };
        if self.0.swap(process_id, Ordering::Relaxed) == process_id {
            return;
        }
        // A broken diagnostic sink must not replace the original refusal.
        let _write_result = writeln!(
            writer,
            "CRUCIBLE-NETWORK-OUTPUT-CONTEXT-V1 phase={phase} pid={process_id} arm_pid={} origin={} original_ps={} original_raw={} observed_ps={logical_icount} observed_raw={raw_icount} write_frontier={} admission={}",
            context.process_id,
            context.origin.label(),
            stop.logical_icount,
            stop.raw_icount,
            stop.write_index,
            context.admission_label(),
        );
    }
}

static REPORTER: FailureReporter = FailureReporter::new();

pub(super) fn report_failure(
    stop: &RetainedNetworkOutputStop,
    logical_icount: u64,
    raw_icount: u64,
    phase: &'static str,
) {
    if stop.context.is_none() {
        return;
    }
    #[cfg(test)]
    if capture::record(stop, logical_icount, raw_icount, phase) {
        return;
    }
    REPORTER.emit(
        &mut io::stderr().lock(),
        std::process::id(),
        stop,
        logical_icount,
        raw_icount,
        phase,
    );
}

#[cfg(test)]
pub(in crate::runtime::live_callbacks) mod capture {
    use super::*;
    use std::cell::RefCell;

    struct Capture {
        reporter: FailureReporter,
        bytes: Vec<u8>,
    }

    thread_local! {
        static CAPTURE: RefCell<Option<Capture>> = const { RefCell::new(None) };
    }

    pub(in crate::runtime::live_callbacks) fn during<T>(action: impl FnOnce() -> T) -> (T, String) {
        CAPTURE.with(|capture| {
            *capture.borrow_mut() = Some(Capture {
                reporter: FailureReporter::new(),
                bytes: Vec::new(),
            });
        });
        let result = action();
        let bytes = CAPTURE.with(|capture| {
            capture
                .borrow_mut()
                .take()
                .unwrap_or_else(|| panic!("active capture"))
                .bytes
        });
        (
            result,
            String::from_utf8(bytes).unwrap_or_else(|error| panic!("ASCII context row: {error}")),
        )
    }

    pub(super) fn record(
        stop: &RetainedNetworkOutputStop,
        logical_icount: u64,
        raw_icount: u64,
        phase: &'static str,
    ) -> bool {
        CAPTURE.with(|capture| {
            let mut capture = capture.borrow_mut();
            let Some(capture) = capture.as_mut() else {
                return false;
            };
            capture.reporter.emit(
                &mut capture.bytes,
                std::process::id(),
                stop,
                logical_icount,
                raw_icount,
                phase,
            );
            true
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_and_repeated_failures_do_not_consume_later_process_notice() {
        let reporter = FailureReporter::new();
        let mut bytes = Vec::new();
        let mut stop = RetainedNetworkOutputStop {
            logical_icount: u64::MAX,
            raw_icount: u64::MAX,
            write_index: u64::MAX,
            context: None,
        };
        reporter.emit(&mut bytes, u32::MAX, &stop, 1, 2, "network-tx-pending");
        assert!(bytes.is_empty());
        assert_eq!(reporter.0.load(Ordering::Relaxed), 0);

        stop.context = ArmContext::new(true, ArmOrigin::IdleAdvanceCompletion);
        let context = stop
            .context
            .as_mut()
            .and_then(Arc::get_mut)
            .unwrap_or_else(|| panic!("exclusive enabled context"));
        context.process_id = u32::MAX;
        context.observe_admission(i32::MIN);
        for _ in 0..100 {
            reporter.emit(
                &mut bytes,
                u32::MAX,
                &stop,
                u64::MAX,
                u64::MAX,
                "idle-advance-completion",
            );
        }
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(bytes.len() <= 512);
        reporter.emit(&mut bytes, 42, &stop, 1, 2, "vcpu-resume");
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    #[test]
    fn before_native_return_keeps_admission_unavailable_and_original_arm_pid() {
        let reporter = FailureReporter::new();
        let mut bytes = Vec::new();
        let stop = RetainedNetworkOutputStop {
            logical_icount: 100,
            raw_icount: 2,
            write_index: 1,
            context: ArmContext::new(true, ArmOrigin::DirectTx),
        };

        reporter.emit(&mut bytes, 42, &stop, 150, 3, "vcpu-resume");

        let row = String::from_utf8(bytes).unwrap_or_else(|error| panic!("ASCII row: {error}"));
        assert!(row.contains(&format!("pid=42 arm_pid={}", std::process::id())));
        assert!(row.ends_with("write_frontier=1 admission=unavailable\n"));
    }

    #[test]
    fn failed_write_is_terminal_only_for_the_diagnostic_notice() {
        let reporter = FailureReporter::new();
        let stop = RetainedNetworkOutputStop {
            logical_icount: 100,
            raw_icount: 2,
            write_index: 1,
            context: ArmContext::new(true, ArmOrigin::DirectTx),
        };
        let mut writer = io::Cursor::new(&mut [0_u8; 0][..]);
        reporter.emit(&mut writer, 42, &stop, 150, 3, "vcpu-resume");
        let mut bytes = Vec::new();
        reporter.emit(&mut bytes, 42, &stop, 150, 3, "vcpu-resume");
        assert!(bytes.is_empty());
    }
}
