//! Best-effort bounded native callback context after an authenticated owned reap.
//!
//! This retains original bytes, not canonical or cross-stream causal evidence.
//! The existing native trace has an admitted finite size; incomplete pairs,
//! malformed rows and omitted bytes remain explicitly inconclusive.

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};

use crucible_qemu::{
    QemuPreparedRunDirectory, QemuRuntimeDeterminismTimerOwner, QemuRuntimeDeterminismTraceRecord,
    QemuRuntimeDeterminismTraceValidator, QemuShutdownReport,
};

pub(super) const ENVIRONMENT: &str = "CRUCIBLE_OUT_RESUME_RUNTIME_TRACE";
const MAXIMUM_BYTES: u64 = 32 * 1024 * 1024;
const TAIL_BYTES: usize = 4096;
const ROW_BYTES: usize = 2048;

pub(super) fn enabled(setting: Option<&std::ffi::OsStr>) -> bool {
    setting == Some(std::ffi::OsStr::new("1"))
}

pub(super) fn report_after_reap(
    directory: &QemuPreparedRunDirectory,
    shutdown: Option<&QemuShutdownReport>,
) {
    let mut output = io::stderr().lock();
    if !shutdown.is_some_and(|report| report.reaped && !report.leaked) {
        let _ = writeln!(
            output,
            "linux probe native runtime trace: unavailable (clean owned reap not proven)"
        );
        return;
    }
    let summary = directory.inspect_runtime_determinism_trace_after_reap(MAXIMUM_BYTES, |reader| {
        summarize(reader).map_err(Box::<dyn std::error::Error>::from)
    });
    match summary {
        Ok(summary) => {
            let _ = writeln!(
                output,
                "linux probe advisory native runtime trace: bytes={}; rows={}; idle_rows={}; timer_rows={}; rr_timer_entries={}; malformed_rows={}; complete_pairs={}; retained_tail_bytes={}; omitted_bytes={}; callback_return=unproven; stalled_interval_attribution=unproven",
                summary.bytes,
                summary.rows,
                summary.idle_rows,
                summary.timer_rows,
                summary.rr_timer_entries,
                summary.malformed_rows,
                summary.complete_pairs,
                summary.tail.len(),
                summary.bytes.saturating_sub(summary.tail.len() as u64),
            );
            let _ = writeln!(
                output,
                "linux probe original native runtime trace tail: escaped={}",
                summary.escaped_tail()
            );
        }
        Err(error) => {
            let detail: String = error
                .to_string()
                .bytes()
                .take(256)
                .flat_map(std::ascii::escape_default)
                .map(char::from)
                .collect();
            let _ = writeln!(
                output,
                "linux probe native runtime trace: unavailable ({detail})"
            );
        }
    }
}

#[derive(Default)]
struct TraceSummary {
    bytes: u64,
    rows: u64,
    idle_rows: u64,
    timer_rows: u64,
    rr_timer_entries: u64,
    malformed_rows: u64,
    complete_pairs: bool,
    tail: VecDeque<u8>,
}

impl TraceSummary {
    fn escaped_tail(&self) -> String {
        self.tail
            .iter()
            .flat_map(|byte| std::ascii::escape_default(*byte))
            .map(char::from)
            .collect()
    }
}

fn summarize(reader: &mut dyn BufRead) -> io::Result<TraceSummary> {
    let mut summary = TraceSummary::default();
    let mut validator = QemuRuntimeDeterminismTraceValidator::default();
    let mut row = Vec::with_capacity(ROW_BYTES);
    let mut row_overflow = false;
    let mut bytes = [0_u8; 8192];
    loop {
        let length = reader.read(&mut bytes)?;
        if length == 0 {
            break;
        }
        summary.bytes += length as u64;
        if summary.bytes > MAXIMUM_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for byte in &bytes[..length] {
            if summary.tail.len() == TAIL_BYTES {
                summary.tail.pop_front();
            }
            summary.tail.push_back(*byte);
            if *byte != b'\n' {
                if row.len() < ROW_BYTES {
                    row.push(*byte);
                } else {
                    row_overflow = true;
                }
                continue;
            }
            summary.rows += 1;
            let record = (!row_overflow)
                .then(|| std::str::from_utf8(&row).ok())
                .flatten()
                .and_then(|row| validator.push_row(row).ok());
            match record {
                Some(QemuRuntimeDeterminismTraceRecord::Idle(_)) => summary.idle_rows += 1,
                Some(QemuRuntimeDeterminismTraceRecord::Timer(timer)) => {
                    summary.timer_rows += 1;
                    if timer.owner == QemuRuntimeDeterminismTimerOwner::Rr {
                        summary.rr_timer_entries += 1;
                    }
                }
                None => summary.malformed_rows += 1,
            }
            row.clear();
            row_overflow = false;
        }
    }
    if !row.is_empty() || row_overflow {
        summary.malformed_rows += 1;
    }
    summary.complete_pairs = summary.malformed_rows == 0 && validator.finish().is_ok();
    Ok(summary)
}

#[cfg(test)]
#[path = "runtime_trace/tests.rs"]
mod tests;
