//! Diagnostic-only trace of the entries an attempt log retains.
//!
//! Replay divergence is reported as a decision index, but the decisions sit
//! between RUN boundaries and observable entries that show which node's
//! publication moved. When `CRUCIBLE_ATTEMPT_LOG_TRACE_DIR` names a directory,
//! every retained attempt log writes one line per entry to its own file there,
//! so two logs of the same prefix can be compared around a divergence:
//!
//! ```text
//! <sequence> <at-ps> <kind> <attributes, truncated>
//! ```
//!
//! The trace is operational evidence only. It never enters identity, and a
//! failed write is ignored.

use std::fs::File;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible::SchedulerEventLogEntry;

/// Environment variable naming the directory that receives trace files.
const TRACE_DIRECTORY_ENV: &str = "CRUCIBLE_ATTEMPT_LOG_TRACE_DIR";

/// Longest attribute rendering one trace line carries.
const ATTRIBUTE_CHARS: usize = 240;

/// Distinguishes the logs one process opens.
static NEXT_TRACE: AtomicU64 = AtomicU64::new(0);

/// An open trace file shared by a log and its clones, or nothing.
#[derive(Clone, Debug, Default)]
pub(super) struct AttemptLogTrace {
    file: Option<Arc<Mutex<File>>>,
}

impl AttemptLogTrace {
    /// Opens a new trace file when the trace directory is configured.
    pub(super) fn open() -> Self {
        let Some(directory) = std::env::var_os(TRACE_DIRECTORY_ENV) else {
            return Self::default();
        };
        let ordinal = NEXT_TRACE.fetch_add(1, Ordering::Relaxed);
        let path = std::path::Path::new(&directory).join(format!(
            "attempt-log-{}-{ordinal}.trace",
            std::process::id()
        ));
        Self {
            file: File::create(path)
                .ok()
                .map(|file| Arc::new(Mutex::new(file))),
        }
    }

    /// Writes one line for an entry the log accepted.
    pub(super) fn record(&self, entry: &SchedulerEventLogEntry) {
        let Some(file) = &self.file else {
            return;
        };
        let payload = entry.event_payload();
        let attributes = format!("{:?}", payload.attributes())
            .chars()
            .filter(|character| *character != '\n')
            .take(ATTRIBUTE_CHARS)
            .collect::<String>();
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(
                file,
                "{} {} {} {attributes}",
                entry.sequence(),
                entry.at().ticks,
                payload.kind()
            );
        }
    }
}
