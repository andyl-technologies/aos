//! Writes canonical native records through the application's existing streams.
//!
//! The paid worker supplies borrowed records synchronously. This adapter adds
//! no descriptor, channel, worker or retained transcript allocation.

use std::io::{self, Write};

use crucible_daemon::{NativeFlightOutputChannel, NativePluginFlightDiagnostic};

/// Writes a complete borrowed record to its canonical application stream.
///
/// # Errors
/// Returns the original standard-stream write failure to the worker, which
/// retains it independently of its actual Source and trace cleanup outcomes.
pub(super) fn emit(record: NativePluginFlightDiagnostic<'_>) -> io::Result<()> {
    match record.channel() {
        NativeFlightOutputChannel::StandardOutput => {
            let stream = io::stdout();
            let mut stream = stream.lock();
            write!(stream, "{record}")
        }
        NativeFlightOutputChannel::StandardError => {
            let stream = io::stderr();
            let mut stream = stream.lock();
            write!(stream, "{record}")
        }
    }
}
