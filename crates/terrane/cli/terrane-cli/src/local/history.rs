//! Formats already authorized committed history without resolving content.

use std::io::{self, Write};
use terrane_sdk::repository::RefHistory;

pub(super) fn write(history: &RefHistory, output: &mut impl Write) -> io::Result<()> {
    for entry in history.entries() {
        write!(output, "sequence={} commit=", entry.record.seq)?;
        for byte in entry.record.commit {
            write!(output, "{byte:02x}")?;
        }
        // Quoting the principal keeps control characters and embedded line
        // breaks from creating apparent additional events in terminal output.
        writeln!(
            output,
            " writer_epoch={} at={} principal={:?} reason={:?}",
            entry.record.writer_epoch, entry.timestamp, entry.principal, entry.reason
        )?;
    }
    output.flush()
}
