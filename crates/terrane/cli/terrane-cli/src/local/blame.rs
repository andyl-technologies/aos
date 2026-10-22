//! Formats authorized entry provenance without credentials or content reads.

use std::io::{self, Write};
use terrane_sdk::repository::{EntryBlame, EntryProvenance};

/// Writes the exact introducing claims followed by parent-ordered merge claims.
///
/// # Errors
/// Propagates output and flush failures.
pub(super) fn write(blame: &EntryBlame, output: &mut impl Write) -> io::Result<()> {
    write!(output, "view=")?;
    digest(&blame.view_commit, output)?;
    writeln!(output)?;
    claims("introduction", &blame.introduction, output)?;
    for entry in &blame.fold_chain {
        claims("fold", entry, output)?;
    }
    output.flush()
}

fn digest(bytes: &[u8], output: &mut impl Write) -> io::Result<()> {
    for byte in bytes {
        write!(output, "{byte:02x}")?;
    }
    Ok(())
}

fn claims(kind: &str, entry: &EntryProvenance, output: &mut impl Write) -> io::Result<()> {
    write!(output, "{kind} commit=")?;
    digest(&entry.commit, output)?;
    write!(output, " issuer={:?} token_id=", entry.issuer)?;
    digest(&entry.token_id, output)?;
    // Debug quoting prevents claim strings from injecting apparent records.
    writeln!(
        output,
        " subject={:?} kind={:?} workload={:?} process={:?} at={} observed_at={} writer_epoch={} source={:?}",
        entry.subject,
        entry.kind,
        entry.workload_identity,
        entry.process,
        entry.timestamp,
        entry.observed_at,
        entry.writer_epoch,
        entry.source,
    )
}
