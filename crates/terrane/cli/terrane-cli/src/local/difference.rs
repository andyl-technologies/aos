//! Formats authorized metadata differences without fetching plaintext objects.
//!
//! Entry paths are quoted and escaped byte by byte so names containing control
//! characters or invalid UTF-8 cannot forge rows. Counts describe changed tree
//! entries, rather than text lines or bytes. Policy declarations remain a separate
//! observation because inherited or graft policy changes need not change entries.

use std::io::{self, Write};

use terrane_sdk::{model::algebra::Change, repository::Difference};

/// Writes quoted entry rows or entry-count statistics for an authorized diff.
///
/// # Errors
/// Preserves canonical metadata decoding and output write or flush failures.
pub(super) fn write(
    difference: &Difference,
    stat: bool,
    output: &mut impl Write,
) -> Result<(), super::Error> {
    let entries = difference.entries()?;
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut modified = 0usize;

    for change in &entries.changes {
        let kind = match change {
            Change::Added(_) => {
                added += 1;
                'A'
            }
            Change::Removed(_) => {
                removed += 1;
                'D'
            }
            Change::Modified { .. } => {
                modified += 1;
                'M'
            }
        };

        if !stat {
            write!(output, "{kind}\t")?;
            write_path(change.path(), output)?;
            writeln!(output)?;
        }
    }

    if stat {
        writeln!(
            output,
            "added={added} removed={removed} modified={modified} policies_changed={}",
            difference.policies_changed()
        )?;
    } else if difference.policies_changed() {
        writeln!(output, "policies_changed=true")?;
    }

    output.flush()?;
    Ok(())
}

/// Keeps every path on one unambiguous ASCII row without replacing invalid bytes.
fn write_path(path: &[u8], output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"\"")?;
    for byte in path {
        write!(output, "{}", std::ascii::escape_default(*byte))?;
    }
    output.write_all(b"\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_output_preserves_bytes_without_forging_rows() -> io::Result<()> {
        let mut output = Vec::new();
        write_path(b"name\nM\tfake\r\x1b[2J\"\\\xff", &mut output)?;

        assert_eq!(output, br#""name\nM\tfake\r\x1b[2J\"\\\xff""#);
        assert!(output.iter().all(u8::is_ascii));
        assert!(!output.contains(&b'\n'));
        assert!(!output.contains(&b'\r'));
        assert!(!output.contains(&b'\t'));
        Ok(())
    }

    #[test]
    fn path_output_preserves_write_failure() {
        struct RefusedOutput;

        impl Write for RefusedOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        assert!(matches!(
            write_path(b"file", &mut RefusedOutput),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe
        ));
    }
}
