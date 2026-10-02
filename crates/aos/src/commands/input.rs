//! Bounded local-file input shared by command families.

use std::fs::File;
use std::io::{Read as _, Take};
use std::path::Path;

use anyhow::{Context as _, Result, bail};

/// Reads at most `limit` bytes from one command input file.
///
/// # Errors
///
/// Returns an error when the file cannot be opened or read, or exceeds the
/// supplied limit. One extra byte distinguishes a full file from oversized
/// input without loading unbounded data into memory.
pub(crate) fn read_bounded_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening {label} {}", path.display()))?;
    let mut reader: Take<File> = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!(
            "{label} {} exceeds the {} byte limit",
            path.display(),
            limit
        );
    }
    Ok(bytes)
}
