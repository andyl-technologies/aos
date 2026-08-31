//! Shared bounded file handling for offline campaign record authoring.

use super::*;

use std::fs::File;
use std::io::{Read, Write};

pub(super) fn read_bounded_utf8(
    path: &Path,
    kind: &str,
    maximum_bytes: usize,
) -> Result<String, CliError> {
    let file = File::open(path).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not open {kind} at {}: {error}", path.display()),
        ))
    })?;
    let maximum = u64::try_from(maximum_bytes)
        .map_err(|_| backend_error(format!("{kind} bound exceeds u64")))?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!("could not read {kind} at {}: {error}", path.display()),
            ))
        })?;
    if bytes.len() > maximum_bytes {
        return Err(usage_error(format!("{kind} exceeds {maximum_bytes} bytes")));
    }
    String::from_utf8(bytes).map_err(|_| usage_error(format!("{kind} is not valid UTF-8")))
}

pub(super) fn write_new_record(path: &Path, kind: &str, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!(
                "could not create temporary {kind} in {}: {error}",
                parent.display()
            ),
        ))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not write {kind} at {}: {error}", path.display()),
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not sync {kind} at {}: {error}", path.display()),
        ))
    })?;
    temporary.persist_noclobber(path).map_err(|error| {
        CliError::Io(io::Error::new(
            error.error.kind(),
            format!(
                "could not install new {kind} at {}: {}",
                path.display(),
                error.error
            ),
        ))
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!(
                    "could not sync {kind} output directory {}: {error}",
                    parent.display()
                ),
            ))
        })
}
