//! Reads bounded ordinary body batches while retaining each exact original.
//!
//! Each row preserves the scalar namespace checks, nofollow capture and complete
//! body read. The worker stops at the first unsuccessful row. These observations
//! carry DATA and closing recipes alone, with no actor or publication authority.

use super::{ByteRange, ExpectedRange, OriginalPayload, RetainedPayloadRanges};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Classifies one actual ordinary read without turning absence into authority.
pub(crate) enum BodyRead {
    /// Observes a missing ancestor or leaf before any successful body read.
    Absent,
    /// Refuses a non-directory ancestor or nonregular leaf before reading it.
    InvalidLayout,
    /// Retains actual complete bytes and their original physical closing recipe.
    Present {
        /// Holds the complete bytes consumed through the original descriptor.
        bytes: Vec<u8>,
        /// Records the leaf metadata matched during actual descriptor capture.
        metadata: Box<std::fs::Metadata>,
        /// Retains that descriptor and its exact bytes for fresh closing checks.
        retained: RetainedPayloadRanges,
    },
}

/// Preserves ordered failure while leaving every later payload unread.
pub(super) fn read(root: PathBuf, relative: Vec<PathBuf>) -> Vec<io::Result<BodyRead>> {
    let mut rows = Vec::with_capacity(relative.len());
    for path in relative {
        let row = read_one(&root, &path);
        let completed = matches!(row, Ok(BodyRead::Present { .. }));
        rows.push(row);
        if !completed {
            break;
        }
    }
    rows
}

fn read_one(root: &Path, relative: &Path) -> io::Result<BodyRead> {
    if !root.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ordinary batch path",
        ));
    }
    let mut parent = root.to_owned();
    let relative_parent = relative
        .parent()
        .ok_or_else(|| io::Error::other("missing ordinary parent"))?;
    for component in relative_parent.components() {
        parent.push(component);
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Ok(BodyRead::InvalidLayout),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BodyRead::Absent),
            Err(error) => return Err(error),
        }
    }
    let path = root.join(relative);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Ok(BodyRead::InvalidLayout),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BodyRead::Absent),
        Err(error) => return Err(error),
    }

    let original = match OriginalPayload::capture(
        path,
        #[cfg(test)]
        None,
    ) {
        Ok(original) => Arc::new(original),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BodyRead::Absent),
        Err(error) => return Err(error),
    };
    let range = ByteRange {
        start: 0,
        length: original.length,
    };
    let bytes = original.read(range)?;
    let metadata = Box::new(original.metadata.clone());
    let retained = RetainedPayloadRanges {
        length: original.length,
        original,
        ranges: vec![ExpectedRange {
            range,
            bytes: bytes.clone(),
        }],
    };
    Ok(BodyRead::Present {
        bytes,
        metadata,
        retained,
    })
}
