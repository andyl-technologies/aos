//! Finite private host artifact allocation for actual native test evidence.

use std::{fs::DirBuilder, io, os::unix::fs::DirBuilderExt, path::PathBuf};

pub fn evidence_root(prefix: &str) -> io::Result<PathBuf> {
    for attempt in 0..10_000 {
        let path = PathBuf::from(format!("/tmp/{prefix}-{}-{attempt}", std::process::id()));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other(
        "native evidence namespace allowance exhausted",
    ))
}
