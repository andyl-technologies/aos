//! Bounded file I/O for durable checkpoint objects.

use std::fs::File;
use std::io::{Read as _, Result};
use std::path::Path;

pub(super) fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its checkpoint read limit",
        ));
    }
    let length = usize::try_from(length).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint file length is not representable",
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "checkpoint file allocation failed",
        )
    })?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint file changed while it was read",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs;

    use super::*;

    #[test]
    fn bounded_file_read_accepts_exact_limit_and_rejects_larger_input() {
        let directory = tempfile::tempdir().expect("create bounded-read directory");
        let path = directory.path().join("checkpoint");
        fs::write(&path, b"12345678").expect("write bounded-read fixture");

        assert_eq!(
            read_bounded_file(&path, 8).expect("read exact-limit checkpoint"),
            b"12345678"
        );
        let error = read_bounded_file(&path, 7).expect_err("reject over-limit checkpoint");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
