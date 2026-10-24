//! Supplies independent deterministic multi-chunk fixture bytes and setup expectations.

use super::{FixtureResult, PAYLOAD, fs};
use std::{io, path::Path};

pub(super) fn manifest() -> Vec<u8> {
    let mut state = 7_u32;
    (0..2_097_153)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

pub(super) fn expected(root: &Path) -> FixtureResult<Vec<u8>> {
    match fs::read(root.join("expected.payload")) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(PAYLOAD.to_vec()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn manifest_fixture_crosses_real_profile_boundaries_within_native_read_bounds() {
        let bytes = super::manifest();
        let ranges = terrane_format::chunking::ChunkProfile::cdc_1m([7; 32]).boundaries(&bytes);
        assert!(ranges.len() >= 2);
        assert!(ranges.iter().all(|range| range.len() < 2_097_152));
        assert_eq!(
            ranges.iter().map(|range| range.len()).sum::<usize>(),
            bytes.len()
        );
    }
}
