//! Consumes native read receipts without replaying physical byte effects.
//!
//! This pure consumer is shared by production reads and transcript tests. It
//! grants no Source authority and never substitutes a counted length for EOF.
// SPDX-License-Identifier: GPL-2.0-only

use super::{FingerprintSamplerError, MaterialDigestProgress};
use sha2::Digest as _;

/// Records an actual read and its independent semantic post.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MaterialRead {
    pub(crate) offset: u64,
    pub(crate) bytes_read: u64,
    pub(crate) read_status: i32,
    pub(crate) post_status: i32,
    pub(crate) attempted: u32,
    pub(crate) eof: u32,
}

pub(super) fn consume(
    progress: &mut MaterialDigestProgress,
    receipt: MaterialRead,
    status: i32,
    workspace: &[u8],
    requested: usize,
    material_length: u64,
    expect_eof: bool,
) -> Result<(), FingerprintSamplerError> {
    if let Some(failure) = &progress.failure {
        return Err(failure.clone());
    }
    let native_status = if receipt.read_status != 0 {
        receipt.read_status
    } else if status != 0 {
        status
    } else {
        receipt.post_status
    };
    let no_read = receipt.attempted == 0 && receipt.bytes_read == 0;
    if no_read && native_status != 0 {
        progress.native_failure.get_or_insert((receipt, status));
        return Err(retain_failure(progress, native_status));
    }
    let valid_extent = progress.consumed <= material_length
        && receipt.offset == progress.consumed
        && receipt.bytes_read <= requested as u64
        && receipt.bytes_read <= workspace.len() as u64
        && receipt.bytes_read <= material_length - progress.consumed
        && receipt.attempted == 1
        && receipt.eof <= 1
        && (receipt.bytes_read == 0 || receipt.eof == 0);
    if !valid_extent {
        progress.native_failure.get_or_insert((receipt, status));
        return Err(retain_failure(progress, -libc::EPROTO));
    }
    if receipt.bytes_read != 0 {
        // The actual effect precedes its independent post. Hash and journal the
        // prefix even when that post refuses further semantic work.
        progress
            .hasher
            .update(&workspace[..receipt.bytes_read as usize]);
        progress.consumed += receipt.bytes_read;
    }
    if native_status != 0 {
        progress.native_failure.get_or_insert((receipt, status));
        return Err(retain_failure(progress, native_status));
    }
    let valid_phase = if expect_eof {
        receipt.offset == material_length && receipt.bytes_read == 0 && receipt.eof == 1
    } else {
        receipt.bytes_read != 0 && receipt.eof == 0
    };
    if !valid_phase {
        progress.native_failure.get_or_insert((receipt, status));
        return Err(retain_failure(progress, -libc::EIO));
    }
    Ok(())
}

pub(super) fn retain_failure(
    progress: &mut MaterialDigestProgress,
    status: i32,
) -> FingerprintSamplerError {
    progress
        .failure
        .get_or_insert(FingerprintSamplerError::NativeMaterial { status })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn prefix(offset: u64, bytes: u64) -> MaterialRead {
        MaterialRead {
            offset,
            bytes_read: bytes,
            attempted: 1,
            ..MaterialRead::default()
        }
    }

    #[test]
    fn positive_prefix_survives_post_failure_without_replay() {
        let mut progress = MaterialDigestProgress::default();
        let receipt = MaterialRead {
            post_status: -libc::ETIMEDOUT,
            ..prefix(0, 3)
        };

        let failure = consume(
            &mut progress,
            receipt,
            -libc::ETIMEDOUT,
            b"abc",
            3,
            3,
            false,
        )
        .unwrap_err();
        assert_eq!(progress.consumed, 3);
        assert_eq!(progress.hasher.clone().finalize(), Sha256::digest(b"abc"));
        assert_eq!(progress.native_failure, Some((receipt, -libc::ETIMEDOUT)));

        let again = consume(&mut progress, receipt, 0, b"abc", 3, 3, false).unwrap_err();
        assert_eq!(again, failure);
        assert_eq!(progress.consumed, 3);
        assert_eq!(progress.hasher.clone().finalize(), Sha256::digest(b"abc"));
    }

    #[test]
    fn short_reads_preserve_hash_and_require_actual_eof() {
        let mut progress = MaterialDigestProgress::default();

        consume(&mut progress, prefix(0, 2), 0, b"ab", 6, 6, false).unwrap();
        consume(&mut progress, prefix(2, 4), 0, b"cdef", 4, 6, false).unwrap();
        let eof = MaterialRead {
            offset: 6,
            attempted: 1,
            eof: 1,
            ..MaterialRead::default()
        };
        consume(&mut progress, eof, 0, b"", 1, 6, true).unwrap();

        assert_eq!(progress.consumed, 6);
        assert_eq!(progress.hasher.finalize(), Sha256::digest(b"abcdef"));
        assert!(progress.failure.is_none());
    }

    #[test]
    fn counted_length_does_not_substitute_for_actual_eof() {
        let mut progress = MaterialDigestProgress::default();
        consume(&mut progress, prefix(0, 1), 0, b"x", 1, 1, false).unwrap();

        let absent = MaterialRead {
            offset: 1,
            ..MaterialRead::default()
        };
        assert!(consume(&mut progress, absent, 0, b"", 1, 1, true).is_err());
        assert_eq!(progress.consumed, 1);
        assert_eq!(progress.hasher.finalize(), Sha256::digest(b"x"));
    }

    #[test]
    fn premature_eof_and_independent_statuses_are_retained() {
        let mut progress = MaterialDigestProgress::default();
        let receipt = MaterialRead {
            read_status: -libc::EIO,
            post_status: -libc::ECANCELED,
            ..prefix(0, 2)
        };

        assert!(consume(&mut progress, receipt, -libc::EIO, b"ab", 2, 4, false).is_err());
        assert_eq!(progress.consumed, 2);
        assert_eq!(progress.native_failure, Some((receipt, -libc::EIO)));
        assert_eq!(progress.hasher.finalize(), Sha256::digest(b"ab"));

        let mut premature = MaterialDigestProgress::default();
        let eof = MaterialRead {
            attempted: 1,
            eof: 1,
            ..MaterialRead::default()
        };
        assert!(consume(&mut premature, eof, 0, b"", 1, 4, true).is_err());
        assert_eq!(premature.native_failure, Some((eof, 0)));
    }
}
