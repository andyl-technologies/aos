//! Matches the consumer's own bounded notes read to its compiled kernel facts.

use std::fs::{File, Metadata, OpenOptions};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use crate::protected_file::positional_hash::{PositionalHashClosedV2, PositionalHashOriginalV2};
use crate::{Error, Result};

const NOTES: &str = "/sys/kernel/notes";
const SYSFS_MAGIC: u64 = 0x6265_6572;

/// Retains one actual notes proof without borrowing another process's proof.
///
/// Construction is inert. The complete native hash/EOF and independent same
/// descriptor/name checks precede success. There is no default kernel mirror,
/// caller path, supplied notes digest, runtime development path or IO fallback.
pub struct ConfiguredKernelCloneOriginalV1 {
    file: Option<std::io::Result<File>>,
    filesystem: Option<rustix::io::Result<rustix::fs::StatFs>>,
    before: Option<std::io::Result<Metadata>>,
    hash: Option<Box<PositionalHashOriginalV2>>,
    digest: Option<std::result::Result<[u8; 32], PositionalHashClosedV2>>,
    eof: Option<rustix::io::Result<usize>>,
    byte: [u8; 1],
    after: Option<std::io::Result<Metadata>>,
    named: Option<std::io::Result<Metadata>>,
    primary: Option<Result<()>>,
    comparison: Option<Result<()>>,
    closed: Option<Error>,
    complete: bool,
}

impl Default for ConfiguredKernelCloneOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfiguredKernelCloneOriginalV1 {
    /// Creates empty destinations without IO or a hash-buffer allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            file: None,
            filesystem: None,
            before: None,
            hash: None,
            digest: None,
            eof: None,
            byte: [0],
            after: None,
            named: None,
            primary: None,
            comparison: None,
            closed: None,
            complete: false,
        }
    }

    /// Reads this running kernel's exact configured notes once.
    ///
    /// The caller pays this complete prospective supplier before entry. An
    /// unconfigured build refuses before opening a file. Every entered opening
    /// owes the same-file and named identity posts even after a primary error.
    ///
    /// # Errors
    /// Retains open/type/filesystem/extent/hash/EOF/identity refusal or reentry.
    /// Failed native file/hash prefixes remain owned; they cannot be retried.
    pub fn capture_once_v1(&mut self) -> Result<()> {
        if self.primary.is_some() || self.closed.is_some() {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        let Some((bytes, digest)) = super::expected_notes_v1() else {
            self.closed = Some(closed());
            return Err(closed());
        };
        self.primary = Some(self.capture_inner(bytes, digest));
        self.after = self
            .file
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(File::metadata);
        self.named = Some(std::fs::symlink_metadata(NOTES));
        self.comparison = Some(match (&self.before, &self.after, &self.named) {
            (Some(Ok(before)), Some(Ok(after)), Some(Ok(named)))
                if same(before, after) && same(before, named) =>
            {
                Ok(())
            }
            _ => Err(closed()),
        });
        if !matches!(self.primary, Some(Ok(()))) || !matches!(self.comparison, Some(Ok(()))) {
            return Err(closed());
        }
        self.complete = true;
        // Kernel notes are fixed for this running kernel's lifetime. The
        // actual full-positive hash/EOF/identity phase may retire its temporary
        // file and work buffer; failed prefixes never enter this transition.
        drop(self.file.take());
        drop(self.hash.take());
        Ok(())
    }

    fn capture_inner(&mut self, bytes: u64, digest: [u8; 32]) -> Result<()> {
        self.file = Some(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(NOTES),
        );
        let file = self
            .file
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        self.filesystem = Some(rustix::fs::fstatfs(file));
        self.before = Some(file.metadata());
        if !matches!(self.filesystem, Some(Ok(ref stat)) if stat.f_type as u64 == SYSFS_MAGIC) {
            return Err(closed());
        }
        let metadata = self
            .before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(closed)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.len() != bytes
        {
            return Err(closed());
        }
        self.hash = Some(Box::new(PositionalHashOriginalV2::new()));
        self.digest = Some(self.hash.as_mut().ok_or_else(closed)?.hash_once_v2(
            file.as_fd(),
            bytes,
            |_| {},
        ));
        if !matches!(self.digest, Some(Ok(actual)) if actual == digest) {
            return Err(closed());
        }
        self.eof = Some(rustix::io::pread(file, &mut self.byte, bytes));
        if !matches!(self.eof, Some(Ok(0))) {
            return Err(closed());
        }
        Ok(())
    }

    /// Reports only the actual successful hash/EOF/identity transition.
    #[must_use]
    pub fn completed_v1(&self) -> bool {
        self.complete && self.closed.is_none()
    }

    /// Prices the same original, fixed hash buffer, file and literal name.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(PositionalHashOriginalV2::receiving_bytes_v2()?)?
            .checked_add(2 * (NOTES.len() + 1))?
            .checked_add(
                2 * ("configured kernel clone source".len()
                    + "original notes proof is incomplete or refused".len()),
            )?;
        Some((bytes, 1, 1))
    }

    /// Borrows the earliest actual failure without opening or resampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.file)
            .or_else(|| error(&self.filesystem))
            .or_else(|| error(&self.before))
            .or_else(|| self.hash.as_ref()?.failure().map(|cause| cause as _))
            .or_else(|| error(&self.digest))
            .or_else(|| error(&self.eof))
            .or_else(|| error(&self.primary))
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.named))
            .or_else(|| error(&self.comparison))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
}

fn error<T, E: std::error::Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn closed() -> Error {
    Error::invalid(
        "configured kernel clone source",
        "original notes proof is incomplete or refused",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "selected-kernel-clone-layout")]
    fn actual_selected_notes_retains_mismatch_or_completes_same_identity_once() {
        use sha2::{Digest as _, Sha256};
        use std::io::Read as _;

        // The build consumer parsed the artifact association and verified its
        // config/layout/notes digests. This independent bounded read samples
        // the running host; a different host is a real negative case, not a
        // replacement fixture or an installed Source qualification.
        let (expected_bytes, expected_digest) = super::super::expected_notes_v1().unwrap();
        assert_ne!(expected_bytes, 0);
        assert_ne!(expected_digest, [0; 32]);
        let mut bytes = Vec::new();
        let sampled = File::open(NOTES).and_then(|file| {
            file.take(expected_bytes.checked_add(1).unwrap())
                .read_to_end(&mut bytes)
        });
        let observed_digest: [u8; 32] = Sha256::digest(&bytes).into();
        let same = sampled.is_ok()
            && u64::try_from(bytes.len()).unwrap() == expected_bytes
            && observed_digest == expected_digest;

        let mut original = ConfiguredKernelCloneOriginalV1::new();
        let result = original.capture_once_v1();
        if same {
            assert!(
                result.is_ok(),
                "matching running notes failed native admission: {:?}",
                original.failure()
            );
            assert!(original.completed_v1());
            assert!(original.failure().is_none());
            assert!(original.after.is_some() && original.named.is_some());
            println!(
                "RFC21_SELECTED_KERNEL_NOTES_MATCH=MATCHED_NATIVE_NOTES_ONLY installed_source_fit=UNQUALIFIED"
            );
        } else {
            assert!(result.is_err());
            assert!(!original.completed_v1());
            let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
            assert!(original.file.is_some() && original.named.is_some());
            if matches!(original.file, Some(Ok(_))) {
                assert!(original.after.is_some());
            }
            assert!(original.capture_once_v1().is_err());
            assert_eq!(
                original.failure().unwrap() as *const dyn std::error::Error as *const (),
                first
            );
            println!(
                "RFC21_SELECTED_KERNEL_NOTES_MATCH=UNQUALIFIED actual_negative_original=retained installed_source_fit=UNQUALIFIED"
            );
        }
        assert!(original.capture_once_v1().is_err());
        assert!(!original.completed_v1());
    }

    #[test]
    #[cfg(not(feature = "selected-kernel-clone-layout"))]
    fn unconfigured_or_reentered_source_never_opens_notes() {
        let mut original = ConfiguredKernelCloneOriginalV1::new();

        assert!(original.capture_once_v1().is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(original.capture_once_v1().is_err());

        assert_eq!(
            original.failure().unwrap() as *const dyn std::error::Error as *const (),
            first
        );
        assert!(original.file.is_none());
        assert!(original.hash.is_none());
        assert!(!original.completed_v1());
    }
}
