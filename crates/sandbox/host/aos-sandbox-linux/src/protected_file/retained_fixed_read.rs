//! Retains one fixed no-follow file read and its independent identity posts.
//!
//! This mechanical reader grants no path, role, executable or financial
//! authority. Its caller owns path/ancestor policy and prepays all storage.

use std::fs::{File, Metadata, OpenOptions};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use aos_linux_descriptors::positional_hash::{PositionalHashClosedV2, PositionalHashOriginalV2};

/// Stops a failed or repeated read while the actual original remains owned.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("fixed protected read remains closed with its original")]
pub struct FixedProtectedReadClosedV3;

#[derive(Debug, thiserror::Error)]
#[error("fixed protected read observed bytes beyond its admitted extent")]
struct UnexpectedTailV3;

#[derive(Debug, thiserror::Error)]
#[error("fixed protected file changed across its independent identity posts")]
struct IdentityChangedV3;

/// Owns one original file, partial bytes/hash and all reached native results.
#[derive(Default)]
pub struct FixedProtectedReadOriginalV3 {
    file: Option<std::io::Result<File>>,
    before: Option<std::io::Result<Metadata>>,
    bytes: Vec<u8>,
    read: Option<Result<(), super::ExactReadFailure>>,
    hash: PositionalHashOriginalV2,
    digest: Option<Result<[u8; 32], PositionalHashClosedV2>>,
    eof: Option<rustix::io::Result<usize>>,
    eof_byte: [u8; 1],
    eof_validation: Option<Result<(), UnexpectedTailV3>>,
    named: Option<std::io::Result<Metadata>>,
    after: Option<std::io::Result<Metadata>>,
    entered: bool,
    read_entered: bool,
    exact_byte_eof: bool,
    post_entered: bool,
    comparison: Option<Result<(), IdentityChangedV3>>,
    refused: bool,
    bytes_taken: bool,
}

impl FixedProtectedReadOriginalV3 {
    /// Constructs empty destinations without allocation or native observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prices the actual fixed native carrier and bounded complete byte output.
    ///
    /// The caller separately prices its path and enclosing semantic models.
    /// No names or descriptors are acquired by this passive supplier.
    #[must_use]
    pub fn receiving_obligations_v3(maximum_materialized_bytes: usize) -> Option<(usize, usize)> {
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(maximum_materialized_bytes.max(4).checked_mul(3)?)?
            .checked_add(std::mem::size_of::<sha2::Sha256>())
            .map(|bytes| (bytes, 1))
    }

    /// Opens the same literal path with CLOEXEC and final-component NOFOLLOW.
    ///
    /// # Errors
    /// Retains the actual open/metadata cause and rejects repeated entry.
    pub fn capture_once_v3(&mut self, path: &Path) -> Result<(), FixedProtectedReadClosedV3> {
        if self.entered {
            return self.refuse();
        }
        self.entered = true;
        self.file = Some(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path),
        );
        let Some(Ok(file)) = self.file.as_ref() else {
            return Err(FixedProtectedReadClosedV3);
        };
        self.before = Some(file.metadata());
        if matches!(self.before, Some(Ok(_))) {
            Ok(())
        } else {
            Err(FixedProtectedReadClosedV3)
        }
    }

    /// Borrows only actual captured metadata for the caller's policy check.
    #[must_use]
    pub fn metadata_v3(&self) -> Option<&Metadata> {
        self.before.as_ref()?.as_ref().ok()
    }

    /// Reads exact admitted bytes using the existing positioned native engine.
    ///
    /// # Errors
    /// Retains partial bytes and the original read/EOF cause. No retry is made.
    pub fn read_bytes_once_v3(
        &mut self,
        admitted_bytes: usize,
    ) -> Result<(), FixedProtectedReadClosedV3> {
        self.begin_read(admitted_bytes as u64)?;
        self.bytes.resize(admitted_bytes, 0);
        let Some(Ok(file)) = self.file.as_ref() else {
            return self.refuse();
        };
        self.read = Some(super::read_exact_positioned_retaining_cause(
            file,
            &mut self.bytes,
        ));
        if matches!(self.read, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedProtectedReadClosedV3)
        }
    }

    /// Reads the exact admitted bytes and observes a real trailing-byte EOF.
    ///
    /// This shares the existing positioned reader and hash-path EOF destination.
    /// The old byte-only entry retains its original behavior.
    ///
    /// # Errors
    /// Retains partial bytes, the actual EOF/native cause and reentry refusal.
    pub fn read_exact_bytes_and_eof_once_v3(
        &mut self,
        admitted_bytes: usize,
    ) -> Result<(), FixedProtectedReadClosedV3> {
        self.exact_byte_eof = true;
        self.read_bytes_once_v3(admitted_bytes)?;
        self.observe_eof_v3(admitted_bytes as u64)
    }

    /// Hashes exact admitted bytes through the shared fixed64KiB SHA256 engine.
    ///
    /// # Errors
    /// Retains native hash/EOF failure, progress and its fixed partial buffer.
    pub fn hash_once_v3(&mut self, admitted_bytes: u64) -> Result<(), FixedProtectedReadClosedV3> {
        self.begin_read(admitted_bytes)?;
        let Some(Ok(file)) = self.file.as_ref() else {
            return self.refuse();
        };
        self.digest = Some(self.hash.hash_once_v2(file.as_fd(), admitted_bytes, |_| {}));
        if !matches!(self.digest, Some(Ok(_))) {
            return Err(FixedProtectedReadClosedV3);
        }
        self.observe_eof_v3(admitted_bytes)
    }

    fn observe_eof_v3(&mut self, admitted_bytes: u64) -> Result<(), FixedProtectedReadClosedV3> {
        let Some(Ok(file)) = self.file.as_ref() else {
            return self.refuse();
        };
        self.eof = Some(rustix::io::pread(file, &mut self.eof_byte, admitted_bytes));
        self.eof_validation = Some(if matches!(self.eof, Some(Ok(0))) {
            Ok(())
        } else {
            Err(UnexpectedTailV3)
        });
        if matches!(self.eof_validation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(FixedProtectedReadClosedV3)
        }
    }

    fn begin_read(&mut self, admitted_bytes: u64) -> Result<(), FixedProtectedReadClosedV3> {
        if self.read_entered
            || self.post_entered
            || self.refused
            || self
                .metadata_v3()
                .is_none_or(|metadata| metadata.len() != admitted_bytes)
        {
            return self.refuse();
        }
        self.read_entered = true;
        Ok(())
    }

    /// Always observes the same opened descriptor and the original named path.
    ///
    /// # Errors
    /// Retains both independent native results before interpreting either, and
    /// rejects substitution or a changed owner/mode/size/timestamp/link count.
    pub fn finish_once_v3(&mut self, path: &Path) -> Result<(), FixedProtectedReadClosedV3> {
        if self.post_entered {
            return self.refuse();
        }
        self.post_entered = true;
        self.after = self
            .file
            .as_ref()
            .and_then(|file| file.as_ref().ok())
            .map(File::metadata);
        self.named = Some(std::fs::symlink_metadata(path));
        self.comparison = Some(
            match (self.metadata_v3(), self.after.as_ref(), self.named.as_ref()) {
                (Some(before), Some(Ok(after)), Some(Ok(named)))
                    if same(before, after) && same(before, named) =>
                {
                    Ok(())
                }
                _ => Err(IdentityChangedV3),
            },
        );
        if self.completed_v3() {
            Ok(())
        } else {
            Err(FixedProtectedReadClosedV3)
        }
    }

    /// Reports actual full-positive native read and independent identity posts.
    #[must_use]
    pub fn completed_v3(&self) -> bool {
        let bytes_complete = matches!(self.read, Some(Ok(())))
            && (!self.exact_byte_eof || matches!(self.eof_validation, Some(Ok(()))));
        let hash_complete = matches!(self.digest, Some(Ok(_))) && matches!(self.eof, Some(Ok(0)));
        !self.refused
            && matches!(self.comparison, Some(Ok(())))
            && self.post_entered
            && (bytes_complete || hash_complete)
    }

    /// Borrows the actual measured digest only after full-positive posts.
    #[must_use]
    pub fn digest_v3(&self) -> Option<[u8; 32]> {
        if !self.completed_v3() {
            return None;
        }
        self.digest.as_ref()?.as_ref().ok().copied()
    }

    /// Moves pure bytes only after the complete same-file native phase.
    #[must_use]
    pub fn take_bytes_completed_v3(&mut self) -> Option<Vec<u8>> {
        if self.bytes_taken || !self.completed_v3() || !matches!(self.read, Some(Ok(()))) {
            return None;
        }
        self.bytes_taken = true;
        Some(std::mem::take(&mut self.bytes))
    }

    /// Borrows complete bytes while their actual file original stays owned.
    ///
    /// A caller validating secret file contents can keep the original bytes
    /// resident on failure. This lends no native handle or path permission.
    #[must_use]
    pub fn bytes_completed_v3(&self) -> Option<&[u8]> {
        if !self.completed_v3() || !matches!(self.read, Some(Ok(()))) {
            return None;
        }
        Some(&self.bytes)
    }

    /// Reports actual unchanged absence across the entered open and named post.
    ///
    /// Both native ENOENT originals remain retained. This is only comparison
    /// DATA for an optional absent file; no read bytes, role or authority arise.
    #[must_use]
    pub fn absent_through_post_v3(&self) -> bool {
        let absent = |result: &Option<std::io::Result<_>>| {
            result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        };
        self.entered
            && self.post_entered
            && !self.refused
            && absent(&self.file)
            && self
                .named
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }

    /// Borrows the earliest native error without changing custody or sampling.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.file
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.before.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.read.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.hash.failure().map(|cause| cause as _))
            .or_else(|| self.eof.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.eof_validation
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.named.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.comparison
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    fn refuse<T>(&mut self) -> Result<T, FixedProtectedReadClosedV3> {
        self.refused = true;
        Err(FixedProtectedReadClosedV3)
    }
}

fn same(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn optional_absence_requires_actual_named_after_absence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("optional");
        let mut original = FixedProtectedReadOriginalV3::new();
        assert!(original.capture_once_v3(&path).is_err());
        assert!(!original.absent_through_post_v3());

        std::fs::write(&path, b"appeared").unwrap();
        assert!(original.finish_once_v3(&path).is_err());
        assert!(!original.absent_through_post_v3());
        assert_eq!(
            original
                .failure()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(original.named.as_ref().unwrap().is_ok());
    }

    #[test]
    fn unchanged_absence_retains_both_native_errors_without_read_completion() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("optional");
        let mut original = FixedProtectedReadOriginalV3::new();
        assert!(original.capture_once_v3(&path).is_err());
        assert!(original.finish_once_v3(&path).is_err());
        assert!(original.absent_through_post_v3());
        assert!(!original.completed_v3());
        assert!(original.bytes_completed_v3().is_none());
        assert!(original.file.as_ref().unwrap().is_err());
        assert!(original.named.as_ref().unwrap().is_err());
    }

    #[test]
    fn positive_hash_never_bypasses_the_independent_identity_post() {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"fixed").unwrap();
        let mut original = FixedProtectedReadOriginalV3::new();
        original.capture_once_v3(file.path()).unwrap();
        original.hash_once_v3(5).unwrap();
        assert!(!original.completed_v3());

        std::fs::remove_file(file.path()).unwrap();
        assert!(original.finish_once_v3(file.path()).is_err());

        assert!(matches!(original.digest, Some(Ok(_))));
        assert_eq!(original.eof, Some(Ok(0)));
        assert!(!original.completed_v3());
        assert!(original.digest_v3().is_none());
        assert!(original.file.as_ref().unwrap().is_ok());
    }

    #[test]
    fn exact_byte_read_requires_a_real_eof_and_retains_late_tail() {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"fixed").unwrap();
        let mut original = FixedProtectedReadOriginalV3::new();
        original.capture_once_v3(file.path()).unwrap();
        original.exact_byte_eof = true;
        original.read_bytes_once_v3(5).unwrap();

        file.write_all(b"tail").unwrap();
        assert!(original.observe_eof_v3(5).is_err());
        assert_eq!(original.eof, Some(Ok(1)));
        assert_eq!(original.bytes, b"fixed");
        assert!(original.finish_once_v3(file.path()).is_err());
        assert!(!original.completed_v3());
        assert!(original.bytes_completed_v3().is_none());
        assert!(original.failure().is_some());
        assert!(original.file.as_ref().unwrap().is_ok());
    }

    #[test]
    fn unexpected_tail_keeps_actual_count_byte_and_both_posts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        std::fs::write(&path, b"ab").unwrap();
        let mut original = FixedProtectedReadOriginalV3::new();
        original.capture_once_v3(&path).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"z")
            .unwrap();

        assert!(original.hash_once_v3(2).is_err());
        assert!(original.finish_once_v3(&path).is_err());

        assert!(matches!(original.eof, Some(Ok(1))));
        assert_eq!(original.eof_byte, [b'z']);
        assert!(original.after.as_ref().unwrap().is_ok());
        assert!(original.named.as_ref().unwrap().is_ok());
        assert!(!original.completed_v3());
        assert!(original.failure().unwrap().to_string().contains("beyond"));
    }

    #[test]
    fn streams_actual_image_through_shared_sha256_without_materializing_image() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        let bytes =
            vec![37; 2 * aos_linux_descriptors::positional_hash::POSITIONAL_HASH_BUFFER_BYTES_V2 + 31];
        std::fs::write(&path, &bytes).unwrap();
        let mut original = FixedProtectedReadOriginalV3::new();

        original.capture_once_v3(&path).unwrap();
        original.hash_once_v3(bytes.len() as u64).unwrap();
        original.finish_once_v3(&path).unwrap();

        assert_eq!(
            original.digest_v3().unwrap(),
            <[u8; 32]>::from(sha2::Sha256::digest(&bytes))
        );
        assert!(original.bytes.is_empty());
        assert_eq!(original.hash.confirmed_bytes_v2(), bytes.len() as u64);
        assert!(original.failure().is_none());
    }

    #[test]
    fn changed_name_retains_actual_original_fd_and_all_native_posts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        std::fs::write(&path, b"one").unwrap();
        let mut original = FixedProtectedReadOriginalV3::new();
        original.capture_once_v3(&path).unwrap();
        original.read_bytes_once_v3(3).unwrap();
        let fd = original
            .file
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_raw_fd();
        let held = format!("/proc/self/fd/{fd}");
        std::fs::rename(&path, directory.path().join("old")).unwrap();
        std::fs::write(&path, b"two").unwrap();

        assert!(original.finish_once_v3(&path).is_err());
        assert!(original.after.as_ref().unwrap().is_ok());
        assert!(original.named.as_ref().unwrap().is_ok());
        assert!(std::fs::read_link(&held).is_ok());
        assert!(original.take_bytes_completed_v3().is_none());
        assert!(original.capture_once_v3(&path).is_err());
        assert!(std::fs::read_link(&held).is_ok());

        drop(original);
        assert!(std::fs::read_link(held).is_err());
    }

    #[test]
    fn actual_short_read_keeps_prefix_and_still_reaches_independent_posts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"abcdef").unwrap();
        let mut original = FixedProtectedReadOriginalV3::new();
        original.capture_once_v3(&path).unwrap();
        file.set_len(3).unwrap();

        assert!(original.read_bytes_once_v3(6).is_err());
        assert!(original.finish_once_v3(&path).is_err());
        assert_eq!(&original.bytes[..3], b"abc");
        assert!(original.after.as_ref().unwrap().is_ok());
        assert!(original.named.as_ref().unwrap().is_ok());
        assert!(original.failure().is_some());
        file.set_len(6).unwrap();
        assert!(original.read_bytes_once_v3(6).is_err());
        assert!(original.take_bytes_completed_v3().is_none());
    }
}
