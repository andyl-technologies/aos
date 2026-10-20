//! Private per-stream retained-output writer, without mount or Host authority.
//!
//! The caller must supply two already-created, private, distinct files and
//! authenticated EOF events. Only a future Storage-owned worker can prove
//! that those files are on the dedicated ZFS capture mount and that no other
//! writer exists. Consequently this module returns an unbound write result,
//! never a physical reservation receipt or Host execution outcome.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::execution_output::ProtectedRetainedCaptureV1;

mod native_io;
pub(crate) use native_io::{CaptureFileIoOriginalV3, CaptureFileIoV3};

const RESULT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-write-result.v1\0";
const READBACK_BUFFER_BYTES: usize = 8192;

/// Bounds the compiled writer/error carriers and the sole readback scratch buffer.
pub(crate) fn capture_writer_receiving_bytes_v2() -> Option<usize> {
    let carriers = std::mem::size_of::<DetachedCaptureWriterV1>()
        .checked_add(std::mem::size_of::<CaptureWriterConstructionFailureV2>())?
        .checked_add(std::mem::size_of::<CaptureWriterFinishFailureV2>())?;
    carriers.checked_mul(3)?.checked_add(READBACK_BUFFER_BYTES)
}

/// Selects exactly one detached execution output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureStreamV1 {
    Stdout,
    Stderr,
}

/// Rejects an incomplete, corrupt, or unbounded capture write.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureWriteErrorV1 {
    /// The protected AOSEOR03 record is not a nonzero, exact-split capture.
    #[error("capture write claim is invalid")]
    InvalidClaim,
    /// Output file descriptors are not empty, private, distinct regular files.
    #[error("capture output file descriptors are invalid")]
    InvalidBacking,
    /// Both authenticated stream EOF events have not been observed.
    #[error("capture streams are incomplete")]
    Incomplete,
    /// A previous I/O failure makes the writer unusable.
    #[error("capture writer is poisoned")]
    Poisoned,
    /// A stream chunk length cannot be represented exactly.
    #[error("capture stream length exceeds the supported range")]
    LengthOverflow,
    /// Synced file content or identity changed between write and readback.
    #[error("capture file readback differs from the written prefix")]
    BackingMismatch,
    /// A file read, write, seek, or sync failed.
    #[error("capture file I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

struct StreamFileV1 {
    file: File,
    device: u64,
    inode: u64,
    maximum_bytes: u64,
    captured_bytes: u64,
    truncated: bool,
    eof: bool,
    write_digest: Sha256,
    native_io: Option<CaptureFileIoOriginalV3>,
}

impl StreamFileV1 {
    fn new_retaining_v2(
        file: File,
        maximum_bytes: u64,
    ) -> Result<Self, StreamFileConstructionFailureV2> {
        let mut observed_metadata = None;
        let identity = (|| -> Result<(u64, u64), CaptureWriteErrorV1> {
            observed_metadata = Some(file.metadata()?);
            let Some(metadata) = observed_metadata.as_ref() else {
                std::process::abort();
            };
            if !metadata.file_type().is_file()
                || metadata.len() != 0
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o7777 != 0o600
            {
                return Err(CaptureWriteErrorV1::InvalidBacking);
            }
            Ok((metadata.dev(), metadata.ino()))
        })();
        match identity {
            Ok((device, inode)) => Ok(Self {
                file,
                device,
                inode,
                maximum_bytes,
                captured_bytes: 0,
                truncated: false,
                eof: false,
                write_digest: Sha256::new(),
                native_io: None,
            }),
            Err(error) => Err(StreamFileConstructionFailureV2 {
                file,
                observed_metadata,
                error,
            }),
        }
    }

    fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), CaptureWriteErrorV1> {
        if self.eof {
            return Err(CaptureWriteErrorV1::Incomplete);
        }
        let chunk_bytes =
            u64::try_from(chunk.len()).map_err(|_| CaptureWriteErrorV1::LengthOverflow)?;
        let remaining = self.maximum_bytes - self.captured_bytes;
        let kept_bytes = chunk_bytes.min(remaining);
        let kept_length =
            usize::try_from(kept_bytes).map_err(|_| CaptureWriteErrorV1::LengthOverflow)?;

        CaptureFileIoV3 { file: &mut self.file, original: self.native_io.as_mut() }
            .write_all(&chunk[..kept_length])?;
        self.write_digest.update(&chunk[..kept_length]);
        self.captured_bytes += kept_bytes;
        self.truncated |= kept_bytes != chunk_bytes;
        Ok(())
    }

    fn readback_retaining_v2(
        mut self,
    ) -> Result<UnboundCapturedStreamV1, StreamReadbackFailureV2> {
        let mut observed_metadata = None;
        match self.readback_inner_v2(&mut observed_metadata) {
            Ok(stream) => Ok(stream),
            Err(error) => Err(StreamReadbackFailureV2 {
                stream: self,
                observed_metadata,
                error,
            }),
        }
    }

    fn readback_inner_v2(
        &mut self,
        observed_metadata: &mut Option<std::fs::Metadata>,
    ) -> Result<UnboundCapturedStreamV1, CaptureWriteErrorV1> {
        if !self.eof {
            return Err(CaptureWriteErrorV1::Incomplete);
        }
        let mut file = CaptureFileIoV3 { file: &mut self.file, original: self.native_io.as_mut() };
        file.sync_data()?;
        file.seek(SeekFrom::Start(0))?;

        let mut digest = Sha256::new();
        let mut remaining = self.captured_bytes;
        let mut buffer = [0_u8; READBACK_BUFFER_BYTES];
        while remaining != 0 {
            let length = usize::try_from(remaining.min(READBACK_BUFFER_BYTES as u64))
                .map_err(|_| CaptureWriteErrorV1::LengthOverflow)?;
            file.read_exact(&mut buffer[..length])?;
            digest.update(&buffer[..length]);
            remaining -= length as u64;
        }
        let mut extra = [0_u8; 1];
        let extra_bytes = file.read(&mut extra)?;
        *observed_metadata = Some(file.metadata()?);
        let Some(metadata) = observed_metadata.as_ref() else {
            std::process::abort();
        };
        let readback_digest: [u8; 32] = digest.finalize().into();
        let written_digest: [u8; 32] = self.write_digest.clone().finalize().into();
        if extra_bytes != 0
            || metadata.len() != self.captured_bytes
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.nlink() != 1
            || readback_digest != written_digest
        {
            return Err(CaptureWriteErrorV1::BackingMismatch);
        }

        Ok(UnboundCapturedStreamV1 {
            maximum_bytes: self.maximum_bytes,
            captured_bytes: self.captured_bytes,
            truncated: self.truncated,
            content_digest: ObjectDigest::from_bytes(readback_digest),
        })
    }
}

struct StreamReadbackFailureV2 {
    stream: StreamFileV1,
    observed_metadata: Option<std::fs::Metadata>,
    error: CaptureWriteErrorV1,
}

impl StreamReadbackFailureV2 {
    fn into_ordinary_error(self) -> CaptureWriteErrorV1 {
        let Self {
            stream,
            observed_metadata,
            error,
        } = self;
        drop(observed_metadata);
        drop(stream);
        error
    }
}

struct StreamFileConstructionFailureV2 {
    file: File,
    observed_metadata: Option<std::fs::Metadata>,
    error: CaptureWriteErrorV1,
}

impl StreamFileConstructionFailureV2 {
    fn into_ordinary_error(self) -> CaptureWriteErrorV1 {
        let Self {
            file,
            observed_metadata,
            error,
        } = self;
        drop(observed_metadata);
        drop(file);
        error
    }
}

/// Retains both input files and the exact failed writer-construction prefix.
pub(crate) struct CaptureWriterConstructionFailureV2 {
    stdout_file: Option<File>,
    stderr_file: Option<File>,
    stdout: Option<StreamFileV1>,
    stderr: Option<StreamFileV1>,
    stream_error: Option<StreamFileConstructionFailureV2>,
    error: Option<CaptureWriteErrorV1>,
}

impl CaptureWriterConstructionFailureV2 {
    pub(crate) fn failure(&self) -> Option<&CaptureWriteErrorV1> {
        self.stream_error
            .as_ref()
            .map(|failure| &failure.error)
            .or(self.error.as_ref())
    }

    pub(super) fn into_ordinary_error(mut self) -> CaptureWriteErrorV1 {
        // An inner constructor's failed file retired before the outer locals.
        let error = match self.stream_error.take() {
            Some(failure) => failure.into_ordinary_error(),
            None => match self.error.take() {
                Some(error) => error,
                None => std::process::abort(),
            },
        };
        drop(self.stderr.take());
        drop(self.stdout.take());
        drop(self.stderr_file.take());
        drop(self.stdout_file.take());
        error
    }
}

impl std::fmt::Debug for CaptureWriterConstructionFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureWriterConstructionFailureV2")
            .field("error", &self.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for CaptureWriterConstructionFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("capture writer construction is incomplete"),
        }
    }
}

impl std::error::Error for CaptureWriterConstructionFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure().map(|error| error as _)
    }
}

/// Writes bounded stream prefixes while draining excess bytes to EOF.
///
/// A write error poisons the whole writer, so a partially written prefix can
/// never be transformed into a success-shaped result. This core does not own
/// the process pipes; its caller must supply real EOF events after draining.
pub(crate) struct DetachedCaptureWriterV1 {
    record_digest: ObjectDigest,
    stdout: StreamFileV1,
    stderr: StreamFileV1,
    poisoned: bool,
}

impl DetachedCaptureWriterV1 {
    pub(crate) fn install_native_io_once_v3(
        &mut self, context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
        boot: [u8; 16], cutoff: u64,
    ) -> Result<(), CaptureWriteErrorV1> {
        if self.stdout.native_io.is_some() || self.stderr.native_io.is_some()
            || self.stdout.captured_bytes != 0 || self.stderr.captured_bytes != 0
            || self.poisoned { return Err(CaptureWriteErrorV1::Poisoned); }
        self.stdout.native_io = Some(CaptureFileIoOriginalV3::from_worker_v3(context, boot, cutoff));
        self.stderr.native_io = Some(CaptureFileIoOriginalV3::from_worker_v3(context, boot, cutoff));
        Ok(())
    }

    pub(crate) fn native_io_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stdout.native_io.as_ref().and_then(CaptureFileIoOriginalV3::failure)
            .or_else(|| self.stderr.native_io.as_ref()?.failure())
    }

    pub(crate) fn new(
        retained: &ProtectedRetainedCaptureV1,
        stdout: File,
        stderr: File,
    ) -> Result<Self, CaptureWriteErrorV1> {
        Self::new_retaining_v2(retained, stdout, stderr)
            .map_err(CaptureWriterConstructionFailureV2::into_ordinary_error)
    }

    /// Uses the same validation engine and retains both files on any refusal.
    pub(crate) fn new_retaining_v2(
        retained: &ProtectedRetainedCaptureV1,
        stdout: File,
        stderr: File,
    ) -> Result<Self, CaptureWriterConstructionFailureV2> {
        let mut original = CaptureWriterConstructionFailureV2 {
            stdout_file: Some(stdout),
            stderr_file: Some(stderr),
            stdout: None,
            stderr: None,
            stream_error: None,
            error: None,
        };
        if retained.admitted_bytes() == 0
            || retained
                .maximum_stdout_bytes()
                .checked_add(retained.maximum_stderr_bytes())
                != Some(retained.admitted_bytes())
        {
            original.error = Some(CaptureWriteErrorV1::InvalidClaim);
            return Err(original);
        }
        let Some(stdout) = original.stdout_file.take() else {
            std::process::abort();
        };
        match StreamFileV1::new_retaining_v2(stdout, retained.maximum_stdout_bytes()) {
            Ok(stdout) => original.stdout = Some(stdout),
            Err(error) => {
                original.stream_error = Some(error);
                return Err(original);
            }
        }
        let Some(stderr) = original.stderr_file.take() else {
            std::process::abort();
        };
        match StreamFileV1::new_retaining_v2(stderr, retained.maximum_stderr_bytes()) {
            Ok(stderr) => original.stderr = Some(stderr),
            Err(error) => {
                original.stream_error = Some(error);
                return Err(original);
            }
        }
        let (Some(stdout), Some(stderr)) = (original.stdout.as_ref(), original.stderr.as_ref())
        else {
            std::process::abort();
        };
        if stdout.device != stderr.device || stdout.inode == stderr.inode {
            original.error = Some(CaptureWriteErrorV1::InvalidBacking);
            return Err(original);
        }
        let Some(stdout) = original.stdout.take() else {
            std::process::abort();
        };
        let Some(stderr) = original.stderr.take() else {
            std::process::abort();
        };
        Ok(Self {
            record_digest: retained.record_digest(),
            stdout,
            stderr,
            poisoned: false,
        })
    }

    pub(crate) fn write_chunk(
        &mut self,
        stream: CaptureStreamV1,
        chunk: &[u8],
    ) -> Result<(), CaptureWriteErrorV1> {
        if self.poisoned {
            return Err(CaptureWriteErrorV1::Poisoned);
        }
        let target = match stream {
            CaptureStreamV1::Stdout => &mut self.stdout,
            CaptureStreamV1::Stderr => &mut self.stderr,
        };
        if let Err(error) = target.write_chunk(chunk) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn finish_stream(
        &mut self,
        stream: CaptureStreamV1,
    ) -> Result<(), CaptureWriteErrorV1> {
        if self.poisoned {
            return Err(CaptureWriteErrorV1::Poisoned);
        }
        let target = match stream {
            CaptureStreamV1::Stdout => &mut self.stdout,
            CaptureStreamV1::Stderr => &mut self.stderr,
        };
        if target.eof {
            self.poisoned = true;
            return Err(CaptureWriteErrorV1::Incomplete);
        }
        target.eof = true;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<UnboundCaptureWriteResultV1, CaptureWriteErrorV1> {
        self.finish_retaining_v2()
            .map_err(CaptureWriterFinishFailureV2::into_ordinary_error)
    }

    /// Finishes the same EOF/readback engine without releasing a failed file prefix.
    pub(crate) fn finish_retaining_v2(
        self,
    ) -> Result<UnboundCaptureWriteResultV1, CaptureWriterFinishFailureV2> {
        let Self {
            record_digest,
            stdout,
            stderr,
            poisoned,
        } = self;
        let mut original = CaptureWriterFinishFailureV2 {
            stdout: Some(stdout),
            stderr: Some(stderr),
            stdout_readback: None,
            stream_error: None,
            error: None,
        };
        if poisoned {
            original.error = Some(CaptureWriteErrorV1::Poisoned);
            return Err(original);
        }
        if original.stdout.as_ref().is_none_or(|stream| !stream.eof)
            || original.stderr.as_ref().is_none_or(|stream| !stream.eof)
        {
            original.error = Some(CaptureWriteErrorV1::Incomplete);
            return Err(original);
        }

        let Some(stdout) = original.stdout.take() else {
            std::process::abort();
        };
        match stdout.readback_retaining_v2() {
            Ok(stdout) => original.stdout_readback = Some(stdout),
            Err(error) => {
                original.stream_error = Some(error);
                return Err(original);
            }
        }
        let Some(stderr) = original.stderr.take() else {
            std::process::abort();
        };
        let stderr = match stderr.readback_retaining_v2() {
            Ok(stderr) => stderr,
            Err(error) => {
                original.stream_error = Some(error);
                return Err(original);
            }
        };
        let Some(stdout) = original.stdout_readback.take() else {
            std::process::abort();
        };

        let result_digest = capture_write_result_digest_v3(record_digest, &stdout, &stderr);
        Ok(UnboundCaptureWriteResultV1 {
            record_digest: record_digest,
            stdout,
            stderr,
            stdout_eof: true,
            stderr_eof: true,
            synced_readback: true,
            result_digest,
        })
    }
}

/// Retains the exact failed stream, the other input, and completed readback DATA.
pub(crate) struct CaptureWriterFinishFailureV2 {
    stdout: Option<StreamFileV1>,
    stderr: Option<StreamFileV1>,
    stdout_readback: Option<UnboundCapturedStreamV1>,
    stream_error: Option<StreamReadbackFailureV2>,
    error: Option<CaptureWriteErrorV1>,
}

impl CaptureWriterFinishFailureV2 {
    pub(crate) fn native_io_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stream_error.as_ref().and_then(|failure| failure.stream.native_io.as_ref()?.failure())
            .or_else(|| self.stdout.as_ref()?.native_io.as_ref()?.failure())
            .or_else(|| self.stderr.as_ref()?.native_io.as_ref()?.failure())
    }

    pub(crate) fn failure(&self) -> Option<&CaptureWriteErrorV1> {
        self.stream_error
            .as_ref()
            .map(|failure| &failure.error)
            .or(self.error.as_ref())
    }

    pub(crate) fn into_ordinary_error(mut self) -> CaptureWriteErrorV1 {
        let error = match self.stream_error.take() {
            Some(failure) => failure.into_ordinary_error(),
            None => match self.error.take() {
                Some(error) => error,
                None => std::process::abort(),
            },
        };
        // After an inner failure only its unvisited sibling remains. Before
        // either readback, Self's declaration order was stdout then stderr.
        drop(self.stdout.take());
        drop(self.stderr.take());
        error
    }
}

impl std::fmt::Debug for CaptureWriterFinishFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureWriterFinishFailureV2")
            .field("error", &self.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for CaptureWriterFinishFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("capture writer readback is incomplete"),
        }
    }
}

impl std::error::Error for CaptureWriterFinishFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure().map(|error| error as _)
    }
}

/// Describes one synced, independently read-back stream prefix.
pub(crate) struct UnboundCapturedStreamV1 {
    pub(crate) maximum_bytes: u64,
    pub(crate) captured_bytes: u64,
    pub(crate) truncated: bool,
    pub(crate) content_digest: ObjectDigest,
}

/// Describes both stream prefixes without asserting ZFS or process provenance.
pub(crate) struct UnboundCaptureWriteResultV1 {
    pub(crate) record_digest: ObjectDigest,
    pub(crate) stdout: UnboundCapturedStreamV1,
    pub(crate) stderr: UnboundCapturedStreamV1,
    pub(crate) stdout_eof: bool,
    pub(crate) stderr_eof: bool,
    pub(crate) synced_readback: bool,
    pub(crate) result_digest: ObjectDigest,
}

#[cfg(test)]
mod retained_tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn private_stream() -> (std::path::PathBuf, StreamFileV1) {
        let path = std::env::temp_dir().join(format!(
            "aos-capture-readback-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed),
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let stream = match StreamFileV1::new_retaining_v2(file, 32) {
            Ok(stream) => stream,
            Err(_) => panic!("new private file must pass stream validation"),
        };
        (path, stream)
    }

    #[test]
    fn failed_readback_keeps_same_file_and_observed_identity() {
        let (path, mut stream) = private_stream();
        stream.file.write_all(b"untracked").unwrap();
        stream.eof = true;
        let inode = stream.inode;

        let failure = match stream.readback_retaining_v2() {
            Ok(_) => panic!("untracked file contents must refuse readback"),
            Err(failure) => failure,
        };

        assert!(matches!(&failure.error, CaptureWriteErrorV1::BackingMismatch));
        assert_eq!(failure.stream.file.metadata().unwrap().ino(), inode);
        assert_eq!(failure.observed_metadata.as_ref().unwrap().ino(), inode);
        drop(failure);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn incomplete_finish_keeps_both_original_streams() {
        let (stdout_path, stdout) = private_stream();
        let (stderr_path, stderr) = private_stream();
        let stdout_inode = stdout.inode;
        let stderr_inode = stderr.inode;
        let writer = DetachedCaptureWriterV1 {
            record_digest: ObjectDigest::from_bytes([9; 32]),
            stdout,
            stderr,
            poisoned: false,
        };

        let failure = writer.finish_retaining_v2().err().unwrap();

        assert!(matches!(failure.failure(), Some(CaptureWriteErrorV1::Incomplete)));
        assert_eq!(failure.stdout.as_ref().unwrap().file.metadata().unwrap().ino(), stdout_inode);
        assert_eq!(failure.stderr.as_ref().unwrap().file.metadata().unwrap().ino(), stderr_inode);
        assert!(failure.stream_error.is_none());
        drop(failure);
        std::fs::remove_file(stdout_path).unwrap();
        std::fs::remove_file(stderr_path).unwrap();
    }
}

pub(crate) fn capture_write_result_digest_v3(
    record_digest: ObjectDigest, stdout: &UnboundCapturedStreamV1, stderr: &UnboundCapturedStreamV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RESULT_DOMAIN);
    digest.update(record_digest.as_bytes());
    // This success shape exists only after both EOFs and file sync/readback.
    digest.update([1_u8, 1_u8, 1_u8]);
    for stream in [&stdout, &stderr] {
        digest.update(stream.maximum_bytes.to_be_bytes());
        digest.update(stream.captured_bytes.to_be_bytes());
        digest.update([u8::from(stream.truncated)]);
        digest.update(stream.content_digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}
