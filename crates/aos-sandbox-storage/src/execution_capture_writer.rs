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

const RESULT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-write-result.v1\0";
const READBACK_BUFFER_BYTES: usize = 8192;

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
}

impl StreamFileV1 {
    fn new(file: File, maximum_bytes: u64) -> Result<Self, CaptureWriteErrorV1> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.len() != 0
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(CaptureWriteErrorV1::InvalidBacking);
        }

        Ok(Self {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            maximum_bytes,
            captured_bytes: 0,
            truncated: false,
            eof: false,
            write_digest: Sha256::new(),
        })
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

        self.file.write_all(&chunk[..kept_length])?;
        self.write_digest.update(&chunk[..kept_length]);
        self.captured_bytes += kept_bytes;
        self.truncated |= kept_bytes != chunk_bytes;
        Ok(())
    }

    fn readback(mut self) -> Result<UnboundCapturedStreamV1, CaptureWriteErrorV1> {
        if !self.eof {
            return Err(CaptureWriteErrorV1::Incomplete);
        }
        self.file.sync_data()?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut digest = Sha256::new();
        let mut remaining = self.captured_bytes;
        let mut buffer = [0_u8; READBACK_BUFFER_BYTES];
        while remaining != 0 {
            let length = usize::try_from(remaining.min(READBACK_BUFFER_BYTES as u64))
                .map_err(|_| CaptureWriteErrorV1::LengthOverflow)?;
            self.file.read_exact(&mut buffer[..length])?;
            digest.update(&buffer[..length]);
            remaining -= length as u64;
        }
        let mut extra = [0_u8; 1];
        let extra_bytes = self.file.read(&mut extra)?;
        let metadata = self.file.metadata()?;
        let readback_digest: [u8; 32] = digest.finalize().into();
        let written_digest: [u8; 32] = self.write_digest.finalize().into();
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
    pub(crate) fn new(
        retained: &ProtectedRetainedCaptureV1,
        stdout: File,
        stderr: File,
    ) -> Result<Self, CaptureWriteErrorV1> {
        if retained.admitted_bytes() == 0
            || retained
                .maximum_stdout_bytes()
                .checked_add(retained.maximum_stderr_bytes())
                != Some(retained.admitted_bytes())
        {
            return Err(CaptureWriteErrorV1::InvalidClaim);
        }
        let stdout = StreamFileV1::new(stdout, retained.maximum_stdout_bytes())?;
        let stderr = StreamFileV1::new(stderr, retained.maximum_stderr_bytes())?;
        if stdout.device != stderr.device || stdout.inode == stderr.inode {
            return Err(CaptureWriteErrorV1::InvalidBacking);
        }

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
        if self.poisoned {
            return Err(CaptureWriteErrorV1::Poisoned);
        }
        if !self.stdout.eof || !self.stderr.eof {
            return Err(CaptureWriteErrorV1::Incomplete);
        }
        let stdout = self.stdout.readback()?;
        let stderr = self.stderr.readback()?;

        let mut digest = Sha256::new();
        digest.update(RESULT_DOMAIN);
        digest.update(self.record_digest.as_bytes());
        // This success shape exists only after both EOFs and file sync/readback.
        digest.update([1_u8, 1_u8, 1_u8]);
        for stream in [&stdout, &stderr] {
            digest.update(stream.maximum_bytes.to_be_bytes());
            digest.update(stream.captured_bytes.to_be_bytes());
            digest.update([u8::from(stream.truncated)]);
            digest.update(stream.content_digest.as_bytes());
        }
        Ok(UnboundCaptureWriteResultV1 {
            record_digest: self.record_digest,
            stdout,
            stderr,
            stdout_eof: true,
            stderr_eof: true,
            synced_readback: true,
            result_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
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
