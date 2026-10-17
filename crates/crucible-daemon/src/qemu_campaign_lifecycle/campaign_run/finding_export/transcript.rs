//! Append-only frame file that holds a final-snapshot finding export.
//!
//! The export is captured while the run's ephemeral repository is live and
//! read after it is torn down, so its exchanges are written to disk as they
//! arrive instead of being retained in memory. Each frame holds one
//! canonical request and its canonical response; one frame is therefore at
//! most two campaign service messages. The file is private to the run that
//! wrote it and is removed when the last handle to it drops.
//!
//! ```text
//! "crucible.daemon.finding-export-transcript.v1\0"
//! campaign_length:u16be || campaign_name_utf8
//! snapshot_length:u16be || snapshot_id_text_utf8
//! repeated frame_count times:
//!   kind:u8                  # 1 finding query, 2 finding object,
//!                            # 3 occurrence query, 4 occurrence object,
//!                            # 5 triage-replay segment
//!   request_length:u32be  || canonical request bytes
//!   response_length:u32be || canonical response bytes
//! trailer:
//!   kind:u8 = 0
//!   frame_count:u64be
//!   digest[32]               # BLAKE3 of every preceding byte
//! EOF
//! ```
//!
//! A transcript is written under a `.partial` name and renamed to its final
//! name only after the trailer is synchronized, so a crash never leaves a
//! file that looks complete. Names carry the writing process ID and a
//! process-local ordinal, so runs sharing one directory never collide:
//!
//! ```text
//! <directory>/
//!   <pid>.<n>.transcript       complete, synchronized transcript
//!   .<pid>.<n>.partial         transcript still being written
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_campaign::{CampaignName, CampaignSnapshotId, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES};

const TRANSCRIPT_MAGIC: &[u8] = b"crucible.daemon.finding-export-transcript.v1\0";
const TRAILER_TAG: u8 = 0;
const TRAILER_BYTES: u64 = 1 + 8 + 32;
const MAX_HEADER_FIELD_BYTES: usize = 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Distinguishes transcripts written concurrently by one process.
static TRANSCRIPT_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// Kind tag of one transcript frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameKind {
    FindingQuery,
    FindingObject,
    OccurrenceQuery,
    OccurrenceObject,
    TriageReplaySegment,
}

impl FrameKind {
    const fn tag(self) -> u8 {
        match self {
            Self::FindingQuery => 1,
            Self::FindingObject => 2,
            Self::OccurrenceQuery => 3,
            Self::OccurrenceObject => 4,
            Self::TriageReplaySegment => 5,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::FindingQuery),
            2 => Some(Self::FindingObject),
            3 => Some(Self::OccurrenceQuery),
            4 => Some(Self::OccurrenceObject),
            5 => Some(Self::TriageReplaySegment),
            _ => None,
        }
    }
}

/// Failure while appending to a transcript.
#[derive(Debug)]
pub(super) enum TranscriptWriteError {
    /// The transcript would exceed its owner's disk quota.
    Quota,
    /// The transcript directory or file rejected a write.
    Io(io::Error),
}

impl From<io::Error> for TranscriptWriteError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// Failure while reading a transcript back.
#[derive(Debug)]
pub(super) enum TranscriptReadError {
    /// The file could not be opened or read to its end.
    Io(io::Error),
    /// The bytes do not form the transcript its handle describes.
    Malformed(&'static str),
}

impl From<io::Error> for TranscriptReadError {
    fn from(source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            Self::Malformed("finding export transcript is truncated")
        } else {
            Self::Io(source)
        }
    }
}

/// Complete transcript file, removed when the last handle drops.
#[derive(Debug)]
pub(super) struct TranscriptFile {
    path: PathBuf,
}

impl TranscriptFile {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TranscriptFile {
    fn drop(&mut self) {
        // Removal is best effort: the file is private to this run and is
        // never read again, so a leftover only costs disk until the owner
        // clears its run-state directory.
        let _ = fs::remove_file(&self.path);
    }
}

/// Terminal identity of one complete transcript.
#[derive(Clone, Debug)]
pub(super) struct SealedTranscript {
    pub(super) file: Arc<TranscriptFile>,
    pub(super) frames: u64,
    pub(super) bytes: u64,
    pub(super) digest: [u8; 32],
}

/// In-flight transcript path, removed unless the transcript is sealed.
struct PartialTranscript {
    path: PathBuf,
    armed: bool,
}

impl Drop for PartialTranscript {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Streaming writer for one transcript.
pub(super) struct TranscriptWriter {
    partial: PartialTranscript,
    final_path: PathBuf,
    file: BufWriter<File>,
    hasher: blake3::Hasher,
    bytes: u64,
    maximum_bytes: u64,
    frames: u64,
}

impl TranscriptWriter {
    /// Creates a new private transcript in `directory` and writes its header.
    ///
    /// The directory and any missing parents are created owner-only. The
    /// quota covers every byte of the finished file, including the trailer.
    pub(super) fn create(
        directory: &Path,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
        maximum_bytes: u64,
    ) -> Result<Self, TranscriptWriteError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;

        let ordinal = TRANSCRIPT_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let process = std::process::id();
        let partial_path = directory.join(format!(".{process}.{ordinal}.partial"));
        let final_path = directory.join(format!("{process}.{ordinal}.transcript"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial_path)?;

        let mut writer = Self {
            partial: PartialTranscript {
                path: partial_path,
                armed: true,
            },
            final_path,
            file: BufWriter::new(file),
            hasher: blake3::Hasher::new(),
            bytes: 0,
            maximum_bytes,
            frames: 0,
        };
        let campaign = campaign.as_str().as_bytes();
        let snapshot = snapshot.to_text();
        let header_bytes =
            TRANSCRIPT_MAGIC.len() as u64 + 2 + campaign.len() as u64 + 2 + snapshot.len() as u64;
        writer.reserve(header_bytes)?;
        writer.write_hashed(TRANSCRIPT_MAGIC)?;
        writer.write_header_field(campaign)?;
        writer.write_header_field(snapshot.as_bytes())?;
        Ok(writer)
    }

    /// Appends one canonical exchange as a frame.
    pub(super) fn append(
        &mut self,
        kind: FrameKind,
        request: &[u8],
        response: &[u8],
    ) -> Result<(), TranscriptWriteError> {
        let request_length = message_length(request)?;
        let response_length = message_length(response)?;
        let frame_bytes = 1 + 4 + u64::from(request_length) + 4 + u64::from(response_length);
        self.reserve(frame_bytes)?;

        self.write_hashed(&[kind.tag()])?;
        self.write_hashed(&request_length.to_be_bytes())?;
        self.write_hashed(request)?;
        self.write_hashed(&response_length.to_be_bytes())?;
        self.write_hashed(response)?;
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(TranscriptWriteError::Quota)?;
        Ok(())
    }

    /// Writes the trailer, synchronizes the file, and gives it its final name.
    pub(super) fn seal(mut self) -> Result<SealedTranscript, TranscriptWriteError> {
        self.write_hashed(&[TRAILER_TAG])?;
        self.write_hashed(&self.frames.to_be_bytes())?;
        let digest = *self.hasher.finalize().as_bytes();
        self.file.write_all(&digest)?;
        self.bytes += 32;

        let file = self
            .file
            .into_inner()
            .map_err(|error| TranscriptWriteError::Io(error.into_error()))?;
        file.sync_all()?;
        drop(file);
        fs::rename(&self.partial.path, &self.final_path)?;
        self.partial.armed = false;

        Ok(SealedTranscript {
            file: Arc::new(TranscriptFile {
                path: self.final_path,
            }),
            frames: self.frames,
            bytes: self.bytes,
            digest,
        })
    }

    /// Rejects a write that would leave no room for the trailer in the quota.
    fn reserve(&self, additional: u64) -> Result<(), TranscriptWriteError> {
        let required = self
            .bytes
            .checked_add(additional)
            .and_then(|bytes| bytes.checked_add(TRAILER_BYTES))
            .ok_or(TranscriptWriteError::Quota)?;
        if required > self.maximum_bytes {
            return Err(TranscriptWriteError::Quota);
        }
        Ok(())
    }

    fn write_header_field(&mut self, value: &[u8]) -> Result<(), TranscriptWriteError> {
        if value.len() > MAX_HEADER_FIELD_BYTES {
            return Err(TranscriptWriteError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "finding export transcript header field exceeds its bound",
            )));
        }
        // The bound above keeps the length representable.
        self.write_hashed(&(value.len() as u16).to_be_bytes())?;
        self.write_hashed(value)
    }

    fn write_hashed(&mut self, bytes: &[u8]) -> Result<(), TranscriptWriteError> {
        self.file.write_all(bytes)?;
        self.hasher.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(())
    }
}

fn message_length(message: &[u8]) -> Result<u32, TranscriptWriteError> {
    if message.len() > MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES {
        return Err(TranscriptWriteError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "finding export exchange exceeds the campaign service message bound",
        )));
    }
    u32::try_from(message.len()).map_err(|_| TranscriptWriteError::Quota)
}

/// One raw frame read back from a transcript.
pub(super) struct RawFrame {
    pub(super) kind: FrameKind,
    pub(super) request: Vec<u8>,
    pub(super) response: Vec<u8>,
}

/// Streaming reader that authenticates a transcript against its handle.
///
/// The reader checks the header against the expected campaign and snapshot
/// before the first frame, bounds every length by the service message limit,
/// and checks the trailer's count and digest against both the bytes read and
/// the values recorded when the transcript was sealed. A caller has read the
/// complete transcript only once [`TranscriptReader::next_frame`] returns
/// `Ok(None)`.
pub(super) struct TranscriptReader {
    file: Arc<TranscriptFile>,
    reader: BufReader<File>,
    hasher: blake3::Hasher,
    frames: u64,
    expected_frames: u64,
    expected_digest: [u8; 32],
    finished: bool,
}

impl TranscriptReader {
    pub(super) fn open(
        sealed: &SealedTranscript,
        campaign: &CampaignName,
        snapshot: CampaignSnapshotId,
    ) -> Result<Self, TranscriptReadError> {
        let file = File::open(sealed.file.path())?;
        let mut reader = Self {
            file: Arc::clone(&sealed.file),
            reader: BufReader::with_capacity(READ_BUFFER_BYTES, file),
            hasher: blake3::Hasher::new(),
            frames: 0,
            expected_frames: sealed.frames,
            expected_digest: sealed.digest,
            finished: false,
        };

        let magic = reader.read_hashed(TRANSCRIPT_MAGIC.len())?;
        if magic != TRANSCRIPT_MAGIC {
            return Err(TranscriptReadError::Malformed(
                "finding export transcript has an unsupported magic or version",
            ));
        }
        let header_campaign = reader.read_header_field()?;
        let header_snapshot = reader.read_header_field()?;
        if header_campaign != campaign.as_str().as_bytes()
            || header_snapshot != snapshot.to_text().as_bytes()
        {
            return Err(TranscriptReadError::Malformed(
                "finding export transcript names another campaign or snapshot",
            ));
        }
        Ok(reader)
    }

    /// Returns the next frame, or `None` after the authenticated trailer.
    pub(super) fn next_frame(&mut self) -> Result<Option<RawFrame>, TranscriptReadError> {
        if self.finished {
            return Ok(None);
        }
        let tag = self.read_hashed(1)?[0];
        if tag == TRAILER_TAG {
            self.read_trailer()?;
            self.finished = true;
            return Ok(None);
        }

        let kind = FrameKind::from_tag(tag).ok_or(TranscriptReadError::Malformed(
            "finding export transcript has an unknown frame kind",
        ))?;
        if self.frames >= self.expected_frames {
            return Err(TranscriptReadError::Malformed(
                "finding export transcript has more frames than it was sealed with",
            ));
        }
        let request = self.read_message()?;
        let response = self.read_message()?;
        self.frames += 1;
        Ok(Some(RawFrame {
            kind,
            request,
            response,
        }))
    }

    pub(super) fn file(&self) -> &Arc<TranscriptFile> {
        &self.file
    }

    fn read_trailer(&mut self) -> Result<(), TranscriptReadError> {
        let count = self.read_hashed(8)?;
        let count = u64::from_be_bytes(
            count
                .try_into()
                .map_err(|_| TranscriptReadError::Malformed("finding export trailer is short"))?,
        );
        let computed = *self.hasher.finalize().as_bytes();
        let mut recorded = [0_u8; 32];
        self.reader.read_exact(&mut recorded)?;

        if count != self.frames
            || count != self.expected_frames
            || recorded != computed
            || recorded != self.expected_digest
        {
            return Err(TranscriptReadError::Malformed(
                "finding export transcript trailer does not match its frames or seal",
            ));
        }
        let mut trailing = [0_u8; 1];
        if self.reader.read(&mut trailing)? != 0 {
            return Err(TranscriptReadError::Malformed(
                "finding export transcript has bytes after its trailer",
            ));
        }
        Ok(())
    }

    fn read_message(&mut self) -> Result<Vec<u8>, TranscriptReadError> {
        let length = self.read_hashed(4)?;
        let length = u32::from_be_bytes(
            length
                .try_into()
                .map_err(|_| TranscriptReadError::Malformed("finding export length is short"))?,
        );
        let length = usize::try_from(length).map_err(|_| {
            TranscriptReadError::Malformed("finding export exchange length is unrepresentable")
        })?;
        if length > MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES {
            return Err(TranscriptReadError::Malformed(
                "finding export exchange exceeds the campaign service message bound",
            ));
        }
        self.read_hashed(length)
    }

    fn read_header_field(&mut self) -> Result<Vec<u8>, TranscriptReadError> {
        let length = self.read_hashed(2)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        if length > MAX_HEADER_FIELD_BYTES {
            return Err(TranscriptReadError::Malformed(
                "finding export transcript header field exceeds its bound",
            ));
        }
        self.read_hashed(length)
    }

    fn read_hashed(&mut self, length: usize) -> Result<Vec<u8>, TranscriptReadError> {
        let mut bytes = vec![0_u8; length];
        self.reader.read_exact(&mut bytes)?;
        self.hasher.update(&bytes);
        Ok(bytes)
    }
}
