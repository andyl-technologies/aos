//! Portable journal frame encoding and verification.
//!
//! Writers emit version 2 frames. Readers also accept the version 1 frames
//! written by earlier releases, so a journal that already exists on a host
//! remains replayable and repairable. All integers are big-endian:
//!
//! ```text
//! offset  version 2 (written)        version 1 (read only)
//! 0       magic "AOSJNL2\n"          magic "AOSJNL1\n"
//! 8       u16 version = 2            u16 version = 1
//! 10      u16 flags = 0              u16 flags = 0
//! 12      u32 body length            u32 body length
//! 16      u64 sequence               u64 sequence
//! 24      body digest                previous-frame digest
//! 56      header digest              body digest
//! 88      body                       header digest
//! 120                                body
//! ```
//!
//! The header digest covers every preceding header byte and the body digest
//! covers the body; both use format-specific domain separation. Version 1 also
//! chained each frame to the digest of its predecessor. That chain is still
//! verified across a legacy prefix, but no caller ever retained the head
//! digest, so it never detected the loss of a complete suffix and version 2
//! drops it.
//!
//! An existing version 1 file keeps its legacy prefix and continues with
//! version 2 frames after the next append. A version 1 frame that follows a
//! version 2 frame is corruption.

use std::fmt;
use std::io::{self, Write};

use aos_core::{Sha256Digest, json, limits::JsonLimits};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

/// Length of the magic prefix that selects a frame layout.
pub(super) const MAGIC_LENGTH: usize = 8;
/// Length of the longest accepted header, which is the legacy layout.
pub(super) const MAX_HEADER_LENGTH: usize = FrameFormat::ChainedV1.header_length();

const DIGEST_LENGTH: usize = 32;
const LEGACY_FRAME_DIGEST_DOMAIN: &str = "aos.ability.execution.journal.frame/v1";

/// Names an on-disk frame layout accepted by the reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FrameFormat {
    /// Legacy frames that also carry the previous frame's digest.
    ChainedV1,
    /// Current frames protected by header and body checksums only.
    ChecksummedV2,
}

impl FrameFormat {
    /// The layout used for every appended frame.
    pub(super) const CURRENT: Self = Self::ChecksummedV2;

    fn from_magic(magic: &[u8]) -> Option<Self> {
        [Self::ChainedV1, Self::ChecksummedV2]
            .into_iter()
            .find(|format| format.magic().as_slice() == magic)
    }

    const fn magic(self) -> &'static [u8; MAGIC_LENGTH] {
        match self {
            Self::ChainedV1 => b"AOSJNL1\n",
            Self::ChecksummedV2 => b"AOSJNL2\n",
        }
    }

    const fn version(self) -> u16 {
        match self {
            Self::ChainedV1 => 1,
            Self::ChecksummedV2 => 2,
        }
    }

    /// Returns the complete header length, including its trailing digest.
    pub(super) const fn header_length(self) -> usize {
        match self {
            Self::ChainedV1 => 120,
            Self::ChecksummedV2 => 88,
        }
    }

    /// Returns the header prefix covered by the header digest.
    const fn checksummed_length(self) -> usize {
        self.header_length() - DIGEST_LENGTH
    }

    /// Returns the offset of the body digest, which precedes the header digest.
    const fn body_digest_offset(self) -> usize {
        self.checksummed_length() - DIGEST_LENGTH
    }

    const fn body_digest_domain(self) -> &'static str {
        match self {
            Self::ChainedV1 => "aos.ability.execution.journal.body/v1",
            Self::ChecksummedV2 => "aos.ability.execution.journal.body/v2",
        }
    }

    const fn header_digest_domain(self) -> &'static str {
        match self {
            Self::ChainedV1 => "aos.ability.execution.journal.header/v1",
            Self::ChecksummedV2 => "aos.ability.execution.journal.header/v2",
        }
    }
}

/// Resource limits enforced for every journal record body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    /// Maximum canonical JSON body length in bytes.
    pub max_body_bytes: usize,
    /// Maximum JSON nesting depth, including the root.
    pub max_depth: usize,
    /// Maximum combined array elements and object members.
    pub max_items: usize,
    /// Maximum UTF-8 byte length of a string or object member name.
    pub max_string_bytes: usize,
    /// Maximum number of frames retained in one journal file.
    pub max_records: usize,
    /// Maximum total journal file length, including frame headers.
    pub max_file_bytes: u64,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            max_depth: 32,
            max_items: 16_384,
            max_string_bytes: 256 * 1024,
            max_records: 65_536,
            max_file_bytes: 64 * 1024 * 1024,
        }
    }
}

impl JournalLimits {
    pub(super) const fn json(self) -> JsonLimits {
        JsonLimits {
            max_bytes: self.max_body_bytes,
            max_depth: self.max_depth,
            max_items: self.max_items,
            max_string_bytes: self.max_string_bytes,
        }
    }
}

/// Defines a trusted, prebounded record body accepted by the journal.
///
/// Implementations must validate their in-memory fields without first
/// serializing or cloning an attacker-controlled recursive value. The journal
/// additionally applies encoded JSON limits during append and recovery.
pub trait JournalPayload: Serialize + DeserializeOwned {
    /// Checks in-memory bounds before canonical serialization allocates output.
    ///
    /// # Errors
    ///
    /// Returns an error when any field or collection exceeds the journal's
    /// configured bounds.
    fn validate_for_journal(&self, limits: JournalLimits) -> Result<(), JournalError>;
}

/// One verified record recovered from the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord<T> {
    pub(super) sequence: u64,
    pub(super) body: T,
}

impl<T> JournalRecord<T> {
    /// Returns the one-based position of this record in the journal.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the decoded record body.
    #[must_use]
    pub const fn body(&self) -> &T {
        &self.body
    }

    /// Consumes the record and returns its decoded body.
    #[must_use]
    pub fn into_body(self) -> T {
        self.body
    }
}

/// Details about journal recovery and any safely discarded torn tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport<T> {
    pub(super) records: Vec<JournalRecord<T>>,
    pub(super) valid_bytes: u64,
    pub(super) discarded_torn_bytes: u64,
}

impl<T> RecoveryReport<T> {
    /// Returns the complete verified record prefix.
    #[must_use]
    pub fn records(&self) -> &[JournalRecord<T>] {
        &self.records
    }

    /// Consumes the report and returns the complete verified record prefix.
    #[must_use]
    pub fn into_records(self) -> Vec<JournalRecord<T>> {
        self.records
    }

    /// Returns the byte length of the complete verified prefix.
    #[must_use]
    pub const fn valid_bytes(&self) -> u64 {
        self.valid_bytes
    }

    /// Returns the number of bytes discarded from a partial final frame.
    #[must_use]
    pub const fn discarded_torn_bytes(&self) -> u64 {
        self.discarded_torn_bytes
    }
}

/// A failure to append, recover, or validate a durable journal.
#[derive(Debug, Error)]
pub enum JournalError {
    /// A filesystem operation failed.
    #[error("journal {operation} failed for {path}: {source}")]
    Io {
        /// The filesystem operation being performed.
        operation: &'static str,
        /// The affected path rendered for diagnostics.
        path: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// A journal body could not be encoded using canonical AOS JSON.
    #[error("journal record {sequence} could not be encoded: {source}")]
    Encode {
        /// The sequence number reserved for the record.
        sequence: u64,
        /// The canonical-encoding failure.
        #[source]
        source: anyhow::Error,
    },

    /// A complete frame failed structural, digest, or schema validation.
    #[error("corrupt journal frame {sequence} at byte {offset}: {reason}")]
    Corrupt {
        /// The expected sequence number at the failure.
        sequence: u64,
        /// The byte offset of the failing frame.
        offset: u64,
        /// The validation failure.
        reason: String,
    },

    /// A configured or representable journal bound was exceeded.
    #[error("journal limit exceeded: {0}")]
    Limit(String),

    /// The journal cannot accept more records after an uncertain write.
    #[error("journal append state is uncertain; reopen and recover it before appending")]
    RequiresRecovery,
}

/// Encodes one body as a complete frame in the current layout.
pub(super) fn encode<T>(
    body: &T,
    sequence: u64,
    limits: JournalLimits,
) -> Result<Vec<u8>, JournalError>
where
    T: JournalPayload,
{
    body.validate_for_journal(limits)?;
    preflight_encoded_size(body, limits.max_body_bytes).map_err(|error| match error {
        PreflightError::Limit => JournalError::Limit(format!(
            "record body exceeds the {} byte limit",
            limits.max_body_bytes
        )),
        PreflightError::Serialize(source) => JournalError::Encode {
            sequence,
            source: source.into(),
        },
    })?;
    let body = json::to_vec(body).map_err(|source| JournalError::Encode { sequence, source })?;
    if body.len() > limits.max_body_bytes {
        return Err(JournalError::Limit(format!(
            "record body has {} bytes, limit is {}",
            body.len(),
            limits.max_body_bytes
        )));
    }
    limits
        .json()
        .decode::<serde_json::Value>(&body, "journal record")
        .map_err(|error| JournalError::Limit(format!("record structure is invalid: {error}")))?;
    let body_length = u32::try_from(body.len()).map_err(|_| {
        JournalError::Limit("record body does not fit the frame length field".to_string())
    })?;

    let format = FrameFormat::CURRENT;
    let mut bytes = Vec::with_capacity(format.header_length() + body.len());
    bytes.extend_from_slice(format.magic());
    bytes.extend_from_slice(&format.version().to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&body_length.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(Sha256Digest::separated(format.body_digest_domain(), &body).as_bytes());
    let header_digest = Sha256Digest::separated(format.header_digest_domain(), &bytes);
    bytes.extend_from_slice(header_digest.as_bytes());
    bytes.extend_from_slice(&body);

    Ok(bytes)
}

#[derive(Debug)]
enum PreflightError {
    Limit,
    Serialize(serde_json::Error),
}

impl fmt::Display for PreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit => formatter.write_str("encoded byte limit"),
            Self::Serialize(error) => write!(formatter, "serialization failed: {error}"),
        }
    }
}

fn preflight_encoded_size<T>(value: &T, limit: usize) -> Result<(), PreflightError>
where
    T: Serialize,
{
    let mut writer = LimitedWriter {
        remaining: limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(PreflightError::Limit);
    }
    result.map_err(PreflightError::Serialize)
}

struct LimitedWriter {
    remaining: usize,
    exceeded: bool,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "serialized value exceeds configured byte limit",
            ));
        }

        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A complete header that passed structural and checksum validation.
pub(super) struct FrameHeader {
    format: FrameFormat,
    body_length: usize,
    body_digest: Sha256Digest,
}

impl FrameHeader {
    /// Returns the body length declared and checksummed by the header.
    pub(super) const fn body_length(&self) -> usize {
        self.body_length
    }
}

/// Tracks the expected position, sequence, and legacy chain while reading.
pub(super) struct FrameCursor {
    offset: u64,
    next_sequence: u64,
    last_format: Option<FrameFormat>,
    /// Digest of the preceding version 1 frame, or zero before the first.
    legacy_previous: Sha256Digest,
}

impl FrameCursor {
    /// Starts at the first frame of a journal.
    pub(super) fn new() -> Self {
        Self {
            offset: 0,
            next_sequence: 1,
            last_format: None,
            legacy_previous: Sha256Digest::from_bytes([0_u8; DIGEST_LENGTH]),
        }
    }

    /// Returns the byte offset of the next frame.
    pub(super) const fn offset(&self) -> u64 {
        self.offset
    }

    /// Selects the header length of a frame that begins with `magic`.
    ///
    /// An unrecognized magic is measured with the preceding frame's layout, or
    /// the current layout for a first frame. A shorter unreadable remainder is
    /// therefore still a torn tail, exactly as it was for that layout, while a
    /// complete unrecognized header is reported as corruption.
    pub(super) fn header_length(&self, magic: &[u8]) -> usize {
        FrameFormat::from_magic(magic)
            .or(self.last_format)
            .unwrap_or(FrameFormat::CURRENT)
            .header_length()
    }

    /// Validates a complete header at the cursor position.
    ///
    /// `header` holds exactly [`FrameCursor::header_length`] bytes. Version 1
    /// headers must also continue the legacy digest chain. This check precedes
    /// any body read, so a broken chain is corruption even when the body is torn.
    pub(super) fn read_header(
        &self,
        header: &[u8],
        limits: JournalLimits,
    ) -> Result<FrameHeader, JournalError> {
        let format = header
            .get(..MAGIC_LENGTH)
            .and_then(FrameFormat::from_magic)
            .ok_or_else(|| self.corrupt("invalid magic"))?;
        if header.len() != format.header_length() {
            return Err(self.corrupt("header length does not match its magic"));
        }
        if format == FrameFormat::ChainedV1 && self.last_format == Some(FrameFormat::ChecksummedV2)
        {
            return Err(self.corrupt("version 1 frame follows a version 2 frame"));
        }

        let checksummed = &header[..format.checksummed_length()];
        let recorded_header_digest = self.digest_field(header, format.checksummed_length())?;
        let actual_header_digest =
            Sha256Digest::separated(format.header_digest_domain(), checksummed);
        if recorded_header_digest != actual_header_digest {
            return Err(self.corrupt("header digest mismatch"));
        }

        let version = u16::from_be_bytes([header[8], header[9]]);
        if version != format.version() {
            return Err(self.corrupt(format!("unsupported frame version {version}")));
        }

        let flags = u16::from_be_bytes([header[10], header[11]]);
        if flags != 0 {
            return Err(self.corrupt(format!("unknown required flags 0x{flags:04x}")));
        }

        let sequence = u64::from_be_bytes(
            header[16..24]
                .try_into()
                .map_err(|_| self.corrupt("invalid sequence field"))?,
        );
        if sequence != self.next_sequence {
            return Err(self.corrupt(format!("found sequence {sequence}")));
        }

        if format == FrameFormat::ChainedV1
            && self.digest_field(header, 24)? != self.legacy_previous
        {
            return Err(self.corrupt("previous-record digest mismatch"));
        }

        let body_length = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
        let body_length = usize::try_from(body_length)
            .map_err(|_| self.corrupt("body length is not representable on this platform"))?;
        if body_length > limits.max_body_bytes {
            return Err(self.corrupt(format!(
                "body length {body_length} exceeds limit {}",
                limits.max_body_bytes
            )));
        }

        Ok(FrameHeader {
            format,
            body_length,
            body_digest: self.digest_field(header, format.body_digest_offset())?,
        })
    }

    /// Verifies and decodes a complete body, then advances past its frame.
    ///
    /// The body must match its checksum and be the exact canonical encoding of
    /// a schema-valid `T`.
    pub(super) fn accept<T>(
        &mut self,
        header_bytes: &[u8],
        header: &FrameHeader,
        body: &[u8],
        limits: JournalLimits,
    ) -> Result<JournalRecord<T>, JournalError>
    where
        T: JournalPayload,
    {
        if body.len() != header.body_length {
            return Err(self.corrupt("body length does not match the complete frame"));
        }
        let actual_body_digest = Sha256Digest::separated(header.format.body_digest_domain(), body);
        if header.body_digest != actual_body_digest {
            return Err(self.corrupt("body digest mismatch"));
        }
        let decoded = self.decode_body::<T>(body, limits)?;

        if header.format == FrameFormat::ChainedV1 {
            let mut frame = Vec::with_capacity(header_bytes.len() + body.len());
            frame.extend_from_slice(header_bytes);
            frame.extend_from_slice(body);
            self.legacy_previous = Sha256Digest::separated(LEGACY_FRAME_DIGEST_DOMAIN, frame);
        }

        let record = JournalRecord {
            sequence: self.next_sequence,
            body: decoded,
        };
        let frame_length = u64::try_from(header_bytes.len() + body.len()).map_err(|_| {
            JournalError::Limit("frame length is not representable as u64".to_string())
        })?;
        self.offset = self
            .offset
            .checked_add(frame_length)
            .ok_or_else(|| JournalError::Limit("journal offset overflow".to_string()))?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| JournalError::Limit("journal sequence number exhausted".to_string()))?;
        self.last_format = Some(header.format);

        Ok(record)
    }

    fn decode_body<T>(&self, body: &[u8], limits: JournalLimits) -> Result<T, JournalError>
    where
        T: JournalPayload,
    {
        let decoded: T = limits
            .json()
            .decode(body, "journal record")
            .map_err(|error| self.corrupt(format!("invalid body: {error}")))?;
        decoded
            .validate_for_journal(limits)
            .map_err(|error| self.corrupt(format!("body invariant violation: {error}")))?;
        preflight_encoded_size(&decoded, limits.max_body_bytes)
            .map_err(|error| self.corrupt(format!("decoded body exceeds bounds: {error}")))?;
        let canonical_body = json::to_vec(&decoded).map_err(|error| {
            self.corrupt(format!("body cannot be canonically re-encoded: {error}"))
        })?;
        if canonical_body != body {
            return Err(
                self.corrupt("body is not the exact canonical encoding of its typed schema")
            );
        }

        Ok(decoded)
    }

    fn digest_field(&self, header: &[u8], start: usize) -> Result<Sha256Digest, JournalError> {
        let bytes = header
            .get(start..start + DIGEST_LENGTH)
            .and_then(|field| <[u8; DIGEST_LENGTH]>::try_from(field).ok())
            .ok_or_else(|| self.corrupt("invalid digest field"))?;
        Ok(Sha256Digest::from_bytes(bytes))
    }

    fn corrupt(&self, reason: impl fmt::Display) -> JournalError {
        JournalError::Corrupt {
            sequence: self.next_sequence,
            offset: self.offset,
            reason: reason.to_string(),
        }
    }
}

/// Encodes a version 1 frame for legacy compatibility tests.
#[cfg(test)]
pub(super) fn encode_legacy<T>(body: &T, sequence: u64, previous: Option<&[u8]>) -> Vec<u8>
where
    T: Serialize,
{
    let format = FrameFormat::ChainedV1;
    let body = json::to_vec(body).expect("test body must encode");
    let previous_digest = previous.map_or_else(
        || Sha256Digest::from_bytes([0_u8; DIGEST_LENGTH]),
        |frame| Sha256Digest::separated(LEGACY_FRAME_DIGEST_DOMAIN, frame),
    );

    let mut bytes = Vec::with_capacity(format.header_length() + body.len());
    bytes.extend_from_slice(format.magic());
    bytes.extend_from_slice(&format.version().to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(body.len())
            .expect("test body fits")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(previous_digest.as_bytes());
    bytes.extend_from_slice(Sha256Digest::separated(format.body_digest_domain(), &body).as_bytes());
    let header_digest = Sha256Digest::separated(format.header_digest_domain(), &bytes);
    bytes.extend_from_slice(header_digest.as_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

/// Recomputes the header digest of a current-format header for tests.
#[cfg(test)]
pub(super) fn reseal_header(header: &mut [u8]) {
    let format = FrameFormat::CURRENT;
    let digest = Sha256Digest::separated(
        format.header_digest_domain(),
        &header[..format.checksummed_length()],
    );
    header[format.checksummed_length()..format.header_length()].copy_from_slice(digest.as_bytes());
}

/// Recomputes body and header digests of one current-format frame for tests.
#[cfg(test)]
pub(super) fn reseal_frame(frame: &mut [u8]) {
    let format = FrameFormat::CURRENT;
    let body_digest = Sha256Digest::separated(
        format.body_digest_domain(),
        &frame[format.header_length()..],
    );
    frame[format.body_digest_offset()..format.checksummed_length()]
        .copy_from_slice(body_digest.as_bytes());
    reseal_header(frame);
}
