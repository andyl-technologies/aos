//! Portable journal frame encoding and verification.
//!
//! Every frame is a fixed 88-byte header followed by its body. All integers
//! are big-endian:
//!
//! ```text
//! offset  field
//! 0       magic "AOSJNL2\n"
//! 8       u16 format version = 2
//! 10      u16 flags = 0
//! 12      u32 body length
//! 16      u64 sequence
//! 24      body digest
//! 56      header digest
//! 88      body
//! ```
//!
//! The header digest covers every preceding header byte and the body digest
//! covers the body, each with its own domain separation. Only this format is
//! read. A frame carrying the magic of an earlier journal format, such as
//! version 1 (`AOSJNL1`), fails with [`JournalError::UnsupportedFormat`].

use std::fmt;
use std::io::{self, Write};

use aos_core::{Sha256Digest, json, limits::JsonLimits};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

/// Length of the magic prefix that identifies the frame format.
pub(super) const MAGIC_LENGTH: usize = 8;
/// Complete header length, including the trailing header digest.
pub(super) const HEADER_LENGTH: usize = 88;

const MAGIC: &[u8; MAGIC_LENGTH] = b"AOSJNL2\n";
/// Prefix shared by every journal format's magic.
const MAGIC_FAMILY: &[u8] = b"AOSJNL";
const FORMAT_VERSION: u16 = 2;
const DIGEST_LENGTH: usize = 32;
const CHECKSUMMED_LENGTH: usize = HEADER_LENGTH - DIGEST_LENGTH;
const BODY_DIGEST_OFFSET: usize = CHECKSUMMED_LENGTH - DIGEST_LENGTH;
const BODY_DIGEST_DOMAIN: &str = "aos.ability.execution.journal.body/v2";
const HEADER_DIGEST_DOMAIN: &str = "aos.ability.execution.journal.header/v2";

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

    /// A frame uses a journal format this release does not read.
    #[error(
        "journal frame at byte {offset} uses unsupported format {format}; \
         only AOSJNL2 journals are supported"
    )]
    UnsupportedFormat {
        /// The byte offset of the frame.
        offset: u64,
        /// The frame's magic, rendered printably, such as `AOSJNL1`.
        format: String,
    },
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

    let mut bytes = Vec::with_capacity(HEADER_LENGTH + body.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&body_length.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(Sha256Digest::separated(BODY_DIGEST_DOMAIN, &body).as_bytes());
    let header_digest = Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &bytes);
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
    body_length: usize,
    body_digest: Sha256Digest,
}

impl FrameHeader {
    /// Returns the body length declared and checksummed by the header.
    pub(super) const fn body_length(&self) -> usize {
        self.body_length
    }
}

/// Tracks the expected position and sequence while reading frames.
pub(super) struct FrameCursor {
    offset: u64,
    next_sequence: u64,
}

impl FrameCursor {
    /// Starts at the first frame of a journal.
    pub(super) const fn new() -> Self {
        Self {
            offset: 0,
            next_sequence: 1,
        }
    }

    /// Returns the byte offset of the next frame.
    pub(super) const fn offset(&self) -> u64 {
        self.offset
    }

    /// Rejects a frame whose magic names another journal format.
    ///
    /// This runs as soon as the magic is available, before torn-tail handling,
    /// so a journal written in an earlier format is reported rather than
    /// truncated by recovery.
    pub(super) fn check_magic(&self, magic: &[u8]) -> Result<(), JournalError> {
        if magic != MAGIC && magic.starts_with(MAGIC_FAMILY) {
            return Err(JournalError::UnsupportedFormat {
                offset: self.offset,
                format: String::from_utf8_lossy(magic).trim_end().to_string(),
            });
        }
        Ok(())
    }

    /// Validates a complete header at the cursor position.
    pub(super) fn read_header(
        &self,
        header: &[u8; HEADER_LENGTH],
        limits: JournalLimits,
    ) -> Result<FrameHeader, JournalError> {
        self.check_magic(&header[..MAGIC_LENGTH])?;
        if &header[..MAGIC_LENGTH] != MAGIC {
            return Err(self.corrupt("invalid magic"));
        }

        let recorded_header_digest = self.digest_field(header, CHECKSUMMED_LENGTH)?;
        let actual_header_digest =
            Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &header[..CHECKSUMMED_LENGTH]);
        if recorded_header_digest != actual_header_digest {
            return Err(self.corrupt("header digest mismatch"));
        }

        let version = u16::from_be_bytes([header[8], header[9]]);
        if version != FORMAT_VERSION {
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
            body_length,
            body_digest: self.digest_field(header, BODY_DIGEST_OFFSET)?,
        })
    }

    /// Verifies and decodes a complete body, then advances past its frame.
    ///
    /// The body must match its checksum and be the exact canonical encoding of
    /// a schema-valid `T`.
    pub(super) fn accept<T>(
        &mut self,
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
        if header.body_digest != Sha256Digest::separated(BODY_DIGEST_DOMAIN, body) {
            return Err(self.corrupt("body digest mismatch"));
        }
        let decoded = self.decode_body::<T>(body, limits)?;

        let record = JournalRecord {
            sequence: self.next_sequence,
            body: decoded,
        };
        let frame_length = u64::try_from(HEADER_LENGTH + body.len()).map_err(|_| {
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

/// Recomputes the header digest of one frame header for tests.
#[cfg(test)]
pub(super) fn reseal_header(header: &mut [u8]) {
    let digest = Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &header[..CHECKSUMMED_LENGTH]);
    header[CHECKSUMMED_LENGTH..HEADER_LENGTH].copy_from_slice(digest.as_bytes());
}

/// Recomputes body and header digests of one complete frame for tests.
#[cfg(test)]
pub(super) fn reseal_frame(frame: &mut [u8]) {
    let body_digest = Sha256Digest::separated(BODY_DIGEST_DOMAIN, &frame[HEADER_LENGTH..]);
    frame[BODY_DIGEST_OFFSET..CHECKSUMMED_LENGTH].copy_from_slice(body_digest.as_bytes());
    reseal_header(frame);
}
