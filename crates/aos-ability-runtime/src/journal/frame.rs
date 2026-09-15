//! Portable journal frame encoding and verification.

use std::fmt;
use std::io::{self, Write};

use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub(super) const MAGIC: [u8; 8] = *b"AOSJNL1\n";
pub(super) const FORMAT_VERSION: u16 = 1;
pub(super) const HEADER_PREFIX_LENGTH: usize = 88;
pub(super) const HEADER_LENGTH: usize = 120;
const BODY_DIGEST_DOMAIN: &str = "aos.ability.execution.journal.body/v1";
pub(super) const HEADER_DIGEST_DOMAIN: &str = "aos.ability.execution.journal.header/v1";
const FRAME_DIGEST_DOMAIN: &str = "aos.ability.execution.journal.frame/v1";

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
    pub(super) digest: Sha256Digest,
    pub(super) body: T,
}

impl<T> JournalRecord<T> {
    /// Returns the one-based position of this record in the journal.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the digest chained into the following frame.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
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

pub(super) struct EncodedFrame {
    pub bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

pub(super) fn encode<T>(
    body: &T,
    sequence: u64,
    previous_digest: Sha256Digest,
    limits: JournalLimits,
) -> Result<EncodedFrame, JournalError>
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
    let body =
        canonical::to_vec(body).map_err(|source| JournalError::Encode { sequence, source })?;
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
        JournalError::Limit("record body does not fit the version 1 length field".to_string())
    })?;
    let body_digest = Sha256Digest::separated(BODY_DIGEST_DOMAIN, &body);

    let mut bytes = Vec::with_capacity(HEADER_LENGTH + body.len());
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&body_length.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(previous_digest.as_bytes());
    bytes.extend_from_slice(body_digest.as_bytes());
    let header_digest = Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &bytes);
    bytes.extend_from_slice(header_digest.as_bytes());
    bytes.extend_from_slice(&body);

    let digest = Sha256Digest::separated(FRAME_DIGEST_DOMAIN, &bytes);
    Ok(EncodedFrame { bytes, digest })
}

pub(super) struct DecodedFrame<T> {
    pub record: JournalRecord<T>,
    pub encoded_length: usize,
}

pub(super) fn decode<T>(
    header: &[u8; HEADER_LENGTH],
    body: &[u8],
    expected_sequence: u64,
    expected_previous: Sha256Digest,
    offset: u64,
    limits: JournalLimits,
) -> Result<DecodedFrame<T>, JournalError>
where
    T: JournalPayload,
{
    validate_header(
        header,
        body,
        expected_sequence,
        expected_previous,
        offset,
        limits,
    )?;

    let decoded: T = limits
        .json()
        .decode(body, "journal record")
        .map_err(|error| corrupt(expected_sequence, offset, format!("invalid body: {error}")))?;
    decoded.validate_for_journal(limits).map_err(|error| {
        corrupt(
            expected_sequence,
            offset,
            format!("body invariant violation: {error}"),
        )
    })?;
    preflight_encoded_size(&decoded, limits.max_body_bytes).map_err(|error| {
        corrupt(
            expected_sequence,
            offset,
            format!("decoded body exceeds bounds: {error}"),
        )
    })?;
    let canonical_body = canonical::to_vec(&decoded).map_err(|error| {
        corrupt(
            expected_sequence,
            offset,
            format!("body cannot be canonically re-encoded: {error}"),
        )
    })?;
    if canonical_body != body {
        return Err(corrupt(
            expected_sequence,
            offset,
            "body is not the exact canonical encoding of its typed schema",
        ));
    }

    let mut frame = Vec::with_capacity(HEADER_LENGTH + body.len());
    frame.extend_from_slice(header);
    frame.extend_from_slice(body);
    let digest = Sha256Digest::separated(FRAME_DIGEST_DOMAIN, frame);

    Ok(DecodedFrame {
        record: JournalRecord {
            sequence: expected_sequence,
            digest,
            body: decoded,
        },
        encoded_length: HEADER_LENGTH + body.len(),
    })
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

pub(super) fn encoded_body_length(
    header: &[u8; HEADER_LENGTH],
    expected_sequence: u64,
    expected_previous: Sha256Digest,
    offset: u64,
    limits: JournalLimits,
) -> Result<usize, JournalError> {
    let recorded_header_digest = Sha256Digest::from_bytes(
        header[HEADER_PREFIX_LENGTH..HEADER_LENGTH]
            .try_into()
            .map_err(|_| corrupt(expected_sequence, offset, "invalid header digest field"))?,
    );
    let actual_header_digest =
        Sha256Digest::separated(HEADER_DIGEST_DOMAIN, &header[..HEADER_PREFIX_LENGTH]);
    if recorded_header_digest != actual_header_digest {
        return Err(corrupt(expected_sequence, offset, "header digest mismatch"));
    }

    if header[..MAGIC.len()] != MAGIC {
        return Err(corrupt(expected_sequence, offset, "invalid magic"));
    }

    let version = u16::from_be_bytes([header[8], header[9]]);
    if version != FORMAT_VERSION {
        return Err(corrupt(
            expected_sequence,
            offset,
            format!("unsupported frame version {version}"),
        ));
    }

    let flags = u16::from_be_bytes([header[10], header[11]]);
    if flags != 0 {
        return Err(corrupt(
            expected_sequence,
            offset,
            format!("unknown required flags 0x{flags:04x}"),
        ));
    }

    let sequence = u64::from_be_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| corrupt(expected_sequence, offset, "invalid sequence field"))?,
    );
    if sequence != expected_sequence {
        return Err(corrupt(
            expected_sequence,
            offset,
            format!("found sequence {sequence}"),
        ));
    }

    let previous = Sha256Digest::from_bytes(
        header[24..56]
            .try_into()
            .map_err(|_| corrupt(expected_sequence, offset, "invalid previous digest field"))?,
    );
    if previous != expected_previous {
        return Err(corrupt(
            expected_sequence,
            offset,
            "previous-record digest mismatch",
        ));
    }

    let body_length = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
    let body_length = usize::try_from(body_length).map_err(|_| {
        corrupt(
            expected_sequence,
            offset,
            "body length is not representable on this platform",
        )
    })?;
    if body_length > limits.max_body_bytes {
        return Err(corrupt(
            expected_sequence,
            offset,
            format!(
                "body length {body_length} exceeds limit {}",
                limits.max_body_bytes
            ),
        ));
    }

    Ok(body_length)
}

fn validate_header(
    header: &[u8; HEADER_LENGTH],
    body: &[u8],
    expected_sequence: u64,
    expected_previous: Sha256Digest,
    offset: u64,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    let declared_length =
        encoded_body_length(header, expected_sequence, expected_previous, offset, limits)?;
    if declared_length != body.len() {
        return Err(corrupt(
            expected_sequence,
            offset,
            "body length does not match the complete frame",
        ));
    }

    let sequence = u64::from_be_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| corrupt(expected_sequence, offset, "invalid sequence field"))?,
    );
    if sequence != expected_sequence {
        return Err(corrupt(
            expected_sequence,
            offset,
            format!("found sequence {sequence}"),
        ));
    }

    let previous = Sha256Digest::from_bytes(
        header[24..56]
            .try_into()
            .map_err(|_| corrupt(expected_sequence, offset, "invalid previous digest field"))?,
    );
    if previous != expected_previous {
        return Err(corrupt(
            expected_sequence,
            offset,
            "previous-record digest mismatch",
        ));
    }

    let recorded_body_digest = Sha256Digest::from_bytes(
        header[56..HEADER_PREFIX_LENGTH]
            .try_into()
            .map_err(|_| corrupt(expected_sequence, offset, "invalid body digest field"))?,
    );
    let actual_body_digest = Sha256Digest::separated(BODY_DIGEST_DOMAIN, body);
    if recorded_body_digest != actual_body_digest {
        return Err(corrupt(expected_sequence, offset, "body digest mismatch"));
    }

    Ok(())
}

fn corrupt(sequence: u64, offset: u64, reason: impl fmt::Display) -> JournalError {
    JournalError::Corrupt {
        sequence,
        offset,
        reason: reason.to_string(),
    }
}
