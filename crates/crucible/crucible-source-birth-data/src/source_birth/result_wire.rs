//! Encodes and verifies the private worker's fixed result envelope as DATA.
//!
//! The 240-byte `CSBR0001` header uses explicit big-endian lengths and tags;
//! Rust layouts never cross the boundary. Success carries SourceBirth bytes,
//! registration bytes and EOF. Failure carries only a bounded UTF-8 diagnostic.
//!
//! ```text
//! 0 magic[8]; 8 status; 9 stage; 10 cause; 11 coordinate-basis;
//! 12 serde-category; 13 reserved[3]; 16 task[32]; 48 input[32];
//! 80 source-length[8]; 88 source-digest[32]; 120 registration-length[8];
//! 128 registration-digest[32]; 160 diagnostic-length[8];
//! 168 diagnostic-digest[32]; 200 line[8]; 208 column[8]; 216 reserved[24]
//! ```
//!
//! A matching checksum is not computation or Source authority. The Engine
//! caller must first authenticate the actual L2 Completion and original job,
//! then pass that Completion's captured stdout to this verifier. Public worker
//! outcome summaries or independently supplied candidate vectors are not that
//! stdout. No JSON parse, accepted bank or native capability is exposed here.

#[path = "result_wire/error.rs"]
mod error;
#[path = "result_wire/hash.rs"]
mod hash;
#[path = "result_wire/tags.rs"]
mod tags;

pub use error::{PayloadKind, TagField, WireError};
pub use hash::PayloadHasher;
pub use tags::{
    Cause, FailureInfo, OperationalReason, SerdeCategory, SerdeMetadata, Stage, Status,
};

/// Names the explicit versioned result codec independently of Rust layout.
pub const RESULT_CODEC_ID: &str = "crucible.source-birth.result/1";
/// Gives the fixed number of header bytes preceding any payload.
pub const HEADER_BYTES: usize = 240;
const MAGIC: &[u8; 8] = b"CSBR0001";

/// Binds raw bytes to the caller's original task and complete input commitment.
///
/// Constructing these public data fields authenticates neither digest's origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Commits the original selected task identifier.
    pub task_digest: [u8; 32],
    /// Commits the entire actual request, including worker/algorithm identities.
    pub input_digest: [u8; 32],
}

/// Restricts actual frame and diagnostic lengths before payload allocation.
#[derive(Clone, Copy, Debug)]
pub struct WireLimits {
    /// Bounds header plus the complete declared payload, including diagnostics.
    pub maximum_frame_bytes: usize,
    /// Bounds a complete diagnostic; truncation never represents an original error.
    pub maximum_diagnostic_bytes: usize,
}

/// Carries a structurally valid fixed header without any authority assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultHeader {
    identity: Identity,
    status: Status,
    stage: Stage,
    cause: Cause,
    metadata: Option<SerdeMetadata>,
    lengths: [u64; 3],
    digests: [[u8; 32]; 3],
}

impl ResultHeader {
    /// Describes both actual nonempty candidate banks and their CNP blob hashes.
    ///
    /// # Errors
    /// Refuses empty banks or lengths unrepresentable by the wire format.
    pub fn success(
        identity: Identity,
        source: &[u8],
        registration: &[u8],
    ) -> Result<Self, WireError> {
        if source.is_empty() || registration.is_empty() {
            return Err(WireError::InvalidShape);
        }
        let mut result = Self {
            identity,
            status: Status::Success,
            stage: Stage::None,
            cause: Cause::None,
            metadata: None,
            lengths: [length(source)?, length(registration)?, 0],
            digests: [[0; 32]; 3],
        };
        result.digests[0] = hash::bank_digest(source)?;
        result.digests[1] = hash::bank_digest(registration)?;
        Ok(result)
    }

    /// Describes one complete original or explicit operational diagnostic.
    ///
    /// The caller must bound actual diagnostic formatting before construction.
    /// An oversized original diagnostic must become `DiagnosticLimit` or an
    /// operational child failure; a truncated original must not be supplied.
    ///
    /// # Errors
    /// Refuses empty or excessive diagnostics and unrepresentable lengths.
    pub fn failure(
        identity: Identity,
        info: FailureInfo,
        diagnostic: &str,
        maximum_diagnostic_bytes: usize,
    ) -> Result<Self, WireError> {
        if diagnostic.is_empty() {
            return Err(WireError::InvalidShape);
        }
        if diagnostic.len() > maximum_diagnostic_bytes {
            return Err(WireError::DiagnosticLimit);
        }
        let result = Self {
            identity,
            status: info.status,
            stage: info.stage,
            cause: info.cause,
            metadata: info.metadata,
            lengths: [0, 0, length(diagnostic.as_bytes())?],
            digests: [
                [0; 32],
                [0; 32],
                hash::diagnostic_digest(diagnostic.as_bytes())?,
            ],
        };
        result.validate_shape()?;
        Ok(result)
    }

    /// Writes the explicit fixed wire representation with zero reserved bytes.
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = self.status as u8;
        bytes[9] = self.stage as u8;
        bytes[10] = self.cause as u8;
        if let Some(metadata) = self.metadata {
            bytes[11] = 1;
            bytes[12] = metadata.category as u8;
            bytes[200..208].copy_from_slice(&metadata.line.to_be_bytes());
            bytes[208..216].copy_from_slice(&metadata.column.to_be_bytes());
        }
        bytes[16..48].copy_from_slice(&self.identity.task_digest);
        bytes[48..80].copy_from_slice(&self.identity.input_digest);
        for (index, (length_offset, digest_offset)) in
            [(80, 88), (120, 128), (160, 168)].into_iter().enumerate()
        {
            bytes[length_offset..length_offset + 8]
                .copy_from_slice(&self.lengths[index].to_be_bytes());
            bytes[digest_offset..digest_offset + 32].copy_from_slice(&self.digests[index]);
        }
        bytes
    }

    /// Decodes tags, reserved fields and status-dependent shape without allocation.
    ///
    /// Coordinate basis `1` means only the actual original serde line/column.
    /// It claims no whole-request, candidate-byte or token-relative offset.
    /// Basis `0` requires zero category, line and column; no offset is inferred.
    ///
    /// # Errors
    /// Refuses unknown magic/tags, nonzero reserved bytes or inconsistent fields.
    pub fn decode(bytes: &[u8; HEADER_BYTES]) -> Result<Self, WireError> {
        if &bytes[..8] != MAGIC {
            return Err(WireError::BadMagic);
        }
        if bytes[13..16]
            .iter()
            .chain(bytes[216..].iter())
            .any(|byte| *byte != 0)
        {
            return Err(WireError::Reserved);
        }
        let metadata = match bytes[11] {
            0 if bytes[12] == 0 && bytes[200..216].iter().all(|byte| *byte == 0) => None,
            0 => return Err(WireError::InvalidShape),
            1 => Some(SerdeMetadata {
                category: SerdeCategory::decode(bytes[12])?,
                line: read_u64(bytes, 200),
                column: read_u64(bytes, 208),
            }),
            value => return Err(WireError::UnknownTag(TagField::CoordinateBasis, value)),
        };
        let result = Self {
            identity: Identity {
                task_digest: read_digest(bytes, 16),
                input_digest: read_digest(bytes, 48),
            },
            status: Status::decode(bytes[8])?,
            stage: Stage::decode(bytes[9])?,
            cause: Cause::decode(bytes[10])?,
            metadata,
            lengths: [
                read_u64(bytes, 80),
                read_u64(bytes, 120),
                read_u64(bytes, 160),
            ],
            digests: [
                read_digest(bytes, 88),
                read_digest(bytes, 128),
                read_digest(bytes, 168),
            ],
        };
        result.validate_shape()?;
        Ok(result)
    }

    fn validate_shape(&self) -> Result<(), WireError> {
        if self.status == Status::Success {
            if self.stage != Stage::None
                || self.cause != Cause::None
                || self.metadata.is_some()
                || self.lengths[0] == 0
                || self.lengths[1] == 0
                || self.lengths[2] != 0
                || self.digests[2] != [0; 32]
            {
                return Err(WireError::InvalidShape);
            }
        } else {
            if self.lengths[0] != 0
                || self.lengths[1] != 0
                || self.lengths[2] == 0
                || self.digests[0] != [0; 32]
                || self.digests[1] != [0; 32]
            {
                return Err(WireError::InvalidShape);
            }
            if !tags::valid_failure(self.status, self.stage, self.cause)
                || self.metadata.is_some() != self.cause.is_serde()
            {
                return Err(WireError::InvalidShape);
            }
        }
        Ok(())
    }

    /// Returns the unauthenticated wire correlation data.
    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// Returns the closed result status.
    pub fn status(&self) -> Status {
        self.status
    }

    /// Returns the actual derivation stage, or `None` before derivation.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Returns the closed underlying error category.
    pub fn cause(&self) -> Cause {
        self.cause
    }

    /// Returns only actual original serde coordinates and category when present.
    pub fn serde_metadata(&self) -> Option<SerdeMetadata> {
        self.metadata
    }

    /// Returns SourceBirth, registration and diagnostic lengths in that order.
    pub fn payload_lengths(&self) -> [u64; 3] {
        self.lengths
    }

    /// Returns the corresponding raw digest bytes in payload order.
    pub fn payload_digests(&self) -> [[u8; 32]; 3] {
        self.digests
    }

    /// Checks both commitments against the caller's same original job.
    ///
    /// # Errors
    /// Refuses either changed correlation or changed complete-input commitment.
    pub fn check_identity(&self, expected: Identity) -> Result<(), WireError> {
        if self.identity != expected {
            return Err(WireError::ForeignIdentity);
        }
        Ok(())
    }

    /// Checks declared lengths and caller limits before any payload allocation.
    ///
    /// # Errors
    /// Refuses host-size/checked-sum overflow or either explicit frame limit.
    pub fn checked_frame_length(&self, limits: WireLimits) -> Result<usize, WireError> {
        let mut total = HEADER_BYTES;
        for value in self.lengths {
            total = total
                .checked_add(usize::try_from(value).map_err(|_| WireError::LengthOverflow)?)
                .ok_or(WireError::LengthOverflow)?;
        }
        if self.lengths[2]
            > u64::try_from(limits.maximum_diagnostic_bytes)
                .map_err(|_| WireError::LengthOverflow)?
        {
            return Err(WireError::DiagnosticLimit);
        }
        if total > limits.maximum_frame_bytes {
            return Err(WireError::FrameLimit);
        }
        Ok(total)
    }
}

/// Borrows checked slices of the same captured stdout, without issuing authority.
#[derive(Debug)]
pub struct VerifiedResult<'a> {
    header: ResultHeader,
    source: &'a [u8],
    registration: &'a [u8],
    diagnostic: &'a str,
}

impl<'a> VerifiedResult<'a> {
    /// Borrows the structurally checked header from this same stdout.
    pub fn header(&self) -> &ResultHeader {
        &self.header
    }

    /// Borrows the actual SourceBirth payload slice.
    pub fn source_bytes(&self) -> &'a [u8] {
        self.source
    }

    /// Borrows the actual registration payload slice.
    pub fn registration_bytes(&self) -> &'a [u8] {
        self.registration
    }

    /// Borrows the complete actual UTF-8 diagnostic, empty on success.
    pub fn diagnostic(&self) -> &'a str {
        self.diagnostic
    }
}

/// Verifies the actual captured stdout's header, correlation, payloads and EOF.
///
/// This allocation-free operation validates exactly the borrowed bytes. A parent
/// must authenticate their L2 Completion provenance separately before this call.
/// It must not substitute L4 summaries or separately supplied candidate banks.
///
/// # Errors
/// Refuses invalid headers, changed identity, lengths/limits, malformed UTF-8,
/// changed digests, truncation or any trailing byte after the final payload.
pub fn verify_stdout(
    stdout: &[u8],
    expected: Identity,
    limits: WireLimits,
) -> Result<VerifiedResult<'_>, WireError> {
    let prefix = stdout.get(..HEADER_BYTES).ok_or(WireError::Truncated)?;
    let bytes: &[u8; HEADER_BYTES] = prefix.try_into().map_err(|_| WireError::Truncated)?;
    let header = ResultHeader::decode(bytes)?;
    header.check_identity(expected)?;
    let total = header.checked_frame_length(limits)?;
    if stdout.len() < total {
        return Err(WireError::Truncated);
    }
    if stdout.len() > total {
        return Err(WireError::Trailing);
    }
    let mut offset = HEADER_BYTES;
    let mut payloads = [&[][..]; 3];
    for (index, length) in header.lengths.into_iter().enumerate() {
        let end = offset
            .checked_add(usize::try_from(length).map_err(|_| WireError::LengthOverflow)?)
            .ok_or(WireError::LengthOverflow)?;
        payloads[index] = stdout.get(offset..end).ok_or(WireError::Truncated)?;
        offset = end;
    }
    if header.status == Status::Success {
        if hash::bank_digest(payloads[0])? != header.digests[0] {
            return Err(WireError::DigestMismatch(PayloadKind::Source));
        }
        if hash::bank_digest(payloads[1])? != header.digests[1] {
            return Err(WireError::DigestMismatch(PayloadKind::Registration));
        }
    } else if hash::diagnostic_digest(payloads[2])? != header.digests[2] {
        return Err(WireError::DigestMismatch(PayloadKind::Diagnostic));
    }
    let diagnostic = std::str::from_utf8(payloads[2]).map_err(|_| WireError::InvalidUtf8)?;
    Ok(VerifiedResult {
        header,
        source: payloads[0],
        registration: payloads[1],
        diagnostic,
    })
}

fn length(bytes: &[u8]) -> Result<u64, WireError> {
    u64::try_from(bytes.len()).map_err(|_| WireError::LengthOverflow)
}

fn read_u64(bytes: &[u8; HEADER_BYTES], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_digest(bytes: &[u8; HEADER_BYTES], offset: usize) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(&bytes[offset..offset + 32]);
    result
}

#[cfg(test)]
#[path = "result_wire/tests.rs"]
mod tests;
