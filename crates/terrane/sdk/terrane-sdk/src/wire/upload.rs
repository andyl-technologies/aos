//! Receives bounded PutPack frames and verifies complete immutable artifacts.
//!
//! The receiver retains bytes privately until actual end-of-stream and complete
//! verification. Its result grants no authorization, member admission, native
//! custody, visibility or durability acknowledgement. A backend must still
//! admit content with its manifest context and durably publish both artifacts.
//!
//! ```text
//! header -> body* -> trailer -> actual EOF -> verified private artifacts
//! any failure -> terminal rejection, with retained upload bytes released
//! ```

use std::fmt;

use terrane_format::identity::{IdentityKind, TERRANE_V1};

use crate::pack::{
    BodyDecoder, FOOTER_SIZE, HEADER_SIZE, PackClass, PackError, PackId, PackReader,
};
use crate::store::{ContentValidator, MetaUpload, StoreFailure};

use super::v1::{self, put_pack_frame::Frame};

/// Bounds a body frame's data field independently of protobuf framing overhead.
pub const MAX_BODY_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Holds explicit finite resources for one privately received pack.
#[derive(Clone, Copy, Debug)]
pub struct UploadLimits {
    pack_bytes: usize,
    index_bytes: usize,
    member_bytes: u64,
    plaintext_bytes: u64,
    frames: u64,
}

impl UploadLimits {
    /// Validates pack, detached-index, decoded-member, total-decoding and frame bounds.
    ///
    /// # Errors
    /// Rejects zero, unbounded or inconsistent limits, including bounds smaller
    /// than an empty version-one pack/index or fewer than three stream frames.
    pub fn new(
        pack_bytes: usize,
        index_bytes: usize,
        member_bytes: u64,
        plaintext_bytes: u64,
        frames: u64,
    ) -> Result<Self, UploadError> {
        let preamble = terrane_format::pack_format::PREAMBLE_SIZE;
        if pack_bytes < HEADER_SIZE + preamble + FOOTER_SIZE
            || index_bytes < HEADER_SIZE + preamble
            || pack_bytes == usize::MAX
            || index_bytes == usize::MAX
            || member_bytes == 0
            || plaintext_bytes == u64::MAX
            || member_bytes > plaintext_bytes
            || frames < 3
            || frames == u64::MAX
        {
            return Err(UploadError::Limits);
        }
        Ok(Self {
            pack_bytes,
            index_bytes,
            member_bytes,
            plaintext_bytes,
            frames,
        })
    }
}

/// Names the checked declaration of one incoming pack without claiming entropy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadHeader {
    id: PackId,
    bytes: usize,
    class: PackClass,
}

impl UploadHeader {
    /// Returns the exact client-supplied pack identifier.
    pub const fn id(self) -> PackId {
        self.id
    }

    /// Returns the exact declared complete pack size.
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Returns the declared separation between data and metadata.
    pub const fn class(self) -> PackClass {
        self.class
    }
}

/// Retains ordered incoming bytes until actual EOF and independent verification.
///
/// The surrounding authenticated service owns request deadlines and cancellation.
/// Dropping this value releases its private bytes; no backend effects occur here.
pub struct PackReceiver {
    limits: UploadLimits,
    header: Option<UploadHeader>,
    body: Vec<u8>,
    trailer: Option<v1::PutPackTrailer>,
    frames: u64,
    failed: bool,
}

impl PackReceiver {
    /// Starts an empty receiver with previously validated finite resources.
    pub const fn new(limits: UploadLimits) -> Self {
        Self {
            limits,
            header: None,
            body: Vec::new(),
            trailer: None,
            frames: 0,
            failed: false,
        }
    }

    /// Borrows the checked declaration, enabling an actual backend idempotency lookup.
    ///
    /// A declaration alone supplies no evidence that this pack is already held.
    pub const fn header(&self) -> Option<UploadHeader> {
        self.header
    }

    /// Returns currently retained body bytes for admission accounting.
    pub fn buffered_bytes(&self) -> usize {
        self.body.len()
    }

    /// Consumes one ordered frame without making any uploaded content visible.
    ///
    /// A failure latches terminal rejection and releases all retained upload data.
    /// A trailing frame does not establish EOF: callers must continue reading the
    /// stream and pass genuine EOF to [`Self::finish`].
    ///
    /// # Errors
    /// Rejects missing/reordered/repeated frames, unsupported pack versions,
    /// malformed identifiers, declared or actual resource excess and allocation
    /// failure. Every later call after a rejection returns [`UploadError::Terminated`].
    pub fn push(&mut self, frame: v1::PutPackFrame) -> Result<(), UploadError> {
        if self.failed {
            return Err(UploadError::Terminated);
        }
        let result = self.push_frame(frame);
        if result.is_err() {
            self.failed = true;
            self.header = None;
            self.trailer = None;
            self.body = Vec::new();
        }
        result
    }

    fn push_frame(&mut self, frame: v1::PutPackFrame) -> Result<(), UploadError> {
        if self.frames >= self.limits.frames {
            return Err(UploadError::Limit);
        }
        self.frames += 1;
        if self.trailer.is_some() {
            return Err(UploadError::Order);
        }
        match frame.frame.ok_or(UploadError::Order)? {
            Frame::Header(header) => {
                if self.header.is_some() || self.frames != 1 {
                    return Err(UploadError::Order);
                }
                if header.format_version != 1 {
                    return Err(UploadError::Version);
                }
                let id: [u8; 16] = header
                    .pack
                    .as_option()
                    .ok_or(UploadError::Header)?
                    .value
                    .as_slice()
                    .try_into()
                    .map_err(|_| UploadError::Header)?;
                let bytes = usize::try_from(header.size).map_err(|_| UploadError::Limit)?;
                if bytes > self.limits.pack_bytes {
                    return Err(UploadError::Limit);
                }
                if bytes < HEADER_SIZE + terrane_format::pack_format::PREAMBLE_SIZE + FOOTER_SIZE {
                    return Err(UploadError::Header);
                }
                self.header = Some(UploadHeader {
                    id: PackId::from_random_bytes(id),
                    bytes,
                    class: if header.meta {
                        PackClass::Meta
                    } else {
                        PackClass::Data
                    },
                });
            }
            Frame::Body(bytes) => {
                let header = self.header.ok_or(UploadError::Order)?;
                let size = self
                    .body
                    .len()
                    .checked_add(bytes.len())
                    .ok_or(UploadError::Limit)?;
                if bytes.len() > MAX_BODY_FRAME_BYTES || size > header.bytes {
                    return Err(UploadError::Limit);
                }
                self.body
                    .try_reserve(bytes.len())
                    .map_err(|_| UploadError::Allocation)?;
                self.body.extend(bytes);
            }
            Frame::Trailer(trailer) => {
                let header = self.header.ok_or(UploadError::Order)?;
                if self.body.len() != header.bytes {
                    return Err(UploadError::Size);
                }
                if trailer.index.len() > self.limits.index_bytes {
                    return Err(UploadError::Limit);
                }
                let claimed = trailer
                    .index_hash
                    .as_option()
                    .ok_or(UploadError::IndexHash)?;
                let identity = TERRANE_V1
                    .calculate(IdentityKind::Index, &trailer.index)
                    .map_err(|_| UploadError::IndexHash)?;
                if claimed.value.as_slice()
                    != identity
                        .terrane_v1_digest()
                        .map_err(|_| UploadError::IndexHash)?
                {
                    return Err(UploadError::IndexHash);
                }
                self.trailer = Some(*trailer);
            }
        }
        Ok(())
    }

    /// Verifies a complete stream after its caller observes actual EOF.
    ///
    /// Every entry's declared decoding cost is checked before any decoder is
    /// called. Each body is then independently decoded and identity-checked;
    /// metadata also passes the backend's configured format validator. Decoded
    /// members are released one at a time. Chunk boundary admission still needs
    /// the enclosing object's final/nonfinal manifest context at the backend.
    ///
    /// # Errors
    /// Rejects incomplete or failed streams, declaration/format disagreement,
    /// detached-index mismatch, decode limits, incorrect body identities and
    /// configured metadata validation failure. Returns no partial result.
    pub fn finish<D: BodyDecoder, V: ContentValidator>(
        self,
        decoder: &D,
        validator: &V,
    ) -> Result<ReceivedPack, UploadError> {
        if self.failed {
            return Err(UploadError::Terminated);
        }
        let header = self.header.ok_or(UploadError::Incomplete)?;
        let trailer = self.trailer.ok_or(UploadError::Incomplete)?;
        if self.body.len() != header.bytes {
            return Err(UploadError::Size);
        }
        let reader = PackReader::open(&self.body).map_err(UploadError::Pack)?;
        if reader.header().id() != header.id || reader.header().class() != header.class {
            return Err(UploadError::Header);
        }
        reader
            .check_index_object(&trailer.index)
            .map_err(UploadError::Pack)?;
        let mut plaintext = 0_u64;
        for entry in reader.entries() {
            let size = u64::from(entry.plaintext_len());
            plaintext = plaintext.checked_add(size).ok_or(UploadError::Limit)?;
            if size > self.limits.member_bytes || plaintext > self.limits.plaintext_bytes {
                return Err(UploadError::Limit);
            }
        }
        for entry in reader.entries() {
            let bytes = reader
                .read(entry.kind(), entry.hash(), decoder)
                .map_err(UploadError::Pack)?;
            if entry.kind() != crate::pack::EntryKind::Chunk {
                let upload = MetaUpload::new(entry.kind().identity_kind(), &bytes)
                    .map_err(UploadError::Validation)?;
                validator
                    .validate_meta(&upload)
                    .map_err(UploadError::Validation)?;
            }
        }
        Ok(ReceivedPack {
            header,
            bytes: self.body,
            index: trailer.index,
        })
    }
}

/// Holds private verified artifacts without granting admission or durability.
///
/// This value does not implement a store receipt or expose an acknowledgement.
/// Its configured backend must still establish all normal publication invariants.
pub struct ReceivedPack {
    header: UploadHeader,
    bytes: Vec<u8>,
    index: Vec<u8>,
}

impl ReceivedPack {
    /// Returns the declaration matched against the actual sealed header.
    pub const fn header(&self) -> UploadHeader {
        self.header
    }

    /// Borrows complete verified pack bytes for backend admission.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the exact detached index matched against the pack itself.
    pub fn index(&self) -> &[u8] {
        &self.index
    }
}

/// Distinguishes invalid resources, malformed uploads and independent validation failures.
#[derive(Debug)]
pub enum UploadError {
    /// Rejects invalid finite receiver configuration.
    Limits,
    /// Rejects missing, repeated or reordered frames.
    Order,
    /// Rejects unsupported pack format versions.
    Version,
    /// Rejects malformed or contradictory pack declarations.
    Header,
    /// Refuses configured byte, decoding or frame-count excess.
    Limit,
    /// Refuses an allocation without acknowledging partial bytes.
    Allocation,
    /// Rejects a body whose exact length differs from the declaration.
    Size,
    /// Rejects a missing, malformed or incorrect detached-index digest.
    IndexHash,
    /// Refuses EOF before a complete header/body/trailer sequence.
    Incomplete,
    /// Refuses any reuse after a prior frame failure.
    Terminated,
    /// Preserves structural, body-hash and decoder failures.
    Pack(PackError),
    /// Preserves the configured metadata validator's failure.
    Validation(StoreFailure),
}

impl fmt::Display for UploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "invalid finite upload limits",
            Self::Order => "invalid upload frame order",
            Self::Version => "unsupported upload pack version",
            Self::Header => "invalid upload pack declaration",
            Self::Limit => "upload resource limit exceeded",
            Self::Allocation => "upload allocation failed",
            Self::Size => "upload pack size mismatch",
            Self::IndexHash => "upload index digest mismatch",
            Self::Incomplete => "incomplete upload stream",
            Self::Terminated => "upload stream already rejected",
            Self::Pack(_) => "upload pack verification failed",
            Self::Validation(_) => "upload metadata validation failed",
        })
    }
}

impl std::error::Error for UploadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pack(error) => Some(error),
            Self::Validation(error) => Some(error),
            _ => None,
        }
    }
}
