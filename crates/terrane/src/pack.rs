//! Reads and writes sealed, self-describing pack containers.
//!
//! The writer retains all bytes privately until sealing consumes it. Readers
//! validate the trailing index and its CRC before any lookup, then verify the
//! selected body's domain-separated identity before returning plaintext.
//! Per-pack indexes and merged shards are derived caches; bundles transport
//! verified metadata independently of pack placement.
//!
//! ```text
//! TRPK | version:u16le | flags:u16le | id:16
//! bodies ...
//! TRIX | count:u64le | entries:56 ...
//! index-offset:u64le | index-crc32c:u32le | TRPE
//! ```

mod binary;
mod bundle;
mod merged;
mod native;
mod reader;
mod writer;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

pub use bundle::{Bundle, BundleObject};
pub use merged::{IndexCatalog, Lookup, MergedEntry, MergedShard, PackIndexSnapshot, RecordState};
pub use native::NativeBodyDecoder;
pub use reader::{Admission, BodyDecoder, PackReader, RawBodyDecoder};
pub use writer::{PackPublisher, PackWriter, PublishedPack, SealedPack};

use std::fmt;
use terrane_core::identity::{Digest, IdentityError, IdentityKind, TERRANE_V1};

/// The fixed header width in bytes.
pub const HEADER_SIZE: usize = terrane_core::pack_format::HEADER_SIZE;

/// The fixed footer width in bytes.
pub const FOOTER_SIZE: usize = terrane_core::pack_format::FOOTER_SIZE;

/// The fixed per-pack index entry width in bytes.
pub const INDEX_ENTRY_SIZE: usize = terrane_core::pack_format::RECORD_SIZE;

/// The maximum body bytes accumulated before a data writer requires sealing.
pub const DATA_PACK_LIMIT: usize = 32 * 1024 * 1024;

/// A writer-supplied random identifier with the exact bytes used in bucket keys.
///
/// Runtime callers must fill all 16 bytes from a cryptographically secure
/// random source providing at least 122 bits of entropy. This format layer
/// cannot establish entropy by inspecting bytes and never substitutes a clock
/// or content hash for a random source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackId([u8; 16]);

impl PackId {
    /// Generates all 128 identifier bits from the operating system random source.
    ///
    /// This native Unix entry point fails if the secure random source is
    /// unavailable; other runtimes supply secure bytes with
    /// [`Self::from_random_bytes`]. No content is acknowledged before generation.
    ///
    /// # Errors
    /// Returns the original I/O error if the system random source cannot be
    /// opened or does not provide all sixteen bytes.
    pub fn generate() -> std::io::Result<Self> {
        use std::io::Read;

        let mut bytes = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Wraps bytes supplied by the runtime's secure random generator.
    pub const fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier's exact 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the registered immutable pack key.
    pub fn pack_key(&self) -> String {
        format!("objects/pack/{:02x}/{self}.pack", self.0[0])
    }

    /// Returns the registered immutable per-pack index key.
    pub fn index_key(&self) -> String {
        format!("objects/pack/{:02x}/{self}.idx", self.0[0])
    }
}

impl fmt::Display for PackId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The pack's immutable separation of data chunks and metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackClass {
    /// Plaintext chunks stored under a chunk codec envelope.
    Data,
    /// Canonically encoded manifests, nodes, commits, bundles, filters, or indexes.
    Meta,
}

/// A registered index kind whose value selects the content identity domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EntryKind {
    /// A data chunk.
    Chunk = 0,
    /// An object manifest.
    Manifest = 1,
    /// A tree node.
    Node = 2,
    /// A commit.
    Commit = 3,
    /// A bundle.
    Bundle = 4,
    /// A membership filter.
    Filter = 5,
    /// A per-pack index copy.
    Index = 6,
}

impl EntryKind {
    /// Returns the domain selected by this kind byte.
    pub const fn identity_kind(self) -> IdentityKind {
        match self {
            Self::Chunk => IdentityKind::Chunk,
            Self::Manifest => IdentityKind::Manifest,
            Self::Node => IdentityKind::Node,
            Self::Commit => IdentityKind::Commit,
            Self::Bundle => IdentityKind::Bundle,
            Self::Filter => IdentityKind::Filter,
            Self::Index => IdentityKind::Index,
        }
    }
}

impl TryFrom<u8> for EntryKind {
    type Error = PackError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Chunk),
            1 => Ok(Self::Manifest),
            2 => Ok(Self::Node),
            3 => Ok(Self::Commit),
            4 => Ok(Self::Bundle),
            5 => Ok(Self::Filter),
            6 => Ok(Self::Index),
            _ => Err(PackError::Kind),
        }
    }
}

/// A codec registered for a pack index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Codec {
    /// An uncompressed body.
    Raw = 0,
    /// One sized zstd frame.
    Zstd = 1,
    /// One sized zstd frame preceded by its dictionary digest.
    Dictionary = 2,
}

impl TryFrom<u8> for Codec {
    type Error = PackError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Zstd),
            2 => Ok(Self::Dictionary),
            _ => Err(PackError::Codec),
        }
    }
}

/// A checked pack header with no reserved flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackHeader {
    id: PackId,
    class: PackClass,
    compressed_default: bool,
}

impl PackHeader {
    /// Returns the identifier under which both immutable objects are stored.
    pub const fn id(&self) -> PackId {
        self.id
    }

    /// Returns whether this pack contains chunks or metadata.
    pub const fn class(&self) -> PackClass {
        self.class
    }

    /// Returns the writer's compression-default flag.
    pub const fn compressed_default(&self) -> bool {
        self.compressed_default
    }
}

/// A validated 56-byte index record describing one stored body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexEntry {
    hash: Digest,
    offset: u64,
    body_len: u32,
    plaintext_len: u32,
    codec: Codec,
    kind: EntryKind,
    dictionary_id: u16,
}

impl IndexEntry {
    /// Returns the content digest in this entry's identity domain.
    pub const fn hash(&self) -> &Digest {
        &self.hash
    }

    /// Returns the body offset from the start of the pack.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the stored body length including a chunk's codec envelope.
    pub const fn body_len(&self) -> u32 {
        self.body_len
    }

    /// Returns the declared plaintext length excluding the codec envelope.
    pub const fn plaintext_len(&self) -> u32 {
        self.plaintext_len
    }

    /// Returns the body's registered codec.
    pub const fn codec(&self) -> Codec {
        self.codec
    }

    /// Returns the kind under which the body may be served.
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Returns the reserved dictionary field, which is always zero in v1.
    pub const fn dictionary_id(&self) -> u16 {
        self.dictionary_id
    }
}

/// A rejected format, identity, or writer-state transition.
#[derive(Debug)]
pub enum PackError {
    /// A header, footer, or index is truncated or structurally malformed.
    Malformed,
    /// A format magic or version is unrecognized.
    Version,
    /// A reserved flag or byte is nonzero.
    Reserved,
    /// The index CRC32C does not match its bytes.
    Crc,
    /// Hash order, body coverage, offsets, or lengths disagree.
    Index,
    /// A content digest occurs more than once.
    Duplicate,
    /// An unknown or inappropriate identity kind was supplied.
    Kind,
    /// A codec envelope or dictionary declaration disagrees with its index.
    Codec,
    /// The requested entry is absent or tombstoned.
    Missing,
    /// The asserted body identity does not match the verified plaintext.
    Identity(IdentityError),
    /// A CBOR object is not canonical or does not match its schema.
    Cbor(terrane_core::cbor::Error),
    /// A format allocation or length limit was exceeded.
    Limit,
    /// This writer reached its seal threshold and cannot append another body.
    SealRequired,
    /// A detached index differs from the authoritative pack index.
    DetachedIndex,
    /// A generation refresh is stale or conflicts with immutable data.
    Generation,
    /// A compressed body requires an appropriate decoder or dictionary.
    Decoder,
    /// The portable pack, shard, or bundle byte format failed validation.
    Format(terrane_core::pack_format::Error),
    /// Native chunk decoding or its bounded admission checks failed.
    Native(crate::codec::FrameError),
    /// Damaged unframed bodies require quarantine rather than guessed recovery.
    RecoveryUnsupported(Box<PackError>),
}

impl fmt::Display for PackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "pack body identity: {error}"),
            Self::Cbor(error) => write!(formatter, "pack metadata: {error}"),
            Self::Format(error) => write!(formatter, "pack format: {error}"),
            Self::Native(error) => write!(formatter, "pack chunk decoding: {error}"),
            Self::RecoveryUnsupported(error) => write!(
                formatter,
                "pack quarantined; unframed scan recovery unsupported: {error}"
            ),
            error => formatter.write_str(match error {
                Self::Malformed => "malformed pack structure",
                Self::Version => "unrecognized pack format",
                Self::Reserved => "nonzero reserved pack field",
                Self::Crc => "pack index CRC32C mismatch",
                Self::Index => "pack index coverage or ordering mismatch",
                Self::Duplicate => "duplicate pack content identity",
                Self::Kind => "pack entry kind mismatch",
                Self::Codec => "pack body codec mismatch",
                Self::Missing => "pack content missing or tombstoned",
                Self::Limit => "pack format limit exceeded",
                Self::SealRequired => "data pack requires sealing",
                Self::DetachedIndex => "per-pack index disagrees with sealed pack",
                Self::Generation => "stale or conflicting index generation",
                Self::Decoder => "pack body decoder or dictionary unavailable",
                Self::Identity(_)
                | Self::Cbor(_)
                | Self::Format(_)
                | Self::Native(_)
                | Self::RecoveryUnsupported(_) => "pack validation failed",
            }),
        }
    }
}

impl std::error::Error for PackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::Cbor(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Format(error) => Some(error),
            Self::RecoveryUnsupported(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<IdentityError> for PackError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<terrane_core::cbor::Error> for PackError {
    fn from(error: terrane_core::cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

fn digest(kind: EntryKind, bytes: &[u8]) -> Result<Digest, PackError> {
    Ok(TERRANE_V1
        .calculate(kind.identity_kind(), bytes)?
        .terrane_v1_digest()?)
}

fn verify(kind: EntryKind, hash: &Digest, bytes: &[u8]) -> Result<(), PackError> {
    if digest(kind, bytes)? != *hash {
        return Err(PackError::Identity(IdentityError::DigestMismatch));
    }
    Ok(())
}

impl From<crate::codec::FrameError> for PackError {
    fn from(error: crate::codec::FrameError) -> Self {
        Self::Native(error)
    }
}

impl From<terrane_core::pack_format::Error> for PackError {
    fn from(error: terrane_core::pack_format::Error) -> Self {
        Self::Format(error)
    }
}
