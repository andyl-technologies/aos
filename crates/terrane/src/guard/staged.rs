//! Retains proposed immutable uploads until current-policy admission succeeds.

use terrane_core::chunking::ChunkProfile;
use terrane_core::identity::{Identity, IdentityKind};
use terrane_core::refs::Commit;

use crate::store::{ChunkPosition, ChunkUpload, ContentUpload, MetaUpload, StoreFailure};

/// An owned upload held in memory before the repository authorizes publication.
#[derive(Clone, Debug)]
pub enum StagedUpload {
    /// Canonical metadata under its registered identity kind.
    Meta {
        /// Registered non-chunk identity domain.
        kind: IdentityKind,
        /// Complete canonical immutable bytes.
        bytes: Vec<u8>,
    },
    /// An encoded chunk with independent admission declarations.
    Chunk {
        /// Codec envelope and encoded body.
        encoded: Vec<u8>,
        /// Offered plaintext identity.
        identity: Identity,
        /// Exact expected decompressed length.
        declared_plaintext_len: usize,
        /// Final or nonfinal object position.
        position: ChunkPosition,
        /// Registered chunk profile to verify.
        profile: Box<ChunkProfile>,
    },
}

impl StagedUpload {
    /// Borrows the upload declarations without publishing bytes.
    ///
    /// # Errors
    /// Rejects a metadata upload declared in the chunk identity domain.
    pub fn as_upload(&self) -> Result<ContentUpload<'_>, StoreFailure> {
        match self {
            Self::Meta { kind, bytes } => Ok(ContentUpload::Meta(MetaUpload::new(*kind, bytes)?)),
            Self::Chunk {
                encoded,
                identity,
                declared_plaintext_len,
                position,
                profile,
            } => Ok(ContentUpload::Chunk(ChunkUpload {
                encoded,
                identity,
                declared_plaintext_len: *declared_plaintext_len,
                position: *position,
                profile,
            })),
        }
    }
}

/// Proposes a signed commit and the immutable objects it needs.
pub struct CommitRequest {
    /// Unsigned metadata; the guard supplies authorization-bound provenance.
    pub commit: Commit,
    /// Objects published only after admission succeeds.
    pub uploads: Vec<StagedUpload>,
    /// Host-held capability chain authorizing this request.
    pub token: Vec<u8>,
    /// Private terminal key matching the capability chain.
    pub terminal_secret: [u8; 32],
    /// Registered surface context for token caveats.
    pub surface: String,
    /// Verified scoped storage records for existing referenced objects.
    pub reference_records: Vec<crate::domain::DomainRecord>,
    /// Explicit authorized disclosure receipts for content entering a wider domain.
    pub disclosures: Vec<crate::domain::DomainDisclosure>,
}
