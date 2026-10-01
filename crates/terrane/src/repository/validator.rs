//! Validates local repository metadata before backend visibility.

use terrane_core::{
    chunking::ChunkProfile,
    derived::AttrRecord,
    identity::{IdentityKind, TERRANE_V1},
    manifest::Manifest,
    refs::Commit,
    tree_format::{self, TreeUse},
};

use crate::store::{
    ChunkPosition, ChunkRequirement, ContentValidator, InvalidReason, MetaUpload, StoreErrorKind,
    StoreFailure,
};

/// Validates the canonical metadata formats admitted by the local Repository.
///
/// Cryptographic authority and complete-tree relationships remain Guard checks.
/// Formats outside this local workflow fail explicitly rather than accepting
/// opaque bytes without a registered validator.
pub struct MetadataValidator {
    profile: Box<ChunkProfile>,
}

impl MetadataValidator {
    /// Captures the exact profile of the backend being opened.
    pub fn new(profile: ChunkProfile) -> Self {
        Self {
            profile: Box::new(profile),
        }
    }
}

impl ContentValidator for MetadataValidator {
    fn chunk_requirements(
        &self,
        upload: &MetaUpload<'_>,
    ) -> Result<Vec<ChunkRequirement>, StoreFailure> {
        if upload.kind() != IdentityKind::Manifest {
            return Ok(Vec::new());
        }
        let invalid = || StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "OBJ-15" });
        let manifest = Manifest::decode(upload.bytes(), &self.profile)
            .map_err(|error| StoreFailure::with_source(invalid(), error))?;
        let count = manifest.chunks.len();
        manifest
            .chunks
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| {
                Ok(ChunkRequirement {
                    identity: TERRANE_V1
                        .from_digest(IdentityKind::Chunk, &chunk.digest)
                        .map_err(|error| StoreFailure::with_source(invalid(), error))?,
                    declared_plaintext_len: usize::try_from(chunk.length)
                        .map_err(|error| StoreFailure::with_source(invalid(), error))?,
                    position: if index + 1 == count {
                        ChunkPosition::Final
                    } else {
                        ChunkPosition::NonFinal
                    },
                    missing_rule_id: "OBJ-15",
                })
            })
            .collect()
    }

    fn validate_meta(&self, upload: &MetaUpload<'_>) -> Result<(), StoreFailure> {
        let (valid, rule_id) = match upload.kind() {
            IdentityKind::Manifest => (
                Manifest::decode(upload.bytes(), &self.profile).is_ok(),
                "OBJ-15",
            ),
            IdentityKind::Node => (
                tree_format::decode_node_for(
                    upload.bytes(),
                    true,
                    self.profile.minimum() as u64,
                    TreeUse::Ordinary,
                )
                .or_else(|_| {
                    tree_format::decode_node_for(
                        upload.bytes(),
                        false,
                        self.profile.minimum() as u64,
                        TreeUse::Ordinary,
                    )
                })
                .is_ok(),
                "TREE-25",
            ),
            IdentityKind::Commit => (Commit::decode(upload.bytes()).is_ok(), "REF-9"),
            IdentityKind::Attribute => (AttrRecord::decode(upload.bytes()).is_ok(), "DRV-1"),
            _ => return Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        };
        if !valid {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload { rule_id },
            )));
        }
        Ok(())
    }
}
