//! Resolves bounded chunk spans from independently checked publication metadata.
//!
//! A plan is metadata, not seal, adoption, pin or domain-authorization evidence.
//! Native readers additionally retain the authenticated publisher handle and
//! actual durable pin before using any span in this plan.

use super::NativeHostLayout;
use std::{collections::BTreeMap, io};
use terrane::host::{
    cache::HostReadLocation,
    publication::{PublicationClaim, PublicationRecipe},
};
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};

/// Describes an exact plaintext chunk range in a verified containing manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeChunkSpan {
    /// Plaintext byte offset in the sealed backing object.
    pub offset: u64,
    /// Exact length bounded by the configured chunk profile.
    pub length: usize,
    /// Whether this occurrence is the manifest's final chunk.
    pub final_chunk: bool,
}

/// Retains a bounded, independently checked object-to-chunk range plan.
pub struct NativeResidencePlan {
    claim: PublicationClaim,
    spans: BTreeMap<Vec<u8>, NativeChunkSpan>,
}

impl NativeResidencePlan {
    /// Validates the exact domain/profile witness and derives checked ranges.
    ///
    /// `max_entries` is an operator inventory budget, not an encoded format
    /// restriction. Repeated identical chunks need only one retained occurrence.
    /// No backing file is read or accepted by constructing this metadata plan.
    ///
    /// # Errors
    /// Rejects another domain, invalid canonical metadata, inconsistent lengths
    /// or offset overflow. Inventory excess returns an out-of-memory resource
    /// error, not an assertion that the encoded manifest is corrupt.
    pub fn new<L: HostReadLocation>(
        layout: &NativeHostLayout<L>,
        claim: &PublicationClaim,
        max_entries: usize,
    ) -> io::Result<Self> {
        layout.recheck()?;
        if claim.domain() != layout.layout().domain() {
            return Err(invalid("residence claim belongs to another domain"));
        }
        let recipe = match claim.canonical_manifest() {
            Some(bytes) => PublicationRecipe::Manifest {
                object: claim.descriptor().clone(),
                canonical_manifest: bytes.to_vec(),
            },
            None => PublicationRecipe::Inline {
                chunk: claim.descriptor().clone(),
            },
        };
        let claim = PublicationClaim::new(
            claim.domain().to_owned(),
            recipe,
            layout.layout().chunk_profile(),
        )?;
        let mut spans: BTreeMap<Vec<u8>, NativeChunkSpan> = BTreeMap::new();
        if let Some(manifest) = claim.manifest() {
            let mut offset = 0_u64;
            for (index, chunk) in manifest.chunks.iter().enumerate() {
                let span = NativeChunkSpan {
                    offset,
                    length: usize::try_from(chunk.length).map_err(invalid)?,
                    final_chunk: index + 1 == manifest.chunks.len(),
                };
                if let Some(previous) = spans.get(chunk.digest.as_slice()) {
                    if previous.length != span.length {
                        return Err(invalid("one chunk digest has differing residence lengths"));
                    }
                } else {
                    if spans.len() >= max_entries {
                        return Err(capacity());
                    }
                    spans.insert(chunk.digest.to_vec(), span);
                }
                offset = offset
                    .checked_add(chunk.length)
                    .ok_or_else(|| invalid("residence range overflow"))?;
            }
            if offset != claim.plaintext_size() {
                return Err(invalid("residence ranges differ from object length"));
            }
        } else {
            if max_entries == 0 {
                return Err(capacity());
            }
            spans.insert(
                claim.descriptor().digest().to_vec(),
                NativeChunkSpan {
                    offset: 0,
                    length: usize::try_from(claim.plaintext_size()).map_err(invalid)?,
                    final_chunk: true,
                },
            );
        }
        Ok(Self { claim, spans })
    }

    /// Returns the independently checked exact publication metadata witness.
    pub fn claim(&self) -> &PublicationClaim {
        &self.claim
    }

    /// Resolves an exact registered chunk identity without a digest-only fallback.
    ///
    /// # Errors
    /// Rejects another identity profile or a non-chunk identity.
    pub fn span(&self, identity: &Identity) -> io::Result<Option<NativeChunkSpan>> {
        if identity.profile() != TERRANE_V1.name() || identity.kind() != IdentityKind::Chunk {
            return Err(invalid(
                "residence lookup requires a registered chunk identity",
            ));
        }
        Ok(self.spans.get(identity.digest()).copied())
    }

    /// Enumerates the unique chunk identities within the configured plan budget.
    ///
    /// # Errors
    /// Returns an error if an internal digest cannot form its registered identity.
    pub fn identities(&self) -> io::Result<Vec<Identity>> {
        self.spans
            .keys()
            .map(|digest| {
                TERRANE_V1
                    .from_digest(IdentityKind::Chunk, digest)
                    .map_err(invalid)
            })
            .collect()
    }
}

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "residence inventory exceeds operator budget",
    )
}
