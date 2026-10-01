//! Complete semantic object identities from a fully verified companion pair.
//!
//! The catalogue contains only OIDs, kinds and decoded sizes. It becomes
//! available after the same whole-pair validation used by content projections;
//! neither index-only membership nor a valid prefix can supply an absence.

use super::{PairReader, VerifiedPair};
use crate::object::{ObjectKind, Oid};

use anyhow::{ensure, Result};

/// Maximum complete semantic catalogue entries accepted by the pack parser.
pub const MAX_CATALOGUE_OBJECTS: usize = super::super::MAX_PUBLISHED_PACK_OBJECTS;

/// One whole-object identity derived from a complete verified pack graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedObjectSummary {
    /// Full SHA-256 identity of the decoded Git object.
    pub oid: Oid,
    /// Kind inherited through every verified delta chain.
    pub kind: ObjectKind,
    /// Full decoded content size; no content bytes are returned.
    pub object_size: u64,
}

/// Complete sorted semantic coverage of a verified encoded companion pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCatalogue {
    /// Exact encoded commitments and measured graph bounds, with objects empty.
    pub pair: VerifiedPair,
    /// Every verified object in strict OID order, without truncation.
    pub objects: Vec<VerifiedObjectSummary>,
}

impl PairReader {
    /// Produces a complete metadata catalogue after whole-pair validation.
    ///
    /// Every decoded body is dropped as its summary is constructed. A caller
    /// may cache this bounded semantic coverage under the exact source and
    /// authorization commitments, then answer positive or negative membership
    /// without fetching or reinterpreting the encoded sources again.
    ///
    /// # Errors
    /// Returns an error for incomplete or corrupt input, any index/pack
    /// disagreement, delta or object budget violations, excessive object count,
    /// allocation failure or a malformed verified OID. No partial result escapes.
    pub fn finish_catalogue(self) -> Result<VerifiedCatalogue> {
        let graph = self.verify()?;
        ensure!(
            graph.objects.len() <= MAX_CATALOGUE_OBJECTS,
            "verified catalogue exceeds its object count"
        );
        let mut objects = Vec::new();
        objects.try_reserve_exact(graph.objects.len())?;

        for (entry, object) in graph.objects {
            objects.push(VerifiedObjectSummary {
                oid: Oid::from_bytes(&entry.oid)?,
                kind: object.kind,
                object_size: object.data.len() as u64,
            });
        }
        Ok(VerifiedCatalogue {
            pair: graph.pair,
            objects,
        })
    }
}

#[cfg(test)]
mod tests;
