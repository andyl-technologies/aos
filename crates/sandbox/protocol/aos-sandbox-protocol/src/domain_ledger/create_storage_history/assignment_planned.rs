//! Frames the actual Controller's proposed immutable assignment as passive DATA.
//!
//! ```text
//! AOSXAP01 | accepted-association[192] | SourceHeld-checksum[32] |
//! CacheHeld-checksum[32] | exact-origin-sha256[32] | Tree-head[32] |
//! lineage-head[32] | manifest-length:u32be | canonical-AssignmentManifest
//! ```
//!
//! The nested manifest is borrowed. Its existing Core codec and the original
//! Native producer separately validate semantics, current absence and custody.
//! A parsed planned record supplies neither an Ownership claim nor InputsReady.

use super::{HistoryErrorV1, nonzero, reader};
use super::association::AcceptedAssociationDataV1;

/// Holds the fixed framing width before the variable canonical manifest.
pub const ASSIGNMENT_PLANNED_FIXED_BYTES_V1: usize = 364;

/// Borrows the exact proposal and its original accepted and held associations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignmentPlannedBodyDataV1<'manifest> {
    /// The original accepted Create association, with its unchanged cutoff.
    pub association: AcceptedAssociationDataV1,
    /// The actual returned and read-back Source Held record checksum.
    pub source_held: [u8; 32],
    /// The actual returned and read-back Cache Held record checksum.
    pub cache_held: [u8; 32],
    /// SHA-256 of the retained complete original AOSPCO03 record.
    pub input_origin: [u8; 32],
    /// The same held Source's structurally current empty generation-one tree.
    pub tree_head: [u8; 32],
    /// That tree's complete validated local lineage head.
    pub lineage_head: [u8; 32],
    /// The exact original producer's Core canonical assignment manifest.
    pub manifest: &'manifest [u8],
}

impl<'manifest> AssignmentPlannedBodyDataV1<'manifest> {
    /// Borrows the exact fixed associations and nested manifest without allocation.
    ///
    /// # Errors
    /// Rejects wrong magic, zero associations, empty manifest or nonexact extent.
    pub fn decode(bytes: &'manifest [u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXAP01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let association = AcceptedAssociationDataV1::decode(input.bytes(192)?)?;
        let source_held = input.array()?;
        let cache_held = input.array()?;
        let input_origin = input.array()?;
        let tree_head = input.array()?;
        let lineage_head = input.array()?;
        let length = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        let manifest = input.bytes(length)?;
        input.finish()?;
        let value = Self { association, source_held, cache_held, input_origin,
            tree_head, lineage_head, manifest };
        value.encoded_bytes()?;
        Ok(value)
    }

    /// Returns the exact checked framing and nested byte width.
    ///
    /// # Errors
    /// Rejects malformed associations, empty manifest or unrepresentable length.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        self.association.encode()?;
        for value in [&self.source_held, &self.cache_held, &self.input_origin,
            &self.tree_head, &self.lineage_head] {
            nonzero(value)?;
        }
        if self.manifest.is_empty() { return Err(HistoryErrorV1::Malformed); }
        u32::try_from(self.manifest.len()).map_err(|_| HistoryErrorV1::Extent)?;
        ASSIGNMENT_PLANNED_FIXED_BYTES_V1.checked_add(self.manifest.len())
            .ok_or(HistoryErrorV1::Extent)
    }

    /// Writes exactly these borrowed fields into already-admitted storage.
    ///
    /// # Errors
    /// Rejects malformed fields or a destination with another exact width.
    pub fn encode_into(self, bytes: &mut [u8]) -> Result<(), HistoryErrorV1> {
        if bytes.len() != self.encoded_bytes()? { return Err(HistoryErrorV1::Extent); }
        bytes[..8].copy_from_slice(b"AOSXAP01");
        bytes[8..200].copy_from_slice(&self.association.encode()?);
        let mut offset = 200;
        for value in [&self.source_held, &self.cache_held, &self.input_origin,
            &self.tree_head, &self.lineage_head] {
            bytes[offset..offset + 32].copy_from_slice(value);
            offset += 32;
        }
        bytes[offset..offset + 4].copy_from_slice(&u32::try_from(self.manifest.len())
            .map_err(|_| HistoryErrorV1::Extent)?.to_be_bytes());
        bytes[offset + 4..].copy_from_slice(self.manifest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_borrows_nested_bytes_and_rejects_truncation_or_substitution() {
        let association = AcceptedAssociationDataV1 {
            operation: [1; 16], project: [2; 16], sandbox: [3; 16],
            accepted_request: [4; 32], coissuance_binding: [5; 32], seed: [6; 32],
            controller_nonce: [7; 16], boot: [8; 16], started: 9, cutoff: 10,
        };
        // This format owns framing only; Core owns the manifest's semantics.
        let value = AssignmentPlannedBodyDataV1 { association, source_held: [11; 32],
            cache_held: [12; 32], input_origin: [13; 32], tree_head: [14; 32],
            lineage_head: [15; 32], manifest: b"canonical-manifest" };
        let mut bytes = vec![0; value.encoded_bytes().unwrap()];
        value.encode_into(&mut bytes).unwrap();

        let parsed = AssignmentPlannedBodyDataV1::decode(&bytes).unwrap();
        assert_eq!(parsed, value);
        assert_eq!(parsed.manifest.as_ptr(), bytes[364..].as_ptr());
        assert!(AssignmentPlannedBodyDataV1::decode(&bytes[..bytes.len() - 1]).is_err());
        bytes[200..232].fill(0);
        assert!(AssignmentPlannedBodyDataV1::decode(&bytes).is_err());
    }
}
