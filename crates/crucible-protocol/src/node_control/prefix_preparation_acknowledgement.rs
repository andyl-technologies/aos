//! Offered acknowledgement of the canonical original initial observation.
//!
//! These fields correlate the exact original facts, Init cut and source epoch.
//! Encoding or echoing them does not prove native consumption. A distinct native
//! consumed getter and owning reply credit are required before command admission.
//!
//! ```text
//! version/size:u32be=1/160 | scope/prefixPreparation/factsSHA/InitCut:[32;4]
//! InitSequence/epochIncarnation/acknowledgementSequence:u64be
//! ```

// SPDX-License-Identifier: Apache-2.0

use crucible_node_contract::U64;

use super::{NativeCommandError, NativePrefixPreparationObservation};

/// Correlates an offered initial acknowledgement without claiming consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixPreparationAcknowledgement {
    /// Names the independently retained complete scope.
    pub scope: [u8; 32],
    /// Names the unchanged complete prefix preparation.
    pub prefix_preparation: [u8; 32],
    /// Names the domain-separated canonical640 original observation.
    pub facts_digest: [u8; 32],
    /// Names the source's original Applied initialization cut.
    pub initialization_cut: [u8; 32],
    /// Identifies the original Applied initialization command.
    pub initialization_sequence: U64,
    /// Identifies the same source-issued original epoch incarnation.
    pub epoch_incarnation: U64,
    /// Selects the original native preparation acknowledgement sequence one.
    pub acknowledgement_sequence: U64,
}

impl NativePrefixPreparationAcknowledgement {
    /// Decodes the closed correlation body without claiming native consumption.
    ///
    /// # Errors
    /// Rejects malformed scalar fields, incomplete extents or trailing bytes.
    /// The receiver must still compare its independently retained original facts.
    pub fn decode_record(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let mut cursor = super::codec::Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != 160 {
            return Err(NativeCommandError::Conflict);
        }
        let record = Self {
            scope: cursor.array()?,
            prefix_preparation: cursor.array()?,
            facts_digest: cursor.array()?,
            initialization_cut: cursor.array()?,
            initialization_sequence: U64::new(cursor.u64()?),
            epoch_incarnation: U64::new(cursor.u64()?),
            acknowledgement_sequence: U64::new(cursor.u64()?),
        };
        if bytes != record.encode()? {
            return Err(NativeCommandError::Conflict);
        }
        Ok(record)
    }

    /// Constructs the offered correlation from the complete original observation.
    ///
    /// # Errors
    /// Rejects malformed original fields. This supplies data only; the caller
    /// must recover authentic native consumption before allowing Compute.
    pub fn from_original(
        original: &NativePrefixPreparationObservation,
    ) -> Result<Self, NativeCommandError> {
        Ok(Self {
            scope: original.initialization.prepared_scope_hash,
            prefix_preparation: original.preparation.identity_digest()?,
            facts_digest: original.identity_digest()?,
            initialization_cut: original.initialization.original_cut_digest,
            initialization_sequence: original.initialization.sequence,
            epoch_incarnation: original.epoch_incarnation,
            acknowledgement_sequence: U64::new(1),
        })
    }

    /// Encodes the complete closed offered record with big-endian scalar fields.
    ///
    /// # Errors
    /// Rejects empty identities, zero original sequence/incarnation or a sequence
    /// other than one. No native handle or consumed disposition is encoded.
    pub fn encode(&self) -> Result<[u8; 160], NativeCommandError> {
        if [
            self.scope,
            self.prefix_preparation,
            self.facts_digest,
            self.initialization_cut,
        ]
        .contains(&[0; 32])
            || self.initialization_sequence.get() == 0
            || self.epoch_incarnation.get() == 0
            || self.acknowledgement_sequence.get() != 1
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = [0; 160];
        bytes[..8].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 160]);
        for (offset, digest) in [
            (8, self.scope),
            (40, self.prefix_preparation),
            (72, self.facts_digest),
            (104, self.initialization_cut),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&digest);
        }
        for (offset, value) in [
            (136, self.initialization_sequence),
            (144, self.epoch_incarnation),
            (152, self.acknowledgement_sequence),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.get().to_be_bytes());
        }
        Ok(bytes)
    }

    /// Decodes only the byte-equal original acknowledgement correlation.
    ///
    /// # Errors
    /// Rejects changed original fields, incomplete extents or trailing bytes.
    /// Matching a record never distinguishes offered from native-consumed data.
    pub fn decode(
        bytes: &[u8],
        original: &NativePrefixPreparationObservation,
    ) -> Result<Self, NativeCommandError> {
        let expected = Self::from_original(original)?;
        if bytes != expected.encode()? {
            return Err(NativeCommandError::Conflict);
        }
        Ok(expected)
    }
}
