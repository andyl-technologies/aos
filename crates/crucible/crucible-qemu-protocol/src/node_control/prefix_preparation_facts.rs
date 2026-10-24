//! Closed canonical preparation records carried by the explicit initial contract.
//!
//! Framing validates the scalar schema only. A receiver must additionally decode
//! against its complete original preparation and Applied receipt before using the
//! observation, then recover the native consumed acknowledgement before Compute.
//!
//! ```text
//! Query: scope[32] | prefixPreparation[32]
//! Facts: canonical source preparation record[640]
//! ```

// SPDX-License-Identifier: Apache-2.0

use super::{
    NativeCommandError, NativeInitializationReceipt, NativeInitializationStatus,
    NativePrefixPreparation, NativePrefixPreparationObservation,
};

/// Retains canonical historical facts without authenticating a native owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixPreparationFacts([u8; 640]);

impl NativePrefixPreparationFacts {
    /// Retains one closed pointer-free source record.
    ///
    /// # Errors
    /// Rejects incomplete extents, later coordinates, open schema fields and
    /// malformed initial companions. This does not correlate an original owner.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let bytes: [u8; 640] = bytes.try_into().map_err(|_| NativeCommandError::Conflict)?;
        if bytes[..8] != [0, 0, 0, 1, 0, 0, 2, 128]
            || bytes[8..16] != [0, 0, 0, 1, 0, 0, 1, 72]
            || bytes[496..520] != [0; 24]
            || bytes[560..568] != [0; 8]
            || bytes[632..640] != [0, 0, 0, 1, 0, 0, 0, 1]
            || bytes[312..328] != [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 1]
            || bytes[332..336] != [0; 4]
        {
            return Err(NativeCommandError::Conflict);
        }
        for offset in [16, 48, 80, 112, 144, 176, 208, 240, 520] {
            if bytes[offset..offset + 32] == [0; 32] {
                return Err(NativeCommandError::Conflict);
            }
        }
        for offset in [296, 304, 552, 568, 576] {
            if bytes[offset..offset + 8] == [0; 8] {
                return Err(NativeCommandError::Conflict);
            }
        }
        let receipt = NativeInitializationReceipt::decode(&bytes[336..496])?;
        if receipt.status != NativeInitializationStatus::Applied
            || bytes[16..48] != receipt.prepared_scope_hash
            || bytes[80..112] != receipt.realize_request_digest
            || bytes[144..176] != receipt.initialization_commitment
        {
            return Err(NativeCommandError::Conflict);
        }
        if bytes[584..632] != [0; 48]
            && (bytes[584..592] == [0; 8]
                || bytes[592..600] == [0; 8]
                || bytes[600..608] == [0; 8]
                || bytes[616..624] != [0; 8]
                || bytes[624..632] != [0, 0, 0, 3, 0, 0, 0, 0])
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(Self(bytes))
    }

    /// Returns the complete immutable big-endian record.
    pub fn canonical_bytes(&self) -> &[u8; 640] {
        &self.0
    }

    /// Correlates the record to independently retained complete original bodies.
    ///
    /// # Errors
    /// Rejects changed original Root, Prefix or Applied initialization fields.
    /// Matching historical facts does not prove native ACK consumption or Ready.
    pub fn observe_original(
        &self,
        preparation: &NativePrefixPreparation,
        initialization: &NativeInitializationReceipt,
    ) -> Result<NativePrefixPreparationObservation, NativeCommandError> {
        NativePrefixPreparationObservation::decode(&self.0, preparation, initialization)
    }
}
