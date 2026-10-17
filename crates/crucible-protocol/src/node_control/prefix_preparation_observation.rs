//! Canonical initial fixed-profile observation before an original command.
//!
//! The record copies historical source facts at raw zero. Decoding requires the
//! independently retained complete preparation and Applied receipt. It neither
//! creates an executable epoch nor confirms a consumed preparation ACK or Ready.
//!
//! ```text
//! version/size:u32be=1/640 | canonical_root_policy328 | AppliedInit160
//! initialPosition24 | prefixPreparation32 | epoch/raw/CPU/nextCPU:u64be
//! timer_id/list/arm/expiry/microstep:u64be | timer_phase/reserved:u32be
//! supported_subset/disposition:u32be=1/1
//! ```

// SPDX-License-Identifier: Apache-2.0

use crucible_node_contract::{Phase, Position, U64};
use sha2::{Digest, Sha256};

use super::{
    NativeCommandError, NativeInitializationReceipt, NativeInitializationStatus,
    NativePrefixPreparation,
};

const BYTES: usize = 640;
const DIGEST_DOMAIN: &[u8] = b"crucible.native-prefix-preparation.v1\0";

/// Identifies the authentic first pending timer without granting its dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixPreparationTimer {
    /// Identifies the original timer allocation.
    pub timer_id: U64,
    /// Identifies its actual native list.
    pub list_id: U64,
    /// Identifies the retained original arm.
    pub arm_generation: U64,
    /// Records the complete original evaluation coordinate.
    pub evaluation: Position,
}

/// Retains the initial source observation of the named output-disabled subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrefixPreparationObservation {
    /// Retains the independently supplied complete original preparation.
    pub preparation: NativePrefixPreparation,
    /// Retains the byte-equal source Applied receipt, without an ACK claim.
    pub initialization: NativeInitializationReceipt,
    /// Records the authentic initial BoundaryControl coordinate at time zero.
    pub initial: Position,
    /// Identifies the source-issued original epoch incarnation.
    pub epoch_incarnation: U64,
    /// Identifies the original native CPU QOM incarnation.
    pub cpu_incarnation: U64,
    /// Records the authentic first CPU deadline, independently of a result count.
    pub next_cpu_deadline_ps: U64,
    /// Retains the authentic timer frontier or its source-authenticated absence.
    pub first_timer: Option<NativePrefixPreparationTimer>,
}

impl NativePrefixPreparationObservation {
    /// Decodes the fixed record against independently retained original owners.
    ///
    /// # Errors
    /// Rejects changed full Root fields, prefix commitments or Applied receipts,
    /// later coordinates, open subset/disposition fields, malformed timer rows,
    /// zero incarnations and any truncated or trailing bytes.
    pub fn decode(
        bytes: &[u8],
        expected: &NativePrefixPreparation,
        initialization: &NativeInitializationReceipt,
    ) -> Result<Self, NativeCommandError> {
        expected.validate()?;
        initialization.validate()?;
        if bytes.len() != BYTES
            || bytes[..8] != [0, 0, 0, 1, 0, 0, 2, 128]
            || bytes[8..336] != canonical_root(expected)?
            || bytes[336..496] != initialization.encode()?
            || bytes[520..552] != expected.identity_digest()?
            || initialization.status != NativeInitializationStatus::Applied
            || bytes[560..568] != [0; 8]
            || bytes[632..640] != [0, 0, 0, 1, 0, 0, 0, 1]
        {
            return Err(NativeCommandError::Conflict);
        }

        let original = &expected
            .original_effect
            .original_root
            .administration
            .phase
            .initialization;
        if initialization.prepared_scope_hash != original.preparation.scope.identity_digest()?
            || initialization.initialization_commitment != original.identity_digest()?
            || initialization.realize_request_digest != original.realize_request_digest
            || initialization.applied_callbacks > original.maximum_callbacks
        {
            return Err(NativeCommandError::Conflict);
        }

        let initial = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if bytes[496..520] != encode_position(&initial) {
            return Err(NativeCommandError::Conflict);
        }
        let first_timer = if bytes[584..632] == [0; 48] {
            None
        } else {
            if u32_at(bytes, 624)? != 3 || u32_at(bytes, 628)? != 0 {
                return Err(NativeCommandError::Conflict);
            }
            Some(NativePrefixPreparationTimer {
                timer_id: positive(bytes, 584)?,
                list_id: positive(bytes, 592)?,
                arm_generation: positive(bytes, 600)?,
                evaluation: Position::new(
                    U64::new(u64_at(bytes, 608)?),
                    U64::new(u64_at(bytes, 616)?),
                    Phase::Reaction,
                ),
            })
        };
        if first_timer
            .as_ref()
            .is_some_and(|timer| timer.evaluation.microstep.get() != 0)
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(Self {
            preparation: expected.clone(),
            initialization: initialization.clone(),
            initial,
            epoch_incarnation: positive(bytes, 552)?,
            cpu_incarnation: positive(bytes, 568)?,
            next_cpu_deadline_ps: positive(bytes, 576)?,
            first_timer,
        })
    }

    /// Encodes historical observation fields with explicit big-endian scalar order.
    ///
    /// # Errors
    /// Rejects malformed original companions or facts that fail the same closed
    /// decoder. No native pointer, Rust enum representation or callback is encoded.
    pub fn encode(&self) -> Result<[u8; BYTES], NativeCommandError> {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(&[0, 0, 0, 1, 0, 0, 2, 128]);
        bytes[8..336].copy_from_slice(&canonical_root(&self.preparation)?);
        bytes[336..496].copy_from_slice(&self.initialization.encode()?);
        bytes[496..520].copy_from_slice(&encode_position(&self.initial));
        bytes[520..552].copy_from_slice(&self.preparation.identity_digest()?);
        for (offset, value) in [
            (552, self.epoch_incarnation),
            (568, self.cpu_incarnation),
            (576, self.next_cpu_deadline_ps),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.get().to_be_bytes());
        }
        if let Some(timer) = &self.first_timer {
            for (offset, value) in [
                (584, timer.timer_id),
                (592, timer.list_id),
                (600, timer.arm_generation),
                (608, timer.evaluation.time_ps),
                (616, timer.evaluation.microstep),
            ] {
                bytes[offset..offset + 8].copy_from_slice(&value.get().to_be_bytes());
            }
            bytes[624..628].copy_from_slice(&(timer.evaluation.phase as u32).to_be_bytes());
        }
        bytes[632..640].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
        Self::decode(&bytes, &self.preparation, &self.initialization)?;
        Ok(bytes)
    }

    /// Hashes the canonical original facts for data correlation, not authority.
    ///
    /// # Errors
    /// Rejects facts that cannot be encoded under the closed initial schema.
    pub fn identity_digest(&self) -> Result<[u8; 32], NativeCommandError> {
        let mut hash = Sha256::new();
        hash.update(DIGEST_DOMAIN);
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}

fn canonical_root(expected: &NativePrefixPreparation) -> Result<[u8; 328], NativeCommandError> {
    let mut bytes = expected.original_effect.original_root.native_policy()?;
    for offset in [0, 4, 304, 308, 312, 316, 320, 324] {
        let value = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| NativeCommandError::Conflict)?,
        );
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    for offset in [264, 272, 280, 288, 296] {
        let value = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| NativeCommandError::Conflict)?,
        );
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    Ok(bytes)
}

fn encode_position(position: &Position) -> [u8; 24] {
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(&position.time_ps.get().to_be_bytes());
    bytes[8..16].copy_from_slice(&position.microstep.get().to_be_bytes());
    bytes[16..20].copy_from_slice(&(position.phase as u32).to_be_bytes());
    bytes
}

fn positive(bytes: &[u8], offset: usize) -> Result<U64, NativeCommandError> {
    let value = u64_at(bytes, offset)?;
    if value == 0 {
        return Err(NativeCommandError::Conflict);
    }
    Ok(U64::new(value))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, NativeCommandError> {
    Ok(u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| NativeCommandError::Conflict)?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, NativeCommandError> {
    Ok(u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| NativeCommandError::Conflict)?,
    ))
}

#[cfg(test)]
#[path = "prefix_preparation_observation_tests.rs"]
mod tests;
