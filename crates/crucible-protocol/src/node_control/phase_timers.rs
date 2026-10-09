//! Typed source births in a separately versioned native timer observation.
//!
//! Unknown and construction births have no logical position. A closed mapped
//! birth records source observations, not proof of execution permission or a
//! complete output bound. Callback ancestry remains diagnostic until an
//! independently admitted finite-phase command authorizes that callback.
//!
//! ```text
//! summary: version:u32=1 | bytes:u32=112 | list_count:u32 | timer_count:u32
//!          current_ps:u64 | mutation_generation:u64 | gate_generation:u64
//!          original_sequence:u64 | prepared_scope[32] | original_digest[32]
//! list: identity:u64 | timer_count:u32 | flags:u32
//! timer: identity:u64 | list:u64 | arm_generation:u64 | expiry_ps:u64
//!        fifo_ordinal:u64 | attributes:u32 | scale:u32
//!        birth_kind:u32 | birth_phase:u32 | birth_flags:u32 | reserved:u32=0
//!        birth_time_ps:u64 | birth_microstep:u64 | source_sequence:u64
//!        parent_timer:u64 | parent_arm_generation:u64 | source_scope[32]
//!        source_digest[32] | construction_commitment[32]
//! ```
//!
//! All integers are big endian. Each timer row preserves the existing 48-byte
//! timer prefix and adds 152 bytes of closed source-birth data. It contains no
//! native pointers, and does not change the legacy timer format.

use std::collections::BTreeSet;

use crucible_node_contract::{Phase, Position, U64};

use super::phase::NativePhasePreparation;
use super::{NativeCommandError, NativeTimerArm, NativeTimerList, codec::Cursor};

/// Sizes the fixed timer summary before bounded lists and birth rows.
pub const NATIVE_PHASE_TIMER_SUMMARY_BYTES: usize = 112;

/// Sizes one timer arm with its separate original source-birth observation.
pub const NATIVE_PHASE_TIMER_ROW_BYTES: usize = 200;

/// Bounds the complete separate observation with 64 lists and 4096 timer rows.
pub const NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES: usize = 820_336;

/// Preserves actual callback ancestry without assigning a logical source position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTimerParent {
    /// Identifies the original process-local timer rather than its address.
    pub timer: U64,
    /// Identifies the actual original arm whose callback produced this arm.
    pub arm_generation: U64,
}

/// Distinguishes unqualified births from construction and closed mapped births.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeTimerBirth {
    /// Preserves absent phase qualification, including genuine callback ancestry.
    Unknown {
        /// Retains actual callback ancestry solely as non-authoritative diagnostics.
        parent: Option<NativeTimerParent>,
    },
    /// Retains a pre-execution construction arm without inventing logical time.
    Construction {
        /// Binds the original complete inactive native owner scope.
        prepared_scope_hash: [u8; 32],
        /// Binds the independently retained original construction preparation.
        initialization_commitment: [u8; 32],
    },
    /// Retains an instruction-born arm under the explicitly selected source mapping.
    Reaction {
        /// Locates the actual instruction birth at reaction, microstep zero.
        position: Position,
        /// Binds the originally prepared native owner scope.
        prepared_scope_hash: [u8; 32],
        /// Names the actual original accepted native execution command.
        sequence: U64,
        /// Binds that original command without issuing a replacement grant.
        command_digest: [u8; 32],
    },
}

impl NativeTimerBirth {
    /// Returns mapped source position data, preserving unknown births as absent.
    pub fn position(&self) -> Option<Position> {
        match self {
            Self::Reaction { position, .. } => Some(*position),
            Self::Unknown { .. } | Self::Construction { .. } => None,
        }
    }

    /// Validates the closed birth shape without authenticating its source.
    ///
    /// # Errors
    /// Rejects missing parent identities, unpinned construction or reaction data,
    /// fabricated callback mapping, excessive native time or nonzero reaction microsteps.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        match self {
            Self::Unknown {
                parent: Some(parent),
            } if parent.timer.get() == 0 || parent.arm_generation.get() == 0 => {
                Err(NativeCommandError::Conflict)
            }
            Self::Construction {
                prepared_scope_hash,
                initialization_commitment,
            } if *prepared_scope_hash == [0; 32] || *initialization_commitment == [0; 32] => {
                Err(NativeCommandError::Conflict)
            }
            Self::Reaction {
                position,
                prepared_scope_hash,
                sequence,
                command_digest,
            } if position.time_ps.get() > i64::MAX as u64
                || position.microstep.get() != 0
                || position.phase != Phase::Reaction
                || *prepared_scope_hash == [0; 32]
                || sequence.get() == 0
                || *command_digest == [0; 32] =>
            {
                Err(NativeCommandError::Conflict)
            }
            _ => Ok(()),
        }
    }

    fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<(), NativeCommandError> {
        self.validate()?;
        let mut row = [0; 152];
        match self {
            Self::Unknown {
                parent: Some(parent),
            } => {
                row[8..12].copy_from_slice(&2u32.to_be_bytes());
                row[40..48].copy_from_slice(&parent.timer.get().to_be_bytes());
                row[48..56].copy_from_slice(&parent.arm_generation.get().to_be_bytes());
            }
            Self::Unknown { parent: None } => {}
            Self::Construction {
                prepared_scope_hash,
                initialization_commitment,
            } => {
                row[..4].copy_from_slice(&1u32.to_be_bytes());
                row[56..88].copy_from_slice(prepared_scope_hash);
                row[120..152].copy_from_slice(initialization_commitment);
            }
            Self::Reaction {
                position,
                prepared_scope_hash,
                sequence,
                command_digest,
            } => {
                row[..4].copy_from_slice(&2u32.to_be_bytes());
                row[4..8].copy_from_slice(&3u32.to_be_bytes());
                row[8..12].copy_from_slice(&1u32.to_be_bytes());
                row[16..24].copy_from_slice(&position.time_ps.get().to_be_bytes());
                row[24..32].copy_from_slice(&position.microstep.get().to_be_bytes());
                row[32..40].copy_from_slice(&sequence.get().to_be_bytes());
                row[56..88].copy_from_slice(prepared_scope_hash);
                row[88..120].copy_from_slice(command_digest);
            }
        }
        bytes.extend_from_slice(&row);
        Ok(())
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self, NativeCommandError> {
        let kind = cursor.u32()?;
        let phase = cursor.u32()?;
        let flags = cursor.u32()?;
        if cursor.u32()? != 0 {
            return Err(NativeCommandError::Invalid(
                "native timer birth reserved field",
            ));
        }
        let time_ps = U64::new(cursor.u64()?);
        let microstep = U64::new(cursor.u64()?);
        let sequence = U64::new(cursor.u64()?);
        let parent_timer = U64::new(cursor.u64()?);
        let parent_arm = U64::new(cursor.u64()?);
        let prepared_scope_hash = cursor.array()?;
        let command_digest = cursor.array()?;
        let initialization_commitment = cursor.array()?;
        let no_position = phase == 0 && time_ps.get() == 0 && microstep.get() == 0;
        let no_command = sequence.get() == 0 && command_digest == [0; 32];
        let no_parent = parent_timer.get() == 0 && parent_arm.get() == 0;

        let value = match kind {
            0 if no_position
                && no_command
                && prepared_scope_hash == [0; 32]
                && initialization_commitment == [0; 32] =>
            {
                let parent = match flags {
                    0 if no_parent => None,
                    2 if parent_timer.get() != 0 && parent_arm.get() != 0 => {
                        Some(NativeTimerParent {
                            timer: parent_timer,
                            arm_generation: parent_arm,
                        })
                    }
                    _ => return Err(NativeCommandError::Conflict),
                };
                Self::Unknown { parent }
            }
            1 if no_position && no_command && no_parent && flags == 0 => Self::Construction {
                prepared_scope_hash,
                initialization_commitment,
            },
            2 if phase == 3 && flags == 1 && no_parent && initialization_commitment == [0; 32] => {
                Self::Reaction {
                    position: Position::new(time_ps, microstep, Phase::Reaction),
                    prepared_scope_hash,
                    sequence,
                    command_digest,
                }
            }
            _ => {
                return Err(NativeCommandError::Invalid(
                    "invalid native timer source-birth shape",
                ));
            }
        };
        value.validate()?;
        Ok(value)
    }
}

/// Preserves an original timer arm and its distinct source-birth observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhaseTimerArm {
    /// Preserves all original fields of the unchanged legacy timer row.
    pub arm: NativeTimerArm,
    /// Preserves absence or explicit source-defined qualification of its birth.
    pub birth: NativeTimerBirth,
}

/// Retains one coherent bounded timer cut with source-birth provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhaseTimerObservation {
    /// Binds the immutable complete prepared native owner scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the original stopped command; zero denotes the initial park.
    pub sequence: U64,
    /// Binds that original command; zero is reserved for the initial park.
    pub command_digest: [u8; 32],
    /// Records actual current native clock time without synthesizing progress.
    pub current_ps: U64,
    /// Records the original coherent native timer mutation generation.
    pub mutation_generation: U64,
    /// Records the original positive native gate lifetime at observation.
    pub gate_generation: U64,
    /// Retains the complete bounded original virtual-list roster.
    pub lists: Vec<NativeTimerList>,
    /// Retains original timer FIFO order together with unchanged birth data.
    pub timers: Vec<NativePhaseTimerArm>,
}

impl NativePhaseTimerObservation {
    /// Validates the closed original cut without claiming native or output closure.
    ///
    /// # Errors
    /// Rejects unpinned scope, inconsistent command identity, missing gate lifetime,
    /// excessive time or counts, incoherent FIFO, invalid births or foreign birth scope.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32]
            || (self.sequence.get() == 0) != (self.command_digest == [0; 32])
            || self.gate_generation.get() == 0
            || self.current_ps.get() > i64::MAX as u64
            || self.lists.len() > 64
            || self.timers.len() > 4096
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut cursor = 0usize;
        let mut previous_list = 0;
        let mut identities = BTreeSet::new();
        for list in &self.lists {
            if list.identity.get() <= previous_list || list.flags & !3 != 0 {
                return Err(NativeCommandError::Conflict);
            }
            previous_list = list.identity.get();
            let end = cursor
                .checked_add(list.timer_count as usize)
                .filter(|end| *end <= self.timers.len())
                .ok_or(NativeCommandError::ResourceLimit)?;
            let mut previous_expiry = None;
            for (ordinal, timer) in self.timers[cursor..end].iter().enumerate() {
                let arm = &timer.arm;
                if arm.list != list.identity
                    || arm.identity.get() == 0
                    || arm.arm_generation.get() == 0
                    || arm.arm_generation > self.mutation_generation
                    || arm.fifo_ordinal.get() != ordinal as u64
                    || arm.expiry_ps.get() > i64::MAX as u64
                    || arm.scale == 0
                    || arm.scale > i32::MAX as u32
                    || !identities.insert(arm.identity)
                    || previous_expiry.is_some_and(|expiry| expiry > arm.expiry_ps)
                {
                    return Err(NativeCommandError::Conflict);
                }
                self.validate_birth(&timer.birth)?;
                previous_expiry = Some(arm.expiry_ps);
            }
            cursor = end;
        }
        if cursor != self.timers.len() {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    fn validate_birth(&self, birth: &NativeTimerBirth) -> Result<(), NativeCommandError> {
        birth.validate()?;
        match birth {
            NativeTimerBirth::Unknown {
                parent: Some(parent),
            } if parent.arm_generation > self.mutation_generation => {
                Err(NativeCommandError::Conflict)
            }
            NativeTimerBirth::Construction {
                prepared_scope_hash,
                ..
            } if *prepared_scope_hash != self.prepared_scope_hash => {
                Err(NativeCommandError::Conflict)
            }
            NativeTimerBirth::Reaction {
                position,
                prepared_scope_hash,
                sequence,
                command_digest,
            } if *prepared_scope_hash != self.prepared_scope_hash
                || position.time_ps > self.current_ps
                || *sequence > self.sequence
                || (*sequence == self.sequence && *command_digest != self.command_digest) =>
            {
                Err(NativeCommandError::Conflict)
            }
            _ => Ok(()),
        }
    }

    /// Compares source policy and every construction commitment with retained data.
    ///
    /// This correlation does not attest native custody or manufacture phase
    /// qualification for unknown timer births.
    ///
    /// # Errors
    /// Rejects malformed observations, changed owner scope or construction policy.
    pub fn validate_against(
        &self,
        preparation: &NativePhasePreparation,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        let policy = preparation.policy()?;
        let construction = preparation.initialization.identity_digest()?;
        if self.prepared_scope_hash != policy.prepared_scope_hash
            || self.timers.iter().any(|timer| {
                matches!(&timer.birth,
                NativeTimerBirth::Construction { initialization_commitment, .. }
                    if *initialization_commitment != construction)
            })
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes the complete separately versioned immutable original observation.
    ///
    /// # Errors
    /// Rejects any invalid original cut or exceeded finite object allowance.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let length = NATIVE_PHASE_TIMER_SUMMARY_BYTES
            + self.lists.len() * 16
            + self.timers.len() * NATIVE_PHASE_TIMER_ROW_BYTES;
        let mut bytes = Vec::with_capacity(length);
        for value in [
            1,
            NATIVE_PHASE_TIMER_SUMMARY_BYTES as u32,
            self.lists.len() as u32,
            self.timers.len() as u32,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.current_ps,
            self.mutation_generation,
            self.gate_generation,
            self.sequence,
        ] {
            bytes.extend_from_slice(&value.get().to_be_bytes());
        }
        bytes.extend_from_slice(&self.prepared_scope_hash);
        bytes.extend_from_slice(&self.command_digest);
        for list in &self.lists {
            bytes.extend_from_slice(&list.identity.get().to_be_bytes());
            bytes.extend_from_slice(&list.timer_count.to_be_bytes());
            bytes.extend_from_slice(&list.flags.to_be_bytes());
        }
        for timer in &self.timers {
            let arm = &timer.arm;
            for value in [
                arm.identity,
                arm.list,
                arm.arm_generation,
                arm.expiry_ps,
                arm.fifo_ordinal,
            ] {
                bytes.extend_from_slice(&value.get().to_be_bytes());
            }
            bytes.extend_from_slice(&arm.attributes.to_be_bytes());
            bytes.extend_from_slice(&arm.scale.to_be_bytes());
            timer.birth.encode_into(&mut bytes)?;
        }
        Ok(bytes)
    }

    /// Decodes bounded closed data while preserving unqualified births as absent.
    ///
    /// # Errors
    /// Rejects oversized or truncated objects, open fields, excessive counts,
    /// inconsistent extents, invalid source births or malformed FIFO inventory.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.u32()? != 1 || cursor.u32()? != NATIVE_PHASE_TIMER_SUMMARY_BYTES as u32 {
            return Err(NativeCommandError::Invalid(
                "native phase timer summary format",
            ));
        }
        let list_count = cursor.u32()? as usize;
        let timer_count = cursor.u32()? as usize;
        if list_count > 64 || timer_count > 4096 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let expected = NATIVE_PHASE_TIMER_SUMMARY_BYTES
            + list_count * 16
            + timer_count * NATIVE_PHASE_TIMER_ROW_BYTES;
        if bytes.len() != expected {
            return Err(NativeCommandError::Invalid(
                "native phase timer object extent",
            ));
        }
        let current_ps = U64::new(cursor.u64()?);
        let mutation_generation = U64::new(cursor.u64()?);
        let gate_generation = U64::new(cursor.u64()?);
        let sequence = U64::new(cursor.u64()?);
        let prepared_scope_hash = cursor.array()?;
        let command_digest = cursor.array()?;
        let mut lists = Vec::with_capacity(list_count);
        let mut timers = Vec::with_capacity(timer_count);
        for _ in 0..list_count {
            lists.push(NativeTimerList {
                identity: U64::new(cursor.u64()?),
                timer_count: cursor.u32()?,
                flags: cursor.u32()?,
            });
        }
        for _ in 0..timer_count {
            let arm = NativeTimerArm {
                identity: U64::new(cursor.u64()?),
                list: U64::new(cursor.u64()?),
                arm_generation: U64::new(cursor.u64()?),
                expiry_ps: U64::new(cursor.u64()?),
                fifo_ordinal: U64::new(cursor.u64()?),
                attributes: cursor.u32()?,
                scale: cursor.u32()?,
            };
            timers.push(NativePhaseTimerArm {
                arm,
                birth: NativeTimerBirth::decode(&mut cursor)?,
            });
        }
        let value = Self {
            prepared_scope_hash,
            sequence,
            command_digest,
            current_ps,
            mutation_generation,
            gate_generation,
            lists,
            timers,
        };
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "phase_timer_tests.rs"]
mod tests;
