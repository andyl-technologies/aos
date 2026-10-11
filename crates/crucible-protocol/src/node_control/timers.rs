//! Immutable timer observations and bounded checked-offset transport custody.
//!
//! The canonical object uses big-endian integers, a tagged format, scope and
//! original-command digests, followed by bounded list and timer rows. These
//! observations do not establish input, IRQ, device or all-owner closure.

use std::collections::BTreeSet;

use crucible_node_contract::U64;

use super::{NativeCommandError, codec::Cursor};

const MAGIC: &[u8; 8] = b"CNTIMER1";
/// Bounds one retained canonical observation independently of datagram size.
pub const NATIVE_TIMER_OBJECT_MAX_BYTES: usize = 198_000;
/// Bounds each portable slice below the native datagram body allowance.
pub const NATIVE_TIMER_CHUNK_BYTES: usize = 3_000;

/// Records one actual virtual timer-list identity, including empty lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTimerList {
    /// Identifies the actual process-local list without a native pointer.
    pub identity: U64,
    /// Counts rows belonging to this original list.
    pub timer_count: u32,
    /// Records global-list and clock-enabled bits; other bits are refused.
    pub flags: u32,
}

/// Preserves one original timer arm in native FIFO order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTimerArm {
    /// Identifies the actual timer independently of its current arm.
    pub identity: U64,
    /// Identifies its original native list.
    pub list: U64,
    /// Distinguishes same-identity, same-expiry rearming.
    pub arm_generation: U64,
    /// Records the original picosecond expiry.
    pub expiry_ps: U64,
    /// Records the original zero-based list queue order.
    pub fifo_ordinal: U64,
    /// Copies native timer attributes as observational data.
    pub attributes: u32,
    /// Copies the native timer scale as observational data.
    pub scale: u32,
}

/// Preserves a coherent original timer observation under its actual native cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTimerObservation {
    /// Binds the immutable prepared native owner scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the original stopped command; zero denotes the initial park.
    pub sequence: U64,
    /// Binds that exact command; the initial park requires the zero digest.
    pub command_digest: [u8; 32],
    /// Records the actual native clock at observation.
    pub current_ps: U64,
    /// Records the coherent native timer mutation generation.
    pub mutation_generation: U64,
    /// Retains the complete bounded actual virtual-list roster.
    pub lists: Vec<NativeTimerList>,
    /// Retains original timer-arm rows in list identity and FIFO order.
    pub timers: Vec<NativeTimerArm>,
}

impl NativeTimerObservation {
    /// Validates local bounds and coherent original list/FIFO structure.
    ///
    /// # Errors
    /// Rejects unpinned scope, inconsistent original command, duplicate identities,
    /// unsupported flags, incoherent counts/order and exceeded finite limits.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32]
            || (self.sequence.get() == 0) != (self.command_digest == [0; 32])
            || self.lists.len() > 64
            || self.timers.len() > 4096
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut cursor = 0usize;
        let mut previous = 0;
        let mut identities = BTreeSet::new();
        for list in &self.lists {
            if list.identity.get() <= previous || list.flags & !3 != 0 {
                return Err(NativeCommandError::Conflict);
            }
            previous = list.identity.get();
            let end = cursor
                .checked_add(list.timer_count as usize)
                .filter(|end| *end <= self.timers.len())
                .ok_or(NativeCommandError::ResourceLimit)?;
            let mut last_expiry = None;
            for (ordinal, arm) in self.timers[cursor..end].iter().enumerate() {
                if arm.list != list.identity
                    || arm.identity.get() == 0
                    || arm.arm_generation.get() == 0
                    || arm.arm_generation > self.mutation_generation
                    || arm.fifo_ordinal.get() != ordinal as u64
                    || arm.expiry_ps.get() > i64::MAX as u64
                    || arm.scale == 0
                    || !identities.insert(arm.identity)
                    || last_expiry.is_some_and(|expiry| expiry > arm.expiry_ps)
                {
                    return Err(NativeCommandError::Conflict);
                }
                last_expiry = Some(arm.expiry_ps);
            }
            cursor = end;
        }
        if cursor != self.timers.len() {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }

    /// Encodes immutable pointer-free canonical bytes for original custody.
    ///
    /// # Errors
    /// Returns local validation or finite object-size failures.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.prepared_scope_hash);
        bytes.extend_from_slice(&self.sequence.get().to_be_bytes());
        bytes.extend_from_slice(&self.command_digest);
        bytes.extend_from_slice(&self.current_ps.get().to_be_bytes());
        bytes.extend_from_slice(&self.mutation_generation.get().to_be_bytes());
        bytes.extend_from_slice(&(self.lists.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.timers.len() as u32).to_be_bytes());
        for list in &self.lists {
            bytes.extend_from_slice(&list.identity.get().to_be_bytes());
            bytes.extend_from_slice(&list.timer_count.to_be_bytes());
            bytes.extend_from_slice(&list.flags.to_be_bytes());
        }
        for timer in &self.timers {
            for value in [
                timer.identity,
                timer.list,
                timer.arm_generation,
                timer.expiry_ps,
                timer.fifo_ordinal,
            ] {
                bytes.extend_from_slice(&value.get().to_be_bytes());
            }
            bytes.extend_from_slice(&timer.attributes.to_be_bytes());
            bytes.extend_from_slice(&timer.scale.to_be_bytes());
        }
        if bytes.len() > NATIVE_TIMER_OBJECT_MAX_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(bytes)
    }

    /// Decodes one complete bounded immutable observation without native authority.
    ///
    /// # Errors
    /// Rejects truncation, unsupported format, trailing data or inconsistent rows.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > NATIVE_TIMER_OBJECT_MAX_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(NativeCommandError::Conflict);
        }
        let prepared_scope_hash = cursor.array()?;
        let sequence = U64::new(cursor.u64()?);
        let command_digest = cursor.array()?;
        let current_ps = U64::new(cursor.u64()?);
        let mutation_generation = U64::new(cursor.u64()?);
        let list_count = cursor.u32()?;
        let timer_count = cursor.u32()?;
        if list_count > 64 || timer_count > 4096 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut lists = Vec::new();
        let mut timers = Vec::new();
        for _ in 0..list_count {
            lists.push(NativeTimerList {
                identity: U64::new(cursor.u64()?),
                timer_count: cursor.u32()?,
                flags: cursor.u32()?,
            });
        }
        for _ in 0..timer_count {
            timers.push(NativeTimerArm {
                identity: U64::new(cursor.u64()?),
                list: U64::new(cursor.u64()?),
                arm_generation: U64::new(cursor.u64()?),
                expiry_ps: U64::new(cursor.u64()?),
                fifo_ordinal: U64::new(cursor.u64()?),
                attributes: cursor.u32()?,
                scale: cursor.u32()?,
            });
        }
        if !cursor.0.is_empty() {
            return Err(NativeCommandError::Conflict);
        }
        let value = Self {
            prepared_scope_hash,
            sequence,
            command_digest,
            current_ps,
            mutation_generation,
            lists,
            timers,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Requests a checked slice of an already retained original timer object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTimerQuery {
    /// Binds the original prepared native owner.
    pub prepared_scope_hash: [u8; 32],
    /// Selects an original stopped command or the initial zero-sequence cut.
    pub sequence: U64,
    /// Selects a checked byte offset into the same original canonical object.
    pub offset: U64,
}

/// Transfers a bounded slice without regenerating the original native observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTimerChunk {
    /// Binds the original prepared native owner.
    pub prepared_scope_hash: [u8; 32],
    /// Selects the exact original native cut.
    pub sequence: U64,
    /// Hashes the complete canonical observation with BLAKE3-256.
    pub object_digest: [u8; 32],
    /// Bounds the complete immutable observation byte length.
    pub total_bytes: U64,
    /// Locates this slice inside that immutable object.
    pub offset: U64,
    /// Copies only portable immutable bytes, with at most 3000 bytes per slice.
    pub bytes: Vec<u8>,
}

impl NativeTimerChunk {
    pub(super) fn validate(&self) -> Result<(), NativeCommandError> {
        let end = self
            .offset
            .get()
            .checked_add(self.bytes.len() as u64)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if self.prepared_scope_hash == [0; 32]
            || self.object_digest == [0; 32]
            || self.bytes.is_empty()
            || self.bytes.len() > NATIVE_TIMER_CHUNK_BYTES
            || self.total_bytes.get() > NATIVE_TIMER_OBJECT_MAX_BYTES as u64
            || end > self.total_bytes.get()
        {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These timers tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::node_control::{NativeFrame, decode_frame, encode_frame};

    fn observation() -> NativeTimerObservation {
        NativeTimerObservation {
            prepared_scope_hash: [1; 32],
            sequence: U64::new(0),
            command_digest: [0; 32],
            current_ps: U64::new(0),
            mutation_generation: U64::new(4),
            lists: vec![
                NativeTimerList {
                    identity: U64::new(1),
                    timer_count: 2,
                    flags: 3,
                },
                NativeTimerList {
                    identity: U64::new(2),
                    timer_count: 0,
                    flags: 2,
                },
            ],
            timers: (0..2)
                .map(|index| NativeTimerArm {
                    identity: U64::new(index + 1),
                    list: U64::new(1),
                    arm_generation: U64::new(index + 1),
                    expiry_ps: U64::new(100),
                    fifo_ordinal: U64::new(index),
                    attributes: 0,
                    scale: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn closed_timer_object_preserves_empty_roster_and_equal_expiry_fifo() {
        let original = observation();
        let bytes = original.encode().unwrap();
        assert_eq!(NativeTimerObservation::decode(&bytes).unwrap(), original);
        for length in 0..bytes.len() {
            assert!(NativeTimerObservation::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(NativeTimerObservation::decode(&trailing).is_err());
        let mut rearmed = original.clone();
        rearmed.timers[0].arm_generation = U64::new(4);
        assert_ne!(rearmed.encode().unwrap(), bytes);
        let mut reordered = original;
        reordered.timers.swap(0, 1);
        assert!(reordered.encode().is_err());
    }

    #[test]
    fn finite_timer_rows_refuse_duplicate_identity_unbound_cut_and_overflow() {
        let original = observation();
        let mut duplicate = original.clone();
        duplicate.timers[1].identity = duplicate.timers[0].identity;
        assert!(duplicate.validate().is_err());
        let mut future = original.clone();
        future.timers[0].arm_generation = U64::new(5);
        assert!(future.validate().is_err());
        let mut foreign = original.clone();
        foreign.sequence = U64::new(1);
        assert!(foreign.validate().is_err());
        let mut count = original;
        count.lists[0].timer_count = u32::MAX;
        assert!(count.validate().is_err());
    }

    #[test]
    fn timer_slices_have_checked_offsets_and_closed_portable_frames() {
        let bytes = observation().encode().unwrap();
        let chunk = NativeTimerChunk {
            prepared_scope_hash: [1; 32],
            sequence: U64::new(0),
            object_digest: *blake3::hash(&bytes).as_bytes(),
            total_bytes: U64::new(bytes.len() as u64),
            offset: U64::new(0),
            bytes,
        };
        let frame = NativeFrame::TimerChunk(chunk.clone());
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap(), frame);
        for length in 0..encoded.len() {
            assert!(decode_frame(&encoded[..length]).is_err());
        }
        let mut overflow = chunk.clone();
        overflow.offset = U64::new(u64::MAX);
        assert!(encode_frame(&NativeFrame::TimerChunk(overflow)).is_err());
        let mut too_large = chunk;
        too_large.bytes = vec![0; NATIVE_TIMER_CHUNK_BYTES + 1];
        assert!(encode_frame(&NativeFrame::TimerChunk(too_large)).is_err());
        let query = NativeFrame::QueryTimers(NativeTimerQuery {
            prepared_scope_hash: [1; 32],
            sequence: U64::new(0),
            offset: U64::new(12),
        });
        assert_eq!(decode_frame(&encode_frame(&query).unwrap()).unwrap(), query);
    }
}
