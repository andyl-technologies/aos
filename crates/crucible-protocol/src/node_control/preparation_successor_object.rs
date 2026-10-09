//! Closed canonical content of one historical native preparation successor.
//!
//! The format preserves native inventory order and scalar identities. The
//! decoder reuses the existing closed CPU, writer, initialization and phase
//! timer schemas; it never promotes their coverage to a whole-owner guarantee.
//!
//! ```text
//! tag-with-NUL, facts-prefix[208], initialization-receipt[160],
//! cpu-park[112], writer-summary[160], phase-timer-summary[112],
//! CPU[32]*n, work[24]*n, Aio[40]*n, BH[24]*n, handler[32]*n,
//! timer-list[16]*n, phase-timer[200]*n
//! ```

use crucible_node_contract::U64;
use sha2::{Digest, Sha256};

use super::preparation_successor::{
    NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES, NativePreparationSuccessorFacts,
};
use super::{
    NativeCommandError, NativeCpuParkFacts, NativeInitializationReceipt,
    NativeInitializationStatus, NativePhaseTimerObservation, NativeTimerBirth,
    NativeWriterObservation, codec::Cursor,
};

const OBJECT_TAG: &[u8] = b"crucible.qemu-native-preparation-successor.v1\0";
const RECEIPT_TAG: &[u8] = b"crucible.qemu-native-applied-receipt.v1\0";

/// Preserves typed views of a single original, historical native source object.
///
/// This decoder authenticates byte hashes and schema consistency only. Actual
/// source registration, socket custody and the retained initialization ACK are
/// independent requirements. Neither this type nor any field is a Ready seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePreparationSuccessorObservation {
    /// Preserves the original source-selected object's correlation facts.
    pub facts: NativePreparationSuccessorFacts,
    /// Preserves exactly the original Applied receipt, without an ACK claim.
    pub initialization: NativeInitializationReceipt,
    /// Preserves original CPU-only park coverage.
    pub cpu_park: NativeCpuParkFacts,
    /// Preserves original held writer inventory, including unknown roots.
    pub writers: NativeWriterObservation,
    /// Preserves original phase timer inventory and unqualified birth kinds.
    pub timers: NativePhaseTimerObservation,
}

impl NativePreparationSuccessorObservation {
    /// Decodes the exact source object under independently obtained fixed facts.
    ///
    /// # Errors
    /// Rejects excessive extents before allocation, hash/prefix disagreement,
    /// malformed nested schemas, open fields, inconsistent counts, or changed
    /// original scope, initialization, HOLD, progress or roster identities.
    pub fn decode(
        facts: NativePreparationSuccessorFacts,
        bytes: &[u8],
    ) -> Result<Self, NativeCommandError> {
        facts.validate()?;
        if bytes.len() > NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES
            || bytes.len() as u64 != facts.content_length.get()
            || <[u8; 32]>::from(Sha256::digest(bytes)) != facts.content_sha256
        {
            return Err(NativeCommandError::Conflict);
        }
        let encoded_facts = facts.encode()?;
        let mut cursor = Cursor(bytes);
        if cursor.take(OBJECT_TAG.len())? != OBJECT_TAG
            || cursor.take(208)? != &encoded_facts[..208]
        {
            return Err(NativeCommandError::Conflict);
        }
        let receipt_bytes = cursor.take(160)?;
        let mut receipt_hash = Sha256::new();
        receipt_hash.update(RECEIPT_TAG);
        receipt_hash.update(receipt_bytes);
        if <[u8; 32]>::from(receipt_hash.finalize()) != facts.applied_receipt_sha256 {
            return Err(NativeCommandError::Conflict);
        }
        let initialization = NativeInitializationReceipt::decode(receipt_bytes)?;
        let cpu_park = decode_cpu_park(cursor.take(112)?)?;
        let writer_summary = cursor.take(160)?;
        let timer_summary = cursor.take(112)?;
        let writer_extent = writer_extent(writer_summary)?;
        let timer_extent = timer_extent(timer_summary)?;
        if cursor.0.len() != writer_extent + timer_extent {
            return Err(NativeCommandError::Invalid(
                "preparation successor inventory extent",
            ));
        }

        let writers = decode_writers(writer_summary, cursor.take(writer_extent)?)?;
        let mut timer_bytes = Vec::new();
        timer_bytes
            .try_reserve_exact(112 + timer_extent)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        timer_bytes.extend_from_slice(timer_summary);
        timer_bytes.extend_from_slice(cursor.take(timer_extent)?);
        let timers = NativePhaseTimerObservation::decode(&timer_bytes)?;
        let value = Self {
            facts,
            initialization,
            cpu_park,
            writers,
            timers,
        };
        value.validate_identity()?;
        Ok(value)
    }

    fn validate_identity(&self) -> Result<(), NativeCommandError> {
        let facts = &self.facts;
        let receipt = &self.initialization;
        if receipt.status != NativeInitializationStatus::Applied
            || receipt.sequence != facts.initialization_sequence
            || receipt.hold_generation != facts.hold_generation
            || receipt.prepared_scope_hash != facts.prepared_scope_hash
            || receipt.initialization_commitment != facts.initialization_commitment
            || receipt.realize_request_digest != facts.realize_request_digest
            || receipt.original_cut_digest != facts.original_cut_digest
            || self.cpu_park.current_ps != facts.current_ps
            || self.cpu_park.retired_count != facts.retired_count
            || self.cpu_park.prepared_scope_hash != facts.prepared_scope_hash
            || self.cpu_park.next_service_deadline_ps.is_some()
            || self.cpu_park.pending_service_credit_ps.get() != 0
            || self.writers.prepared_scope_hash != facts.prepared_scope_hash
            || self.writers.gate_generation != facts.hold_generation
            || self.writers.current_ps != facts.current_ps
            || self.writers.retired_count != facts.retired_count
            || self.writers.cpus.len() as u32 != self.cpu_park.cpu_count
            || self.writers.roster_sha256 != self.cpu_park.roster_sha256
            || self.writers.coverage != 7
            || self.writers.flags != 15
            || self.timers.prepared_scope_hash != facts.prepared_scope_hash
            || self.timers.gate_generation != facts.hold_generation
            || self.timers.current_ps != facts.current_ps
            || self.timers.sequence.get() != 0
            || self.timers.command_digest != [0; 32]
        {
            return Err(NativeCommandError::Conflict);
        }
        for timer in &self.timers.timers {
            match &timer.birth {
                NativeTimerBirth::Unknown { .. } => {}
                NativeTimerBirth::Construction {
                    initialization_commitment,
                    ..
                } if *initialization_commitment == facts.initialization_commitment => {}
                _ => return Err(NativeCommandError::Conflict),
            }
        }
        Ok(())
    }
}

fn decode_cpu_park(bytes: &[u8]) -> Result<NativeCpuParkFacts, NativeCommandError> {
    let mut cursor = Cursor(bytes);
    if cursor.u32()? != 1 || cursor.u32()? != 112 {
        return Err(NativeCommandError::Invalid("successor CPU park format"));
    }
    let coverage = cursor.u32()?;
    let cpu_count = cursor.u32()?;
    let current_ps = U64::new(cursor.u64()?);
    let retired_count = U64::new(cursor.u64()?);
    let deadline = cursor.u64()?;
    let value = NativeCpuParkFacts {
        coverage,
        cpu_count,
        current_ps,
        retired_count,
        next_service_deadline_ps: (deadline != u64::MAX).then_some(U64::new(deadline)),
        pending_service_credit_ps: U64::new(cursor.u64()?),
        prepared_scope_hash: cursor.array()?,
        roster_sha256: cursor.array()?,
    };
    value.validate()?;
    Ok(value)
}

fn writer_extent(summary: &[u8]) -> Result<usize, NativeCommandError> {
    let mut cursor = Cursor(summary);
    if cursor.u32()? != 1 || cursor.u32()? != 160 {
        return Err(NativeCommandError::Invalid(
            "successor writer summary format",
        ));
    }
    cursor.take(8)?;
    let mut total = 0;
    for (maximum, width) in [(1024, 32), (4096, 24), (64, 40), (4096, 24), (4096, 32)] {
        let count = cursor.u32()? as usize;
        if count > maximum {
            return Err(NativeCommandError::ResourceLimit);
        }
        total += count * width;
    }
    if cursor.u32()? != 0 {
        return Err(NativeCommandError::Invalid(
            "successor writer reserved field",
        ));
    }
    Ok(total)
}

fn timer_extent(summary: &[u8]) -> Result<usize, NativeCommandError> {
    let mut cursor = Cursor(summary);
    if cursor.u32()? != 1 || cursor.u32()? != 112 {
        return Err(NativeCommandError::Invalid("successor phase timer format"));
    }
    let lists = cursor.u32()? as usize;
    let timers = cursor.u32()? as usize;
    if lists > 64 || timers > 4096 {
        return Err(NativeCommandError::ResourceLimit);
    }
    Ok(lists * 16 + timers * 200)
}

fn decode_writers(
    summary: &[u8],
    rows: &[u8],
) -> Result<NativeWriterObservation, NativeCommandError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(196 + rows.len())
        .map_err(|_| NativeCommandError::ResourceLimit)?;
    bytes.extend_from_slice(b"CNPWRT01");
    bytes.extend_from_slice(&summary[96..128]);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&summary[40..96]);
    bytes.extend_from_slice(&summary[8..16]);
    bytes.extend_from_slice(&summary[128..160]);
    bytes.extend_from_slice(&summary[16..36]);
    bytes.extend_from_slice(rows);
    NativeWriterObservation::decode(&bytes)
}

#[cfg(test)]
#[path = "preparation_successor_tests.rs"]
pub(crate) mod tests;
