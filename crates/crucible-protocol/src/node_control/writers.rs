//! Bounded pointer-free observations of an original held native writer cut.
//!
//! Rows preserve the native roster and FIFO order. CPU interrupts, unknown birth
//! flags, coroutine counts and descriptor slots remain diagnostic observations;
//! neither empty rows nor a successfully decoded object establish writer closure.
//! Scope and command digests require independent comparison with trusted original
//! custody. The codec confers no authority and never reconstructs callback bodies.
//!
//! ```text
//! CNPWRT01 | scope[32] | command_sequence:u64 | command_digest[32]
//! seven u64 counters | coverage:u32 | flags:u32 | roster_sha256[32]
//! five u32 row counts | CPU[32] | work[24] | AIO[40] | BH[24] | handler[32]
//! ```
//!
//! Integers use big endian; signed diagnostic fields use two's complement. The
//! seven counters follow the declaration order in [`NativeWriterObservation`].

use std::collections::BTreeSet;

use crucible_node_contract::U64;

use super::{NativeCommandError, codec::Cursor};

const MAGIC: &[u8; 8] = b"CNPWRT01";
const HEADER_BYTES: usize = 196;
const ROW_BYTES: [usize; 5] = [32, 24, 40, 24, 32];
const ROW_LIMITS: [usize; 5] = [1024, 4096, 64, 4096, 4096];

/// Bounds one complete retained observation before any variable-size allocation.
pub const NATIVE_WRITER_OBJECT_MAX_BYTES: usize = 512 * 1024;

/// Records one original physical CPU and its retained native work FIFO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterCpu {
    /// Identifies the original native CPU roster slot.
    pub cpu_index: u32,
    /// Copies the native interrupt mask without proving producer closure.
    pub interrupt_mask: u32,
    /// Copies the signed native exception index.
    pub exception_index: i32,
    /// Records halted, stop, stopped, exit-request and crash bits.
    pub flags: u32,
    /// Counts this CPU's retained original work rows.
    pub work_count: U64,
    /// Records the next native work identity, saturated at the u64 ceiling.
    pub next_work_sequence: U64,
}

/// Preserves one native work identity in its original CPU FIFO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterWork {
    /// Identifies the original CPU containing this row.
    pub cpu_index: u32,
    /// Records heap ownership, exclusivity and explicitly unknown birth bits.
    pub flags: u32,
    /// Identifies work within its original CPU; it is never a pointer.
    pub work_id: U64,
    /// Records the original one-based position in that CPU's FIFO.
    pub fifo_ordinal: U64,
}

/// Records an original retained asynchronous context without callback payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterAio {
    /// Identifies the native context within the retained registry.
    pub context_id: U64,
    /// Copies its process-local home-thread diagnostic identifier.
    pub home_thread_id: i64,
    /// Counts active native polls; a held cut requires zero.
    pub active_polls: u32,
    /// Counts active native dispatches; a held cut requires zero.
    pub active_dispatches: u32,
    /// Records pending bottom halves without proving their semantics.
    pub pending_bhs: u32,
    /// Counts active native bottom halves; a held cut requires zero.
    pub active_bhs: u32,
    /// Records queued coroutines whose payloads remain unknown.
    pub queued_coroutines: u32,
    /// Records the original notification-pending bit.
    pub flags: u32,
}

/// Records an allocated native bottom-half identity and pending flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterBh {
    /// Identifies the original native bottom half.
    pub bh_id: U64,
    /// Identifies its actual retained asynchronous context.
    pub context_id: U64,
    /// Counts active callbacks; a held cut requires zero.
    pub active_callbacks: u32,
    /// Records pending, scheduled, deleted, one-shot and idle bits.
    pub flags: u32,
}

/// Records one native POSIX handler slot without transferring descriptor authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterHandler {
    /// Identifies the original allocated native handler.
    pub handler_id: U64,
    /// Identifies its actual retained asynchronous context.
    pub context_id: U64,
    /// Copies the original process-local descriptor slot, never a portable FD.
    pub descriptor_slot: i64,
    /// Counts active callbacks; a held cut requires zero.
    pub active_callbacks: u32,
    /// Records deleted, read, write, poll, ready, begin and end bits.
    pub flags: u32,
}

/// Preserves finite source-specific facts from one original native writer cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterObservation {
    /// Binds the exact original prepared scope, subject to trusted comparison.
    pub prepared_scope_hash: [u8; 32],
    /// Names the original stopped command; zero denotes the initial park.
    pub sequence: U64,
    /// Binds that exact command; the initial park requires the zero digest.
    pub command_digest: [u8; 32],
    /// Identifies the actual held gate generation.
    pub gate_generation: U64,
    /// Records the observed native picosecond clock.
    pub current_ps: U64,
    /// Copies raw native instruction count as a diagnostic observation.
    pub retired_count: U64,
    /// Records the native asynchronous-context registry generation.
    pub aio_generation: U64,
    /// Records the native bottom-half registry generation.
    pub bh_generation: U64,
    /// Records the native POSIX-handler registry generation.
    pub handler_generation: U64,
    /// Counts active gate admissions; a held cut requires zero.
    pub admissions_in_flight: U64,
    /// Records CPU-park, asynchronous-HOLD and CPU-work coverage bits.
    pub coverage: u32,
    /// Records HOLD and unknown CPU-producer, callback and device-I/O bits.
    pub flags: u32,
    /// Binds the actual original CPU roster; it is not an authority token.
    pub roster_sha256: [u8; 32],
    /// Preserves the ascending actual CPU roster.
    pub cpus: Vec<NativeWriterCpu>,
    /// Preserves each original CPU FIFO, in ascending CPU-roster order.
    pub work: Vec<NativeWriterWork>,
    /// Preserves the native asynchronous-context registry order.
    pub aio: Vec<NativeWriterAio>,
    /// Preserves the original allocated bottom-half registry order.
    pub bottom_halves: Vec<NativeWriterBh>,
    /// Preserves the original allocated native handler registry order.
    pub handlers: Vec<NativeWriterHandler>,
}

impl NativeWriterObservation {
    /// Validates finite row structure and source-specific held-cut consistency.
    ///
    /// Successful validation leaves unknown producer and callback semantics
    /// unknown. It does not authenticate the scope, roster or original command.
    ///
    /// # Errors
    /// Rejects exceeded row limits, unsupported bits, inconsistent FIFO/counts,
    /// duplicate identities, foreign contexts, active writers and unpinned scope.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        checked_length(self.counts())?;
        if self.prepared_scope_hash == [0; 32]
            || self.roster_sha256 == [0; 32]
            || (self.sequence.get() == 0) != (self.command_digest == [0; 32])
            || self.gate_generation.get() == 0
            || self.admissions_in_flight.get() != 0
            || self.coverage & !7 != 0
            || self.flags & !15 != 0
            || self.flags & 1 == 0
            || self.cpus.is_empty()
        {
            return Err(NativeCommandError::Conflict);
        }

        let mut previous_cpu = None;
        let mut work_cursor = 0usize;
        let mut work_identities = BTreeSet::new();
        for cpu in &self.cpus {
            if previous_cpu.is_some_and(|previous| previous >= cpu.cpu_index)
                || cpu.flags & !31 != 0
                || cpu.next_work_sequence.get() == 0
            {
                return Err(NativeCommandError::Conflict);
            }
            previous_cpu = Some(cpu.cpu_index);
            let count = usize::try_from(cpu.work_count.get())
                .map_err(|_| NativeCommandError::ResourceLimit)?;
            let end = work_cursor
                .checked_add(count)
                .filter(|end| *end <= self.work.len())
                .ok_or(NativeCommandError::Conflict)?;
            for (index, work) in self.work[work_cursor..end].iter().enumerate() {
                let sequence = work.work_id.get();
                let next = cpu.next_work_sequence.get();
                if work.cpu_index != cpu.cpu_index
                    || work.flags & !7 != 0
                    || sequence == 0
                    || (sequence >= next && !(sequence == u64::MAX && next == u64::MAX))
                    || work.fifo_ordinal.get() != index as u64 + 1
                    || !work_identities.insert((work.cpu_index, work.work_id))
                {
                    return Err(NativeCommandError::Conflict);
                }
            }
            work_cursor = end;
        }
        if work_cursor != self.work.len() {
            return Err(NativeCommandError::Conflict);
        }

        let mut contexts = BTreeSet::new();
        for context in &self.aio {
            if context.context_id.get() == 0
                || !contexts.insert(context.context_id)
                || context.flags & !1 != 0
                || context.active_polls != 0
                || context.active_dispatches != 0
                || context.active_bhs != 0
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        let mut identities = BTreeSet::new();
        for bh in &self.bottom_halves {
            if bh.bh_id.get() == 0
                || !identities.insert(bh.bh_id)
                || !contexts.contains(&bh.context_id)
                || bh.flags & !31 != 0
                || bh.active_callbacks != 0
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        identities.clear();
        for handler in &self.handlers {
            if handler.handler_id.get() == 0
                || !identities.insert(handler.handler_id)
                || !contexts.contains(&handler.context_id)
                || handler.flags & !127 != 0
                || handler.active_callbacks != 0
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        Ok(())
    }

    /// Encodes original pointer-free rows without sorting or repairing them.
    ///
    /// # Errors
    /// Returns finite-size or structural held-cut validation failures.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let counts = self.counts();
        let mut bytes = Vec::with_capacity(checked_length(counts)?);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.prepared_scope_hash);
        push_u64(&mut bytes, self.sequence);
        bytes.extend_from_slice(&self.command_digest);
        for value in [
            self.gate_generation,
            self.current_ps,
            self.retired_count,
            self.aio_generation,
            self.bh_generation,
            self.handler_generation,
            self.admissions_in_flight,
        ] {
            push_u64(&mut bytes, value);
        }
        push_u32(&mut bytes, self.coverage);
        push_u32(&mut bytes, self.flags);
        bytes.extend_from_slice(&self.roster_sha256);
        for count in counts {
            push_u32(&mut bytes, count as u32);
        }
        for row in &self.cpus {
            push_u32(&mut bytes, row.cpu_index);
            push_u32(&mut bytes, row.interrupt_mask);
            bytes.extend_from_slice(&row.exception_index.to_be_bytes());
            push_u32(&mut bytes, row.flags);
            push_u64(&mut bytes, row.work_count);
            push_u64(&mut bytes, row.next_work_sequence);
        }
        for row in &self.work {
            push_u32(&mut bytes, row.cpu_index);
            push_u32(&mut bytes, row.flags);
            push_u64(&mut bytes, row.work_id);
            push_u64(&mut bytes, row.fifo_ordinal);
        }
        for row in &self.aio {
            push_u64(&mut bytes, row.context_id);
            bytes.extend_from_slice(&row.home_thread_id.to_be_bytes());
            for value in [
                row.active_polls,
                row.active_dispatches,
                row.pending_bhs,
                row.active_bhs,
                row.queued_coroutines,
                row.flags,
            ] {
                push_u32(&mut bytes, value);
            }
        }
        for row in &self.bottom_halves {
            push_u64(&mut bytes, row.bh_id);
            push_u64(&mut bytes, row.context_id);
            push_u32(&mut bytes, row.active_callbacks);
            push_u32(&mut bytes, row.flags);
        }
        for row in &self.handlers {
            push_u64(&mut bytes, row.handler_id);
            push_u64(&mut bytes, row.context_id);
            bytes.extend_from_slice(&row.descriptor_slot.to_be_bytes());
            push_u32(&mut bytes, row.active_callbacks);
            push_u32(&mut bytes, row.flags);
        }
        Ok(bytes)
    }

    /// Decodes one complete bounded object without granting native authority.
    ///
    /// All row counts and the exact byte length are checked before row allocation.
    /// Native row order and every unknown flag remain unchanged.
    ///
    /// # Errors
    /// Rejects oversized objects, unsupported tags, truncation, trailing bytes,
    /// impossible row counts and structurally inconsistent held observations.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() > NATIVE_WRITER_OBJECT_MAX_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(NativeCommandError::Conflict);
        }
        let prepared_scope_hash = cursor.array()?;
        let sequence = read_u64(&mut cursor)?;
        let command_digest = cursor.array()?;
        let gate_generation = read_u64(&mut cursor)?;
        let current_ps = read_u64(&mut cursor)?;
        let retired_count = read_u64(&mut cursor)?;
        let aio_generation = read_u64(&mut cursor)?;
        let bh_generation = read_u64(&mut cursor)?;
        let handler_generation = read_u64(&mut cursor)?;
        let admissions_in_flight = read_u64(&mut cursor)?;
        let coverage = cursor.u32()?;
        let flags = cursor.u32()?;
        let roster_sha256 = cursor.array()?;
        let mut counts = [0usize; 5];
        for count in &mut counts {
            *count = cursor.u32()? as usize;
        }
        if checked_length(counts)? != bytes.len() {
            return Err(NativeCommandError::Conflict);
        }

        let mut cpus = Vec::with_capacity(counts[0]);
        let mut work = Vec::with_capacity(counts[1]);
        let mut aio = Vec::with_capacity(counts[2]);
        let mut bottom_halves = Vec::with_capacity(counts[3]);
        let mut handlers = Vec::with_capacity(counts[4]);
        for _ in 0..counts[0] {
            cpus.push(NativeWriterCpu {
                cpu_index: cursor.u32()?,
                interrupt_mask: cursor.u32()?,
                exception_index: i32::from_be_bytes(cursor.array()?),
                flags: cursor.u32()?,
                work_count: read_u64(&mut cursor)?,
                next_work_sequence: read_u64(&mut cursor)?,
            });
        }
        for _ in 0..counts[1] {
            work.push(NativeWriterWork {
                cpu_index: cursor.u32()?,
                flags: cursor.u32()?,
                work_id: read_u64(&mut cursor)?,
                fifo_ordinal: read_u64(&mut cursor)?,
            });
        }
        for _ in 0..counts[2] {
            aio.push(NativeWriterAio {
                context_id: read_u64(&mut cursor)?,
                home_thread_id: i64::from_be_bytes(cursor.array()?),
                active_polls: cursor.u32()?,
                active_dispatches: cursor.u32()?,
                pending_bhs: cursor.u32()?,
                active_bhs: cursor.u32()?,
                queued_coroutines: cursor.u32()?,
                flags: cursor.u32()?,
            });
        }
        for _ in 0..counts[3] {
            bottom_halves.push(NativeWriterBh {
                bh_id: read_u64(&mut cursor)?,
                context_id: read_u64(&mut cursor)?,
                active_callbacks: cursor.u32()?,
                flags: cursor.u32()?,
            });
        }
        for _ in 0..counts[4] {
            handlers.push(NativeWriterHandler {
                handler_id: read_u64(&mut cursor)?,
                context_id: read_u64(&mut cursor)?,
                descriptor_slot: i64::from_be_bytes(cursor.array()?),
                active_callbacks: cursor.u32()?,
                flags: cursor.u32()?,
            });
        }
        let value = Self {
            prepared_scope_hash,
            sequence,
            command_digest,
            gate_generation,
            current_ps,
            retired_count,
            aio_generation,
            bh_generation,
            handler_generation,
            admissions_in_flight,
            coverage,
            flags,
            roster_sha256,
            cpus,
            work,
            aio,
            bottom_halves,
            handlers,
        };
        value.validate()?;
        Ok(value)
    }

    fn counts(&self) -> [usize; 5] {
        [
            self.cpus.len(),
            self.work.len(),
            self.aio.len(),
            self.bottom_halves.len(),
            self.handlers.len(),
        ]
    }
}

fn checked_length(counts: [usize; 5]) -> Result<usize, NativeCommandError> {
    let mut length = HEADER_BYTES;
    for ((count, limit), width) in counts.into_iter().zip(ROW_LIMITS).zip(ROW_BYTES) {
        if count > limit {
            return Err(NativeCommandError::ResourceLimit);
        }
        length = count
            .checked_mul(width)
            .and_then(|bytes| length.checked_add(bytes))
            .ok_or(NativeCommandError::ResourceLimit)?;
    }
    if length > NATIVE_WRITER_OBJECT_MAX_BYTES {
        return Err(NativeCommandError::ResourceLimit);
    }
    Ok(length)
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: U64) {
    bytes.extend_from_slice(&value.get().to_be_bytes());
}

fn read_u64(cursor: &mut Cursor<'_>) -> Result<U64, NativeCommandError> {
    Ok(U64::new(cursor.u64()?))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These writers tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn observation() -> NativeWriterObservation {
        NativeWriterObservation {
            prepared_scope_hash: [1; 32],
            sequence: U64::new(7),
            command_digest: [2; 32],
            gate_generation: U64::new(3),
            current_ps: U64::new(50),
            retired_count: U64::new(1),
            aio_generation: U64::new(4),
            bh_generation: U64::new(5),
            handler_generation: U64::new(6),
            admissions_in_flight: U64::new(0),
            coverage: 7,
            flags: 15,
            roster_sha256: [3; 32],
            cpus: vec![NativeWriterCpu {
                cpu_index: 0,
                interrupt_mask: 0x8000_0000,
                exception_index: -1,
                flags: 5,
                work_count: U64::new(2),
                next_work_sequence: U64::new(12),
            }],
            work: vec![
                NativeWriterWork {
                    cpu_index: 0,
                    flags: 5,
                    work_id: U64::new(2),
                    fifo_ordinal: U64::new(1),
                },
                NativeWriterWork {
                    cpu_index: 0,
                    flags: 2,
                    work_id: U64::new(9),
                    fifo_ordinal: U64::new(2),
                },
            ],
            aio: vec![NativeWriterAio {
                context_id: U64::new(4),
                home_thread_id: -5,
                active_polls: 0,
                active_dispatches: 0,
                pending_bhs: 1,
                active_bhs: 0,
                queued_coroutines: 2,
                flags: 1,
            }],
            bottom_halves: vec![NativeWriterBh {
                bh_id: U64::new(8),
                context_id: U64::new(4),
                active_callbacks: 0,
                flags: 3,
            }],
            handlers: vec![NativeWriterHandler {
                handler_id: U64::new(13),
                context_id: U64::new(4),
                descriptor_slot: -1,
                active_callbacks: 0,
                flags: 14,
            }],
        }
    }

    #[test]
    fn canonical_bytes_preserve_source_diagnostics_and_unknowns() {
        let original = observation();
        let bytes = original.encode().unwrap();

        assert_eq!(bytes.len(), HEADER_BYTES + 32 + 48 + 40 + 24 + 32);
        assert_eq!(&bytes[..8], b"CNPWRT01");
        assert_eq!(&bytes[40..48], &7u64.to_be_bytes());
        assert_eq!(&bytes[80..88], &3u64.to_be_bytes());
        assert_eq!(&bytes[136..140], &7u32.to_be_bytes());
        assert_eq!(&bytes[140..144], &15u32.to_be_bytes());
        assert_eq!(
            &bytes[176..196],
            &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]
        );
        assert_eq!(&bytes[204..208], &(-1i32).to_be_bytes());
        let decoded = NativeWriterObservation::decode(&bytes).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.flags, 15);
        assert_eq!(decoded.work[0].flags & 4, 4);
        assert_eq!(decoded.aio[0].queued_coroutines, 2);
        assert_eq!(decoded.handlers[0].descriptor_slot, -1);
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    #[test]
    fn every_truncation_and_trailing_byte_is_rejected() {
        let bytes = observation().encode().unwrap();

        for end in 0..bytes.len() {
            assert!(
                NativeWriterObservation::decode(&bytes[..end]).is_err(),
                "{end}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(NativeWriterObservation::decode(&trailing).is_err());
    }

    #[test]
    fn malicious_counts_fail_before_row_allocation() {
        let original = observation().encode().unwrap();
        for (index, limit) in ROW_LIMITS.into_iter().enumerate() {
            let mut bytes = original.clone();
            let offset = 176 + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&(limit as u32 + 1).to_be_bytes());
            assert!(matches!(
                NativeWriterObservation::decode(&bytes),
                Err(NativeCommandError::ResourceLimit)
            ));
        }
        assert!(matches!(
            NativeWriterObservation::decode(&vec![0; NATIVE_WRITER_OBJECT_MAX_BYTES + 1]),
            Err(NativeCommandError::ResourceLimit)
        ));
    }

    #[test]
    fn foreign_contexts_duplicate_ids_and_changed_fifo_are_refused() {
        let mut changed = observation();
        changed.bottom_halves[0].context_id = U64::new(99);
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.handlers[0].context_id = U64::new(99);
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.aio.push(changed.aio[0].clone());
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.bottom_halves.push(changed.bottom_halves[0].clone());
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.handlers.push(changed.handlers[0].clone());
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.work[1].work_id = changed.work[0].work_id;
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.work.swap(0, 1);
        assert!(changed.encode().is_err());
    }

    #[test]
    fn cpu_counts_roster_and_native_sequence_are_not_repaired() {
        let mut changed = observation();
        changed.cpus[0].work_count = U64::new(1);
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.cpus.push(changed.cpus[0].clone());
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.work[0].cpu_index = 1;
        assert!(changed.validate().is_err());

        let mut changed = observation();
        changed.cpus[0].next_work_sequence = U64::new(9);
        assert!(changed.validate().is_err());

        // Retired later work may leave gaps in the retained FIFO identities.
        let mut changed = observation();
        changed.cpus[0].next_work_sequence = U64::new(u64::MAX);
        changed.work[1].work_id = U64::new(u64::MAX);
        assert!(changed.validate().is_ok());
    }

    #[test]
    fn held_cut_refuses_active_writers_and_unrecognized_bits() {
        for field in 0..5 {
            let mut changed = observation();
            match field {
                0 => changed.admissions_in_flight = U64::new(1),
                1 => changed.aio[0].active_polls = 1,
                2 => changed.aio[0].active_dispatches = 1,
                3 => changed.aio[0].active_bhs = 1,
                _ => changed.bottom_halves[0].active_callbacks = 1,
            }
            assert!(changed.validate().is_err());
        }
        let mut changed = observation();
        changed.handlers[0].active_callbacks = 1;
        assert!(changed.validate().is_err());
        let mut changed = observation();
        changed.flags &= !1;
        assert!(changed.validate().is_err());
        let mut changed = observation();
        changed.flags |= 16;
        assert!(changed.validate().is_err());
        let mut changed = observation();
        changed.coverage |= 8;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn initial_park_and_original_scope_remain_explicit_data() {
        let mut initial = observation();
        initial.sequence = U64::new(0);
        assert!(initial.validate().is_err());
        initial.command_digest = [0; 32];
        assert!(initial.validate().is_ok());
        initial.sequence = U64::new(1);
        assert!(initial.validate().is_err());

        // A foreign nonzero scope is structurally valid, never authenticated by
        // this codec. Its changed bytes must reach the trusted scope verifier.
        let original = observation();
        let mut foreign = original.encode().unwrap();
        foreign[8] ^= 0x80;
        let decoded = NativeWriterObservation::decode(&foreign).unwrap();
        assert_ne!(decoded.prepared_scope_hash, original.prepared_scope_hash);
        assert_ne!(decoded, original);
        assert_eq!(decoded.encode().unwrap(), foreign);
    }

    #[test]
    fn native_registry_order_is_preserved_without_sorting() {
        let mut original = observation();
        let mut second = original.aio[0].clone();
        second.context_id = U64::new(2);
        original.aio.push(second);

        let decoded = NativeWriterObservation::decode(&original.encode().unwrap()).unwrap();
        assert_eq!(decoded.aio[0].context_id.get(), 4);
        assert_eq!(decoded.aio[1].context_id.get(), 2);
    }
}
