//! Staged native bytes and atomic validation of an authenticated accepted prefix.

use crucible_protocol::native_console::{
    NativeConsoleAuthorization, NativeConsoleFrontier, NativeConsolePlan, NativeConsoleRecord,
};

use super::*;
use crate::{RingHeader, SpscRingError};

/// A prepared complete prefix, with no consumer-index effect yet.
///
/// The host commits these original records to evidence before acknowledging the
/// prepared ring end. A partial/malformed prefix never yields this value.
pub struct NativeConsolePrefix<'a> {
    ring: &'a RingHeader,
    start: u64,
    end: u64,
    records: Vec<NativeConsoleRecord>,
    stream_sequences: Vec<u64>,
    node_sequence: u64,
}

impl NativeConsolePrefix<'_> {
    /// Returns the validated immutable original records.
    #[must_use]
    pub fn records(&self) -> &[NativeConsoleRecord] {
        &self.records
    }

    /// Returns the validated final sequence of each sorted plan stream.
    #[must_use]
    pub fn stream_sequences(&self) -> &[u64] {
        &self.stream_sequences
    }

    /// Returns the final cumulative node sequence.
    #[must_use]
    pub const fn node_sequence(&self) -> u64 {
        self.node_sequence
    }
}

/// A ring publication or complete-prefix validation failure.
#[derive(Debug, thiserror::Error)]
pub enum NativeConsoleRingError {
    /// Original shared ring admission or cursor validation failed.
    #[error("native-console ring rejected: {0}")]
    Ring(#[from] SpscRingError),
    /// A console record, plan or accepted tuple differs.
    #[error("native-console prefix rejected: {0}")]
    Console(#[from] NativeConsoleError),
}

impl RingHeader {
    /// Stages one complete already-preflighted native UART operation.
    ///
    /// The producer adapter must enforce the original authenticated grant's
    /// private allowance before calling this storage primitive. Host drain
    /// timing cannot authorize or refill that allowance. All records and the
    /// entire capacity are checked before any record or write-index effect.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleRingError`] for invalid storage, held producer
    /// admission, corrupt/overflowing cursors, capacity exhaustion or malformed
    /// records. Refusal leaves the published write index and entries unchanged.
    pub fn stage_native_console(
        &self,
        entries: &[NativeConsoleEntry],
        records: &[NativeConsoleRecord],
    ) -> Result<(), NativeConsoleRingError> {
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
        check_storage(entries)?;
        let start = self.write_idx.load(Ordering::Relaxed);
        let read = self.read_idx.load(Ordering::Acquire);
        let live = checked_live(read, start)?;
        let count = u64::try_from(records.len()).map_err(|_| NativeConsoleError::Length)?;
        if count > u64::from(NATIVE_CONSOLE_CAPACITY) - live {
            return Err(SpscRingError::QueueFull {
                capacity: u64::from(NATIVE_CONSOLE_CAPACITY),
            }
            .into());
        }
        let end = start
            .checked_add(count)
            .ok_or(NativeConsoleError::Sequence)?;
        let encoded = records
            .iter()
            .map(|record| record.encode())
            .collect::<Result<Vec<_>, _>>()?;
        for (offset, bytes) in encoded.iter().enumerate() {
            entries[((start + offset as u64) % u64::from(NATIVE_CONSOLE_CAPACITY)) as usize]
                .store(bytes);
        }
        self.write_idx.store(end, Ordering::Release);
        Ok(())
    }

    /// Copies the last byte of an exact unconsumed operation endpoint.
    ///
    /// This bounded observation neither validates a whole prefix nor consumes
    /// it. The native stopped-occurrence owner and exact current node framing
    /// must be authenticated separately before using it for stop discovery.
    ///
    /// # Errors
    ///
    /// Refuses held consumer admission, corrupt storage/cursors or malformed
    /// bytes. A replaced endpoint or an empty ring returns no observation.
    pub fn peek_native_console_operation_tail(
        &self,
        entries: &[NativeConsoleEntry],
        endpoint: u64,
    ) -> Result<Option<NativeConsoleRecord>, NativeConsoleRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
        check_storage(entries)?;
        let read = self.read_idx.load(Ordering::Relaxed);
        let write = self.write_idx.load(Ordering::Acquire);
        let live = checked_live(read, write)?;
        if live == 0 || write != endpoint {
            return Ok(None);
        }

        let bytes = entries[((write - 1) % u64::from(NATIVE_CONSOLE_CAPACITY)) as usize].load();
        let record = NativeConsoleRecord::decode(&bytes)?;
        if self.write_idx.load(Ordering::Acquire) != write {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Validates a complete prefix after original completed-boundary acceptance.
    ///
    /// The caller must first join `frontier` to the original authenticated odd
    /// ACK/publication snapshot and authenticate the actual original phase
    /// transaction in `authorization`. Those authorities cannot be supplied by
    /// this codec/ring function. Emission authorization advance and accepted
    /// clamp advance remain distinct; their relationship is checked by the
    /// original pending/discovery owner, not by inventing an equality here.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleRingError`] for held consumer admission, short or
    /// corrupt storage, future/missing/duplicate/gapped records, wrong physical
    /// owner or logical stream, future coordinates, invalid owner masks or an
    /// inconsistent accepted end. Prior read index and evidence remain unchanged.
    pub fn prepare_native_console_prefix(
        &self,
        entries: &[NativeConsoleEntry],
        plan: &NativeConsolePlan,
        authorization: NativeConsoleAuthorization,
        frontier: NativeConsoleFrontier,
        prior_node_sequence: u64,
        prior_stream_sequences: &[u64],
    ) -> Result<NativeConsolePrefix<'_>, NativeConsoleRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
        check_storage(entries)?;
        plan.encode()?;
        authorization.encode()?;
        frontier.encode()?;
        let start = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        checked_live(start, tail)?;
        if authorization.owner != frontier.owner
            || plan.slot != frontier.owner.slot
            || plan.logical_generation != frontier.logical_generation
            || authorization.logical_generation != frontier.logical_generation
            || frontier.plan_hash != plan.digest()?
            || prior_stream_sequences.len() != plan.streams.len()
            || authorization.prior_sequence != prior_node_sequence
            || authorization.prior_ring_end != start
            || frontier.ring_end < start
            || frontier.ring_end > tail
        {
            return Err(NativeConsoleError::Binding.into());
        }
        let count = frontier.ring_end - start;
        if count > u64::from(authorization.allowance)
            || prior_node_sequence.checked_add(count) != Some(frontier.sequence)
        {
            return Err(NativeConsoleError::Sequence.into());
        }
        let mut node_sequence = prior_node_sequence;
        let mut stream_sequences = prior_stream_sequences.to_vec();
        let mut records = Vec::with_capacity(count as usize);
        for cursor in start..frontier.ring_end {
            let bytes = entries[(cursor % u64::from(NATIVE_CONSOLE_CAPACITY)) as usize].load();
            let record = NativeConsoleRecord::decode(&bytes)?;
            node_sequence = node_sequence
                .checked_add(1)
                .ok_or(NativeConsoleError::Sequence)?;
            let index = plan
                .streams
                .binary_search_by_key(&record.origin.stream, |row| row.stream)
                .map_err(|_| NativeConsoleError::Plan)?;
            stream_sequences[index] = stream_sequences[index]
                .checked_add(1)
                .ok_or(NativeConsoleError::Sequence)?;
            if record.owner != authorization.owner
                || record.phase != authorization.phase
                || record.authorization_advance != authorization.advance
                || record.origin.logical_generation != plan.logical_generation
                || record.origin.node_sequence != node_sequence
                || record.origin.stream_sequence != stream_sequences[index]
                || plan.streams[index].owner_mask & (1_u64 << record.origin.vcpu) == 0
                || record.origin.logical_ps > frontier.logical_ps
                || record.origin.raw_prefix > frontier.raw_prefix
            {
                return Err(NativeConsoleError::Binding.into());
            }
            records.push(record);
        }
        Ok(NativeConsolePrefix {
            ring: self,
            start,
            end: frontier.ring_end,
            records,
            stream_sequences,
            node_sequence,
        })
    }

    /// Releases an already-evidence-committed validated prefix to the producer.
    ///
    /// No evidence operation occurs here. The host must keep its single-consumer
    /// ownership and commit the prepared records before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleRingError`] if admission is held or another
    /// consumer changed the cursor; refusal leaves the cursor unchanged.
    pub fn acknowledge_native_console_prefix(
        &self,
        prefix: NativeConsolePrefix<'_>,
    ) -> Result<(), NativeConsoleRingError> {
        if !std::ptr::eq(self, prefix.ring) {
            return Err(NativeConsoleError::Binding.into());
        }
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
        self.read_idx
            .compare_exchange(
                prefix.start,
                prefix.end,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .map_err(|_| NativeConsoleError::Sequence)?;
        Ok(())
    }
}

fn check_storage(entries: &[NativeConsoleEntry]) -> Result<(), NativeConsoleError> {
    if entries.len() != NATIVE_CONSOLE_CAPACITY as usize {
        return Err(NativeConsoleError::Length);
    }
    Ok(())
}

fn checked_live(read: u64, write: u64) -> Result<u64, NativeConsoleError> {
    let live = write
        .checked_sub(read)
        .ok_or(NativeConsoleError::Sequence)?;
    if live > u64::from(NATIVE_CONSOLE_CAPACITY) {
        return Err(NativeConsoleError::Sequence);
    }
    Ok(live)
}
