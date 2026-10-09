//! Original source-held writer cuts retained before socket slicing or ACK.

use super::super::writer_abi as abi;
use super::*;
use crucible_protocol::node_control::{
    NATIVE_WRITER_CHUNK_BYTES, NativeFrame, NativeWriterAio, NativeWriterBh, NativeWriterChunk,
    NativeWriterCpu, NativeWriterHandler, NativeWriterObservation, NativeWriterQuery,
    NativeWriterWork,
};

const RETAINED_WRITER_BYTES: usize = 16 * 1024 * 1024;

impl NativeNodeControl {
    pub(crate) fn with_writer_query(mut self, query: Option<abi::QueryWriters>) -> Self {
        self.writer_query = query;
        self
    }

    pub(super) fn observe_writers(&self, sequence: U64) -> Result<(), NativeCommandError> {
        let Some(query) = self.writer_query else {
            return Ok(());
        };
        let (digest, clock, retired, roster, expected_generation) = {
            let state = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            if state.quarantined || state.writer_objects.contains_key(&sequence.get()) {
                return Ok(());
            }
            let Some(park) = state.cpu_park.as_ref() else {
                return Ok(());
            };
            let (digest, clock, retired) = if sequence.get() == 0 {
                if !state.journal.is_pristine() {
                    return Ok(());
                }
                ([0; 32], park.current_ps, park.retired_count)
            } else {
                let Some(stop) = state.receipts.get(&sequence.get()) else {
                    return Ok(());
                };
                (
                    stop.grant_hash,
                    U64::new(stop.current_ps),
                    U64::new(stop.raw_icount),
                )
            };
            let generation = state.writer_generation.unwrap_or(0);
            (digest, clock, retired, park.roster_sha256, generation)
        };
        let mut summary = abi::NativeWriterCut::default();
        let mut cpus = vec![abi::NativeWriterCpu::default(); abi::CPU_MAXIMUM];
        let mut work = vec![abi::NativeWriterWork::default(); abi::WORK_MAXIMUM];
        let mut aio = vec![abi::NativeWriterAio::default(); abi::AIO_MAXIMUM];
        let mut bhs = vec![abi::NativeWriterBh::default(); abi::BH_MAXIMUM];
        let mut handlers = vec![abi::NativeWriterHandler::default(); abi::HANDLER_MAXIMUM];
        // Only the genuine RR/BQL getter or original stopped callback invokes
        // the source query. The reader never acquires or samples the native gate.
        let result = query(
            self.prepared_scope_hash.as_ptr(),
            expected_generation,
            &mut summary,
            cpus.as_mut_ptr(),
            abi::CPU_MAXIMUM as u32,
            work.as_mut_ptr(),
            abi::WORK_MAXIMUM as u32,
            aio.as_mut_ptr(),
            abi::AIO_MAXIMUM as u32,
            bhs.as_mut_ptr(),
            abi::BH_MAXIMUM as u32,
            handlers.as_mut_ptr(),
            abi::HANDLER_MAXIMUM as u32,
        );
        if result != 0 {
            return Ok(());
        }
        if summary.version != abi::WRITER_CUT_VERSION
            || summary.size != 160
            || summary.reserved != 0
            || summary.prepared_scope_hash != self.prepared_scope_hash
            || summary.current_ps != clock.get()
            || summary.raw_icount != retired.get()
            || summary.roster_hash != roster
            || summary.cpu_count as usize > cpus.len()
            || summary.work_count as usize > work.len()
            || summary.aio_count as usize > aio.len()
            || summary.bh_count as usize > bhs.len()
            || summary.handler_count as usize > handlers.len()
            || (expected_generation != 0 && summary.gate_generation != expected_generation)
        {
            return Err(NativeCommandError::Conflict);
        }
        let observation = NativeWriterObservation {
            prepared_scope_hash: self.prepared_scope_hash,
            sequence,
            command_digest: digest,
            gate_generation: U64::new(summary.gate_generation),
            current_ps: clock,
            retired_count: retired,
            aio_generation: U64::new(summary.aio_generation),
            bh_generation: U64::new(summary.bh_generation),
            handler_generation: U64::new(summary.handler_generation),
            admissions_in_flight: U64::new(summary.admissions_in_flight),
            coverage: summary.coverage,
            flags: summary.flags,
            roster_sha256: roster,
            cpus: cpus[..summary.cpu_count as usize]
                .iter()
                .map(|cpu| NativeWriterCpu {
                    cpu_index: cpu.cpu_index,
                    interrupt_mask: cpu.interrupt_mask,
                    exception_index: cpu.exception_index,
                    flags: cpu.flags,
                    work_count: U64::new(cpu.work_count),
                    next_work_sequence: U64::new(cpu.next_work_sequence),
                })
                .collect(),
            work: work[..summary.work_count as usize]
                .iter()
                .map(|row| NativeWriterWork {
                    cpu_index: row.cpu_index,
                    flags: row.flags,
                    work_id: U64::new(row.work_id),
                    fifo_ordinal: U64::new(row.fifo_ordinal),
                })
                .collect(),
            aio: aio[..summary.aio_count as usize]
                .iter()
                .map(|row| NativeWriterAio {
                    context_id: U64::new(row.context_id),
                    home_thread_id: row.home_thread_id,
                    active_polls: row.active_polls,
                    active_dispatches: row.active_dispatches,
                    pending_bhs: row.pending_bhs,
                    active_bhs: row.active_bhs,
                    queued_coroutines: row.queued_coroutines,
                    flags: row.flags,
                })
                .collect(),
            bottom_halves: bhs[..summary.bh_count as usize]
                .iter()
                .map(|row| NativeWriterBh {
                    bh_id: U64::new(row.bh_id),
                    context_id: U64::new(row.context_id),
                    active_callbacks: row.active_callbacks,
                    flags: row.flags,
                })
                .collect(),
            handlers: handlers[..summary.handler_count as usize]
                .iter()
                .map(|row| NativeWriterHandler {
                    handler_id: U64::new(row.handler_id),
                    context_id: U64::new(row.context_id),
                    descriptor_slot: row.fd,
                    active_callbacks: row.active_callbacks,
                    flags: row.flags,
                })
                .collect(),
        };
        let bytes = observation.encode()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        if state.quarantined || (sequence.get() == 0 && !state.journal.is_pristine()) {
            return Ok(());
        }
        if state
            .writer_object_bytes
            .checked_add(bytes.len())
            .is_none_or(|total| total > RETAINED_WRITER_BYTES)
        {
            // Never replace old originals or promote retention exhaustion to a
            // complete cut. Subsequent new work stays unavailable.
            return Err(NativeCommandError::ResourceLimit);
        }
        state.writer_object_bytes += bytes.len();
        if sequence.get() == 0 {
            state.writer_generation = Some(observation.gate_generation.get());
        }
        state.writer_objects.insert(sequence.get(), bytes);
        Ok(())
    }

    pub(super) fn send_writer_chunk(
        &self,
        query: &NativeWriterQuery,
    ) -> Result<(), NativeCommandError> {
        query.validate()?;
        if query.prepared_scope_hash != self.prepared_scope_hash {
            return Err(NativeCommandError::Conflict);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        let Some(original) = state.writer_objects.get(&query.sequence.get()) else {
            return Ok(());
        };
        let offset =
            usize::try_from(query.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        if offset >= original.len() {
            return Err(NativeCommandError::Conflict);
        }
        let end = offset
            .saturating_add(NATIVE_WRITER_CHUNK_BYTES)
            .min(original.len());
        let chunk = NativeWriterChunk {
            prepared_scope_hash: self.prepared_scope_hash,
            sequence: query.sequence,
            object_digest: *blake3::hash(original).as_bytes(),
            total_bytes: U64::new(original.len() as u64),
            offset: query.offset,
            bytes: original[offset..end].to_vec(),
        };
        drop(state);
        #[cfg(unix)]
        if let Some(channel) = &self.channel {
            let _sent = channel
                .send(&NativeFrame::WriterChunk(chunk))
                .map_err(|_| NativeCommandError::Conflict)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static QUERIES: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn writer_cut(
        scope: *const u8,
        _generation: u64,
        summary: *mut abi::NativeWriterCut,
        cpus: *mut abi::NativeWriterCpu,
        _cpu_capacity: u32,
        _work: *mut abi::NativeWriterWork,
        _work_capacity: u32,
        _aio: *mut abi::NativeWriterAio,
        _aio_capacity: u32,
        _bhs: *mut abi::NativeWriterBh,
        _bh_capacity: u32,
        _handlers: *mut abi::NativeWriterHandler,
        _handler_capacity: u32,
    ) -> i32 {
        let number = QUERIES.fetch_add(1, Ordering::SeqCst);
        // SAFETY: The fixture receives the exact source ABI and exclusive
        // bounded buffers. It initializes one CPU and no other rows.
        unsafe {
            let scope = std::ptr::read(scope.cast::<[u8; 32]>());
            summary.write(abi::NativeWriterCut {
                version: 1,
                size: 160,
                coverage: 7,
                flags: 15,
                cpu_count: 1,
                gate_generation: 4,
                current_ps: if number == 0 { 0 } else { 110 },
                raw_icount: if number == 0 { 0 } else { 2 },
                prepared_scope_hash: scope,
                roster_hash: [9; 32],
                ..Default::default()
            });
            cpus.write(abi::NativeWriterCpu {
                exception_index: -1,
                next_work_sequence: 1,
                ..Default::default()
            });
        }
        0
    }

    #[test]
    fn original_writer_cuts_remain_independent_of_later_clock_and_acknowledgement() {
        QUERIES.store(0, Ordering::SeqCst);
        let original = super::super::tests::command();
        let control = NativeNodeControl::new(original.scope.clone(), original.kind.start(), 4)
            .unwrap()
            .with_writer_query(Some(writer_cut));
        control.state.lock().unwrap().cpu_park =
            Some(crucible_protocol::node_control::NativeCpuParkFacts {
                coverage: 1,
                cpu_count: 1,
                current_ps: U64::new(0),
                retired_count: U64::new(0),
                next_service_deadline_ps: None,
                pending_service_credit_ps: U64::new(0),
                prepared_scope_hash: control.prepared_scope_hash,
                roster_sha256: [9; 32],
            });
        control.observe_writers(U64::new(0)).unwrap();
        let initial = control.state.lock().unwrap().writer_objects[&0].clone();
        control.retain(original.clone()).unwrap();
        control
            .record_stop(super::super::tests::receipt(control.command().unwrap()))
            .unwrap();
        control.observe_writers(U64::new(1)).unwrap();
        let stop = control.state.lock().unwrap().writer_objects[&1].clone();
        control
            .acknowledge(U64::new(1), &original.authorization_digest)
            .unwrap();
        control.observe_writers(U64::new(0)).unwrap();
        control.observe_writers(U64::new(1)).unwrap();
        assert_eq!(QUERIES.load(Ordering::SeqCst), 2);
        assert_eq!(control.state.lock().unwrap().writer_objects[&0], initial);
        assert_eq!(control.state.lock().unwrap().writer_objects[&1], stop);
        let observation = NativeWriterObservation::decode(&stop).unwrap();
        assert_eq!(
            observation.command_digest,
            original.identity_digest().unwrap()
        );
        assert_eq!(observation.current_ps.get(), 110);
        assert_eq!(observation.flags, 15);
    }
}
