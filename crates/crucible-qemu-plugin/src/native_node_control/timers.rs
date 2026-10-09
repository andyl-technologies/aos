//! Original native timer cuts retained independently of socket transmission.

use super::*;
use crucible_protocol::node_control::{
    NATIVE_TIMER_CHUNK_BYTES, NativeFrame, NativeTimerArm, NativeTimerChunk, NativeTimerList,
    NativeTimerObservation, NativeTimerQuery,
};

// Native objects remain after acknowledgement so lost slice replies recover
// original bytes. A finite total allowance prevents unbounded tombstone growth.
const RETAINED_TIMER_BYTES: usize = 16 * 1024 * 1024;

impl NativeNodeControl {
    pub(crate) fn with_timer_query(
        mut self,
        query: Option<super::super::abi::QueryTimers>,
    ) -> Self {
        self.timer_query = query;
        self
    }

    pub(super) fn observe_timers(&self, sequence: U64) -> Result<(), NativeCommandError> {
        let Some(query) = self.timer_query else {
            return Ok(());
        };
        let (command_digest, expected_time) = {
            let state = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            if state.quarantined || state.timer_objects.contains_key(&sequence.get()) {
                return Ok(());
            }
            if sequence.get() == 0 {
                if !state.journal.is_pristine() || state.cpu_park.is_none() {
                    return Ok(());
                }
                (
                    [0; 32],
                    state.cpu_park.as_ref().map(|facts| facts.current_ps),
                )
            } else {
                let Some(receipt) = state.receipts.get(&sequence.get()) else {
                    return Ok(());
                };
                (receipt.grant_hash, Some(U64::new(receipt.current_ps)))
            }
        };
        let mut summary = super::super::abi::NativeTimerInventory::default();
        let mut lists = vec![super::super::abi::NativeTimerList::default(); 64];
        let mut timers = vec![super::super::abi::NativeTimerArm::default(); 4096];
        // The actual getter/stop native callback holds BQL. No reader thread
        // invokes this query; unsupported native queue state produces no object.
        if query(
            &mut summary,
            lists.as_mut_ptr(),
            64,
            timers.as_mut_ptr(),
            4096,
        ) != 0
        {
            return Ok(());
        }
        if summary.version != 1
            || summary.size != 32
            || summary.list_count > 64
            || summary.timer_count > 4096
            || expected_time != Some(U64::new(summary.current_ps))
        {
            return Err(NativeCommandError::Conflict);
        }
        let observation = NativeTimerObservation {
            prepared_scope_hash: self.prepared_scope_hash,
            sequence,
            command_digest,
            current_ps: U64::new(summary.current_ps),
            mutation_generation: U64::new(summary.mutation_generation),
            lists: lists[..summary.list_count as usize]
                .iter()
                .map(|list| NativeTimerList {
                    identity: U64::new(list.list_id),
                    timer_count: list.timer_count,
                    flags: list.flags,
                })
                .collect(),
            timers: timers[..summary.timer_count as usize]
                .iter()
                .map(|timer| NativeTimerArm {
                    identity: U64::new(timer.timer_id),
                    list: U64::new(timer.list_id),
                    arm_generation: U64::new(timer.arm_generation),
                    expiry_ps: U64::new(timer.expiry_ps),
                    fifo_ordinal: U64::new(timer.fifo_ordinal),
                    attributes: timer.attributes,
                    scale: timer.scale,
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
            .timer_object_bytes
            .checked_add(bytes.len())
            .is_none_or(|total| total > RETAINED_TIMER_BYTES)
        {
            // Evidence retention exhaustion does not invent closure or evict old
            // originals; future inventory requests remain unavailable.
            return Ok(());
        }
        state.timer_object_bytes += bytes.len();
        state.timer_objects.insert(sequence.get(), bytes);
        Ok(())
    }

    pub(super) fn send_timer_chunk(
        &self,
        request: &NativeTimerQuery,
    ) -> Result<(), NativeCommandError> {
        if request.prepared_scope_hash != self.prepared_scope_hash {
            return Err(NativeCommandError::Conflict);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        let Some(original) = state.timer_objects.get(&request.sequence.get()) else {
            return Ok(());
        };
        let offset =
            usize::try_from(request.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        if offset >= original.len() {
            return Err(NativeCommandError::Conflict);
        }
        let end = offset
            .saturating_add(NATIVE_TIMER_CHUNK_BYTES)
            .min(original.len());
        let chunk = NativeTimerChunk {
            prepared_scope_hash: self.prepared_scope_hash,
            sequence: request.sequence,
            object_digest: *blake3::hash(original).as_bytes(),
            total_bytes: U64::new(original.len() as u64),
            offset: request.offset,
            bytes: original[offset..end].to_vec(),
        };
        drop(state);
        #[cfg(unix)]
        if let Some(channel) = &self.channel {
            let _sent = channel
                .send(&NativeFrame::TimerChunk(chunk))
                .map_err(|_| NativeCommandError::Conflict)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static QUERIES: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn native_inventory(
        summary: *mut super::super::super::abi::NativeTimerInventory,
        lists: *mut super::super::super::abi::NativeTimerList,
        _list_capacity: u32,
        timers: *mut super::super::super::abi::NativeTimerArm,
        _timer_capacity: u32,
    ) -> i32 {
        QUERIES.fetch_add(1, Ordering::SeqCst);
        // SAFETY: The controller passes ABI-sized exclusive output buffers and
        // fixed capacities64/4096. The fixture writes exactly one row each.
        unsafe {
            summary.write(super::super::super::abi::NativeTimerInventory {
                version: 1,
                size: 32,
                list_count: 1,
                timer_count: 1,
                current_ps: 110,
                mutation_generation: 4,
            });
            lists.write(super::super::super::abi::NativeTimerList {
                list_id: 1,
                timer_count: 1,
                flags: 3,
            });
            timers.write(super::super::super::abi::NativeTimerArm {
                timer_id: 2,
                list_id: 1,
                arm_generation: 4,
                expiry_ps: 200,
                fifo_ordinal: 0,
                attributes: 0,
                scale: 1,
            });
        }
        0
    }

    #[test]
    fn original_native_timer_query_occurs_once_and_survives_acknowledgement() {
        QUERIES.store(0, Ordering::SeqCst);
        let command = super::super::tests::command();
        let control = NativeNodeControl::new(command.scope.clone(), command.kind.start(), 4)
            .unwrap()
            .with_timer_query(Some(native_inventory));
        control.retain(command.clone()).unwrap();
        control
            .record_stop(super::super::tests::receipt(control.command().unwrap()))
            .unwrap();
        control.observe_timers(U64::new(1)).unwrap();
        let original = control
            .state
            .lock()
            .unwrap()
            .timer_objects
            .get(&1)
            .unwrap()
            .clone();
        control
            .acknowledge(U64::new(1), &command.authorization_digest)
            .unwrap();
        control.observe_timers(U64::new(1)).unwrap();
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        assert_eq!(
            control.state.lock().unwrap().timer_objects.get(&1),
            Some(&original)
        );
        let observation = NativeTimerObservation::decode(&original).unwrap();
        assert_eq!(
            observation.command_digest,
            command.identity_digest().unwrap()
        );
        assert_eq!(observation.timers[0].arm_generation.get(), 4);
    }
}
