//! Original CPU-only observations taken exclusively inside the native RR getter.

use super::*;
use crate::native_node_control::abi::{NativeCpuParkReceipt, QueryCpuPark};
use crucible_protocol::node_control::{NativeCpuParkFacts, NativeFrame};

impl NativeNodeControl {
    pub(crate) fn with_cpu_park_query(mut self, query: Option<QueryCpuPark>) -> Self {
        self.cpu_query = query;
        self
    }

    pub(super) fn observe_initial_cpu_park(&self) -> Result<(), NativeCommandError> {
        let Some(query) = self.cpu_query else {
            return Ok(());
        };
        {
            let state = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            if state.quarantined || state.cpu_park.is_some() || !state.journal.is_pristine() {
                return Ok(());
            }
        }
        let mut raw = NativeCpuParkReceipt::default();
        // Only this registered getter invokes the C query, on QEMU's actual
        // BQL-held RR callback seam. A reader thread cannot manufacture it.
        let status = query(self.prepared_scope_hash.as_ptr(), &mut raw);
        if status != 0 {
            return Ok(());
        }
        if raw.version != 1
            || raw.size != 112
            || raw.prepared_scope_hash != self.prepared_scope_hash
        {
            return Err(NativeCommandError::Conflict);
        }
        let facts = NativeCpuParkFacts {
            coverage: raw.coverage,
            cpu_count: raw.cpu_count,
            current_ps: U64::new(raw.current_ps),
            retired_count: U64::new(raw.raw_icount),
            next_service_deadline_ps: (raw.next_service_deadline_ps != u64::MAX)
                .then_some(U64::new(raw.next_service_deadline_ps)),
            pending_service_credit_ps: U64::new(raw.pending_service_credit_ps),
            prepared_scope_hash: raw.prepared_scope_hash,
            roster_sha256: raw.roster_hash,
        };
        crucible_protocol::node_control::encode_frame(&NativeFrame::CpuPark(facts.clone()))?;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            // A simultaneous command arrival must not turn this observation
            // into an invented initial readiness fact. No guest work is run.
            if state.quarantined || !state.journal.is_pristine() {
                return Ok(());
            }
            state.cpu_park = Some(facts);
        }
        self.send_cpu_park()
    }

    pub(super) fn send_cpu_park(&self) -> Result<(), NativeCommandError> {
        #[cfg(unix)]
        if let Some(channel) = &self.channel {
            let facts = self
                .state
                .lock()
                .map_err(|_| NativeCommandError::Conflict)?
                .cpu_park
                .clone();
            if let Some(facts) = facts {
                // A full socket retains the original bytes. The host's pinned
                // frame8 request can recover them without a new observation.
                let _sent = channel
                    .send(&NativeFrame::CpuPark(facts))
                    .map_err(|_| NativeCommandError::Conflict)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    extern "C" fn unavailable(_scope: *const u8, _facts: *mut NativeCpuParkReceipt) -> i32 {
        -libc::EAGAIN
    }

    #[test]
    fn unavailable_native_query_cannot_construct_initial_park_facts() {
        let command = super::super::tests::command();
        let control = NativeNodeControl::new(command.scope, command.kind.start(), 4)
            .unwrap()
            .with_cpu_park_query(Some(unavailable));
        control.observe_initial_cpu_park().unwrap();
        assert!(control.state.lock().unwrap().cpu_park.is_none());
    }
}
