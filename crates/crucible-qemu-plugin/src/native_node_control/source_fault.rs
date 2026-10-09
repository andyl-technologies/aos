//! Original source-fault diagnostics beneath native journal custody.

use crucible_node_contract::U64;
use crucible_protocol::node_control::{NativeCommandError, NativeFrame, SourceFaultFacts};

use super::NativeNodeControl;
use crate::native_node_control::source_fault_abi::{NativeSourceFault, QuerySourceFault};

impl NativeNodeControl {
    /// Installs an observational query without asserting complete native coverage.
    pub(crate) fn with_source_fault_query(mut self, query: Option<QuerySourceFault>) -> Self {
        self.source_fault_query = query;
        self
    }

    /// Copies an immutable diagnostic without BQL, retirement or queue dispatch.
    pub(super) fn observe_source_fault(&self) -> Result<bool, NativeCommandError> {
        let Some(query) = self.source_fault_query else {
            return Ok(false);
        };
        let mut raw = NativeSourceFault::default();
        let status = query(self.prepared_scope_hash.as_ptr(), &mut raw);
        if status != 0 {
            if raw != NativeSourceFault::default()
                || (status != -libc::EAGAIN && status != -libc::EPERM)
            {
                return Err(NativeCommandError::Conflict);
            }
            return Ok(false);
        }
        if raw.version != 1 || raw.size != 112 {
            return Err(NativeCommandError::Conflict);
        }
        let facts = SourceFaultFacts {
            code: raw.code,
            flags: raw.flags,
            fault_id: U64::new(raw.fault_id),
            command_sequence: U64::new(raw.command_sequence),
            ingress_id: U64::new(raw.ingress_id),
            cpu_index: raw.cpu_index,
            ingress_kind: raw.ingress_kind,
            prepared_scope_hash: raw.prepared_scope_hash,
            command_digest: raw.original_command_digest,
        };
        facts.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?;
        if facts.prepared_scope_hash != self.prepared_scope_hash
            || state
                .source_fault
                .as_ref()
                .is_some_and(|original| original != &facts)
        {
            return Err(NativeCommandError::Conflict);
        }
        if facts.command_sequence.get() != 0 {
            let original = state
                .journal
                .original(facts.command_sequence)
                .ok_or(NativeCommandError::Conflict)?;
            if original.identity_digest()? != facts.command_digest {
                return Err(NativeCommandError::Conflict);
            }
        }
        // The exact original journal, receipts and socket bytes remain owned.
        // Withholding commands is containment intent, not a physical-stop proof.
        state.source_fault = Some(facts);
        state.quarantined = true;
        state.current = None;
        Ok(true)
    }

    /// Recovers the same original diagnostic after a full datagram endpoint.
    pub(super) fn send_source_fault(&self) -> Result<(), NativeCommandError> {
        let Some(channel) = &self.channel else {
            return Ok(());
        };
        let facts = self
            .state
            .lock()
            .map_err(|_| NativeCommandError::Conflict)?
            .source_fault
            .clone()
            .ok_or(NativeCommandError::Conflict)?;
        let _sent = channel
            .send(&NativeFrame::SourceFault(Box::new(facts)))
            .map_err(|_| NativeCommandError::Conflict)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_node_control::controller::tests::command;

    extern "C" fn initial_fault(scope: *const u8, output: *mut NativeSourceFault) -> i32 {
        let mut scope_hash = [0; 32];
        // SAFETY: The exact test callback supplies live 32-byte scope storage.
        unsafe {
            scope_hash.copy_from_slice(std::slice::from_raw_parts(scope, 32));
        }
        let facts = NativeSourceFault {
            version: 1,
            size: 112,
            code: 3,
            flags: 7,
            fault_id: 1,
            ingress_id: 1,
            cpu_index: 0,
            ingress_kind: 2,
            prepared_scope_hash: scope_hash,
            ..Default::default()
        };
        // SAFETY: The callback supplies an aligned writable source-fault object.
        unsafe {
            *output = facts;
        }
        0
    }

    extern "C" fn changed_fault(scope: *const u8, output: *mut NativeSourceFault) -> i32 {
        initial_fault(scope, output);
        // SAFETY: The preceding exact callback initialized the live output.
        unsafe {
            (*output).ingress_id = 2;
        }
        0
    }

    #[test]
    fn unknown_effects_preserve_original_journal_and_reject_changed_diagnostics() {
        let original = command();
        let mut owner = NativeNodeControl::new(original.scope.clone(), original.kind.start(), 4)
            .unwrap()
            .with_source_fault_query(Some(initial_fault));
        owner.retain(original.clone()).unwrap();
        let before = owner
            .state
            .lock()
            .unwrap()
            .journal
            .snapshot()
            .unwrap()
            .encode(64 * 1024 * 1024)
            .unwrap();

        assert!(owner.observe_source_fault().unwrap());
        let first = owner.state.lock().unwrap().source_fault.clone().unwrap();
        assert!(owner.command().is_none());
        assert!(owner.retain(original.clone()).is_err());
        assert!(
            owner
                .acknowledge(original.sequence, &original.authorization_digest)
                .is_err()
        );
        assert!(owner.observe_source_fault().unwrap());
        owner.source_fault_query = Some(changed_fault);
        assert!(owner.observe_source_fault().is_err());

        let state = owner.state.lock().unwrap();
        assert_eq!(state.source_fault.as_ref(), Some(&first));
        assert_eq!(
            state
                .journal
                .snapshot()
                .unwrap()
                .encode(64 * 1024 * 1024)
                .unwrap(),
            before
        );
        assert!(state.receipts.is_empty());
    }
}
