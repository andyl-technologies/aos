//! Live terminal closure from complete scheduler custody and authenticated native scope.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, Id, Position, U64, canonical};

use crate::node_contract::{NativeTerminalDisposition, NativeTerminalInventory, RuntimeError};

use super::CausalScheduler;

impl CausalScheduler {
    pub(crate) fn terminal_identity_available(&self, operation: &Id) -> bool {
        !self.used_operations.contains(operation)
    }

    pub(crate) fn retain_terminal_identity(&mut self, operation: Id) -> Result<(), RuntimeError> {
        // Terminal admission consumes the same original-operation namespace,
        // but creates no scheduling reservation or execution permission.
        if !self.used_operations.insert(operation) {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(())
    }

    pub(crate) fn terminal_preflight(&self, maximum_bytes: usize) -> Result<(), RuntimeError> {
        // Bound retained histories before cloning the complete coordinator
        // record. This deliberately conservative admission budget covers JSON
        // byte-array expansion and bounded identity/metadata rows.
        let mut rows = self
            .owners
            .len()
            .saturating_add(self.bounds.len())
            .saturating_add(self.native_sequences.len())
            .saturating_add(self.used_operations.len())
            .saturating_add(self.used_input_batches.len())
            // Reserve one original terminal identity before any effects fence.
            .saturating_add(1);
        let mut payload_bytes = self.payloads.values().try_fold(0_usize, |total, bytes| {
            total
                .checked_add(bytes.len())
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        for input in self.input_batches.values() {
            rows = rows
                .saturating_add(1)
                .saturating_add(input.batch.deliveries.len())
                .saturating_add(input.consumed.len());
            for payload in &input.batch.payloads {
                payload_bytes = payload_bytes
                    .checked_add(payload.bytes.len())
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        let estimate = rows
            .checked_mul(4096)
            .and_then(|metadata| {
                payload_bytes
                    .checked_mul(4)
                    .and_then(|payloads| metadata.checked_add(payloads))
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        if maximum_bytes == 0 || rows > 65_536 || estimate > maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }

    pub(crate) fn terminal_closure(
        &self,
        inventories: &BTreeMap<Id, NativeTerminalInventory>,
        maximum_bytes: usize,
    ) -> Result<(Position, Bytes), RuntimeError> {
        self.terminal_preflight(maximum_bytes)?;
        if !self.pending.is_empty()
            || !self.operations.is_empty()
            || !self.external_roots.is_empty()
            || self.owners.values().any(|owner| owner.reserved.is_some())
            || self.input_batches.values().any(|input| {
                input.acknowledgement.is_none()
                    || input.activated_by.is_some()
                    || input.consumed.len() != input.batch.deliveries().len()
            })
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let expected: BTreeSet<_> = self.node_owners.keys().cloned().collect();
        if inventories.keys().cloned().collect::<BTreeSet<_>>() != expected {
            return Err(RuntimeError::InvalidRoute);
        }
        for (node, inventory) in inventories {
            let owner = self
                .node_owners
                .get(node)
                .ok_or(RuntimeError::UnknownNode)?;
            if self.owners.get(owner).map(|owner| owner.cursor) != Some(inventory.boundary) {
                return Err(RuntimeError::InvalidTiming);
            }
        }

        // Closure propagates only from independently authenticated native EOF.
        // An input-dependent cycle cannot bootstrap its own terminal condition.
        let mut closed: BTreeSet<_> = inventories
            .iter()
            .filter(|(_, inventory)| {
                inventory.disposition == NativeTerminalDisposition::Unconditional
            })
            .map(|(node, _)| node.clone())
            .collect();
        loop {
            let previous = closed.len();
            for (node, owner) in &self.node_owners {
                if self.owners.get(owner).is_some_and(|owner| {
                    owner
                        .inputs
                        .iter()
                        .all(|path| !path.external && closed.contains(&path.producer))
                }) {
                    closed.insert(node.clone());
                }
            }
            if closed.len() == previous {
                break;
            }
        }
        if closed != expected {
            return Err(RuntimeError::OutstandingObligations);
        }
        let cut = self
            .owners
            .values()
            .map(|owner| owner.cursor)
            .max()
            .ok_or(RuntimeError::InvalidTiming)?;

        // This is a terminal record, not a capture: it has no invented capture
        // ordinal. Reuse the bounded complete state extractor, then remove its
        // capture-only envelope before encoding the independent closed edition.
        let snapshot = self
            .snapshot(cut, U64::new(0))
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        let mut state = serde_json::to_value(snapshot).map_err(|_| RuntimeError::InvalidReceipt)?;
        let object = state.as_object_mut().ok_or(RuntimeError::InvalidReceipt)?;
        object.remove("capture_ordinal");
        object.remove("schema_version");
        object.insert(
            "format".into(),
            "crucible.world-terminal-coordinator".into(),
        );
        object.insert("version".into(), 1.into());
        let bytes = canonical::canonical_json(&state).map_err(|_| RuntimeError::InvalidReceipt)?;
        if bytes.len() > maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok((cut, Bytes::new(bytes)))
    }
}
