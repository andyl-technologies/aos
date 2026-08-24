//! Aggregate occurrence-event staging across the live QEMU node set.

use super::*;

impl QemuNodeSet {
    /// Reports whether any node has an event awaiting runtime admission.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when any event transport is invalid.
    pub fn has_pending_fault_events(&mut self) -> Result<bool, BackendError> {
        for node in self.nodes.values_mut() {
            if node.fault_event_pending().map_err(BackendError::from)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Freezes every node at its current share of one aggregate staging ceiling.
    ///
    /// A later operation must arm exactly the node it is about to pump through
    /// [`Self::fault_event_staging_allowance`]. Copying the aggregate remainder
    /// into every per-node runtime would multiply the authored budget by the
    /// node count.
    pub(crate) fn set_fault_event_staging_limit(
        &mut self,
        maximum_event_records: usize,
        configured_event_records: usize,
    ) -> Result<(), BackendError> {
        let current = self.staged_fault_event_count()?;
        let _remaining = maximum_event_records.checked_sub(current).ok_or_else(|| {
            BackendError::Rejected {
                message: format!(
                    "QEMU staged fault events exceed the aggregate ceiling: current {current}, configured {maximum_event_records}"
                ),
            }
        })?;
        let canonical_base = configured_event_records
            .checked_sub(maximum_event_records)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from(
                    "QEMU fault-event staging allowance exceeds the configured ceiling",
                ),
            })?;
        let canonical_current =
            canonical_base
                .checked_add(current)
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from("QEMU canonical fault-event count is not representable"),
                })?;
        for node in self.nodes.values_mut() {
            let node_limit = node.staged_fault_event_count();
            let current_offset = canonical_current.checked_sub(node_limit).ok_or_else(|| {
                BackendError::Rejected {
                    message: String::from("QEMU fault-event staging offset moved backwards"),
                }
            })?;
            node.set_fault_event_staging_limit(
                node_limit,
                current_offset,
                configured_event_records,
            )
            .map_err(BackendError::from)?;
        }
        Ok(())
    }

    pub(crate) fn fault_event_staging_allowance(
        &mut self,
        node: &NodeId,
        maximum_event_records: usize,
        configured_event_records: usize,
    ) -> Result<usize, BackendError> {
        let aggregate_current = self.staged_fault_event_count()?;
        self.set_fault_event_staging_limit(maximum_event_records, configured_event_records)?;
        let remaining = maximum_event_records
            .checked_sub(aggregate_current)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from(
                    "QEMU aggregate fault-event allowance is smaller than staged ownership",
                ),
            })?;
        let backend = self
            .nodes
            .get_mut(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("QEMU node `{}` has no event-staging allowance", node.name),
            })?;
        let node_limit = backend
            .staged_fault_event_count()
            .checked_add(remaining)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("QEMU per-node fault-event allowance is not representable"),
            })?;
        let canonical_base = configured_event_records
            .checked_sub(maximum_event_records)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from(
                    "QEMU fault-event staging allowance exceeds the configured ceiling",
                ),
            })?;
        let current_offset = canonical_base
            .checked_add(aggregate_current)
            .and_then(|current| current.checked_sub(backend.staged_fault_event_count()))
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("QEMU fault-event staging offset is not representable"),
            })?;
        backend
            .set_fault_event_staging_limit(node_limit, current_offset, configured_event_records)
            .map_err(BackendError::from)?;
        Ok(node_limit)
    }

    pub(crate) fn staged_fault_event_count(&self) -> Result<usize, BackendError> {
        self.nodes
            .values()
            .try_fold(0_usize, |total, node| {
                total.checked_add(node.staged_fault_event_count())
            })
            .ok_or_else(|| BackendError::Rejected {
                message: String::from("QEMU staged fault-event count is not representable"),
            })
    }

    /// Iterates live fingerprints while spending one shared event allowance.
    pub(crate) fn execution_fingerprint_entries(
        &mut self,
        maximum_event_records: usize,
        configured_event_records: usize,
    ) -> Result<
        impl ExactSizeIterator<Item = Result<(&NodeId, crucible::ContentHash), BackendError>>,
        BackendError,
    > {
        let current = self.staged_fault_event_count()?;
        let mut remaining = maximum_event_records.checked_sub(current).ok_or_else(|| {
            BackendError::Rejected {
                message: format!(
                    "QEMU staged fault events exceed the aggregate ceiling: current {current}, configured {maximum_event_records}"
                ),
            }
        })?;
        let canonical_base = configured_event_records
            .checked_sub(maximum_event_records)
            .ok_or_else(|| BackendError::Rejected {
                message: String::from(
                    "QEMU fingerprint event allowance exceeds the configured ceiling",
                ),
            })?;
        self.set_fault_event_staging_limit(maximum_event_records, configured_event_records)?;
        Ok(self.nodes.iter_mut().map(move |(node, backend)| {
            let before = backend.staged_fault_event_count();
            let node_limit =
                before
                    .checked_add(remaining)
                    .ok_or_else(|| BackendError::Rejected {
                        message: String::from(
                            "QEMU per-node fingerprint event allowance is not representable",
                        ),
                    })?;
            let aggregate_current = maximum_event_records
                .checked_sub(remaining)
                .and_then(|staged| canonical_base.checked_add(staged))
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from(
                        "QEMU fingerprint canonical event count is not representable",
                    ),
                })?;
            let current_offset =
                aggregate_current
                    .checked_sub(before)
                    .ok_or_else(|| BackendError::Rejected {
                        message: String::from(
                            "QEMU fingerprint event staging offset moved backwards",
                        ),
                    })?;
            backend
                .set_fault_event_staging_limit(node_limit, current_offset, configured_event_records)
                .map_err(BackendError::from)?;
            let fingerprint = backend
                .execution_fingerprint()
                .map_err(BackendError::from)?;
            let after = backend.staged_fault_event_count();
            let consumed = after
                .checked_sub(before)
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from("QEMU fingerprint event staging count moved backwards"),
                })?;
            remaining = remaining
                .checked_sub(consumed)
                .ok_or_else(|| BackendError::Rejected {
                    message: String::from(
                        "QEMU fingerprint pumps exceeded the aggregate event allowance",
                    ),
                })?;
            Ok((node, fingerprint.hash))
        }))
    }
}
