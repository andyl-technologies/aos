//! Exact resource admission for checkpoint-store reads.

use super::*;

/// Aggregate owned-byte budget for one authenticated checkpoint load.
pub(super) struct CheckpointReadBudget {
    configured: u64,
    used: u64,
    identities: BTreeSet<ContentHash>,
}

impl CheckpointReadBudget {
    /// Creates an empty budget under the scenario-authored byte ceiling.
    pub(super) const fn new(configured: u64) -> Self {
        Self {
            configured,
            used: 0,
            identities: BTreeSet::new(),
        }
    }

    /// Admits bytes before invoking the allocation-bearing read operation.
    ///
    /// # Errors
    ///
    /// Returns an exact resource-limit error before `read` when the requested
    /// bytes exceed the configured or compiled ceiling. Allocation failure in
    /// `read` is mapped to the same pre-reservation coordinates.
    pub(super) fn read_admitted(
        &mut self,
        requested: u64,
        read: impl FnOnce() -> Result<Vec<u8>, BoundedReadError>,
    ) -> Result<Vec<u8>, LifecycleApiError> {
        let current = self.used;
        self.reserve(requested)?;
        read().map_err(|error| self.map_read_error(error, current))
    }

    /// Admits and reads a content identity only once in the aggregate closure.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read_admitted`].
    pub(super) fn read_identity(
        &mut self,
        identity: ContentHash,
        requested: u64,
        read: impl FnOnce() -> Result<Vec<u8>, BoundedReadError>,
    ) -> Result<Vec<u8>, LifecycleApiError> {
        let current = self.used;
        if self.identities.insert(identity) {
            self.reserve(requested)?;
        }
        read().map_err(|error| self.map_read_error(error, current))
    }

    /// Charges referenced artifact bytes once without reading them eagerly.
    ///
    /// # Errors
    ///
    /// Returns an exact resource-limit error when the new identity exceeds the
    /// aggregate byte ceiling.
    pub(super) fn reserve_identity_once(
        &mut self,
        identity: ContentHash,
        requested: u64,
    ) -> Result<(), LifecycleApiError> {
        if !self.identities.insert(identity) {
            return Ok(());
        }
        self.reserve(requested)
    }

    fn reserve(&mut self, requested: u64) -> Result<(), LifecycleApiError> {
        let current = self.used;
        let hard = FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes;
        let Some(total) = current.checked_add(requested) else {
            return Err(resource_limit(current, requested, self.configured, hard));
        };
        if total > self.configured || total > hard {
            return Err(resource_limit(current, requested, self.configured, hard));
        }
        self.used = total;
        Ok(())
    }

    fn map_read_error(&self, error: BoundedReadError, current: u64) -> LifecycleApiError {
        match error {
            BoundedReadError::Allocation { requested }
            | BoundedReadError::Representation { length: requested } => resource_limit(
                current,
                requested,
                self.configured,
                FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
            ),
            error => loop_factory_error(error.to_string()),
        }
    }
}

fn resource_limit(current: u64, requested: u64, configured: u64, hard: u64) -> LifecycleApiError {
    LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
        field: "fat_checkpoint_bytes",
        current,
        requested,
        configured,
        hard,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::cell::Cell;

    #[test]
    fn checkpoint_read_budget_rejects_manifest_before_file_allocation() {
        let invoked = Cell::new(false);
        let mut budget = CheckpointReadBudget::new(7);
        let error = budget
            .read_admitted(8, || {
                invoked.set(true);
                Ok(vec![0; 8])
            })
            .expect_err("over-limit manifest must fail before its read closure");

        assert!(!invoked.get());
        assert!(matches!(
            error,
            LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: 8,
                configured: 7,
                hard,
            }) if hard == FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes
        ));
    }

    #[test]
    fn checkpoint_read_allocation_failure_keeps_pre_reservation_coordinates() {
        let mut budget = CheckpointReadBudget::new(32);
        let error = budget
            .read_admitted(8, || Err(BoundedReadError::Allocation { requested: 8 }))
            .expect_err("allocation refusal must remain typed");

        assert!(matches!(
            error,
            LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: 8,
                configured: 32,
                hard,
            }) if hard == FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes
        ));
    }
}
