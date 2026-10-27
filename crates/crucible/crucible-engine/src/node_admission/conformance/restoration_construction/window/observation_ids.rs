//! Retains real observation IDs before the prospective transaction is quoted.
//!
//! The full immutable Source declaration selects this distinct route. Each ID
//! enters a permanent Window slot before another fallible constructor runs.
//! A later quote refusal keeps those owners and cannot renew the transaction.

use super::*;

impl CompleteOriginalRestorationWindow {
    pub(super) fn retain_original_observation_request_ids_data(
        &self,
        activation: &ActivationRecord,
        observed_current_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let mut selected = None;
        for source in &self.sources {
            let actual = source.is_original_restoration_observation_declaration_data()?;
            if selected.is_some_and(|previous| previous != actual) {
                return Err(RuntimeError::ForeignAuthority);
            }
            selected = Some(actual);
        }
        if selected != Some(true) {
            return Ok(());
        }
        if self
            .observation_request_ids
            .iter()
            .any(|slot| slot.get().is_some())
        {
            return Err(RuntimeError::DuplicateOperation);
        }

        let prefix = "cnp-restoration-observe-";
        let capacity = prefix
            .len()
            .checked_add(activation.activation_id.as_str().len())
            .ok_or(RuntimeError::ResourceLimit)?;
        // Id::new remains the defining validator. This precheck avoids any
        // constructor bank for a combined identifier it necessarily rejects.
        if capacity > 128 {
            return Err(RuntimeError::InvalidReceipt);
        }
        let future = capacity
            .checked_mul(self.observation_request_ids.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut previous = observed_current_bytes;
        for id in self
            .activation_request_ids
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
        {
            previous = checked_sum(
                &[previous, id.allocated_capacity()],
                self.policy.maximum_requested_bytes,
            )?;
        }
        checked_sum(&[previous, future], self.policy.maximum_requested_bytes)?;

        let mut actual = previous;
        for slot in &self.observation_request_ids {
            let mut body = String::new();
            body.try_reserve_exact(capacity)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            body.push_str(prefix);
            body.push_str(activation.activation_id.as_str());
            let id = Id::new(body).map_err(|_| RuntimeError::InvalidReceipt)?;
            slot.set(id).map_err(|_| RuntimeError::DuplicateOperation)?;
            // The actual owner is installed before checking observed capacity.
            // Failure preserves this ID together with all earlier slot owners.
            actual = checked_sum(
                &[
                    actual,
                    slot.get()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .allocated_capacity(),
                ],
                self.policy.maximum_requested_bytes,
            )?;
        }
        Ok(())
    }
}
