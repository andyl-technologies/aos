//! Retains the actual new mapping normalization as the sixth restoration input.
//!
//! This is an independently prepaid Value and canonical Vec, not the Source's
//! separate normalization copy or its old restore slot. Both actual owners stay
//! in the target after failure. Only this same mapping's projection is encoded;
//! no caller body supplies the sixth role or its reference.

use super::*;
use crate::node_contract::runtime_owned_counter::OwnedStorage;

impl CompleteOriginalRestorationTransactionTarget {
    pub(in crate::node_admission::conformance::restoration_construction) fn construct_original_normalization_data(
        &self,
        admitted: &OriginalRestorationNodeConstructionData,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.phase.authenticate_mapping_started()?;
        if self.normalization_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        let row = admitted
            .signer
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mapping = self.mapping_data()?;
        let mut value = self
            .normalization_value
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if value.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *value = Some(
            serde_json::to_value(mapping.normalization_view())
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let value = value.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let mut bank = self
            .normalization_partial
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if bank.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *bank = Some(
            crucible_node_format::canonical::canonical_json(value)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
        );
        let bytes = bank.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let actual = value
            .owned_storage()?
            .checked_add(bytes.capacity())
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes.len() > admitted.maximum_mapping_bytes
            || actual > row.mapping_normalization_requested_bytes_data()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let original = bank.take().ok_or(RuntimeError::OwnerUnavailable)?;
        if let Err(original) = self.normalization.set(original) {
            *bank = Some(original);
            return Err(RuntimeError::DuplicateOperation);
        }
        self.origin()
    }
}
