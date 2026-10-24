//! Binds the separately selected input-prepare and commit dialect to native policy.

use super::super::complete_restore::{transfer::*, *};
use super::*;

impl Native5PolicyData {
    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn complete_restore_transfer_schemas() -> Result<[SchemaRef; 7], ProviderError> {
        use PacketCompleteRestoreTransferPhase::{Commit, Prepare};
        use PacketCompleteRestoreTransferSchema::{Proof, Receipt, Request};
        Ok([
            complete_restore_transfer_schema(Prepare, Request)?,
            complete_restore_transfer_schema(Prepare, Proof)?,
            complete_restore_transfer_schema(Prepare, Receipt)?,
            complete_restore_transfer_schema(Commit, Request)?,
            complete_restore_transfer_schema(Commit, Proof)?,
            complete_restore_transfer_schema(Commit, Receipt)?,
            native_restored_record_schema()?,
        ])
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn bind_complete_restore_transfer_definitions(&mut self) -> Result<(), ProviderError> {
        if self.complete_restore_selection
            == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            self.complete_restore_transfer_definitions =
                Some(Self::complete_restore_transfer_schemas()?.map(|schema| schema.definition));
        }
        Ok(())
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn validate_complete_restore_transfer_content(&self) -> Result<(), ProviderError> {
        self.validate_restore_input_emitter_content()?;
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return if self.complete_restore_transfer_definitions.is_none() {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "native unselected restore transfer definitions",
                ))
            };
        }
        let schemas = Self::complete_restore_transfer_schemas()?;
        if self
            .complete_restore_transfer_definitions
            .as_ref()
            .is_none_or(|actual| {
                actual
                    .iter()
                    .zip(&schemas)
                    .any(|(reference, schema)| reference != &schema.definition)
            })
            || schemas.iter().any(|schema| {
                !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(schema)
            })
        {
            return Err(ProviderError::Correlation(
                "native restore transfer full definitions differ",
            ));
        }
        Ok(())
    }

    /// Returns the original immutable policy DATA projection.
    pub fn complete_restore_transfer_definitions(&self) -> Option<&[ContentRef; 7]> {
        self.complete_restore_transfer_definitions.as_ref()
    }
}

pub(super) struct TransferPolicyView<'a>(pub(super) &'a Native5PolicyData);
impl Serialize for TransferPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.complete_restore_selection
            == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            (
                "source-private.native5-policy-restore-transfer/15",
                &self.0.complete_restore_transfer_definitions,
                super::restore_policy::CompleteRestorePolicyView(self.0),
            )
                .serialize(serializer)
        } else {
            super::restore_policy::CompleteRestorePolicyView(self.0).serialize(serializer)
        }
    }
}
