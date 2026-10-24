//! Binds the selected complete restoration mechanism to immutable native policy.
//!
//! The portable selection and syntax checks allow only its registered frames.
//! The native boot's actual fresh key verifier remains the sole token issuer.

use super::super::complete_restore::*;
use super::*;

/// Carries the owned fields used to construct a complete-restoration policy.
///
/// Fields follow the original constructor's evaluation and binding order.
/// This input contains DATA only and grants no restoration authority.
pub struct Native5CompleteRestorePolicyInput {
    /// Supplies the original selection operand.
    pub selection: PacketControlSelection,
    /// Supplies the original coordinator operand.
    pub coordinator: InstalledContent,
    /// Supplies the original profile operand.
    pub profile: super::super::PacketNative5CaptureProfile,
    /// Supplies the original confirmation operand.
    pub confirmation: super::super::PacketNative5ConfirmationSelection,
    /// Supplies the original emitter operand.
    pub emitter: super::super::PacketNative5AckEmitterSelection,
    /// Supplies the original extent operand.
    pub extent: client::CanonicalAckCodecMetadataExtent,
    /// Supplies the original metadata operand.
    pub metadata: super::super::PacketNative5ProtocolMetadataLimits,
    /// Supplies the original restoration operand.
    pub restoration: PacketNative5CompleteRestoreSelection,
}

impl Native5PolicyData {
    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch_with_complete_restore(
        input: Native5CompleteRestorePolicyInput,
    ) -> Result<Self, ProviderError> {
        let Native5CompleteRestorePolicyInput {
            selection,
            coordinator,
            profile,
            confirmation,
            emitter,
            extent,
            metadata,
            restoration,
        } = input;

        let mut policy = Self::from_original_launch_with_protocol_metadata(
            selection,
            coordinator,
            profile,
            confirmation,
            emitter,
            extent,
            metadata,
        )?;
        let schemas = [
            complete_restore_request_schema()?,
            complete_restore_proof_schema()?,
            complete_restore_receipt_schema()?,
        ];
        policy.complete_restore_selection = Some(restoration);
        policy.complete_restore_definitions = Some(schemas.map(|schema| schema.definition));
        policy.bind_complete_restore_transfer_definitions()?;
        policy.validate_immutable_content()?;
        serialized_credit(&policy.protocol_view(), 512 * 1024)?;
        Ok(policy)
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn validate_complete_restore_content(&self) -> Result<(), ProviderError> {
        self.validate_complete_restore_transfer_content()?;
        let Some(_) = self.complete_restore_selection else {
            return if self.complete_restore_definitions.is_none() {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "native absent complete restore definitions",
                ))
            };
        };
        let schemas = [
            complete_restore_request_schema()?,
            complete_restore_proof_schema()?,
            complete_restore_receipt_schema()?,
        ];
        if self.protocol_metadata_limits.is_none()
            || self.native_codec_metadata_extent.is_none()
            || self.ack_emitter_selection.is_none()
            || !matches!(
                self.capture_profile,
                super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || self
                .complete_restore_definitions
                .as_ref()
                .is_none_or(|definitions| {
                    definitions
                        .iter()
                        .zip(schemas.iter())
                        .any(|(actual, schema)| actual != &schema.definition)
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
                "native complete restore source definitions differ",
            ));
        }
        Ok(())
    }

    /// Returns the original immutable policy DATA projection.
    pub fn complete_restore_selection(&self) -> Option<PacketNative5CompleteRestoreSelection> {
        self.complete_restore_selection
    }

    /// Returns the original immutable policy DATA projection.
    pub fn complete_restore_definitions(&self) -> Option<&[ContentRef; 3]> {
        self.complete_restore_definitions.as_ref()
    }
}

pub(super) struct CompleteRestorePolicyView<'a>(pub(super) &'a Native5PolicyData);
impl Serialize for CompleteRestorePolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.complete_restore_selection {
            Some(selection) => (
                "source-private.native5-policy-complete-restore/14",
                selection,
                &self.0.complete_restore_definitions,
                Native5PolicyDataView(self.0),
            )
                .serialize(serializer),
            None => Native5PolicyDataView(self.0).serialize(serializer),
        }
    }
}
