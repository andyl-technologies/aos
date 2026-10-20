//! Binds the optional inactive-target report family to the native policy.

use super::super::fresh_restore_allocation::{self as fresh, *};
use super::*;

impl Native5PolicyData {
    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn with_fresh_restore_allocation_selection(
        mut self,
        selection: Option<PacketNative5FreshRestoreAllocationSelection>,
    ) -> Result<Self, ProviderError> {
        if selection.is_some() {
            self.fresh_restore_allocation_definitions =
                Some(fresh::policy::selected_schemas()?.map(|schema| schema.definition));
        }
        self.fresh_restore_allocation_selection = selection;
        self.validate_fresh_restore_allocation_content()?;
        Ok(self)
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn validate_fresh_restore_allocation_content(&self) -> Result<(), ProviderError> {
        match (
            self.fresh_restore_allocation_selection,
            self.fresh_restore_allocation_definitions.as_ref(),
        ) {
            (None, None) => Ok(()),
            (
                Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13),
                Some(definitions),
            ) => {
                if self.complete_restore_selection != Some(super::super::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                    || self.restore_input_emitter_selection != Some(super::super::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
                    || !matches!(self.capture_profile, super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
                    || self.protocol_metadata_limits.is_none()
                    || self.native_codec_metadata_extent != Some(client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                    || self.ack_emitter_selection != Some(super::super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                    || self.selection.realization.bindings.len() != 1
                    || self.selection.realization.owner_bindings.len() != 1
                {
                    return Err(refused());
                }
                fresh::policy::validate_selection_content(&self.selection, definitions)
            }
            _ => Err(refused()),
        }
    }

    /// Returns the original immutable policy DATA projection.
    pub fn fresh_restore_allocation_selection(
        &self,
    ) -> Option<PacketNative5FreshRestoreAllocationSelection> {
        self.fresh_restore_allocation_selection
    }
}

pub(super) struct FreshPolicyView<'a>(pub(super) &'a Native5PolicyData);

macro_rules! fresh_view {
    ($wrapper:ident, $old:ident, $tag:literal) => {
        impl Serialize for $wrapper<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let old = super::capture_metadata::$old(self.0);
                if self.0.fresh_restore_allocation_selection.is_some() {
                    (
                        $tag,
                        &self.0.fresh_restore_allocation_selection,
                        &self.0.fresh_restore_allocation_definitions,
                        old,
                    )
                        .serialize(serializer)
                } else {
                    old.serialize(serializer)
                }
            }
        }
    };
}

fresh_view!(
    FreshPolicyView,
    CapturePolicyView,
    "source-private.native5-policy-fresh-restore-allocation/18"
);

fn refused() -> ProviderError {
    ProviderError::Correlation("native fresh restoration allocation selection differs")
}
