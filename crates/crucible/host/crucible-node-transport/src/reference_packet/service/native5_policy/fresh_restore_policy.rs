//! Binds the optional inactive-target report family to the native policy.

use super::super::fresh_restore_allocation::{self as fresh, *};
use super::*;

impl Native5Policy {
    pub(in crate::reference_packet::service) fn with_fresh_restore_allocation_selection(
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

    pub(super) fn validate_fresh_restore_allocation_content(&self) -> Result<(), ProviderError> {
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
                    || self.native_codec_metadata_extent != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
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

    pub(super) fn validate_fresh_restore_allocation_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        if self.fresh_restore_allocation_selection.is_some() {
            fresh::policy::validate_selection_negotiation(authority)?;
        }
        Ok(())
    }

    pub(super) fn verify_fresh_restore_allocation_envelope(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        received: &ReceivedBody,
    ) -> Result<bool, ProviderError> {
        if self.fresh_restore_allocation_selection.is_none() {
            return if fresh::policy::contains_selected_data(envelope) {
                Err(refused())
            } else {
                Ok(false)
            };
        }
        fresh::policy::verify_envelope(&self.selection, authority, envelope, received)
    }

    pub(crate) fn fresh_restore_allocation_selection(
        &self,
    ) -> Option<PacketNative5FreshRestoreAllocationSelection> {
        self.fresh_restore_allocation_selection
    }
}

pub(super) struct FreshPolicyView<'a>(pub(super) &'a Native5Policy);
pub(super) struct FreshCompactPolicyView<'a>(pub(super) &'a Native5Policy);
pub(super) struct FreshOwnedPolicyView<'a>(pub(super) &'a Native5Policy);

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
fresh_view!(
    FreshCompactPolicyView,
    CaptureCompactPolicyView,
    "source-private.native5-policy-compact-fresh-restore-allocation/18"
);
fresh_view!(
    FreshOwnedPolicyView,
    CaptureOwnedPolicyView,
    "source-private.native5-policy-owned-fresh-restore-allocation/18"
);

fn refused() -> ProviderError {
    ProviderError::Correlation("native fresh restoration allocation selection differs")
}

// crucible-lint: allow panic-shortcut -- immutable policy data and full schema roster refusals are the observations.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::MetadataObserver;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn fresh_none_preserves_actual_policy_bytes_and_metadata_and_refuses_old_arrays_selection()
    -> TestResult {
        let (_, _, selection, coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let policy = Native5Policy::prepare_original_profile(
            selection,
            coordinator,
            super::super::super::PacketNative5CaptureProfile::OriginalArrays6,
        )?;
        let bytes = serde_json::to_vec(&policy.protocol_view())?;
        let compact = serde_json::to_vec(&policy.compact_protocol_view())?;
        let owned = serde_json::to_vec(&policy.borrowed_owned11_protocol_view())?;
        let mut before = MetadataObserver::new();
        policy.observe_retained_metadata(&mut before)?;
        let before = before.finish();
        let policy = policy.with_fresh_restore_allocation_selection(None)?;
        let mut after = MetadataObserver::new();
        policy.observe_retained_metadata(&mut after)?;
        assert_eq!(before, after.finish());
        assert_eq!(bytes, serde_json::to_vec(&policy.protocol_view())?);
        assert_eq!(
            compact,
            serde_json::to_vec(&policy.compact_protocol_view())?
        );
        assert_eq!(
            owned,
            serde_json::to_vec(&policy.borrowed_owned11_protocol_view())?
        );
        assert!(
            policy
                .with_fresh_restore_allocation_selection(Some(
                    PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13
                ))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn fresh_full_definition_check_requires_both_actual_format_rosters_and_exact_references()
    -> TestResult {
        let (_, _, mut data, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let schemas = fresh::policy::selected_schemas()?;
        let definitions = schemas.clone().map(|schema| schema.definition);
        // This is a schema DATA test. The modified declaration is never passed
        // to a live constructor, handshake, Source action or native boot.
        data.provider
            .extensions_supported
            .push(Id::new(PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)?);
        for schema in &schemas {
            data.provider.implementation.formats.push(schema.clone());
            data.realization.bindings[0]
                .compatibility
                .implementation
                .formats
                .push(schema.clone());
        }
        fresh::policy::validate_selection_content(&data, &definitions)?;
        for index in 0..schemas.len() {
            let mut foreign = definitions.clone();
            foreign[index].length = U64::new(
                foreign[index]
                    .length
                    .get()
                    .checked_add(1)
                    .ok_or("length overflow")?,
            );
            assert!(fresh::policy::validate_selection_content(&data, &foreign).is_err());
            let position = data.realization.bindings[0]
                .compatibility
                .implementation
                .formats
                .iter()
                .position(|schema| schema == &schemas[index])
                .ok_or("binding format absent")?;
            let schema = data.realization.bindings[0]
                .compatibility
                .implementation
                .formats
                .remove(position);
            assert!(fresh::policy::validate_selection_content(&data, &definitions).is_err());
            data.realization.bindings[0]
                .compatibility
                .implementation
                .formats
                .insert(position, schema);
        }
        let schema = data
            .provider
            .implementation
            .formats
            .pop()
            .ok_or("provider format absent")?;
        assert!(fresh::policy::validate_selection_content(&data, &definitions).is_err());
        data.provider.implementation.formats.push(schema);
        fresh::policy::validate_selection_content(&data, &definitions)?;
        Ok(())
    }
}
