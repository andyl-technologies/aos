//! Retains the explicit installed snapshot edition without native authority.
//!
//! The binder uses borrowed DATA in the ordinary operator-install phase before
//! banks or private birth. A failed declaration stays poisoned. The later DATA
//! query remains valid across legitimate Source phases; live purpose/currentness
//! and complete historical reconstruction are separate mandatory predicates.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_contract::SchemaRef;
use crucible_node_provider::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::service::{
        PacketNative5AckEmitterSelection, PacketNative5ConfirmationSelection,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        native_snapshot::{
            authenticate_native_owned14_snapshot_schema_data,
            native_owned14_snapshot_schema_counter_scratch_data,
        },
    },
};
use std::mem::size_of;

#[derive(Clone, Copy)]
pub(super) enum Declaration {
    Attempted,
    Invocation14,
    RestorationActivation14,
    RestorationObservation14,
    RestorationSuffix14,
    RestoredSettledRecapture17,
}

impl PacketCompleteSemanticSource {
    /// Binds the explicit invocation snapshot declaration before preparation.
    ///
    /// This borrowed allocation-free check belongs to ordinary operator-install
    /// validation. It issues no Source member, purpose, report grant or native
    /// permission. Refusal after a valid prebirth entry poisons this occurrence.
    ///
    /// # Errors
    /// Refuses foreign creation, repeated/late entry, an incomplete tuple, or a
    /// missing, duplicate or changed full definition in either immutable roster.
    pub fn bind_original_invocation_snapshot_declaration(&mut self) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_declaration.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if self.invocation_snapshot_declaration.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self.complete_bytes_launch_reserved.get()
            || self.registry_retention_attempted.get()
            || self.registry_retention_failed.get()
            || self.capture_banks.get_mut().is_some()
            || self.capture_execution.get_mut().is_some()
            || self.registry_capture.get_mut().is_some()
            || self.original_extension_registry.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
        };
        if !unbound {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.invocation_snapshot_declaration = Some(Declaration::Attempted);
        self.authenticate_invocation_snapshot_declaration_tuple_data()?;
        self.storage_origin_with_error::<RuntimeError>()?;
        self.invocation_snapshot_declaration = Some(Declaration::Invocation14);
        Ok(())
    }

    /// Reports the completed installed declaration as DATA in later Source phases.
    ///
    /// This never chooses original versus target purpose, authorizes a live
    /// action, or replaces full cold validation. Unselected old editions stay
    /// false; an attempted but unsuccessful new declaration cannot fall back.
    ///
    /// # Errors
    /// Refuses foreign creation, a failed attempt or changed immutable selection.
    pub fn is_original_invocation_snapshot_declaration_data(&self) -> Result<bool, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        match self.invocation_snapshot_declaration {
            None => Ok(false),
            Some(Declaration::Attempted) => Err(RuntimeError::UnsupportedFacet),
            Some(
                Declaration::Invocation14
                | Declaration::RestorationActivation14
                | Declaration::RestorationObservation14
                | Declaration::RestorationSuffix14
                | Declaration::RestoredSettledRecapture17,
            ) => {
                self.authenticate_invocation_snapshot_declaration_tuple_data()?;
                if matches!(
                    self.invocation_snapshot_declaration,
                    Some(
                        Declaration::RestorationActivation14
                            | Declaration::RestorationObservation14
                            | Declaration::RestorationSuffix14
                            | Declaration::RestoredSettledRecapture17
                    )
                ) {
                    self.authenticate_restoration_activation_declaration_tuple_data()?;
                }
                if matches!(
                    self.invocation_snapshot_declaration,
                    Some(
                        Declaration::RestorationObservation14
                            | Declaration::RestorationSuffix14
                            | Declaration::RestoredSettledRecapture17
                    )
                ) {
                    self.authenticate_restoration_observation_declaration_tuple_data()?;
                }
                if matches!(
                    self.invocation_snapshot_declaration,
                    Some(
                        Declaration::RestorationSuffix14 | Declaration::RestoredSettledRecapture17
                    )
                ) {
                    self.authenticate_restored_suffix_declaration_tuple_data()?;
                }
                if matches!(
                    self.invocation_snapshot_declaration,
                    Some(Declaration::RestoredSettledRecapture17)
                ) {
                    self.authenticate_restored_settled_recapture_declaration_tuple_data()?;
                }
                Ok(true)
            }
        }
    }

    /// Names fixed borrowed declaration views for later precredit queries.
    ///
    /// This DATA is not an issuer for ordinary operator-install validation.
    /// The inline marker is already included by the existing actual Source
    /// `size_of::<Self>()` and Rc header observations; it owns no new heap bank.
    pub fn original_invocation_snapshot_declaration_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<[&[SchemaRef]; 2]>()
            + size_of::<std::array::IntoIter<&[SchemaRef], 2>>()
            + size_of::<std::slice::Iter<'_, SchemaRef>>()
            + size_of::<&SchemaRef>()
            + size_of::<std::cell::Ref<'_, Option<CnpSemanticSourceRead>>>()
            + size_of::<
                Result<std::cell::Ref<'_, Option<CnpSemanticSourceRead>>, std::cell::BorrowError>,
            >()
            + size_of::<Option<&PacketNative5CaptureProfile>>()
            + size_of::<Option<Option<PacketNative5ConfirmationSelection>>>()
            + size_of::<(
                Option<&PacketNative5CaptureProfile>,
                Option<Option<PacketNative5ConfirmationSelection>>,
            )>()
            + size_of::<&CnpSemanticInstallation>()
            + size_of::<bool>()
            + size_of::<Option<Declaration>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + native_owned14_snapshot_schema_counter_scratch_data()
            + restoration_activation::counter_scratch_data()
            + restoration_observation::counter_scratch_data()
            + restored_suffix::counter_scratch_data()
            + restored_settled_recapture::counter_scratch_data()
    }

    fn authenticate_invocation_snapshot_declaration_tuple_data(&self) -> Result<(), RuntimeError> {
        let (profile, confirmation) = match &self.original {
            CompletePacketOriginal::Producer(source) => (
                source.complete_capture_profile.as_ref(),
                source.complete_confirmation_selection,
            ),
            CompletePacketOriginal::Reactive(source) => (
                source.complete_capture_profile.as_ref(),
                source.complete_confirmation_selection,
            ),
        };
        if !matches!(
            profile,
            Some(PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        ) || confirmation != Some(Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5))
            || self.capture_allocation_selection
                != Some(Some(
                    PacketNative5CaptureAllocationSelection::OriginalObserve12,
                ))
            || self.fresh_restore_allocation_selection
                != Some(Some(
                    PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13,
                ))
            || self.complete_restore_selection
                != Some(Some(
                    PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
                ))
            || self.restore_input_emitter_selection
                != Some(Some(
                    PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12,
                ))
            || self.ack_emitter_selection
                != Some(Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5))
            || self.ack_codec_metadata_extent
                != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || self.native_ack_codec_metadata_extent
                != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || self.protocol_metadata_limits.is_none()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let installation = self.installation();
        for formats in [
            installation.provider.implementation.formats.as_slice(),
            installation
                .binding
                .compatibility
                .implementation
                .formats
                .as_slice(),
        ] {
            let mut found = false;
            for schema in formats {
                if schema.id.as_str() == "source-owned.packet-native-continuation/14" {
                    if found {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    authenticate_native_owned14_snapshot_schema_data(schema)
                        .map_err(|_| RuntimeError::ForeignAuthority)?;
                    found = true;
                }
            }
            if !found {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> PacketCompleteSemanticSource {
        let coordinator = super::super::tests::coordinator();
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            super::super::tests::installation(&coordinator, 0),
            super::super::tests::producer(),
            coordinator,
            super::super::tests::storage_selection(),
        )
        .unwrap()
    }

    #[test]
    fn failed_declaration_stays_spent_without_promoting_original_source_data() {
        let mut source = source();
        assert!(
            !source
                .is_original_invocation_snapshot_declaration_data()
                .unwrap()
        );
        assert!(matches!(
            source.selected_complete_native_snapshot_class().unwrap(),
            super::super::archive_owner::CompleteNativeSnapshotClass::Legacy11
        ));

        assert!(matches!(
            source.bind_original_invocation_snapshot_declaration(),
            Err(RuntimeError::UnsupportedFacet)
        ));
        assert!(matches!(
            source.is_original_invocation_snapshot_declaration_data(),
            Err(RuntimeError::UnsupportedFacet)
        ));
        assert!(matches!(
            source.bind_original_invocation_snapshot_declaration(),
            Err(RuntimeError::DuplicateOperation)
        ));
        assert!(source.ack_peer_birth.get_mut().is_none());
        assert!(source.capture_banks.get_mut().is_none());
        assert!(source.capture_execution.get_mut().is_none());
        assert!(
            source
                .original_complete_native_snapshot_schema_data()
                .is_err()
        );
        assert!(source.authenticate_current_native().is_err());
    }

    #[test]
    fn foreign_declaration_origin_precedes_binding_and_poison_state() {
        let mut source = source();
        let original_process = source.process;
        source.process = original_process.wrapping_add(1);

        assert!(matches!(
            source.bind_original_invocation_snapshot_declaration(),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(matches!(
            source.is_original_invocation_snapshot_declaration_data(),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(source.invocation_snapshot_declaration.is_none());

        source.process = original_process;
        assert!(
            !source
                .is_original_invocation_snapshot_declaration_data()
                .unwrap()
        );
        assert!(source.ack_peer_birth.get_mut().is_none());
    }
}

#[path = "invocation_snapshot/restoration_activation.rs"]
mod restoration_activation;

#[path = "invocation_snapshot/restoration_observation.rs"]
mod restoration_observation;

#[path = "invocation_snapshot/restored_suffix.rs"]
mod restored_suffix;

#[path = "invocation_snapshot/restored_settled_recapture.rs"]
mod restored_settled_recapture;

#[path = "invocation_snapshot/coordinator_policy17.rs"]
mod coordinator_policy17;

pub(super) use coordinator_policy17::CoordinatorPolicy17;

#[path = "invocation_snapshot/coordinator_policy18.rs"]
mod coordinator_policy18;

pub(super) use coordinator_policy18::CoordinatorPolicy18;
