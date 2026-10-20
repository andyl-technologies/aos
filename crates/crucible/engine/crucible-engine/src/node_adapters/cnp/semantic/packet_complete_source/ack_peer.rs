//! Reserves a complete Source's private preparation-only ACK peer birth.
//!
//! Declarations and planning values do not issue a native marker. The later
//! original post-Hello issuer must compare the actual immutable controller,
//! SDK emitter lease, full original Hello, native read and kernel association
//! before signing the exact assigned Admit envelope.

use super::*;
use crucible_node_transport::client::CanonicalAckCodecMetadataExtent;
use crucible_node_transport::reference_packet::service::{
    PacketNative5ConfirmationSelection, PacketNative5SourceLaunch,
    ack_emitter::{
        PacketNative5AckEmitterSelection, native_canonical_ack_admission_schema,
        native_canonical_blob_ack_schema,
    },
    confirmation::native_after_confirmation_schema,
};

#[path = "ack_peer/import18_declaration.rs"]
mod import18_declaration;
pub(super) use import18_declaration::Import18Declaration;

#[path = "ack_peer/import18_recipe.rs"]
mod import18_recipe;
pub(super) use import18_recipe::Import18RecipeOwner;

#[path = "ack_peer/association.rs"]
mod association;
#[path = "ack_peer/birth.rs"]
mod birth;
#[path = "ack_peer/import18_prebirth.rs"]
mod import18_prebirth;
pub use import18_prebirth::NativeImport18BirthConstructionQuote;
pub(super) use import18_prebirth::{
    NativeImport18BirthConstruction, NativeImport18DerivationState,
};
#[path = "ack_peer/frame.rs"]
mod frame;
pub(super) use association::OriginalAckPeerAssociation;
pub use association::PacketCompleteRestorePreparation;
pub(super) use birth::OriginalAckPeerBirth;
pub use birth::{
    PacketCompleteAckPeerBootMaterial, PacketCompleteNativeImport18StartupWire,
    PacketCompleteNativeRestoredSuffixStartupWire, PacketCompleteNativeStartupWire,
    PacketCompleteOriginalHostSdk,
};
pub use frame::PacketCompleteAckPeerBootFrame;

/// Selects one full planned controller registration for preparation only.
///
/// The Source derives session and incarnation from its original binding. It
/// checks these planned values against the actual post-Hello authority before
/// any proof signature. Construction or deserialization grants no authority.
pub struct PacketCompleteAckHostRegistrationPlan {
    /// Names the independently planned host-local physical connection.
    pub connection_id: Id,
    /// Retains the exact mutually selected feature roster expected after Hello.
    pub features: IdSet,
    /// Retains complete typed extension selections expected after Hello.
    pub extensions: Vec<ExtensionSelection>,
    /// Names the exact sorted envelope-extension roster expected after Hello.
    pub envelope_extensions: Vec<String>,
}

impl PacketCompleteSemanticSource {
    /// Binds the expected ACK grammar before banks, keys or Child exist.
    ///
    /// This fixes declaration data only. It neither issues a host emitter lease
    /// nor reduces a native frame bound; old unselected Sources keep None.
    ///
    /// # Errors
    /// Refuses changed origin, repeated or late binding, missing confirmation,
    /// or any changed full selected schema or supported feature.
    pub fn bind_original_ack_emitter_selection(
        &mut self,
        selection: Option<PacketNative5AckEmitterSelection>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.ack_emitter_selection.is_some()
            || self.capture_banks.get_mut().is_some()
            || self.ack_peer_birth.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
        {
            return Err(refused(
                "complete ACK selection is repeated or follows preparation",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound()?,
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound()?,
        };
        if !unbound {
            return Err(refused("complete ACK selection follows native association"));
        }
        if selection.is_some() {
            if self.selected_confirmation_selection()?
                != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
            {
                return Err(refused("complete ACK selection requires confirmation"));
            }
            for schema in [
                native_after_confirmation_schema().map_err(unknown)?,
                native_canonical_blob_ack_schema().map_err(unknown)?,
                native_canonical_ack_admission_schema().map_err(unknown)?,
            ] {
                let installation = self.installation();
                if !installation
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
                    || !installation
                        .binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&schema)
                    || !installation
                        .provider
                        .extensions_supported
                        .contains(&schema.id)
                {
                    return Err(refused("complete ACK source definition differs"));
                }
            }
        }
        self.ack_emitter_selection = Some(selection);
        Ok(())
    }

    /// Returns the expected immutable ACK selection without issuing its mechanism.
    ///
    /// # Errors
    /// Refuses another creator process or thread.
    pub fn selected_ack_emitter_selection(
        &self,
    ) -> Result<Option<PacketNative5AckEmitterSelection>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.ack_emitter_selection.flatten())
    }

    /// Binds the closed selected codec metadata extent before bank or Child creation.
    ///
    /// This selection bounds encoded immutable codec data only. Actual backing,
    /// parsed trees, protocol reservations and complete Capture admission remain
    /// independent. It cannot enlarge the Node or whole scenario memory budget.
    ///
    /// # Errors
    /// Refuses repeated/late binding, changed origin or selection without ACKSome.
    pub fn bind_original_ack_codec_metadata_extent(
        &mut self,
        extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.ack_codec_metadata_extent.is_some()
            || self.capture_banks.get_mut().is_some()
            || self.ack_birth_attempted
            || self.selected_ack_emitter_selection()?
                != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        {
            return Err(refused(
                "complete ACK codec extent is repeated, late or unsupported",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound()?,
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound()?,
        };
        if !unbound {
            return Err(refused(
                "complete ACK codec extent follows native association",
            ));
        }
        self.ack_codec_metadata_extent = Some(extent);
        Ok(())
    }

    /// Returns the expected closed codec extent without storage or marker authority.
    ///
    /// # Errors
    /// Refuses another creator process or thread.
    pub fn selected_ack_codec_metadata_extent(
        &self,
    ) -> Result<Option<CanonicalAckCodecMetadataExtent>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.ack_codec_metadata_extent)
    }

    /// Binds the independent native immutable codec extent before banks or Child.
    ///
    /// This fixes a closed declaration choice, separately from the controller's
    /// codec extent. It grants no native marker, storage, world or Capture rights.
    ///
    /// # Errors
    /// Refuses foreign origin, repeated/late binding, absent canonical ACK
    /// selection, or an already associated original preparation.
    pub fn bind_original_native_ack_codec_metadata_extent(
        &mut self,
        extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.native_ack_codec_metadata_extent.is_some()
            || self.capture_banks.get_mut().is_some()
            || self.ack_birth_attempted
            || self.preconstruction.get_mut().is_some()
            || self.selected_ack_emitter_selection()?
                != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        {
            return Err(refused(
                "native ACK codec extent is repeated, late or unsupported",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound()?,
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound()?,
        };
        if !unbound {
            return Err(refused(
                "native ACK codec extent follows native association",
            ));
        }
        self.native_ack_codec_metadata_extent = Some(extent);
        Ok(())
    }

    /// Returns the independently expected native codec extent as declaration data.
    ///
    /// # Errors
    /// Refuses another original creator process or thread.
    pub fn selected_native_ack_codec_metadata_extent(
        &self,
    ) -> Result<Option<CanonicalAckCodecMetadataExtent>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.native_ack_codec_metadata_extent)
    }

    /// Reserves the original source-generated key and full private birth banks.
    ///
    /// This preparation-only reservation precedes Rc publication and Child.
    /// `admitted_bank_bytes` covers only the existing and new byte banks. It
    /// does not cover typed/JSON trees, Rc headers, file/kernel resources or
    /// native copies and cannot issue complete memory or Capture admission. The
    /// actual Source, full coordinator and physical bank selection remain the
    /// constructor's independent inputs. Its caller retains a failed original
    /// key/bank slot; an earlier refusal cannot be retried or rebound.
    ///
    /// # Errors
    /// Refuses a foreign, late or repeated birth, changed selected launch,
    /// unsupported full planned registration, exhausted source budget or actual
    /// host executable/entropy failure. Capture remains separately refused.
    pub fn reserve_original_canonical_ack_peer_birth(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        private_launch: Id,
        registration: PacketCompleteAckHostRegistrationPlan,
        admitted_bank_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.original_restored_settled_coordinator_policy17_data()
            .map_err(unknown)?;
        self.ensure_origin()?;
        if self.ack_birth_attempted
            || self.complete_bytes_launch_reserved.get()
            || self.ack_peer_birth.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
        {
            return Err(refused("complete private ACK birth was already attempted"));
        }
        self.ack_birth_attempted = true;
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound()?,
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound()?,
        };
        if !unbound {
            return Err(refused(
                "complete private ACK birth follows native association",
            ));
        }
        launch.validate().map_err(unknown)?;
        private_launch.validate().map_err(unknown)?;
        registration.connection_id.validate().map_err(unknown)?;
        let coordinator = PacketNative5CoordinatorInstallation::decode(
            launch.initial_coordinator.bytes.as_slice(),
            &launch.selection,
        )
        .map_err(unknown)?;
        self.authenticate_collecting_world_scope(&coordinator)?;
        self.authenticate_ack_birth_launch(launch)?;

        for feature in &registration.features {
            feature.validate().map_err(unknown)?;
        }
        for extension in &registration.extensions {
            extension.validate().map_err(unknown)?;
        }
        for name in &registration.envelope_extensions {
            Id::new(name.clone()).map_err(unknown)?;
        }
        let mandatory = [
            native_after_confirmation_schema().map_err(unknown)?.id,
            native_canonical_blob_ack_schema().map_err(unknown)?.id,
            native_canonical_ack_admission_schema().map_err(unknown)?.id,
        ];
        if mandatory
            .iter()
            .any(|feature| !registration.features.contains(feature))
            || registration
                .features
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || registration
                .envelope_extensions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || [mandatory[0].as_str(), mandatory[2].as_str()]
                .iter()
                .any(|extension| {
                    !registration
                        .envelope_extensions
                        .iter()
                        .any(|name| name == extension)
                })
        {
            return Err(refused(
                "complete private ACK registration plan is incomplete",
            ));
        }
        if let Some(selection) = self.selected_complete_restore_selection()? {
            use crucible_node_transport::reference_packet::service::complete_restore::{
                complete_restore_selected_envelope_extensions, complete_restore_selected_features,
            };
            let feature_missing =
                complete_restore_selected_features(selection)
                    .iter()
                    .any(|name| {
                        !registration
                            .features
                            .iter()
                            .any(|feature| feature.as_str() == *name)
                    });
            let extension_missing = complete_restore_selected_envelope_extensions(selection)
                .iter()
                .any(|name| {
                    !registration
                        .envelope_extensions
                        .iter()
                        .any(|extension| extension.as_str() == *name)
                });
            if feature_missing || extension_missing {
                return Err(refused(
                    "complete restore planned registration is incomplete",
                ));
            }
        }
        if self.selected_restore_input_emitter_selection()?.is_some()
            && !registration.features.iter().any(|feature| feature.as_str()
                == crucible_node_transport::reference_packet::service::complete_restore::PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
        {
            return Err(refused("restore input emitter planned feature absent"));
        }
        if self
            .selected_fresh_restore_allocation_selection()?
            .is_some()
        {
            use crucible_node_transport::reference_packet::service::fresh_restore_allocation::{
                PACKET_FRESH_RESTORE_ALLOCATION_FEATURE,
                PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
                PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            };
            if !registration
                .features
                .iter()
                .any(|feature| feature.as_str() == PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
                || [
                    PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
                    PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
                ]
                .iter()
                .any(|name| {
                    !registration
                        .envelope_extensions
                        .iter()
                        .any(|actual| actual == name)
                })
            {
                return Err(refused(
                    "fresh allocation planned registration is incomplete",
                ));
            }
        }
        let frame_bytes = usize::try_from(launch.limits.frame_bytes.get())
            .map_err(|_| refused("ACK assigned frame bank extent overflow"))?;
        let association_bank_minimum = OriginalAckPeerAssociation::minimum_bank_bytes(frame_bytes)?;
        let restore_bank_minimum = if self.selected_complete_restore_selection()?.is_some() {
            OriginalAckPeerAssociation::minimum_complete_restore_bank_bytes(frame_bytes)?
        } else {
            0
        };

        let transfer_phase_bank_minimum = if self.selected_complete_restore_selection()?
            == Some(crucible_node_transport::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            OriginalAckPeerAssociation::minimum_restore_transfer_phase_bank_bytes(frame_bytes)?
        } else {
            0
        };
        let original_bank_bytes = self.original_capture_bank_facts()?.total_bytes;
        let selected_bank_minimum = original_bank_bytes
            .checked_add(association_bank_minimum)
            .and_then(|sum| sum.checked_add(restore_bank_minimum))
            .and_then(|sum| sum.checked_add(transfer_phase_bank_minimum))
            .and_then(|sum| sum.checked_add(frame::MAXIMUM_ACK_SOURCE_BIRTH_BYTES))
            .and_then(|sum| sum.checked_add(frame::MAXIMUM_ACK_HOST_REGISTRATION_BYTES))
            .and_then(|sum| sum.checked_add(frame::MAXIMUM_ACK_PRIVATE_BOOT_BYTES + 4))
            .ok_or_else(|| refused("complete private ACK bank admission overflow"))?;
        if selected_bank_minimum > admitted_bank_bytes {
            return Err(refused(
                "complete private ACK banks exceed original reservation",
            ));
        }
        OriginalAckPeerAssociation::reserve_into(frame_bytes, self.ack_peer_association.get_mut())?;
        if self.selected_complete_restore_selection()?.is_some() {
            self.ack_peer_association
                .get_mut()
                .as_mut()
                .ok_or_else(|| refused("complete selected restore association slot absent"))?
                .reserve_complete_restore_banks(frame_bytes)?;
        }
        if transfer_phase_bank_minimum != 0 {
            self.ack_peer_association
                .get_mut()
                .as_mut()
                .ok_or_else(|| refused("selected12 phase association slot absent"))?
                .reserve_restore_transfer_phase_banks(frame_bytes)?;
        }
        let association_bank_bytes = self
            .ack_peer_association
            .get_mut()
            .as_ref()
            .ok_or_else(|| refused("ACK association bank slot absent"))?
            .allocated_bank_bytes()?;
        let storage = self.selected_storage_selection()?;
        let installation = self.installation();
        let mut birth = serde_json::json!({
            "schema": "source-owned.packet-canonical-ack-source-binding/6",
            "selection": launch.selection,
            "program": launch.program,
            "coordinator": coordinator,
            "limits": launch.limits,
            "storage": launch.storage,
            "capture_profile": launch.capture_profile,
            "confirmation_selection": launch.confirmation_selection,
            "ack_emitter_selection": launch.ack_emitter_selection,
            "codec_metadata_extent": self.selected_ack_codec_metadata_extent()?,
        });
        if let Some(extent) = self.selected_native_ack_codec_metadata_extent()? {
            // The old binding/6 keeps its exact closed shape when unselected.
            // A native codec choice gets a distinct complete binding/7; it is
            // never inferred from the controller's independently selected bound.
            let value = birth
                .as_object_mut()
                .ok_or_else(|| refused("native ACK source binding is not an object"))?;
            value.insert(
                "schema".into(),
                serde_json::Value::String(
                    "source-owned.packet-canonical-ack-source-binding/7".into(),
                ),
            );
            value.insert(
                "native_codec_metadata_extent".into(),
                serde_json::to_value(extent).map_err(unknown)?,
            );
        }
        if let Some(limits) = self.selected_protocol_metadata_limits()? {
            let value = birth
                .as_object_mut()
                .ok_or_else(|| refused("native metadata source binding is not an object"))?;
            value.insert(
                "schema".into(),
                serde_json::Value::String(
                    "source-owned.packet-canonical-ack-source-binding/8".into(),
                ),
            );
            value.insert(
                "protocol_metadata_limits".into(),
                serde_json::to_value(limits).map_err(unknown)?,
            );
        }
        if let Some(selection) = self.selected_complete_restore_selection()? {
            let value = birth
                .as_object_mut()
                .ok_or_else(|| refused("complete restore source binding is not an object"))?;
            value.insert(
                "schema".into(),
                serde_json::Value::String(
                    match selection {
                        crucible_node_transport::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedOwned11 =>
                            "source-owned.packet-canonical-ack-source-binding/9",
                        crucible_node_transport::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12 =>
                            "source-owned.packet-canonical-ack-source-binding/10",
                    }.into(),
                ),
            );
            value.insert(
                "complete_restore_selection".into(),
                serde_json::to_value(selection).map_err(unknown)?,
            );
        }
        if let Some(selection) = self.selected_restore_input_emitter_selection()? {
            let value = birth
                .as_object_mut()
                .ok_or_else(|| refused("restore input emitter source binding is not an object"))?;
            value.insert(
                "schema".into(),
                serde_json::Value::String(
                    "source-owned.packet-canonical-ack-source-binding/11".into(),
                ),
            );
            value.insert(
                "restore_input_emitter_selection".into(),
                serde_json::to_value(selection).map_err(unknown)?,
            );
        }
        if let Some(selection) = self.selected_capture_allocation_selection()? {
            let value = birth
                .as_object_mut()
                .ok_or_else(|| refused("capture allocation source binding is not an object"))?;
            value.insert(
                "schema".into(),
                serde_json::Value::String(
                    "source-owned.packet-canonical-ack-source-binding/12".into(),
                ),
            );
            // Binding12 is a distinct closed shape, including literal nulls for
            // independent unselected restore routes. Earlier editions stay exact.
            value.insert(
                "native_codec_metadata_extent".into(),
                serde_json::to_value(self.selected_native_ack_codec_metadata_extent()?)
                    .map_err(unknown)?,
            );
            value.insert(
                "protocol_metadata_limits".into(),
                serde_json::to_value(self.selected_protocol_metadata_limits()?).map_err(unknown)?,
            );
            value.insert(
                "complete_restore_selection".into(),
                serde_json::to_value(self.selected_complete_restore_selection()?)
                    .map_err(unknown)?,
            );
            value.insert(
                "restore_input_emitter_selection".into(),
                serde_json::to_value(self.selected_restore_input_emitter_selection()?)
                    .map_err(unknown)?,
            );
            value.insert(
                "capture_allocation_selection".into(),
                serde_json::to_value(selection).map_err(unknown)?,
            );
        }
        let host = serde_json::json!({
            "schema": "source-owned.packet-canonical-ack-registration/5",
            "role": "controller",
            "connection_id": registration.connection_id,
            "session_id": installation.binding.authority.session_id,
            "incarnation_id": installation.binding.authority.incarnation_id,
            "limits": storage.limits,
            "features": registration.features,
            "extensions": registration.extensions,
            "envelope_extensions": registration.envelope_extensions,
        });
        let mut source_bank = Vec::new();
        source_bank
            .try_reserve_exact(frame::MAXIMUM_ACK_SOURCE_BIRTH_BYTES)
            .map_err(|_| refused("complete private ACK source bank reservation unavailable"))?;
        self.ack_birth_input_banks = Some((source_bank, Vec::new()));
        let banks = self
            .ack_birth_input_banks
            .as_mut()
            .ok_or_else(|| refused("complete private ACK input bank slot absent"))?;
        banks
            .1
            .try_reserve_exact(frame::MAXIMUM_ACK_HOST_REGISTRATION_BYTES)
            .map_err(|_| {
                refused("complete private ACK registration bank reservation unavailable")
            })?;
        let selected_total = original_bank_bytes
            .checked_add(association_bank_bytes)
            .and_then(|sum| sum.checked_add(banks.0.capacity()))
            .and_then(|sum| sum.checked_add(banks.1.capacity()))
            .and_then(|sum| sum.checked_add(frame::MAXIMUM_ACK_PRIVATE_BOOT_BYTES + 4))
            .ok_or_else(|| refused("complete private ACK birth allocation overflow"))?;
        if selected_total > admitted_bank_bytes {
            return Err(refused(
                "complete private ACK birth exceeds source reservation",
            ));
        }
        encode_canonical_birth_bank(&birth, frame::MAXIMUM_ACK_SOURCE_BIRTH_BYTES, &mut banks.0)?;
        encode_canonical_birth_bank(
            &host,
            frame::MAXIMUM_ACK_HOST_REGISTRATION_BYTES,
            &mut banks.1,
        )?;
        let (source_bank, registration_bank) = self
            .ack_birth_input_banks
            .take()
            .ok_or_else(|| refused("complete private ACK original input banks absent"))?;
        let mut source_birth = Some(source_bank);
        let mut host_registration = Some(registration_bank);

        let result = OriginalAckPeerBirth::reserve_into(
            &launch.controller_executable,
            &private_launch,
            &mut source_birth,
            &mut host_registration,
            self.ack_peer_birth.get_mut(),
            launch.capture_allocation_selection.is_some()
                || launch.fresh_restore_allocation_selection.is_some(),
        );
        if let (Some(source), Some(registration)) = (source_birth, host_registration) {
            self.ack_birth_input_banks = Some((source, registration));
        }
        result
    }

    fn authenticate_ack_birth_launch(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), OperationFailure> {
        let actual = self.installation();
        let selected = self.selected_storage_selection()?;
        if self.selected_ack_emitter_selection()?
            != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || self.selected_ack_codec_metadata_extent()?
                != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || launch.native_codec_metadata_extent
                != self.selected_native_ack_codec_metadata_extent()?
            || launch.protocol_metadata_limits != self.selected_protocol_metadata_limits()?
            || launch.complete_restore_selection != self.selected_complete_restore_selection()?
            || launch.restore_input_emitter_selection
                != self.selected_restore_input_emitter_selection()?
            || launch.capture_allocation_selection
                != self.selected_capture_allocation_selection()?
            || launch.fresh_restore_allocation_selection
                != self.selected_fresh_restore_allocation_selection()?
            || launch.ack_emitter_selection != self.selected_ack_emitter_selection()?
            || launch.confirmation_selection != self.selected_confirmation_selection()?
            || &launch.capture_profile != self.selected_capture_profile()?
            || launch.storage != selected.storage
            || launch.limits != selected.limits
            || launch.controller_pid.get() != u64::from(std::process::id())
            || launch.controller_uid.get() != u64::from(rustix::process::geteuid().as_raw())
            || launch.selection.provider != actual.provider
            || launch.selection.realize != actual.realize
            || launch.selection.realization.bindings.as_slice()
                != std::slice::from_ref(&actual.binding)
            || launch.selection.realization.owner_bindings.as_slice()
                != std::slice::from_ref(&actual.owner)
            || launch.selection.realization.descriptors.as_slice()
                != std::slice::from_ref(&actual.descriptor)
            || launch.selection.admission != actual.admission
            || launch.selection.transaction != actual.transaction
            || launch.selection.gate != actual.gate
            || launch.selection.world != actual.world_binding_hash
            || launch.selection.admission_receipt != actual.admission_receipt
        {
            return Err(refused(
                "complete private ACK launch differs from original Source",
            ));
        }
        Ok(())
    }

    /// Borrows the original source-born private boot exactly once.
    ///
    /// The same source allocation stays retained throughout the private writer
    /// transfer. This is not a portable permit or a post-Hello admission issuer.
    ///
    /// # Errors
    /// Refuses foreign origin, absent/busy/failed birth or repeated boot transfer.
    pub fn begin_original_canonical_ack_private_boot(
        &self,
    ) -> Result<PacketCompleteAckPeerBootMaterial<'_>, OperationFailure> {
        self.ensure_origin()?;
        self.is_original_native_import18_declaration_data()
            .map_err(unknown)?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("complete private ACK birth is busy"))?;
        let original = std::cell::Ref::filter_map(slot, Option::as_ref)
            .map_err(|_| refused("complete private ACK birth is absent"))?;
        original.authenticate_report_startup_before_boot(self)?;
        original.authenticate_native_startup_before_boot(self)?;
        original.begin_private_boot()?;
        Ok(PacketCompleteAckPeerBootMaterial::from_original(
            self, original,
        ))
    }
}

fn encode_canonical_birth_bank(
    value: &serde_json::Value,
    maximum: usize,
    bytes: &mut Vec<u8>,
) -> Result<(), OperationFailure> {
    canonical::canonical_json_to_writer(value, &mut BirthBankWriter { bytes, maximum })
        .map_err(|_| refused("complete private ACK full birth bank exceeds selection"))
}

struct BirthBankWriter<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl std::io::Write for BirthBankWriter<'_> {
    fn write(&mut self, body: &[u8]) -> std::io::Result<usize> {
        let end = self
            .bytes
            .len()
            .checked_add(body.len())
            .ok_or_else(|| std::io::Error::other("ACK birth bank extent overflow"))?;
        if end > self.maximum || end > self.bytes.capacity() {
            return Err(std::io::Error::other("ACK birth bank reservation exceeded"));
        }
        self.bytes.extend_from_slice(body);
        Ok(body.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) use birth::{
    PacketCompleteInitialLifecycleIdentity, PacketCompleteInitialLifecycleQuote,
};

pub(crate) use association::{
    OriginalSourceRestoreSignerConstructionData, OriginalSourceRestoreVerifiedPhase,
    OriginalSourceRestoreVerifiedPhaseKind,
};

pub use association::{
    OriginalSourceRestorationActivationConstructionData,
    OriginalSourceRestorationActivationVerifiedPhase,
    OriginalSourceRestorationObservationConstructionData,
    OriginalSourceRestorationObservationVerifiedPhase,
};

pub(crate) use association::OriginalSourceRestoredObservationCompletion;

pub(crate) use association::OriginalSourceRestoredProducerPhaseCompletion;

pub(crate) use association::{
    OriginalSourceRestoredFirstObservationHistory17Read, OriginalSourceRestoredInstallation17,
    OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17,
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Prelude, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs,
};

pub use birth::PacketCompleteNativeRestoredSettledStartupWire;

pub(crate) use association::{
    OriginalSourceRestoredCaptureCompletion, OriginalSourceRestoredCaptureQuoteInputs,
};

pub(crate) use association::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use association::OriginalSourceRestoredCaptureCountingBanksData;

pub use association::OriginalSourceRestoredCaptureConstructionData;
