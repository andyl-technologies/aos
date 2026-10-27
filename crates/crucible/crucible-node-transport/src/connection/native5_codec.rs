//! Retains the installed immutable source-five codec and its complete private view.
//!
//! This closed enum holds actual typed source policies rather than serializing
//! caller callbacks. Installation selects transport grammar only; complete source,
//! semantic, process and restoration custody remain independent conjunctions.

use super::*;
#[path = "controller_fresh_restore.rs"]
mod controller_fresh_restore;
#[path = "controller_input_emitter.rs"]
mod controller_input_emitter;
#[path = "controller_restore.rs"]
mod controller_restore;
use crate::reference_packet::{
    Native5Policy, continuation_contracts as contracts, control::PacketControlSelection,
    coordinator::PacketNative5CoordinatorInstallation,
};
use crate::reference_service::InstalledContent;
use crucible_node_format::*;

pub(crate) enum Native5CodecOwner {
    ControllerPacket(Box<ControllerNative5Policy>),
    NativePacket(Rc<Native5Policy>),
}

pub(crate) struct ProtocolCodecView<'a> {
    pub(crate) codec: &'a Native5CodecOwner,
    pub(crate) compact: bool,
}

impl serde::Serialize for ProtocolCodecView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.compact {
            self.codec.compact_protocol_view().serialize(serializer)
        } else {
            self.codec.protocol_view().serialize(serializer)
        }
    }
}

trait CanonicalAckCodecMetadataExtentData {
    fn maximum_encoded_bytes(self) -> usize;
}

impl CanonicalAckCodecMetadataExtentData for CanonicalAckCodecMetadataExtent {
    fn maximum_encoded_bytes(self) -> usize {
        match self {
            Self::CanonicalAck512KiB => 512 * 1024,
        }
    }
}

pub(crate) struct ControllerNative5Policy {
    metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    selection: PacketControlSelection,
    coordinator: InstalledContent,
    definition: ContentRef,
    connected: PacketNative5CoordinatorInstallation,
    wire: packet_schema::ConnectedPacketSchema,
    capture_profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    confirmation_selection:
        Option<crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection>,
    confirmation_definition: Option<ContentRef>,
    ack_emitter_selection:
        Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
    ack_emitter_definition: Option<ContentRef>,
    complete_restore_selection: Option<
        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    >,
    complete_restore_definitions: Option<[ContentRef; 3]>,
    complete_restore_transfer_definitions: Option<[ContentRef; 7]>,
    restore_input_emitter_selection: Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    restore_input_emitter_definition: Option<ContentRef>,
    fresh_restore_allocation_selection: Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
    fresh_restore_allocation_definitions: Option<[ContentRef; 5]>,
}

impl ControllerNative5Policy {
    fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            metadata_extent,
            selection,
            coordinator,
            definition,
            connected,
            wire,
            capture_profile,
            confirmation_selection,
            confirmation_definition,
            ack_emitter_selection,
            ack_emitter_definition,
            complete_restore_selection,
            complete_restore_definitions,
            complete_restore_transfer_definitions,
            restore_input_emitter_selection,
            restore_input_emitter_definition,
            fresh_restore_allocation_selection,
            fresh_restore_allocation_definitions,
        } = self;
        // The unit selection is inline; actual retained allocations are walked below.
        match metadata_extent {
            None | Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB) => {}
        }
        observer.observe(selection)?;
        observer.observe(coordinator)?;
        observer.observe(definition)?;
        observer.observe(connected)?;
        wire.observe_retained_metadata(observer)?;
        observer.observe(capture_profile)?;
        observer.observe(confirmation_selection)?;
        observer.observe(confirmation_definition)?;
        observer.observe(ack_emitter_selection)?;
        observer.observe(ack_emitter_definition)?;
        observer.observe(complete_restore_selection)?;
        match restore_input_emitter_selection { None | Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12) => {} }
        if let Some(definitions) = complete_restore_definitions {
            for definition in definitions {
                observer.observe(definition)?;
            }
        }
        if let Some(definitions) = complete_restore_transfer_definitions {
            for definition in definitions {
                observer.observe(definition)?;
            }
        }
        observer.observe(restore_input_emitter_definition)?;
        observer.observe(fresh_restore_allocation_selection)?;
        observer.observe(fresh_restore_allocation_definitions)?;
        Ok(())
    }

    pub(crate) fn from_source_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
    ) -> Result<Self, ProviderError> {
        Self::from_source_installation_with_profile(
            authority,
            selection,
            coordinator,
            crate::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
        )
    }

    fn from_source_installation_with_profile(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        Self::from_source_installation_with_metadata_extent(
            authority,
            selection,
            coordinator,
            capture_profile,
            None,
        )
    }

    fn from_source_installation_with_metadata_extent(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    ) -> Result<Self, ProviderError> {
        capture_profile.validate()?;
        serialized_credit(&selection, 65_536)?;
        coordinator.reference.verify(coordinator.bytes.as_slice())?;
        let connected =
            PacketNative5CoordinatorInstallation::decode(coordinator.bytes.as_slice(), &selection)?;
        if selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || selection.realization.owners.len() != 1
            || selection.realization.descriptors.len() != 1
            || selection.provider.implementation.implementation_id.as_str()
                != contracts::PACKET_NATIVE5_IMPLEMENTATION
        {
            return Err(ProviderError::Correlation(
                "native5 controller source cardinality/implementation differs",
            ));
        }
        let schema = contracts::complete_packet_ingress_schema()?;
        if !selection.provider.implementation.formats.contains(&schema)
            || !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == contracts::PACKET_COMPLETE_LINEAGE_FEATURE)
        {
            return Err(ProviderError::Correlation(
                "native5 controller complete codec not installed",
            ));
        }
        let wire = packet_schema::ConnectedPacketSchema::new(
            authority,
            &selection.realization.bindings[0],
            &selection.realization.owner_bindings[0],
        )?;
        let original = Self {
            metadata_extent,
            selection,
            coordinator,
            definition: schema.definition,
            connected,
            wire,
            capture_profile,
            confirmation_selection: None,
            confirmation_definition: None,
            ack_emitter_selection: None,
            ack_emitter_definition: None,
            complete_restore_selection: None,
            complete_restore_definitions: None,
            complete_restore_transfer_definitions: None,
            restore_input_emitter_selection: None,
            restore_input_emitter_definition: None,
            fresh_restore_allocation_selection: None,
            fresh_restore_allocation_definitions: None,
        };
        original.validate_installation(authority)?;
        serialized_credit(
            &original.protocol_view(),
            original.metadata_extent.map_or(
                256 * 1024,
                CanonicalAckCodecMetadataExtent::maximum_encoded_bytes,
            ),
        )?;
        Ok(original)
    }

    fn from_source_confirmation_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        Self::from_source_confirmation_with_metadata_extent(
            authority,
            selection,
            coordinator,
            capture_profile,
            None,
        )
    }

    fn from_source_confirmation_with_metadata_extent(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    ) -> Result<Self, ProviderError> {
        use crate::reference_packet::service::confirmation::{
            PacketNative5ConfirmationSelection, native_after_confirmation_schema,
        };
        let mut original = Self::from_source_installation_with_metadata_extent(
            authority,
            selection,
            coordinator,
            capture_profile,
            metadata_extent,
        )?;
        let schema = native_after_confirmation_schema()?;
        if !original
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        {
            return Err(ProviderError::Correlation(
                "confirmation source schema absent",
            ));
        }
        original.confirmation_selection =
            Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5);
        original.confirmation_definition = Some(schema.definition);
        original.validate_current_confirmation(authority)?;
        serialized_credit(
            &original.protocol_view(),
            original.metadata_extent.map_or(
                256 * 1024,
                CanonicalAckCodecMetadataExtent::maximum_encoded_bytes,
            ),
        )?;
        Ok(original)
    }

    fn from_source_ack_emitter_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        Self::from_source_ack_emitter_with_metadata_extent(
            authority,
            selection,
            coordinator,
            profile,
            None,
        )
    }

    fn from_source_ack_emitter_with_metadata_extent(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    ) -> Result<Self, ProviderError> {
        use crate::reference_packet::service::ack_emitter::{
            PacketNative5AckEmitterSelection, native_canonical_blob_ack_schema,
        };
        let mut policy = Self::from_source_confirmation_with_metadata_extent(
            authority,
            selection,
            coordinator,
            profile,
            metadata_extent,
        )?;
        let schema = native_canonical_blob_ack_schema()?;
        let admission_schema =
            crate::reference_packet::service::ack_emitter::native_canonical_ack_admission_schema()?;
        if !policy
            .selection
            .provider
            .implementation
            .formats
            .contains(&admission_schema)
        {
            return Err(ProviderError::Correlation(
                "canonical ACK Admit proof schema absent",
            ));
        }
        if !policy
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        {
            return Err(ProviderError::Correlation(
                "canonical ACK controller source schema absent",
            ));
        }
        policy.ack_emitter_selection = Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5);
        policy.ack_emitter_definition = Some(schema.definition);
        validate_ack_emitter_selection(
            authority,
            policy.ack_emitter_selection,
            policy.ack_emitter_definition.as_ref(),
        )?;
        serialized_credit(
            &policy.protocol_view(),
            policy.metadata_extent.map_or(
                256 * 1024,
                CanonicalAckCodecMetadataExtent::maximum_encoded_bytes,
            ),
        )?;
        Ok(policy)
    }

    fn validate_current_confirmation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        validate_confirmation_selection(
            authority,
            self.confirmation_selection,
            self.confirmation_definition.as_ref(),
        )
    }

    fn validate_installation(&self, authority: &ConnectionAuthority) -> Result<(), ProviderError> {
        authority.ensure_live()?;
        self.connected.validate(&self.selection)?;
        self.coordinator
            .reference
            .verify(self.coordinator.bytes.as_slice())?;
        self.validate_current_negotiation(authority)
    }

    // Complete immutable source fields are validated at original construction
    // and one-shot installation. Every frame still checks its live negotiation.
    fn validate_current_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        authority.ensure_live()?;
        let binding =
            self.selection
                .realization
                .bindings
                .first()
                .ok_or(ProviderError::Correlation(
                    "native5 controller binding absent",
                ))?;
        if binding.authority.session_id != *authority.session_id()
            || binding.authority.incarnation_id != *authority.incarnation_id()
            || !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == contracts::PACKET_COMPLETE_LINEAGE_FEATURE)
            || !authority.selected_features().iter().any(|feature| {
                feature.as_str() == crate::reference_packet::input::PACKET_INPUT_FEATURE
            })
            || !authority
                .envelope_extensions()
                .contains(crate::reference_packet::input::PACKET_INPUT_FEATURE)
            || authority.limits().frame_bytes.get() > 65_536
            || authority.limits().blob_chunk_bytes.get() > 4096
        {
            return Err(ProviderError::Correlation(
                "native5 controller original authority changed",
            ));
        }
        if self.confirmation_selection.is_some() {
            self.validate_current_confirmation(authority)?;
        }
        if self.ack_emitter_selection.is_some() {
            validate_ack_emitter_selection(
                authority,
                self.ack_emitter_selection,
                self.ack_emitter_definition.as_ref(),
            )?;
        }
        self.validate_current_restore(authority)?;
        self.validate_current_fresh_restore(authority)?;
        authority.ensure_live()
    }

    fn base_owned_protocol_view(&self) -> impl serde::Serialize + '_ {
        // This unpublished edition follows the exhaustive metadata walk exactly.
        // Legacy array/compact policy tuples remain unchanged.
        (
            "source-private.controller-policy/11",
            self.metadata_extent,
            &self.selection,
            (
                &self.coordinator.reference,
                self.coordinator.bytes.allocation_capacity(),
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(
                    self.coordinator.bytes.as_slice(),
                ),
            ),
            &self.definition,
            &self.connected,
            self.wire.protocol_view(),
            &self.capture_profile,
            self.confirmation_selection,
            &self.confirmation_definition,
            self.ack_emitter_selection,
            &self.ack_emitter_definition,
        )
    }

    fn base_compact_protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a ControllerNative5Policy);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let policy = self.0;
                let ordinary = (
                    &policy.selection,
                    (
                        &policy.coordinator.reference,
                        policy.coordinator.bytes.allocation_capacity(),
                        crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(
                            policy.coordinator.bytes.as_slice(),
                        ),
                    ),
                    &policy.definition,
                    &policy.connected,
                    policy.wire.protocol_view(),
                    &policy.capture_profile,
                );
                if let Some(emitter) = policy.ack_emitter_selection {
                    let original = (
                        "source-private.controller5-policy-canonical-ack/9",
                        ordinary,
                        &policy.confirmation_selection,
                        &policy.confirmation_definition,
                        emitter,
                        &policy.ack_emitter_definition,
                    );
                    return match policy.metadata_extent {
                        None => serde::Serialize::serialize(&original, serializer),
                        Some(extent) => serde::Serialize::serialize(
                            &(
                                "source-private.controller5-codec-metadata/10",
                                extent,
                                original,
                            ),
                            serializer,
                        ),
                    };
                }
                match policy.confirmation_selection {
                    None => serde::Serialize::serialize(&ordinary, serializer),
                    Some(selection) => serde::Serialize::serialize(
                        &(
                            "source-private.controller5-policy-confirmed/8",
                            ordinary,
                            selection,
                            &policy.confirmation_definition,
                        ),
                        serializer,
                    ),
                }
            }
        }
        View(self)
    }

    fn base_protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a ControllerNative5Policy);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let policy = self.0;
                let ordinary = (
                    &policy.selection,
                    &policy.coordinator,
                    &policy.definition,
                    &policy.connected,
                    policy.wire.protocol_view(),
                );
                if let Some(emitter) = policy.ack_emitter_selection {
                    let original = (
                        "source-private.controller5-policy-canonical-ack/9",
                        ordinary,
                        &policy.confirmation_selection,
                        &policy.confirmation_definition,
                        emitter,
                        &policy.ack_emitter_definition,
                    );
                    return match policy.metadata_extent {
                        None => serde::Serialize::serialize(&original, serializer),
                        Some(extent) => serde::Serialize::serialize(
                            &(
                                "source-private.controller5-codec-metadata/10",
                                extent,
                                original,
                            ),
                            serializer,
                        ),
                    };
                }
                match policy.confirmation_selection {
                    None => serde::Serialize::serialize(&ordinary, serializer),
                    Some(selection) => serde::Serialize::serialize(
                        &(
                            "source-private.controller5-policy-confirmed/8",
                            ordinary,
                            selection,
                            &policy.confirmation_definition,
                        ),
                        serializer,
                    ),
                }
            }
        }
        View(self)
    }
}

impl ControllerNative5Policy {
    fn owned_protocol_view(&self) -> impl serde::Serialize + '_ {
        controller_fresh_restore::ControllerFreshRestoreView {
            policy: self,
            encoding: controller_restore::Encoding::Owned,
        }
    }
    fn compact_protocol_view(&self) -> impl serde::Serialize + '_ {
        controller_fresh_restore::ControllerFreshRestoreView {
            policy: self,
            encoding: controller_restore::Encoding::Compact,
        }
    }
    fn protocol_view(&self) -> impl serde::Serialize + '_ {
        controller_fresh_restore::ControllerFreshRestoreView {
            policy: self,
            encoding: controller_restore::Encoding::Ordinary,
        }
    }
}

impl Native5CodecOwner {
    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        match self {
            Self::ControllerPacket(policy) => {
                observer.boxed_value(policy.as_ref())?;
                policy.observe_retained_metadata(observer)
            }
            Self::NativePacket(policy) => {
                observer.shared_value(policy.as_ref())?;
                policy.observe_retained_metadata(observer)
            }
        }
    }

    pub(crate) fn complete_restore_selection(
        &self,
    ) -> Option<
        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    > {
        match self {
            Self::ControllerPacket(policy) => policy.complete_restore_selection,
            Self::NativePacket(policy) => policy.complete_restore_selection(),
        }
    }

    pub(crate) fn ack_emitter_selection(
        &self,
    ) -> Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>
    {
        match self {
            Self::ControllerPacket(policy) => policy.ack_emitter_selection,
            Self::NativePacket(policy) => policy.ack_emitter_selection(),
        }
    }

    pub(crate) fn authenticate_ack_emitter_selection(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.authenticate_confirmation_selection(authority)?;
        match self {
            Self::ControllerPacket(policy) => validate_ack_emitter_selection(
                authority,
                policy.ack_emitter_selection,
                policy.ack_emitter_definition.as_ref(),
            ),
            Self::NativePacket(policy) => validate_ack_emitter_selection(
                authority,
                policy.ack_emitter_selection(),
                policy.ack_emitter_definition(),
            ),
        }
    }

    pub(crate) fn confirmation_selection(
        &self,
    ) -> Option<crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection>
    {
        match self {
            Self::ControllerPacket(policy) => policy.confirmation_selection,
            Self::NativePacket(policy) => policy.confirmation_selection(),
        }
    }

    pub(crate) fn authenticate_confirmation_selection(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        match self {
            Self::ControllerPacket(policy) => {
                policy.validate_current_negotiation(authority)?;
                policy.validate_current_confirmation(authority)
            }
            Self::NativePacket(policy) => validate_confirmation_selection(
                authority,
                policy.confirmation_selection(),
                policy.confirmation_definition(),
            ),
        }
    }

    pub(crate) fn capture_profile(
        &self,
    ) -> &crate::reference_packet::service::PacketNative5CaptureProfile {
        match self {
            Self::ControllerPacket(policy) => &policy.capture_profile,
            Self::NativePacket(policy) => policy.capture_profile(),
        }
    }

    pub(crate) fn validate_installation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        match self {
            Self::ControllerPacket(policy) => policy.validate_installation(authority),
            Self::NativePacket(policy) => policy.validate_installation(authority),
        }
    }

    /// Compares durable grammar from two actual installed controller policies.
    ///
    /// Live admissions and the full coordinator mapping are retained separately
    /// for the source factory's target-context authentication. This necessary
    /// compatibility check cannot authorize installing captured state.
    pub(crate) fn authenticate_durable_controller_grammar(
        &self,
        fresh: &Self,
    ) -> Result<(), ProviderError> {
        let (Self::ControllerPacket(original), Self::ControllerPacket(target)) = (self, fresh)
        else {
            return Err(ProviderError::Correlation(
                "fresh controller mapping requires two actual controller codecs",
            ));
        };
        if original.metadata_extent != target.metadata_extent
            || original.complete_restore_selection != target.complete_restore_selection
            || original.complete_restore_definitions != target.complete_restore_definitions
            || original.complete_restore_transfer_definitions
                != target.complete_restore_transfer_definitions
            || original.restore_input_emitter_selection != target.restore_input_emitter_selection
            || original.restore_input_emitter_definition != target.restore_input_emitter_definition
            || original.ack_emitter_selection != target.ack_emitter_selection
            || original.ack_emitter_definition != target.ack_emitter_definition
            || original.confirmation_selection != target.confirmation_selection
            || original.confirmation_definition != target.confirmation_definition
            || original.capture_profile != target.capture_profile
            || original.definition != target.definition
            || !same_durable_selection(&original.selection, &target.selection)
            || original.connected.schema != target.connected.schema
            || original.connected.participants.len() != target.connected.participants.len()
            || !original
                .connected
                .participants
                .iter()
                .zip(&target.connected.participants)
                .all(|(original, target)| same_durable_selection(original, target))
            || original.connected.host.descriptor != target.connected.host.descriptor
            || original.connected.host.binding.compatibility
                != target.connected.host.binding.compatibility
            || original.connected.host.binding.extensions
                != target.connected.host.binding.extensions
            || original.connected.host.owner != target.connected.host.owner
        {
            return Err(ProviderError::Correlation(
                "fresh native5 durable controller grammar changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn owned_protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a Native5CodecOwner);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                match self.0 {
                    Native5CodecOwner::ControllerPacket(policy) => serde::Serialize::serialize(
                        &(
                            "source-private.controller-codec/11",
                            policy.owned_protocol_view(),
                        ),
                        serializer,
                    ),
                    Native5CodecOwner::NativePacket(_) => Err(serde::ser::Error::custom(
                        "complete native bootstrap/admission owning view absent",
                    )),
                }
            }
        }
        View(self)
    }

    pub(crate) fn controller_owned_layout() -> usize {
        std::mem::size_of::<ControllerNative5Policy>()
    }

    pub(crate) fn compact_protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a Native5CodecOwner);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                match self.0 {
                    Native5CodecOwner::ControllerPacket(policy) => serde::Serialize::serialize(
                        &(
                            "controller-packet-compact/7",
                            policy.compact_protocol_view(),
                        ),
                        serializer,
                    ),
                    Native5CodecOwner::NativePacket(policy) => serde::Serialize::serialize(
                        &("native-packet-compact/7", policy.compact_protocol_view()),
                        serializer,
                    ),
                }
            }
        }
        View(self)
    }

    pub(crate) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a>(&'a Native5CodecOwner);
        impl serde::Serialize for View<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                match self.0 {
                    Native5CodecOwner::ControllerPacket(policy) => serde::Serialize::serialize(
                        &("controller-packet/5", policy.protocol_view()),
                        serializer,
                    ),
                    Native5CodecOwner::NativePacket(policy) => serde::Serialize::serialize(
                        &("native-packet/5", policy.protocol_view()),
                        serializer,
                    ),
                }
            }
        }
        View(self)
    }
}

impl BodySchemaVerifier for Native5CodecOwner {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        match self {
            Self::ControllerPacket(policy) => {
                policy.validate_current_negotiation(authority)?;
                if super::native_import18::verify_selected_wire_data(
                    &policy.selection,
                    authority,
                    envelope,
                    body,
                )? {
                    return authority.ensure_live();
                }
                if crate::reference_packet::service::restored_input_reactive17::verify_selected_wire_data(
                    &policy.selection, authority, envelope, body,
                )? {
                    return authority.ensure_live();
                }
                if crate::reference_packet::service::complete_restore::restoration_observe::verify_selected_wire_data(&policy.selection,authority,envelope,body)? {
                    return authority.ensure_live();
                }
                if crate::reference_packet::service::complete_restore::activation::verify_selected_wire_data(
                    &policy.selection, authority, envelope, body,
                )? {
                    return authority.ensure_live();
                }
                if controller_fresh_restore::verify_selected_fresh(
                    policy, authority, envelope, body,
                )? {
                    return authority.ensure_live();
                }
                if controller_restore::verify_selected_transfer(policy, authority, envelope, body)?
                {
                    return authority.ensure_live();
                }
                if controller_restore::verify_selected_restore(policy, authority, envelope, body)? {
                    return authority.ensure_live();
                }
                if let Some(proof) = envelope.extensions.get(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE) {
                    validate_ack_emitter_selection(authority, policy.ack_emitter_selection, policy.ack_emitter_definition.as_ref())?;
                    if envelope.extensions.len() != 1
                        || envelope.message != MessageKind::Request
                        || envelope.method != Method::Admit
                        || controller_node(policy) != envelope.node_id.0.as_ref()
                        || envelope.body.get("extensions").is_none_or(|value| value.as_object().is_none_or(|extensions| !extensions.is_empty()))
                        || !matches!(body, ReceivedBody::Request(request) if matches!(request.as_ref(), RequestBody::Admit(_)))
                    {
                        return Err(ProviderError::Correlation("controller assigned Admit proof scope"));
                    }
                    crate::reference_packet::service::ack_emitter::validate_proof_value(proof)?;
                    authority.ensure_live()
                } else if envelope.extensions.contains_key(crate::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION) {
                    policy.validate_current_confirmation(authority)?;
                    if controller_node(policy) != envelope.node_id.0.as_ref() {
                        return Err(ProviderError::Correlation("confirmation changed installed controller node"));
                    }
                    super::ConfirmationProjection::from_envelope(envelope)?;
                    super::confirmation_projection::validate_typed_poll(envelope, body)?;
                    authority.ensure_live()
                } else {
                    policy.wire.verify(authority, envelope, body)
                }
            }
            Self::NativePacket(policy) => policy.verify(authority, envelope, body),
        }
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn retained_native5_codec_owner(&self) -> Option<&Rc<Native5CodecOwner>> {
        self.native5_codec.as_ref()
    }

    /// Rechecks the original actor, registration and exact installed verifier Rc.
    ///
    /// Immutable policy was fully validated at one-shot installation. This
    /// borrowed check invokes no callback, hashes or serialization allocations.
    /// It proves only codec currentness, never semantic capture or adoption.
    pub(crate) fn authenticate_native5_source_codec(&self) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "native5 codec connection fenced",
            ));
        }
        self.authority.ensure_live()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 actual immutable source codec is absent",
            ))?;
        let installed: Rc<dyn BodySchemaVerifier> = codec.clone();
        if self.packet_schema
            || self.connected_packet_schema
            || !Rc::ptr_eq(&self.schemas, &installed)
        {
            return Err(ProviderError::Correlation(
                "native5 installed verifier identity changed",
            ));
        }
        self.authority.ensure_live()
    }

    pub(crate) fn retain_original_ack_emitter(
        &self,
    ) -> Result<
        (
            Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
            crate::handshake::RegistrationRead,
            Rc<Native5CodecOwner>,
        ),
        ProviderError,
    > {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "canonical ACK emitter is not original controller",
            ));
        }
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("canonical ACK codec absent"))?;
        codec.authenticate_ack_emitter_selection(&self.authority)?;
        Ok((
            self.protocol_owner.clone(),
            self.authority.original_registration_read()?,
            codec.clone(),
        ))
    }

    pub(crate) fn authenticate_original_ack_emitter(
        &self,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        registration: &crate::handshake::RegistrationRead,
        codec: &Rc<Native5CodecOwner>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if !Rc::ptr_eq(owner, &self.protocol_owner)
            || self.role != EndpointRole::Controller
            || self
                .native5_codec
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, codec))
            || !registration.same_original(&self.authority.original_registration_read()?)
        {
            return Err(ProviderError::Correlation(
                "canonical ACK original connection/registrar/codec changed",
            ));
        }
        registration.ensure_current()
    }

    /// Observes the closed emitter selection on this same installed source codec.
    ///
    /// # Errors
    /// Refuses foreign or revoked actors, changed verifier ownership or a selected
    /// emitter whose source definition and negotiated feature are absent.
    pub fn original_native5_ack_emitter_selection(
        &self,
    ) -> Result<
        Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        ProviderError,
    > {
        self.authenticate_native5_source_codec()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("canonical ACK codec absent"))?;
        let selected = codec.ack_emitter_selection();
        if selected.is_some() {
            codec.authenticate_ack_emitter_selection(&self.authority)?;
        }
        Ok(selected)
    }

    /// Observes the selection of this same actually installed immutable codec.
    ///
    /// A selected value is checked against the current negotiated feature and
    /// extension. It supplies no source ticket, Capture or restoration authority.
    ///
    /// # Errors
    /// Refuses another original actor, revoked registration, replaced codec or
    /// a selected confirmation whose negotiated installation no longer matches.
    pub fn original_native5_confirmation_selection(
        &self,
    ) -> Result<
        Option<crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection>,
        ProviderError,
    > {
        self.authenticate_native5_source_codec()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("confirmation codec absent"))?;
        let selection = codec.confirmation_selection();
        if selection.is_some() {
            codec.authenticate_confirmation_selection(&self.authority)?;
        }
        Ok(selection)
    }

    /// Borrows the profile from this same actually installed immutable codec.
    ///
    /// # Errors
    /// Refuses changed original actor, revoked registration, absent source codec
    /// or replaced verifier owner. The profile grants no Capture or adoption.
    pub fn original_native5_capture_profile(
        &self,
    ) -> Result<&crate::reference_packet::service::PacketNative5CaptureProfile, ProviderError> {
        self.authenticate_native5_source_codec()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 actual immutable source codec is absent",
            ))?;
        Ok(codec.capture_profile())
    }

    /// Installs the same source-owned native policy and its original literal bank.
    ///
    /// Only the genuine service5 factory calls this after its private launch,
    /// kernel peer and executable checks. Transport capture still grants no
    /// complete semantic/native installation or fresh restoration permission.
    pub(crate) fn install_native5_native_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        policy: Rc<Native5Policy>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation(
                "native5 native codec requires provider endpoint",
            ));
        }
        policy.validate_installation(&self.authority)?;
        if policy.ack_emitter_selection().is_some() {
            validate_ack_emitter_selection(
                &self.authority,
                policy.ack_emitter_selection(),
                policy.ack_emitter_definition(),
            )?;
        }
        if policy.confirmation_selection().is_some() {
            validate_confirmation_selection(
                &self.authority,
                policy.confirmation_selection(),
                policy.confirmation_definition(),
            )?;
        }
        self.install_original_native5_codec(bank, Native5CodecOwner::NativePacket(policy))
    }

    pub(crate) fn install_native5_controller_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "native5 controller codec requires controller endpoint",
            ));
        }
        let policy = ControllerNative5Policy::from_source_installation(
            &self.authority,
            selection,
            coordinator,
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    pub(crate) fn install_native5_controller_codec_with_profile(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "native5 profile requires controller endpoint",
            ));
        }
        let policy = ControllerNative5Policy::from_source_installation_with_profile(
            &self.authority,
            selection,
            coordinator,
            profile,
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    pub(crate) fn install_native5_controller_confirmation_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "confirmation source requires controller",
            ));
        }
        let policy = ControllerNative5Policy::from_source_confirmation_installation(
            &self.authority,
            selection,
            coordinator,
            profile,
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    pub(crate) fn install_native5_controller_ack_emitter_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "canonical ACK source requires controller",
            ));
        }
        let policy = ControllerNative5Policy::from_source_ack_emitter_installation(
            &self.authority,
            selection,
            coordinator,
            profile,
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    pub(crate) fn original_native5_codec_metadata_extent(
        &self,
    ) -> Result<Option<CanonicalAckCodecMetadataExtent>, ProviderError> {
        self.authenticate_native5_source_codec()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 actual immutable source codec is absent",
            ))?;
        match codec.as_ref() {
            Native5CodecOwner::ControllerPacket(policy) => {
                policy.validate_current_negotiation(&self.authority)?;
                Ok(policy.metadata_extent)
            }
            Native5CodecOwner::NativePacket(_) => Ok(None),
        }
    }

    pub(crate) fn install_native5_controller_ack_emitter_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "canonical ACK source requires controller",
            ));
        }
        let policy = ControllerNative5Policy::from_source_ack_emitter_with_metadata_extent(
            &self.authority,
            selection,
            coordinator,
            profile,
            Some(metadata_extent),
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    pub(crate) fn install_native5_controller_complete_restore_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "canonical ACK source requires controller",
            ));
        }
        let policy = ControllerNative5Policy::from_source_complete_restore_installation(
            &self.authority,
            selection,
            coordinator,
            profile,
            Some(metadata_extent),
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    pub(crate) fn install_native5_controller_complete_restore_transfer_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "canonical ACK source requires controller",
            ));
        }
        let policy = ControllerNative5Policy::from_source_complete_restore_transfer_installation(
            &self.authority,
            selection,
            coordinator,
            profile,
            Some(metadata_extent),
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }

    fn install_original_native5_codec(
        &mut self,
        original: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        codec: Native5CodecOwner,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if !self.guard.unused()
            || self.packet_schema
            || self.connected_packet_schema
            || self.native5_codec.is_some()
            || self.original_frames.is_some()
            || original
                .as_ref()
                .is_none_or(|bank| bank.frames().next().is_some())
        {
            return Err(ProviderError::Correlation(
                "native5 codec requires original unused source endpoint and bank",
            ));
        }
        let authority = self.authority.clone();
        authority.with_live(|| {
            codec.validate_installation(&authority)?;
            let bank = original
                .take()
                .ok_or(ProviderError::Correlation("native5 original bank absent"))?;
            let bank = Rc::new(std::cell::RefCell::new(bank));
            let codec = Rc::new(codec);
            self.schemas = codec.clone();
            self.native5_codec = Some(codec);
            self.reader.install_originals(bank.clone());
            self.original_frames = Some(bank);
            Ok(())
        })
    }
}

// Live authority, realization/admission IDs and coordinator initialization are
// deliberately not projected into compatibility. The full actual policies stay
// retained for the source's separate authenticated target-association check.
fn same_durable_selection(
    original: &PacketControlSelection,
    target: &PacketControlSelection,
) -> bool {
    original.provider == target.provider
        && original.realization.schema_version == target.realization.schema_version
        && original.realization.provider_manifest == target.realization.provider_manifest
        && original.realization.descriptors == target.realization.descriptors
        && original.realization.owners == target.realization.owners
        && original.realization.owner_bindings == target.realization.owner_bindings
        && original.realization.extensions == target.realization.extensions
        && original.realization.bindings.len() == target.realization.bindings.len()
        && original
            .realization
            .bindings
            .iter()
            .zip(&target.realization.bindings)
            .all(|(original, target)| {
                original.compatibility == target.compatibility
                    && original.extensions == target.extensions
            })
        && original.realize.configuration == target.realize.configuration
        && original.realize.requested_node_ids == target.realize.requested_node_ids
        && original.realize.resource_limits == target.realize.resource_limits
        && original.realize.extensions == target.realize.extensions
        && original.world == target.world
}

// The static definition is authenticated at construction. This fast path only
// observes the same immutable selection and current negotiated registration.
fn validate_confirmation_selection(
    authority: &ConnectionAuthority,
    selection: Option<
        crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection,
    >,
    definition: Option<&ContentRef>,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::confirmation::{
        PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE, PacketNative5ConfirmationSelection,
    };
    authority.ensure_live()?;
    if selection != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        || definition.is_none()
        || !authority
            .selected_features()
            .iter()
            .any(|feature| feature.as_str() == PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE)
        || !authority
            .envelope_extensions()
            .contains(PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE)
    {
        return Err(ProviderError::Correlation(
            "confirmation immutable selection not installed and negotiated",
        ));
    }
    authority.ensure_live()
}

fn controller_node(policy: &ControllerNative5Policy) -> Option<&Id> {
    policy
        .selection
        .realization
        .bindings
        .first()
        .map(|binding| &binding.compatibility.node_id)
}

fn validate_ack_emitter_selection(
    authority: &ConnectionAuthority,
    selected: Option<
        crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection,
    >,
    definition: Option<&ContentRef>,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::ack_emitter::{
        PACKET_NATIVE_CANONICAL_ACK_FEATURE, PacketNative5AckEmitterSelection,
    };
    authority.ensure_live()?;
    if selected != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        || definition.is_none()
        || !authority
            .selected_features()
            .iter()
            .any(|feature| feature.as_str() == PACKET_NATIVE_CANONICAL_ACK_FEATURE)
        || !authority.selected_features().iter().any(|feature| feature.as_str() == crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
        || !authority.envelope_extensions().contains(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
    {
        return Err(ProviderError::Correlation(
            "canonical ACK source mechanism not installed and negotiated",
        ));
    }
    authority.ensure_live()
}

impl Native5CodecOwner {
    pub(crate) fn original_host_initial_selection_data(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<&PacketControlSelection, ProviderError> {
        let Self::ControllerPacket(policy) = self else {
            return Err(ProviderError::Correlation(
                "initial host codec is not a controller",
            ));
        };
        policy.validate_current_negotiation(authority)?;
        if policy.ack_emitter_selection.is_none() {
            return Err(ProviderError::Correlation(
                "initial host codec has no original ACK grammar",
            ));
        }
        Ok(&policy.selection)
    }
}

pub(crate) fn original_host_initial_codec_layout_data() -> Result<usize, ProviderError> {
    use crate::retained_metadata::requested_storage::shared_header_storage_data;
    use std::mem::{align_of, size_of};
    let mut total = size_of::<ControllerNative5Policy>();
    for bytes in [
        size_of::<Native5CodecOwner>(),
        shared_header_storage_data(1, align_of::<Native5CodecOwner>())?,
        size_of::<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>(
        ),
        shared_header_storage_data(
            1,
            align_of::<
                std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
            >(),
        )?,
    ] {
        total = total
            .checked_add(bytes)
            .ok_or(ProviderError::ResourceExhausted(
                "initial host codec header",
            ))?;
    }
    Ok(total)
}

#[path = "codec_settled_history.rs"]
mod settled_history;
pub(crate) use settled_history::Native5CodecHistoricalData;

#[path = "native5_codec/native_import18.rs"]
mod native_import18;

pub use crucible_source_birth_data::profile::client::CanonicalAckCodecMetadataExtent;
