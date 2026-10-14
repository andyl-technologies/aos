//! Retains the installed immutable source-five codec and its complete private view.
//!
//! This closed enum holds actual typed source policies rather than serializing
//! caller callbacks. Installation selects transport grammar only; complete source,
//! semantic, process and restoration custody remain independent conjunctions.

use super::*;
use crate::reference_packet::{
    Native5Policy, continuation_contracts as contracts, control::PacketControlSelection,
    coordinator::PacketNative5CoordinatorInstallation,
};
use crate::reference_service::InstalledContent;
use crucible_node_contract::*;

pub(crate) enum Native5CodecOwner {
    ControllerPacket(Box<ControllerNative5Policy>),
    NativePacket(Rc<Native5Policy>),
}

pub(crate) struct ControllerNative5Policy {
    selection: PacketControlSelection,
    coordinator: InstalledContent,
    definition: ContentRef,
    connected: PacketNative5CoordinatorInstallation,
    wire: packet_schema::ConnectedPacketSchema,
}

impl ControllerNative5Policy {
    pub(crate) fn from_source_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
    ) -> Result<Self, ProviderError> {
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
            selection,
            coordinator,
            definition: schema.definition,
            connected,
            wire,
        };
        original.validate_installation(authority)?;
        serialized_credit(&original.protocol_view(), 256 * 1024)?;
        Ok(original)
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
        authority.ensure_live()
    }

    fn protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            &self.selection,
            &self.coordinator,
            &self.definition,
            &self.connected,
            self.wire.protocol_view(),
        )
    }
}

impl Native5CodecOwner {
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
        if original.definition != target.definition
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
                policy.wire.verify(authority, envelope, body)
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
