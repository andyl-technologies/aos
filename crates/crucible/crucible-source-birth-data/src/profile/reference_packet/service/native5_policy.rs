//! Owns the original policy DATA, pure constructor checks and byte views.
//!
//! This record contains portable DATA only. Successful construction grants no
//! connection, native endpoint, source activation, key or capture permission.

use crate::profile::{
    ProviderError, client,
    connection::serialized_credit,
    reference_packet::{
        continuation_contracts::{PACKET_NATIVE5_IMPLEMENTATION, complete_packet_ingress_schema},
        control::PacketControlSelection,
        coordinator::PacketNative5CoordinatorInstallation,
    },
    reference_service::InstalledContent,
};
use crucible_node_format::*;
use serde::Serialize;

mod capture_metadata;
mod fresh_restore_policy;
mod restore_input_policy;
mod restore_policy;
mod restore_transfer_policy;

pub use restore_policy::Native5CompleteRestorePolicyInput;

/// Carries the original portable policy fields without live authority.
#[derive(Serialize)]
#[serde(rename = "Native5Policy")]
pub struct Native5PolicyData {
    /// Preserves the original selection field.
    pub selection: PacketControlSelection,
    /// Preserves the original coordinator field.
    pub coordinator: InstalledContent,
    /// Preserves the original definition field.
    pub definition: ContentRef,
    /// Preserves the original connected field.
    pub connected: PacketNative5CoordinatorInstallation,
    #[serde(skip_serializing_if = "super::PacketNative5CaptureProfile::is_original_arrays")]
    /// Preserves the original capture profile field.
    pub capture_profile: super::PacketNative5CaptureProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original confirmation selection field.
    pub confirmation_selection: Option<super::PacketNative5ConfirmationSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original confirmation definition field.
    pub confirmation_definition: Option<ContentRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original ack emitter selection field.
    pub ack_emitter_selection: Option<super::PacketNative5AckEmitterSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original ack emitter definition field.
    pub ack_emitter_definition: Option<ContentRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original native codec metadata extent field.
    pub native_codec_metadata_extent: Option<client::CanonicalAckCodecMetadataExtent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original protocol metadata limits field.
    pub protocol_metadata_limits: Option<super::PacketNative5ProtocolMetadataLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original complete restore selection field.
    pub complete_restore_selection:
        Option<super::complete_restore::PacketNative5CompleteRestoreSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original complete restore definitions field.
    pub complete_restore_definitions: Option<[ContentRef; 3]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original complete restore transfer definitions field.
    pub complete_restore_transfer_definitions: Option<[ContentRef; 7]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original restore input emitter selection field.
    pub restore_input_emitter_selection:
        Option<super::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original restore input emitter definition field.
    pub restore_input_emitter_definition: Option<ContentRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original capture allocation selection field.
    pub capture_allocation_selection:
        Option<super::capture_allocation::PacketNative5CaptureAllocationSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original capture allocation definitions field.
    pub capture_allocation_definitions: Option<[ContentRef; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original fresh restore allocation selection field.
    pub fresh_restore_allocation_selection:
        Option<super::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Preserves the original fresh restore allocation definitions field.
    pub fresh_restore_allocation_definitions: Option<[ContentRef; 5]>,
}

impl Native5PolicyData {
    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
    ) -> Result<Self, ProviderError> {
        Self::from_original_launch_with_profile(
            selection,
            coordinator,
            super::PacketNative5CaptureProfile::OriginalArrays6,
        )
    }

    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch_with_profile(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: super::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        let policy = Self::prepare_original_profile(selection, coordinator, capture_profile)?;
        serialized_credit(&policy.protocol_view(), 256 * 1024)?;
        policy.validate_immutable_content()?;
        Ok(policy)
    }

    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn prepare_original_profile(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: super::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        capture_profile.validate()?;
        serialized_credit(&selection, 65_536)?;
        coordinator.reference.verify(coordinator.bytes.as_slice())?;
        let connected =
            PacketNative5CoordinatorInstallation::decode(coordinator.bytes.as_slice(), &selection)?;
        let schema = complete_packet_ingress_schema()?;
        if selection.provider.implementation.implementation_id.as_str()
            != PACKET_NATIVE5_IMPLEMENTATION
            || !selection.provider.implementation.formats.contains(&schema)
        {
            return Err(ProviderError::Correlation(
                "native5 source codec not installed",
            ));
        }
        let policy = Self {
            selection,
            coordinator,
            definition: schema.definition,
            connected,
            capture_profile,
            confirmation_selection: None,
            confirmation_definition: None,
            ack_emitter_selection: None,
            ack_emitter_definition: None,
            native_codec_metadata_extent: None,
            protocol_metadata_limits: None,
            complete_restore_selection: None,
            complete_restore_definitions: None,
            complete_restore_transfer_definitions: None,
            restore_input_emitter_selection: None,
            restore_input_emitter_definition: None,
            capture_allocation_selection: None,
            capture_allocation_definitions: None,
            fresh_restore_allocation_selection: None,
            fresh_restore_allocation_definitions: None,
        };
        Ok(policy)
    }

    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch_with_confirmation(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
    ) -> Result<Self, ProviderError> {
        let mut policy = Self::from_original_launch_with_profile(selection, coordinator, profile)?;
        let schema = super::confirmation::native_after_confirmation_schema()?;
        if !policy
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        {
            return Err(ProviderError::Correlation(
                "native5 confirmation schema not installed",
            ));
        }
        policy.confirmation_selection = Some(confirmation);
        policy.confirmation_definition = Some(schema.definition);
        policy.validate_immutable_content()?;
        serialized_credit(&policy.protocol_view(), 256 * 1024)?;
        Ok(policy)
    }

    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch_with_ack_emitter(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
        emitter: super::PacketNative5AckEmitterSelection,
    ) -> Result<Self, ProviderError> {
        let mut policy = Self::from_original_launch_with_confirmation(
            selection,
            coordinator,
            profile,
            confirmation,
        )?;
        let schema = super::ack_emitter::native_canonical_blob_ack_schema()?;
        let admission_schema = super::ack_emitter::native_canonical_ack_admission_schema()?;
        if !policy
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
            || !policy
                .selection
                .provider
                .implementation
                .formats
                .contains(&admission_schema)
        {
            return Err(ProviderError::Correlation(
                "native5 canonical ACK schema not installed",
            ));
        }
        policy.ack_emitter_selection = Some(emitter);
        policy.ack_emitter_definition = Some(schema.definition);
        policy.validate_immutable_content()?;
        serialized_credit(&policy.protocol_view(), 256 * 1024)?;
        Ok(policy)
    }

    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch_with_ack_emitter_metadata_extent(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
        emitter: super::PacketNative5AckEmitterSelection,
        extent: client::CanonicalAckCodecMetadataExtent,
    ) -> Result<Self, ProviderError> {
        let mut policy = Self::prepare_original_profile(selection, coordinator, profile)?;
        let confirmation_schema = super::confirmation::native_after_confirmation_schema()?;
        let ack_schema = super::ack_emitter::native_canonical_blob_ack_schema()?;
        let admission_schema = super::ack_emitter::native_canonical_ack_admission_schema()?;
        if [
            confirmation_schema.clone(),
            ack_schema.clone(),
            admission_schema,
        ]
        .iter()
        .any(|schema| {
            !policy
                .selection
                .provider
                .implementation
                .formats
                .contains(schema)
        }) {
            return Err(ProviderError::Correlation(
                "selected native codec definition absent",
            ));
        }
        policy.confirmation_selection = Some(confirmation);
        policy.confirmation_definition = Some(confirmation_schema.definition);
        policy.ack_emitter_selection = Some(emitter);
        policy.ack_emitter_definition = Some(ack_schema.definition);
        policy.native_codec_metadata_extent = Some(extent);
        policy.validate_immutable_content()?;
        let maximum = match extent {
            client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB => 512 * 1024,
        };
        serialized_credit(&policy.protocol_view(), maximum)?;
        Ok(policy)
    }

    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn from_original_launch_with_protocol_metadata(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
        emitter: super::PacketNative5AckEmitterSelection,
        extent: client::CanonicalAckCodecMetadataExtent,
        metadata: super::PacketNative5ProtocolMetadataLimits,
    ) -> Result<Self, ProviderError> {
        metadata.validate_data()?;
        if !matches!(
            profile,
            super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            return Err(ProviderError::Correlation(
                "native metadata requires owned protocol",
            ));
        }
        let mut policy = Self::from_original_launch_with_ack_emitter_metadata_extent(
            selection,
            coordinator,
            profile,
            confirmation,
            emitter,
            extent,
        )?;
        policy.protocol_metadata_limits = Some(metadata);
        policy.validate_immutable_content()?;
        serialized_credit(&policy.protocol_view(), 512 * 1024)?;
        Ok(policy)
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    // This validates the current DATA fields. The upper service owner keeps
    // its payload private after construction; this record grants no immutability.
    pub fn validate_immutable_content(&self) -> Result<(), ProviderError> {
        self.validate_capture_allocation_content()?;
        self.validate_fresh_restore_allocation_content()?;
        self.validate_complete_restore_content()?;
        if let Some(metadata) = self.protocol_metadata_limits {
            metadata.validate_data()?;
            if !matches!(
                self.capture_profile,
                super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            ) {
                return Err(ProviderError::Correlation(
                    "native metadata source profile differs",
                ));
            }
        }
        if self.ack_emitter_selection.is_some() {
            let schema = super::ack_emitter::native_canonical_blob_ack_schema()?;
            let admission_schema = super::ack_emitter::native_canonical_ack_admission_schema()?;
            if self.confirmation_selection
                != Some(super::PacketNative5ConfirmationSelection::AfterProtocolPoll5)
                || self.ack_emitter_definition.as_ref() != Some(&schema.definition)
                || !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
                || !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&admission_schema)
            {
                return Err(ProviderError::Correlation(
                    "native5 canonical ACK definition changed",
                ));
            }
        } else if self.ack_emitter_definition.is_some() {
            return Err(ProviderError::Correlation(
                "native5 absent canonical ACK definition",
            ));
        }
        if self.confirmation_selection.is_some() {
            let schema = super::confirmation::native_after_confirmation_schema()?;
            if self.confirmation_definition.as_ref() != Some(&schema.definition)
                || !self
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&schema)
            {
                return Err(ProviderError::Correlation(
                    "native5 confirmation definition changed",
                ));
            }
        } else if self.confirmation_definition.is_some() {
            return Err(ProviderError::Correlation(
                "native5 absent confirmation definition",
            ));
        }
        self.connected.validate(&self.selection)?;
        self.coordinator
            .reference
            .verify(self.coordinator.bytes.as_slice())?;
        if self.selection.realization.bindings.len() != 1
            || self.selection.realization.owner_bindings.len() != 1
            || self.selection.realization.owners.len() != 1
            || self.selection.realization.descriptors.len() != 1
        {
            return Err(ProviderError::Correlation(
                "native5 complete local owner population",
            ));
        }
        Ok(())
    }

    /// Returns the original immutable policy DATA projection.
    pub fn protocol_view(&self) -> impl Serialize + '_ {
        fresh_restore_policy::FreshPolicyView(self)
    }

    /// Returns the original immutable policy DATA projection.
    pub fn protocol_metadata_limits(&self) -> Option<super::PacketNative5ProtocolMetadataLimits> {
        self.protocol_metadata_limits
    }

    /// Returns the original immutable policy DATA projection.
    pub fn ack_emitter_selection(&self) -> Option<super::PacketNative5AckEmitterSelection> {
        self.ack_emitter_selection
    }

    /// Returns the original immutable policy DATA projection.
    pub fn ack_emitter_definition(&self) -> Option<&ContentRef> {
        self.ack_emitter_definition.as_ref()
    }

    /// Returns the original immutable policy DATA projection.
    pub fn confirmation_selection(&self) -> Option<super::PacketNative5ConfirmationSelection> {
        self.confirmation_selection
    }

    /// Returns the original immutable policy DATA projection.
    pub fn confirmation_definition(&self) -> Option<&ContentRef> {
        self.confirmation_definition.as_ref()
    }

    /// Returns the original immutable policy DATA projection.
    pub fn capture_profile(&self) -> &super::PacketNative5CaptureProfile {
        &self.capture_profile
    }
}

struct Native5PolicyDataView<'a>(&'a Native5PolicyData);

impl Serialize for Native5PolicyDataView<'_> {
    fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        if let Some(metadata) = self.0.protocol_metadata_limits {
            return (
                "source-private.native5-policy-selected-metadata/13",
                metadata,
                self.0,
            )
                .serialize(serializer);
        }
        match self.0.native_codec_metadata_extent {
            None => self.0.serialize(serializer),
            Some(extent) => {
                ("source-private.native5-policy-metadata/12", extent, self.0).serialize(serializer)
            }
        }
    }
}
