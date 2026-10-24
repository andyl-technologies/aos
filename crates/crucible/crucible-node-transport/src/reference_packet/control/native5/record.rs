//! Checks complete live receipt data against an independently authenticated original.
//!
//! The caller supplies the PID and request from its actual private source guard
//! and original controller journal. Decoding this data never authenticates that
//! caller, creates a capture ticket, or admits historical restored records.

use super::*;

/// Contains the unchanged typed record beneath a checked live receipt.
///
/// These owned records are inert data. Original source currentness, the private
/// child/controller association and any installed preservation authority remain
/// mandatory independent checks.
pub enum PacketNative5UnderlyingRecord {
    /// Contains the complete unchanged producer-two record.
    Producer(Box<PacketNativeRecord>),
    /// Contains the complete unchanged reactive-four record.
    Reactive(Box<PacketConnectedNativeRecord>),
}

impl PacketNative5Record {
    /// Checks the exact live tuple and complete underlying original record bytes.
    ///
    /// `expected_pid` and `original` must come from the caller's independently
    /// authenticated child and original controller journal. This method checks
    /// their complete correlation; it grants no authority from matching data.
    /// Historical captured records require the separate fresh-adopter mechanism
    /// and cannot satisfy this live check by rewriting their original identities.
    ///
    /// # Errors
    /// Refuses a foreign dialect, changed full owner/request tuple, wrong typed
    /// content reference, noncanonical or oversized bytes, or a native grant
    /// whose operation/inventory differs from its complete original record.
    pub fn verify_original_record_data(
        &self,
        selection: &PacketControlSelection,
        expected_pid: u32,
        original: &Envelope,
        bytes: &[u8],
    ) -> Result<PacketNative5UnderlyingRecord, ProviderError> {
        self.storage_selection.validate()?;
        self.capture_profile.validate()?;
        if let Some(limits) = self.protocol_metadata_limits {
            limits.validate_data()?;
        }
        if matches!(
            self.capture_profile,
            super::super::super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) != self.protocol_metadata_limits.is_some()
        {
            return Err(ProviderError::Correlation(
                "native5 metadata limits differ from owning profile",
            ));
        }

        match (
            self.protocol_metadata_limits,
            self.protocol_metadata_birth_facts,
        ) {
            (Some(limits), Some(facts)) => facts.validate_data(&limits)?,
            (None, None) => {}
            _ => {
                return Err(ProviderError::Correlation(
                    "native5 metadata birth facts are incomplete",
                ));
            }
        }
        if let Some(restoration) = self.complete_restore_selection {
            use crate::reference_packet::service::complete_restore::complete_restore_selected_schemas;
            if self.protocol_metadata_limits.is_none() || self.ack_emitter_selection.is_none()
                || self.confirmation_selection.is_none()
                || !matches!(self.capture_profile, crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            {
                return Err(ProviderError::Correlation("native5 complete restore receipt selection is incomplete"));
            }
            for schema in complete_restore_selected_schemas(restoration)? {
                if !selection.provider.implementation.formats.contains(&schema)
                    || !selection.realization.bindings.iter().all(|binding| {
                        binding
                            .compatibility
                            .implementation
                            .formats
                            .contains(&schema)
                    })
                {
                    return Err(ProviderError::Correlation(
                        "native5 complete restore receipt schema differs",
                    ));
                }
            }
        }
        if self.restore_input_emitter_selection.is_some() {
            use crate::reference_packet::service::complete_restore::{
                PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5CompleteRestoreSelection,
                canonical_restore_inputs_schema,
            };
            let schema = canonical_restore_inputs_schema()?;
            if self.complete_restore_selection
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || !selection.provider.implementation.formats.contains(&schema)
                || !selection.realization.bindings.iter().all(|binding| {
                    binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&schema)
                })
                || !selection
                    .provider
                    .extensions_supported
                    .iter()
                    .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
            {
                return Err(ProviderError::Correlation(
                    "native5 restore input emitter receipt differs",
                ));
            }
        }
        selection.provider.validate()?;
        selection.realization.validate()?;
        original.validate()?;
        let binding = selection
            .realization
            .bindings
            .first()
            .ok_or(ProviderError::Correlation("native5 live binding absent"))?;
        let owner = selection
            .realization
            .owner_bindings
            .first()
            .ok_or(ProviderError::Correlation("native5 live owner absent"))?;
        let descriptor = selection
            .realization
            .descriptors
            .first()
            .ok_or(ProviderError::Correlation("native5 live descriptor absent"))?;
        if self.schema != "source-owned.packet-receipt/5"
            || expected_pid == 0
            || self.native_pid.get() != u64::from(expected_pid)
            || selection.provider.implementation.implementation_id.as_str()
                != "source-owned.packet-native/5"
            || selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || selection.realization.descriptors.len() != 1
            || self.original != *original
            || self.binding_hash != owner.identity()?
            || self.session != binding.authority.session_id
            || self.incarnation != binding.authority.incarnation_id
            || self.node != binding.compatibility.node_id
            || self.owner != binding.compatibility.capture_owner.id
            || binding.compatibility.execution_owner != binding.compatibility.capture_owner
            || self.owner_generation != binding.authority.owner_generation
            || self.input_epoch != binding.authority.input_epoch
            || self.world != selection.world
            || original.session_id.0.as_ref() != Some(&self.session)
            || original.incarnation_id.0.as_ref() != Some(&self.incarnation)
            || original
                .node_id
                .0
                .as_ref()
                .is_some_and(|node| node != &self.node)
            || original
                .execution_owner_id
                .0
                .as_ref()
                .is_some_and(|owner| owner != &self.owner)
            || original
                .capture_owner_id
                .0
                .as_ref()
                .is_some_and(|owner| owner != &self.owner)
            || bytes.len() > FRAME
        {
            return Err(ProviderError::Correlation(
                "native5 complete live receipt tuple changed",
            ));
        }
        self.native_record.verify(bytes)?;
        if reference(bytes)? != self.native_record {
            return Err(ProviderError::Correlation(
                "native5 underlying full content role changed",
            ));
        }
        let reactive = descriptor.ports.iter().any(|port| {
            port.lanes
                .iter()
                .any(|lane| lane.direction == Direction::Input)
        });
        if reactive {
            let record: PacketConnectedNativeRecord = decode_record(bytes)?;
            if record.schema != "source-owned.packet-native/4"
                || record.native_pid != self.native_pid
                || record.original != *original
                || record.grant.as_ref().is_some_and(|grant| {
                    original.operation_id.0.as_ref() != Some(&grant.operation)
                        || grant.inventory != record.inventory
                })
            {
                return Err(ProviderError::Correlation(
                    "native5 complete reactive original changed",
                ));
            }
            Ok(PacketNative5UnderlyingRecord::Reactive(Box::new(record)))
        } else {
            let record: PacketNativeRecord = decode_record(bytes)?;
            if record.schema != "source-owned.packet-native/2"
                || record.native_pid != self.native_pid
                || record.original != *original
                || record.grant.as_ref().is_some_and(|grant| {
                    original.operation_id.0.as_ref() != Some(&grant.operation)
                        || grant.inventory != record.inventory
                })
            {
                return Err(ProviderError::Correlation(
                    "native5 complete producer original changed",
                ));
            }
            Ok(PacketNative5UnderlyingRecord::Producer(Box::new(record)))
        }
    }
}
