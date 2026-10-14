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
