//! Constructs complete selected native actors and seals their live receipt association.
//!
//! The receipt retains a separate unchanged producer-two or reactive-four object.
//! It is issued only by the same live Control, never by a portable decoder. Neither
//! construction nor this receipt installs historical restoration associations or
//! authenticates the enclosing endpoint, client journal, archive or Host2 ticket.
//!
//! ```text
//! {schema:"source-owned.packet-receipt/5", native_pid, original,
//!  binding_hash, session, incarnation, node, owner, owner_generation,
//!  input_epoch, world, native_record}
//! ```

use super::super::{
    connected::{PacketConnectedNativeRecord, PacketConnectedProgram},
    coordinator::PacketNative5CoordinatorInstallation,
};
mod record;

pub use record::PacketNative5UnderlyingRecord;

use super::*;
use crate::{
    handshake::Limits,
    reference_packet::service::{PacketNative5CaptureProfile, PacketNative5StorageLimits},
};

/// Retains one service-selected native storage and negotiated transport tuple.
///
/// This is inert correlation data. The original service must bind it before any
/// public dispatch, after authenticating its actual connection and allocating
/// its selected banks. Neither decoding nor validation proves those allocations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5StorageSelection {
    /// Retains every selected native snapshot, literal bank and journal ceiling.
    pub storage: PacketNative5StorageLimits,
    /// Retains the actual original negotiated receiving limits.
    pub limits: Limits,
}

impl PacketNative5StorageSelection {
    /// Checks the closed selected geometry against implementation hard ceilings.
    ///
    /// # Errors
    /// Refuses unsupported, nonpositive, overflowing or incomplete data geometry.
    pub fn validate(&self) -> Result<(), ProviderError> {
        self.storage.validate(&self.limits)
    }
}

/// Retains a live complete actor's exact original native-record association.
///
/// Its referenced underlying record remains a separate complete immutable proof
/// object in the same reply. Historical record bytes and process identities are
/// preserved. Fresh-target history requires a separate authenticated adopter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5Record {
    /// Selects the live receipt dialect exclusively.
    pub schema: String,
    /// Names the actual live process issuing this receipt.
    pub native_pid: U64,
    /// Retains the exact original request under this live control owner.
    pub original: Envelope,
    /// Binds the complete independently installed original owner tuple.
    pub binding_hash: HashRef,
    /// Names this live original session without rewriting historical sessions.
    pub session: Id,
    /// Names this original actor incarnation.
    pub incarnation: Id,
    /// Names the original selected native node.
    pub node: Id,
    /// Names its independently selected execution and capture owner.
    pub owner: Id,
    /// Retains the actual selected owner generation.
    pub owner_generation: U64,
    /// Retains the actual selected live input epoch.
    pub input_epoch: Id,
    /// Retains the complete four-owner world identity.
    pub world: HashRef,
    /// Names the separate complete original producer-two or reactive-four bytes.
    pub native_record: ContentRef,
    /// Retains the original service-selected storage and negotiated limits.
    pub storage_selection: PacketNative5StorageSelection,
    /// Retains the codec edition selected at this original service birth.
    #[serde(
        default,
        skip_serializing_if = "PacketNative5CaptureProfile::is_original_arrays"
    )]
    pub capture_profile: PacketNative5CaptureProfile,
}

impl PacketControl {
    // This seam is available only to the original native service. It binds data,
    // not capture permission, and refuses renewal once dispatch has begun.
    pub(crate) fn bind_complete_original_storage(
        &mut self,
        storage: PacketNative5StorageLimits,
        limits: Limits,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 storage foreign creator",
            ));
        }
        if self.complete_coordinator.is_none()
            || self.complete_storage.is_some()
            || self.realized
            || self.admitted
            || self.staged.is_some()
            || self.active.is_some()
            || self.fenced
            || self.native_effect_attempted
            || self.current_operation.is_some()
            || !self.originals.is_empty()
            || !self.begins.is_empty()
            || !self.begin_requests.is_empty()
            || !self.content.is_empty()
            || self.content_bytes != 0
            || !self.terminals.is_empty()
        {
            return Err(ProviderError::Conflict(
                "native5 storage binding is not original unused birth",
            ));
        }
        let selected = PacketNative5StorageSelection { storage, limits };
        selected.validate()?;
        self.complete_storage = Some(selected);
        Ok(())
    }

    /// Binds the original capture profile before this complete actor's dispatch.
    ///
    /// The native service calls this after authenticating its actual connection
    /// and selected allocations. Matching profile data alone never installs a
    /// codec, proves an allocation, or grants capture and restoration.
    ///
    /// # Errors
    /// Refuses a foreign creator, unbound storage, previous profile binding,
    /// any dispatched original, or invalid finite compact bounds.
    pub fn bind_complete_original_capture_profile(
        &mut self,
        profile: PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 profile foreign creator",
            ));
        }
        if self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_capture_profile.is_some()
            || self.realized
            || self.admitted
            || self.staged.is_some()
            || self.active.is_some()
            || self.fenced
            || self.native_effect_attempted
            || self.current_operation.is_some()
            || !self.originals.is_empty()
            || !self.begins.is_empty()
            || !self.begin_requests.is_empty()
            || !self.content.is_empty()
            || self.content_bytes != 0
            || !self.terminals.is_empty()
        {
            return Err(ProviderError::Conflict(
                "native5 profile binding is not original unused birth",
            ));
        }

        profile.validate()?;
        self.complete_capture_profile = Some(profile);
        Ok(())
    }

    /// Checks this original birth's profile against an independently owned policy.
    ///
    /// The endpoint must authenticate its actual installed policy and codec
    /// before calling this data comparison. Equality does not install a codec,
    /// allocate a bank, or authenticate historical restoration associations.
    ///
    /// # Errors
    /// Refuses a foreign creator, absent complete storage/coordinator, invalid
    /// expected bounds, or a different immutable original capture profile.
    pub fn authenticate_complete_capture_profile(
        &self,
        expected: &PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 profile foreign creator",
            ));
        }
        if self.complete_coordinator.is_none() || self.complete_storage.is_none() {
            return Err(ProviderError::Correlation(
                "native5 original profile birth is absent",
            ));
        }

        expected.validate()?;
        let original = self
            .complete_capture_profile
            .as_ref()
            .unwrap_or(&PacketNative5CaptureProfile::OriginalArrays6);
        if original != expected {
            return Err(ProviderError::Correlation(
                "native5 original capture profile changed",
            ));
        }
        Ok(())
    }

    /// Constructs a complete selected producer beneath its actual unopened gate.
    ///
    /// This route retains the original producer configuration and event IDs. The
    /// distinct complete coordinator validates all three native selections and
    /// the genuine Host2 declaration. Actual source installation and preservation
    /// qualification remain independent requirements.
    ///
    /// # Errors
    /// Refuses incomplete or changed edition-five scope, a foreign configuration,
    /// an opened/advanced actor, or malformed initial native custody.
    pub fn new_complete_producer(
        selection: PacketControlSelection,
        program: PacketProgram,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Result<Self, ProviderError> {
        Self::new_complete_native(selection, NativeProgram::OutputOnly(program), coordinator)
    }

    /// Constructs a complete selected reactive actor with its original effect socket.
    ///
    /// All declared incoming routes must match the complete installed world. The
    /// underlying input grammar and complete model records remain edition four;
    /// restored historical input association is a separate source-owned route.
    ///
    /// # Errors
    /// Refuses wrong complete scope, changed routes/configuration, an opened or
    /// advanced actor, or missing genuine initial model ownership.
    pub fn new_complete_reactive(
        selection: PacketControlSelection,
        program: PacketConnectedProgram,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Result<Self, ProviderError> {
        coordinator.validate(&selection)?;
        let world: WorldBinding = serde_json::from_value(coordinator.template["world"].clone())
            .map_err(ContractError::from)?;
        let node = &selection.realization.descriptors[0].id;
        let incoming = world
            .connections
            .iter()
            .filter(|route| &route.consumer.node_id == node);
        let mut count = 0usize;
        for route in incoming {
            count += 1;
            if !program.definition().connections.iter().any(|native| {
                route.id == native.id
                    && route.policy_ref == native.policy
                    && route.producer == native.producer
                    && route.consumer == native.consumer
                    && route.minimum_latency_ps == native.delay_ps
            }) {
                return Err(ProviderError::Correlation(
                    "native5 original reactive routes changed",
                ));
            }
        }
        if count != program.definition().connections.len() {
            return Err(ProviderError::Correlation(
                "native5 original reactive route population",
            ));
        }
        let inventory = program.inventory()?;
        if !inventory.reactions.is_empty()
            || !inventory.delivered_inputs.is_empty()
            || !inventory.publications.is_empty()
            || !inventory.retained_outputs.is_empty()
        {
            return Err(ProviderError::Correlation(
                "native5 boot contains prior input history",
            ));
        }
        Self::new_complete_native(selection, NativeProgram::Connected(program), coordinator)
    }

    fn new_complete_native(
        selection: PacketControlSelection,
        program: NativeProgram,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Result<Self, ProviderError> {
        coordinator.validate(&selection)?;
        let inventory = program.inventory()?;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if inventory.reached != zero
            || !inventory.gate_closed
            || inventory.private_mutations.get() != 0
            || inventory.packet_effects.get() != 0
            || !inventory.retained_outputs.is_empty()
        {
            return Err(ProviderError::Correlation(
                "native5 constructor requires unopened boot state",
            ));
        }
        let mut control = Self::new_native(selection, program)?;
        control.immediate = true;
        control.complete_coordinator = Some(coordinator);
        Ok(control)
    }

    pub(super) fn retain_complete_record(
        &mut self,
        request: &Envelope,
        native_record: ContentRef,
    ) -> Result<(ContentRef, Vec<u8>), ProviderError> {
        // No owner, model or retained bytes are read in an inherited process.
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 receipt foreign creator",
            ));
        }
        let installed = self
            .complete_coordinator
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 receipt lacks complete original installation",
            ))?;
        installed.validate(&self.selection)?;
        let bytes = self
            .content
            .get(&native_record)
            .ok_or(ProviderError::Correlation(
                "native5 underlying original bytes absent",
            ))?;
        native_record.verify(bytes)?;
        let current = U64::new(u64::from(std::process::id()));
        let (pid, original) = if self.program.is_connected() {
            let record: PacketConnectedNativeRecord = decode_record(bytes)?;
            if record.schema != "source-owned.packet-native/4" {
                return Err(ProviderError::Correlation(
                    "native5 underlying reactive dialect",
                ));
            }
            (record.native_pid, record.original)
        } else {
            let record: PacketNativeRecord = decode_record(bytes)?;
            if record.schema != "source-owned.packet-native/2" {
                return Err(ProviderError::Correlation(
                    "native5 underlying producer dialect",
                ));
            }
            (record.native_pid, record.original)
        };
        if pid != current || original != *request {
            return Err(ProviderError::Correlation(
                "native5 underlying live original differs",
            ));
        }
        let binding = &self.selection.realization.bindings[0];
        let receipt = PacketNative5Record {
            schema: "source-owned.packet-receipt/5".into(),
            native_pid: current,
            original: request.clone(),
            binding_hash: self.selection.realization.owner_bindings[0].identity()?,
            session: binding.authority.session_id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            node: binding.compatibility.node_id.clone(),
            owner: binding.compatibility.capture_owner.id.clone(),
            owner_generation: binding.authority.owner_generation,
            input_epoch: binding.authority.input_epoch.clone(),
            world: self.selection.world.clone(),
            native_record,
            capture_profile: self.complete_capture_profile.clone().unwrap_or_default(),
            storage_selection: self
                .complete_storage
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native5 original storage birth is unbound",
                ))?
                .clone(),
        };
        let bytes = encode(&receipt)?;
        let root = reference(&bytes)?;
        self.install_content(root.clone(), &bytes)?;
        Ok((root, bytes))
    }

    pub(super) fn record_evidence(
        &self,
        proof: (ContentRef, Vec<u8>),
    ) -> Result<Vec<(ContentRef, Vec<u8>)>, ProviderError> {
        if self.complete_coordinator.is_none() {
            return Ok(vec![proof]);
        }
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 evidence foreign creator",
            ));
        }
        let receipt: PacketNative5Record = decode_record(&proof.1)?;
        proof.0.verify(&proof.1)?;
        let raw = self
            .content
            .get(&receipt.native_record)
            .ok_or(ProviderError::Correlation(
                "native5 reply lost underlying original record",
            ))?;
        // Charge both complete retained copies before their allocation.
        crate::connection::serialized_credit(&(proof.1.as_slice(), raw.as_slice()), CONTENT_BYTES)?;
        let mut evidence = Vec::new();
        evidence
            .try_reserve_exact(2)
            .map_err(|_| ProviderError::ResourceExhausted("native5 proof slots"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(raw.len())
            .map_err(|_| ProviderError::ResourceExhausted("native5 original proof bytes"))?;
        bytes.extend_from_slice(raw);
        evidence.push((receipt.native_record, bytes));
        evidence.push(proof);
        Ok(evidence)
    }
}

// These complete source records deliberately implement no capability-bearing
// Validate trait. Canonical decoding checks structure; the same-owner producer
// above independently checks the raw original and installed live association.
fn decode_record<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProviderError> {
    let value = canonical::parse_json(bytes, FRAME)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Correlation(
            "native5 record canonical bytes changed",
        ));
    }
    Ok(serde_json::from_value(value).map_err(ContractError::from)?)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod capture_tests;
