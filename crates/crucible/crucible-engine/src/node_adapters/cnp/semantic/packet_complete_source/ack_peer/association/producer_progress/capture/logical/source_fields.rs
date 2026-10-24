//! Checks the closed modeled Source root and unchanged immutable installation.
//!
//! ```text
//! {schema,installation,world,once,limits,first_observation,producer,
//!  current_observations,input_history,capture,inherited}
//! limits = {maximum_operations,maximum_originals,producer_used,
//!           current_observations_used,input_used}
//! ```
//!
//! The installation projection excludes the process-private FacetKind enum.
//! Complete public provider/profile/facet/capability/guarantee contracts remain
//! exact. A matching historical record issues no live capability or new budget.

use super::producer_fields::{field, object, read};
use crate::node_adapters::cnp::CnpSemanticInstallation;
use crate::node_contract::RuntimeError;
use crucible_node_format::{
    CapabilityProfile, ContentRef, FacetSelection, GuaranteeProfile, HashRef, Id, NodeBinding,
    NodeDescriptor, NodeManifest, OwnerBinding, ProviderManifest, SchemaRef, Validate, canonical,
};
use crucible_node_transport::{
    bodies::RealizeRequest,
    reference_packet::service::PacketNative5SourceLaunch,
    retained_metadata::{RetainedArchivedSourceInstallation17, observe_retained_native_launch},
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Map, Value};

pub(super) const ROOT_FIELDS: [&str; 11] = [
    "schema",
    "installation",
    "world",
    "once",
    "limits",
    "first_observation",
    "producer",
    "current_observations",
    "input_history",
    "capture",
    "inherited",
];

const INSTALLATION_FIELDS: [&str; 20] = [
    "provider",
    "profile",
    "descriptor",
    "binding",
    "capabilities",
    "exact_facet",
    "guarantees",
    "owner",
    "realize",
    "admission",
    "transaction",
    "gate",
    "admission_receipt",
    "world_binding_hash",
    "receipt_schema",
    "maximum_operations",
    "maximum_result_bytes",
    "maximum_authorization_bytes",
    "maximum_semantic_bytes",
    "launch",
];

/// Retains exact modeled lifetime counters, separately from host allocation rows.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalSourceRestoredLimits17 {
    pub(crate) maximum_operations: usize,
    pub(crate) maximum_originals: usize,
    pub(crate) producer_used: usize,
    pub(crate) current_observations_used: usize,
    pub(crate) input_used: usize,
}

/// Owns the closed archived installation without constructing a live selection.
///
/// ```text
/// {provider,profile,descriptor,binding,capabilities,exact_facet,guarantees,
///  owner,realize,admission,transaction,gate,admission_receipt,world_binding_hash,
///  receipt_schema,maximum_operations,maximum_result_bytes,
///  maximum_authorization_bytes,maximum_semantic_bytes,launch}
/// ```
///
/// The Source's authenticated native Boot and signed archive closure establish
/// its correspondence. No live Source, process, FacetKind table or admission
/// guard is reconstructed from these values. Fresh target selection is separate.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalSourceRestoredInstallation17 {
    /// Retains the archived provider declaration.
    pub(crate) provider: ProviderManifest,
    /// Retains the archived selected node profile.
    pub(crate) profile: NodeManifest,
    /// Retains complete archived roles and ports.
    pub(crate) descriptor: NodeDescriptor,
    /// Retains archived compatibility and historical authority DATA.
    pub(crate) binding: NodeBinding,
    /// Retains the full referenced capability contract.
    pub(crate) capabilities: CapabilityProfile,
    /// Retains the selected exact facet and schemas.
    pub(crate) exact_facet: FacetSelection,
    /// Retains the full referenced guarantee contract.
    pub(crate) guarantees: GuaranteeProfile,
    /// Retains complete indivisible archived ownership DATA.
    pub(crate) owner: OwnerBinding,
    /// Retains the original realization request.
    pub(crate) realize: RealizeRequest,
    /// Names the archived host admission.
    pub(crate) admission: Id,
    /// Names the archived world transaction.
    pub(crate) transaction: Id,
    /// Names the archived native gate.
    pub(crate) gate: Id,
    /// Names the archived host admission evidence.
    pub(crate) admission_receipt: ContentRef,
    /// Names the archived world binding.
    pub(crate) world_binding_hash: HashRef,
    /// Retains the selected receipt schema.
    pub(crate) receipt_schema: SchemaRef,
    /// Bounds the original lifetime semantic association count.
    pub(crate) maximum_operations: usize,
    /// Bounds the original expanded result extent.
    pub(crate) maximum_result_bytes: usize,
    /// Bounds the original authorization extent.
    pub(crate) maximum_authorization_bytes: usize,
    /// Bounds original aggregate semantic retention.
    pub(crate) maximum_semantic_bytes: usize,
    /// Retains the actual archived native launch as inert DATA.
    pub(crate) launch: PacketNative5SourceLaunch,
}

impl OriginalSourceRestoredInstallation17 {
    /// Checks exact public selection roles against this retained native launch.
    ///
    /// The owning reader separately authenticates the launch to the real sealed
    /// archived Boot and the full Source to the signed archive. These checks
    /// authenticate correspondence DATA, never a live incarnation or budget.
    ///
    /// # Errors
    /// Refuses malformed declarations, missing/duplicate native realization
    /// roles, changed identity/schema/reference bodies or inconsistent selection.
    fn authenticate_archived_selection_data(&self) -> Result<(), RuntimeError> {
        self.provider.validate().map_err(invalid)?;
        self.profile.validate().map_err(invalid)?;
        self.descriptor.validate().map_err(invalid)?;
        self.binding.validate().map_err(invalid)?;
        self.capabilities.validate().map_err(invalid)?;
        self.exact_facet.validate().map_err(invalid)?;
        self.guarantees.validate().map_err(invalid)?;
        self.owner.validate().map_err(invalid)?;
        self.realize.validate().map_err(invalid)?;
        self.receipt_schema.validate().map_err(invalid)?;
        self.world_binding_hash.validate().map_err(invalid)?;
        authenticate_original_limits_data(
            [
                self.maximum_operations,
                self.maximum_semantic_bytes,
                self.maximum_result_bytes,
                self.maximum_authorization_bytes,
            ],
            self.realize.resource_limits.maximum_operations.get(),
            self.realize.resource_limits.memory_bytes.get(),
        )?;
        let selection = &self.launch.selection;
        let compatibility = &self.binding.compatibility;
        let descriptors = selection
            .realization
            .descriptors
            .iter()
            .filter(|value| value.id == self.descriptor.id);
        let bindings = selection
            .realization
            .bindings
            .iter()
            .filter(|value| value.compatibility.node_id == self.descriptor.id);
        let owners = selection
            .realization
            .owner_bindings
            .iter()
            .filter(|value| value.owner.id == self.owner.owner.id);
        let declared_owners = selection
            .realization
            .owners
            .iter()
            .filter(|value| value.id == self.owner.owner.id);
        if self.launch.schema_version != 5
            || self.provider != selection.provider
            || self.realize != selection.realize
            || self.admission != selection.admission
            || self.transaction != selection.transaction
            || self.gate != selection.gate
            || self.admission_receipt != selection.admission_receipt
            || self.world_binding_hash != selection.world
            || !unique_exact_data(descriptors, &self.descriptor)
            || !unique_exact_data(bindings, &self.binding)
            || !unique_exact_data(owners, &self.owner)
            || !unique_exact_data(declared_owners, &self.owner.owner)
        {
            return Err(RuntimeError::InvalidReceipt);
        }

        if compatibility.node_id != self.descriptor.id
            || compatibility.descriptor_hash != self.descriptor.identity().map_err(invalid)?
            || compatibility.implementation != self.provider.implementation
            || compatibility.execution_owner != self.owner.owner
            || compatibility.capture_owner != self.owner.owner
            || self.owner.owner.participant_ids.as_slice()
                != std::slice::from_ref(&self.descriptor.id)
            || self.realize.requested_node_ids.as_slice()
                != std::slice::from_ref(&self.descriptor.id)
            || self.binding.authority.realization_id != self.realize.realization_id
        {
            return Err(RuntimeError::InvalidReceipt);
        }

        if self.profile.roles != self.descriptor.roles
            || !self.provider.supported_profiles.contains(&self.profile)
            || !self
                .provider
                .implementation
                .formats
                .contains(&self.receipt_schema)
            || self.profile.operation_facets != compatibility.operating_contract.facets
            || self.capabilities.facets != compatibility.operating_contract.facets
            || !self.capabilities.facets.contains(&self.exact_facet)
            || self.exact_facet.guarantees_ref != compatibility.guarantees_ref
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let owner_binding = self
            .owner
            .node_bindings
            .first()
            .ok_or(RuntimeError::InvalidReceipt)?;
        if self.owner.node_bindings.len() != 1
            || owner_binding.node_id != self.descriptor.id
            || owner_binding.binding_hash != self.binding.identity().map_err(invalid)?
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        verify_typed_data(&selection.realization.provider_manifest, &self.provider)?;
        verify_typed_data(&compatibility.profile_ref, &self.profile)?;
        verify_typed_data(&compatibility.capabilities_ref, &self.capabilities)?;
        verify_typed_data(&compatibility.guarantees_ref, &self.guarantees)?;
        Ok(())
    }

    /// Counts actual independently owned typed backing, excluding this inline root.
    ///
    /// # Errors
    /// Refuses finite metadata/layout exhaustion, checked overflow or the maximum.
    pub(crate) fn retained_heap_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::semantic::PacketCompleteSemanticSource;
        let Self {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            receipt_schema,
            maximum_operations: _,
            maximum_result_bytes: _,
            maximum_authorization_bytes: _,
            maximum_semantic_bytes: _,
            launch,
        } = self;
        let fields = RetainedArchivedSourceInstallation17 {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            receipt_schema,
        };
        let facts = fields.observe_retained_metadata().map_err(invalid)?;
        let installation =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts, maximum,
            )?;
        let remaining = maximum
            .checked_sub(installation)
            .ok_or(RuntimeError::ResourceLimit)?;
        let launch_facts = observe_retained_native_launch(launch).map_err(invalid)?;
        let launch =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &launch_facts,
                remaining,
            )?;
        installation
            .checked_add(launch)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Names the actual typed decode/validation and defining metadata controls.
    pub(crate) fn counter_scratch_data() -> usize {
        use crucible_node_transport::retained_metadata::retained_native_launch_counter_scratch_data;
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<RetainedArchivedSourceInstallation17<'static>>()
            + RetainedArchivedSourceInstallation17::counter_scratch_data()
            + retained_native_launch_counter_scratch_data()
            + size_of::<[&str; 20]>()
            + size_of::<HashRef>()
            + size_of::<ContentRef>()
    }
}

// These are the original live preparation bounds, not new restoration credit.
fn authenticate_original_limits_data(
    limits: [usize; 4],
    resource_operations: u64,
    resource_memory: u64,
) -> Result<(), RuntimeError> {
    let [operations, semantic, result, authorization] = limits;
    if operations == 0
        || operations > 4096
        || u64::try_from(operations).map_err(|_| RuntimeError::ResourceLimit)? > resource_operations
        || semantic == 0
        || semantic > 256 * 1024 * 1024
        || u64::try_from(semantic).map_err(|_| RuntimeError::ResourceLimit)? > resource_memory
        || result < 4096
        || result > semantic
        || authorization == 0
        || authorization > semantic
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

fn unique_exact_data<'a, T: PartialEq + 'a>(
    mut rows: impl Iterator<Item = &'a T>,
    expected: &T,
) -> bool {
    rows.next() == Some(expected) && rows.next().is_none()
}

fn verify_typed_data(reference: &ContentRef, value: &impl Serialize) -> Result<(), RuntimeError> {
    let value = serde_json::to_value(value).map_err(invalid)?;
    let bytes = canonical::canonical_json(&value).map_err(invalid)?;
    reference.verify(&bytes).map_err(invalid)
}

fn invalid<E>(_: E) -> RuntimeError {
    RuntimeError::InvalidReceipt
}

/// Borrows the genuine immutable installation's complete durable field roster.
pub(crate) struct OriginalSourceRestoredInstallationExpected17<'a>(
    pub(crate) &'a CnpSemanticInstallation,
    pub(crate) &'a PacketNative5SourceLaunch,
);

pub(super) fn root_data(history: &Value) -> Result<&Map<String, Value>, RuntimeError> {
    let root = object(history, &ROOT_FIELDS)?;
    if field(root, "schema")?.as_str() != Some("source-private.source-restored-settled-state/17") {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(root)
}

pub(super) fn installation_data(
    value: &Value,
) -> Result<OriginalSourceRestoredInstallation17, RuntimeError> {
    object(value, &INSTALLATION_FIELDS)?;
    let installation: OriginalSourceRestoredInstallation17 = read(value)?;
    installation.authenticate_archived_selection_data()?;
    Ok(installation)
}

pub(super) fn limits_data(value: &Value) -> Result<OriginalSourceRestoredLimits17, RuntimeError> {
    object(
        value,
        &[
            "maximum_operations",
            "maximum_originals",
            "producer_used",
            "current_observations_used",
            "input_used",
        ],
    )?;
    let limits: OriginalSourceRestoredLimits17 = read(value)?;
    if serde_json::to_value(&limits).map_err(|_| RuntimeError::InvalidReceipt)? != *value
        || limits.producer_used > limits.maximum_operations
        || limits.current_observations_used > limits.maximum_originals
        || limits.input_used > limits.maximum_operations
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(limits)
}

pub(super) fn empty_current_data(value: &Value) -> Result<(), RuntimeError> {
    let history = object(value, &["schema", "failed", "attempts"])?;
    if field(history, "schema")?.as_str()
        != Some("source-private.source-restored-observation-state/17")
        || field(history, "failed")?.as_bool() != Some(false)
        || !field(history, "attempts")?
            .as_array()
            .is_some_and(Vec::is_empty)
    {
        return Err(RuntimeError::OutstandingObligations);
    }
    Ok(())
}

impl Serialize for OriginalSourceRestoredInstallationExpected17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let CnpSemanticInstallation {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            facets: _,
            receipt_schema,
            maximum_operations,
            maximum_result_bytes,
            maximum_authorization_bytes,
            maximum_semantic_bytes,
        } = self.0;
        let mut value = serializer.serialize_struct("SourceRestoredInstallation17", 20)?;
        value.serialize_field("provider", provider)?;
        value.serialize_field("profile", profile)?;
        value.serialize_field("descriptor", descriptor)?;
        value.serialize_field("binding", binding)?;
        value.serialize_field("capabilities", capabilities)?;
        value.serialize_field("exact_facet", exact_facet)?;
        value.serialize_field("guarantees", guarantees)?;
        value.serialize_field("owner", owner)?;
        value.serialize_field("realize", realize)?;
        value.serialize_field("admission", admission)?;
        value.serialize_field("transaction", transaction)?;
        value.serialize_field("gate", gate)?;
        value.serialize_field("admission_receipt", admission_receipt)?;
        value.serialize_field("world_binding_hash", world_binding_hash)?;
        value.serialize_field("receipt_schema", receipt_schema)?;
        value.serialize_field("maximum_operations", maximum_operations)?;
        value.serialize_field("maximum_result_bytes", maximum_result_bytes)?;
        value.serialize_field("maximum_authorization_bytes", maximum_authorization_bytes)?;
        value.serialize_field("maximum_semantic_bytes", maximum_semantic_bytes)?;
        value.serialize_field("launch", self.1)?;
        value.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn archived_realization_role_must_be_unique_and_match_every_field() {
        let selected = (
            Id::new("node").unwrap(),
            String::from("actual archived body"),
        );
        let changed = (
            selected.0.clone(),
            String::from("same identifier different body"),
        );
        assert!(unique_exact_data(std::iter::once(&selected), &selected));
        assert!(!unique_exact_data(std::iter::empty(), &selected));
        assert!(!unique_exact_data(std::iter::once(&changed), &selected));
        assert!(!unique_exact_data(
            [&selected, &selected].into_iter(),
            &selected
        ));
    }

    #[test]
    fn original_installation_limits_preserve_live_policy_validity() {
        let valid = [3, 8192, 4096, 128];
        authenticate_original_limits_data(valid, 64, 16384).unwrap();
        for (index, value) in [
            (0, 0),
            (0, 4097),
            (0, 65),
            (1, 0),
            (1, 256 * 1024 * 1024 + 1),
            (1, 16385),
            (2, 0),
            (2, 4095),
            (2, 8193),
            (3, 0),
            (3, 8193),
        ] {
            let mut invalid = valid;
            invalid[index] = value;
            assert!(authenticate_original_limits_data(invalid, 64, 16384).is_err());
        }
    }

    #[test]
    fn modeled_limits_preserve_used_counts_and_refuse_overflow_or_extra_debits() {
        let original = json!({"maximum_operations":7,"maximum_originals":9,
            "producer_used":7,"current_observations_used":0,"input_used":0});
        let limits = limits_data(&original).unwrap();
        assert_eq!(limits.producer_used, 7);
        assert_eq!(limits.maximum_operations, 7);
        let mut extra = original.clone();
        extra["debit"] = json!({"retained":0,"transient":0,"scratch":0});
        assert!(limits_data(&extra).is_err());
        extra = original;
        extra["producer_used"] = json!(8);
        assert!(limits_data(&extra).is_err());
    }

    #[test]
    fn completed_source_does_not_reopen_old16_recurring_history() {
        let unused = json!({"schema":"source-private.source-restored-observation-state/17",
            "failed":false,"attempts":[]});
        empty_current_data(&unused).unwrap();
        let mut used = unused.clone();
        used["attempts"] = json!([{"stage":"verified"}]);
        assert!(empty_current_data(&used).is_err());
        used = unused;
        used["failed"] = json!(true);
        assert!(empty_current_data(&used).is_err());
    }
}
