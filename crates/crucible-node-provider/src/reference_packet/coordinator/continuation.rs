//! Validates the distinct complete three-native plus Host2 coordinator grammar.
//!
//! Portable fields authenticate only canonical static membership. The actual
//! Source5 installer must additionally join the original native source guards,
//! concrete Host2 source, whole archive issuer and fresh restoration tickets.
//! An edition-four tuple is never normalized into a complete continuation.
//!
//! ```text
//! {"schema":"source-owned.packet-complete-coordinator-installation/5",
//!  "participants":[{...},{...},{...}],"host":{...},"template":{...}}
//! ```

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    PACKET_CONNECTED_COORDINATOR_BYTES, PacketConnectedHostSelection,
    connected::{CoordinatorEdition, CoordinatorView},
    refused,
};
use crate::{
    ProviderError,
    bodies::ActivateRequest,
    reference_packet::{continuation_contracts as contracts, control::PacketControlSelection},
};

/// Bounds the complete immutable installation independently of its Control template.
///
/// The installation contains three independently bounded native selections, one
/// Host selection and one template. Its extra full schema rosters are private
/// startup data, not a single socket frame or a larger Control content object.
/// The exact wrapper extent accounts for its fixed schema/keys and separators.
/// Connected edition four and all published template limits remain unchanged.
pub const PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES: usize = 4 * super::LIMIT
    + PACKET_CONNECTED_COORDINATOR_BYTES
    + b"{\"schema\":\"source-owned.packet-complete-coordinator-installation/5\",\"participants\":["
        .len()
    + 2
    + b"],\"host\":".len()
    + b",\"template\":".len()
    + 1;

/// Names fixed borrowed views of the complete installation extent checks.
pub fn packet_native5_coordinator_installation_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&super::connected::CoordinatorView<'static>>()
        + size_of::<&[PacketControlSelection]>()
        + size_of::<std::slice::Iter<'static, PacketControlSelection>>()
        + size_of::<&PacketControlSelection>()
        + size_of::<&PacketConnectedHostSelection>()
        + size_of::<&Value>()
        + 2 * size_of::<usize>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

/// Retains the distinct complete continuation's original four-owner static roster.
///
/// This closed data type supplies neither a capture ticket nor restored native
/// authority. The separately installed complete source/factory remain mandatory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5CoordinatorInstallation {
    /// Selects the complete coordinator installation schema, edition five.
    pub schema: String,
    /// Retains all three independently selected complete native participants.
    pub participants: Vec<PacketControlSelection>,
    /// Retains the independently selected concrete complete Host2 source tuple.
    pub host: PacketConnectedHostSelection,
    /// Retains the complete initial template without predicted preparation rows.
    pub template: Value,
}

impl PacketNative5CoordinatorInstallation {
    /// Decodes bounded canonical complete source scope without issuing authority.
    ///
    /// # Errors
    /// Refuses malformed, oversized, noncanonical or foreign complete scope.
    pub fn decode(bytes: &[u8], local: &PacketControlSelection) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused());
        }
        let installed: Self = serde_json::from_value(value).map_err(ContractError::from)?;
        installed.validate(local)?;
        Ok(installed)
    }

    /// Checks complete static membership and independently selected codec contracts.
    ///
    /// # Errors
    /// Refuses incomplete, changed, unsupported or earlier-edition source scope.
    pub fn validate(&self, local: &PacketControlSelection) -> Result<(), ProviderError> {
        self.view().validate(local)
    }

    /// Checks an exact empty-preparation template against this installed original.
    ///
    /// # Errors
    /// Refuses oversize, changed or unsupported static scope or template bytes.
    pub fn validate_template(&self, template: &Value) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(template, PACKET_CONNECTED_COORDINATOR_BYTES)?;
        let local = self.participants.first().ok_or_else(refused)?;
        self.validate(local)?;
        if template != &self.template {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the full static body and finite complete preparation roster.
    ///
    /// Native/host preparation authenticity remains the original issuer's duty.
    ///
    /// # Errors
    /// Refuses noncanonical, changed or incomplete portable preparation bodies.
    pub fn validate_body(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        let local = self.participants.first().ok_or_else(refused)?;
        self.validate(local)?;
        self.view().validate_body(bytes)
    }

    /// Joins all portable preparations to the same original local staged receipt.
    ///
    /// # Errors
    /// Refuses changed static scope, a foreign Arm or mismatched activation.
    pub fn authenticate_staged(
        &self,
        bytes: &[u8],
        local: &PacketControlSelection,
        staged: &ActivateRequest,
        ready: &ContentRef,
        manifest: &ActivationManifest,
    ) -> Result<(), ProviderError> {
        self.view()
            .authenticate_staged(bytes, local, staged, ready, manifest)
    }

    fn view(&self) -> CoordinatorView<'_> {
        CoordinatorView {
            schema: &self.schema,
            participants: &self.participants,
            host: &self.host,
            template: &self.template,
            edition: CoordinatorEdition::CompleteFive,
        }
    }
}

pub(super) fn validate_native(
    peer: &PacketControlSelection,
    initial: &Value,
) -> Result<(), ProviderError> {
    let descriptor = &peer.realization.descriptors[0];
    let binding = &peer.realization.bindings[0].compatibility;
    let implementation = &binding.implementation;
    let configuration = &binding.configuration_ref;
    let guarantees = &binding.guarantees_ref;
    let facets = &binding.operating_contract.facets;
    let expected_facets = [
        "source-owned.packet-exact/5",
        contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
    ];
    // Facet tables are canonical ID order, independently of runtime FacetKind.
    let mut expected_facets = expected_facets;
    expected_facets.sort();
    let profile = peer
        .provider
        .supported_profiles
        .first()
        .ok_or_else(refused)?;
    let receipt = contracts::complete_packet_receipt_schema()?;
    let continuation = contracts::complete_packet_continuation_schema()?;
    let ingress = contracts::complete_packet_ingress_schema()?;
    let configuration_id = match descriptor.ports.iter().any(|port| {
        port.lanes
            .iter()
            .any(|lane| lane.direction == Direction::Input)
    }) {
        true => ("source-owned.packet-connected-program/4", 4),
        false => ("source-owned.packet-program/1", 1),
    };
    if implementation.implementation_id.as_str() != contracts::PACKET_NATIVE5_IMPLEMENTATION
        || peer.provider.implementation != *implementation
        || peer.provider.supported_profiles.len() != 1
        || profile.profile_id.as_str() != contracts::PACKET_COMPLETE_LINEAGE_PROFILE
        || profile.roles != descriptor.roles
        || descriptor.roles.iter().map(Id::as_str).collect::<Vec<_>>() != ["external_device"]
        || descriptor.model_ref != *configuration
        || descriptor.configuration_ref != *configuration
        || descriptor.initialization_ref != *configuration
        || peer.realize.configuration != *configuration
        || canonical::content_ref(
            &canonical::canonical_json(&json!(profile))?,
            "application/json",
        )? != binding.profile_ref
        || profile.configuration_schema.id.as_str() != configuration_id.0
        || profile.configuration_schema.version != configuration_id.1
        || profile.configuration_schema.definition != receipt.definition
        || !profile.configuration_schema.extensions.is_empty()
        || !profile.state_formats.contains(&continuation)
        || profile.operation_facets != *facets
        || binding.operating_contract.mode != OperatingMode::Exact
        || binding.operating_contract.ordering_profile != "superdense-v1"
        || binding.execution_owner != binding.capture_owner
        || facets.len() != expected_facets.len()
        || facets.iter().zip(expected_facets).any(|(facet, name)| {
            facet.id.as_str() != name
                || facet.version != 5
                || facet.configuration_ref != *configuration
                || facet.guarantees_ref != *guarantees
                || !facet.extensions.is_empty()
        })
        || [&receipt, &continuation, &ingress]
            .iter()
            .any(|schema| !implementation.formats.contains(schema))
        || [
            contracts::PACKET_COMPLETE_LINEAGE_FEATURE,
            super::super::input::PACKET_INPUT_FEATURE,
        ]
        .iter()
        .any(|name| {
            !peer
                .provider
                .extensions_supported
                .iter()
                .any(|feature| feature.as_str() == *name)
        })
    {
        return Err(refused());
    }
    validate_guarantees(&initial["guarantees"])
}

pub(super) fn validate_host(
    host: &PacketConnectedHostSelection,
    template: &Value,
) -> Result<(), ProviderError> {
    let descriptor = &host.descriptor;
    let binding = &host.binding.compatibility;
    let definition = contracts::complete_host_definition()?;
    let configuration = host_configuration(host, template)?;
    let continuation = contracts::complete_host_continuation_schema()?;
    let preparation = SchemaRef {
        id: Id::new("source-owned.host-scheduling-complete-preparation/2")?,
        version: 2,
        definition: definition.clone(),
        extensions: Default::default(),
    };
    let facets = &binding.operating_contract.facets;
    if descriptor.roles.iter().map(Id::as_str).collect::<Vec<_>>() != ["coordinator-state"]
        || descriptor.model_ref != definition
        || binding.profile_ref != definition
        || descriptor.configuration_ref != configuration
        || descriptor.configuration_ref != descriptor.initialization_ref
        || binding.configuration_ref != descriptor.configuration_ref
        || binding.execution_owner != binding.capture_owner
        || binding.implementation.implementation_id.as_str()
            != "source-owned.host-scheduling-owner/2"
        || binding.operating_contract.mode != OperatingMode::Exact
        || binding.operating_contract.scheduling_role != SchedulingRole::EventDriven
        || host
            .owner
            .owner_roles
            .iter()
            .map(Id::as_str)
            .collect::<Vec<_>>()
            != ["capture", "execution"]
        || host.initial_node["facets"] != json!(["preservation"])
        || host.initial_node["native_thread_custody"] != json!("owner-thread")
        || host.initial_node["effective_repeatability"] != json!(Repeatability::Unqualified)
        || facets.len() != 1
        || facets[0].id.as_str() != "source-owned.host-scheduling-original-lineage/2"
        || facets[0].version != 2
        || facets[0].configuration_ref != binding.configuration_ref
        || facets[0].guarantees_ref != binding.guarantees_ref
        || !facets[0].extensions.is_empty()
        || !binding.implementation.formats.contains(&continuation)
        || !binding.implementation.formats.contains(&preparation)
    {
        return Err(refused());
    }
    validate_guarantees(&host.initial_node["guarantees"])
}

// Domain roles come from complete declared connection policies, never ID labels.
fn host_configuration(
    host: &PacketConnectedHostSelection,
    template: &Value,
) -> Result<ContentRef, ProviderError> {
    let rows = template["connections"].as_array().ok_or_else(refused)?;
    if rows.is_empty() || rows.len() > 4 {
        return Err(refused());
    }
    let mut domains = std::collections::BTreeSet::new();
    let mut connections = Vec::new();
    for row in rows {
        let pair = row
            .as_array()
            .filter(|pair| pair.len() == 2)
            .ok_or_else(refused)?;
        let connection: Id =
            serde_json::from_value(pair[0].clone()).map_err(ContractError::from)?;
        connection.validate()?;
        let selected: Vec<Id> = serde_json::from_value(pair[1]["state_domain_ids"].clone())
            .map_err(ContractError::from)?;
        if selected.len() != 1
            || !domains.insert(selected[0].clone())
            || !host.owner.owner.state_domain_ids.contains(&selected[0])
        {
            return Err(refused());
        }
        selected[0].validate()?;
        connections.push(json!({"connection":connection,"domain":selected[0]}));
    }
    let coordinator = host
        .owner
        .owner
        .state_domain_ids
        .iter()
        .filter(|domain| !domains.contains(*domain))
        .collect::<Vec<_>>();
    if coordinator.len() != 1 {
        return Err(refused());
    }
    let value = json!({"schema":"source-owned.host-scheduling-complete-configuration/2",
        "definition":contracts::complete_host_definition()?,
        "domains":{"coordinator":coordinator[0],"connections":connections}});
    Ok(canonical::content_ref(
        &canonical::canonical_json(&value)?,
        "application/json",
    )?)
}

fn validate_guarantees(value: &Value) -> Result<(), ProviderError> {
    let guarantees: GuaranteeProfile =
        serde_json::from_value(value.clone()).map_err(ContractError::from)?;
    guarantees.validate()?;
    if guarantees.repeatability != Repeatability::Unqualified
        || guarantees.capture_scope != CaptureScope::CompleteModel
        || guarantees.continuation != Continuation::Exact
        || !guarantees.durable_restart
        || guarantees.isolated_fork
        || guarantees.conditional_replay
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn original_native5_controller_scope() -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    tests::original_native5_controller_scope()
}

#[cfg(test)]
pub(crate) fn original_canonical_ack_controller_scope() -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    tests::original_canonical_ack_controller_scope()
}

#[cfg(test)]
pub(crate) fn original_canonical_ack_controller_scope_with_identity_suffix(
    suffix: Option<&str>,
) -> (
    crate::handshake::Handshake,
    crate::handshake::ConnectionAuthority,
    PacketControlSelection,
    crate::reference_service::InstalledContent,
) {
    tests::original_canonical_ack_controller_scope_with_identity_suffix(suffix)
}


/// Names concrete native/Host validation views reached by CoordinatorView.
///
/// This supplements installation extent controls. Typed field partials, JSON
/// adapters, canonical/hash work and owned backing remain separately admitted.
pub(super) fn validation_counter_scratch_data() -> usize {
    use std::collections::BTreeSet;
    use std::mem::{size_of, size_of_val};

    // This is the exact function-item iterator used by role comparisons;
    // obtaining its layout does not require an installed participant or DTO.
    let roles: &[Id] = &[];
    let mapped_roles = roles.iter().map(Id::as_str);

    type ExpectedFacets = [&'static str; 2];
    type FacetPairs = std::iter::Zip<
        std::slice::Iter<'static, FacetSelection>,
        std::array::IntoIter<&'static str, 2>,
    >;

    // validate_native owns the literal roster and a mutable copy for sorting,
    // then consumes that actual copy while zipping the selected facets.
    size_of::<ExpectedFacets>()
        + size_of::<ExpectedFacets>()
        + size_of::<&mut [&str]>()
        + size_of::<std::array::IntoIter<&str, 2>>()
        + size_of::<FacetPairs>()
        + size_of::<[&SchemaRef; 3]>()
        + size_of::<std::slice::Iter<'static, &'static SchemaRef>>()
        + size_of::<[&str; 2]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of_val(&mapped_roles)
        + size_of::<&[Id]>()
        + size_of::<Vec<&str>>()
        + size_of::<&NodeDescriptor>()
        + size_of::<&BindingCompatibility>()
        + size_of::<&ImplementationIdentity>()
        + size_of::<&NodeManifest>()
        + size_of::<&Vec<FacetSelection>>()
        + size_of::<(&str, Version)>()
        + size_of::<ContentRef>()
        + size_of::<SchemaRef>()
        + size_of::<Result<ContentRef, ProviderError>>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<GuaranteeProfile>()
        + size_of::<Result<GuaranteeProfile, serde_json::Error>>()
        + size_of::<BTreeSet<Id>>()
        + size_of::<Vec<Value>>()
        + size_of::<Vec<&Id>>()
        + size_of::<Value>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<Vec<Id>>()
        + size_of::<Result<Vec<Id>, serde_json::Error>>()
        + size_of::<Result<Id, serde_json::Error>>()
        + size_of::<Result<(), ProviderError>>()
}
