//! Quotes the actual complete coordinator DTO and its separate validator work.
//!
//! Raw Value templates are not arrays of Control/model DTOs. The original
//! decoder and validator still run unchanged after admission; this borrowed
//! counter grants no source, allocation, native birth or currentness rights.

use super::*;

mod expanded;
mod typed_backing;
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
};
use crate::reference_packet::{
    control::PacketControlSelection,
    coordinator::{PacketConnectedHostSelection, PacketNative5CoordinatorInstallation},
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};
use crucible_node_format::*;
pub(super) use expanded::construction_storage_data;

/// Preserves original upper decode/construction accounting for shared coordinator DATA.
///
/// The immutable record owns no native authority. These original rows remain
/// upper because they observe actual retained metadata and native parser work.
pub trait PacketNative5CoordinatorConstructionStorage {
    /// Quotes retained DTO and complete temporary decode/validation demand.
    ///
    /// Returns `[retained, transient, counter_scratch]` from the actual canonical
    /// input, including potential reserved-Value reparses and subsequent typed,
    /// clone, canonical and diagnostic work. It never parses or validates the
    /// installation. The caller first admits the defining fixed counter, then
    /// independently admits all returned axes beside every still-live owner
    /// before calling the unchanged decoder. The actual local selection and its
    /// counting-serializer formatter are independently retained and funded by
    /// the caller: the decoder checks their extent before membership equality.
    /// The row grants no native rights.
    ///
    /// # Errors
    /// Refuses unsupported raw framing, zero/oversized input, arithmetic or
    /// compiled-layout failure, or complete requested demand above `maximum`.
    fn decode_construction_storage_data(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError>;

    /// Names direct decode-quote and actual retained-coordinator observer views.
    ///
    /// The caller admits this before the borrowed raw-marker scan or retained
    /// census. Input-dependent reparse controls are returned by the complete
    /// quote and admitted before decoding; neither quantity is heap permission.
    fn decode_construction_counter_scratch_data() -> usize;
}

impl PacketNative5CoordinatorConstructionStorage for PacketNative5CoordinatorInstallation {
    /// Quotes retained DTO and complete temporary decode/validation demand.
    ///
    /// Returns `[retained, transient, counter_scratch]` from the actual canonical
    /// input, including potential reserved-Value reparses and subsequent typed,
    /// clone, canonical and diagnostic work. It never parses or validates the
    /// installation. The caller first admits the defining fixed counter, then
    /// independently admits all returned axes beside every still-live owner
    /// before calling the unchanged decoder. The actual local selection and its
    /// counting-serializer formatter are independently retained and funded by
    /// the caller: the decoder checks their extent before membership equality.
    /// The row grants no native rights.
    ///
    /// # Errors
    /// Refuses unsupported raw framing, zero/oversized input, arithmetic or
    /// compiled-layout failure, or complete requested demand above `maximum`.
    fn decode_construction_storage_data(
        bytes: &[u8],
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let actual = construction_storage_data(bytes, maximum)?;
        let scratch = sum(
            &[
                Self::decode_construction_counter_scratch_data(),
                actual.additional_scratch,
            ],
            maximum,
        )?;
        sum(&[actual.retained, actual.transient, scratch], maximum)?;
        Ok([actual.retained, actual.transient, scratch])
    }

    /// Names direct decode-quote and actual retained-coordinator observer views.
    ///
    /// The caller admits this before the borrowed raw-marker scan or retained
    /// census. Input-dependent reparse controls are returned by the complete
    /// quote and admitted before decoding; neither quantity is heap permission.
    fn decode_construction_counter_scratch_data() -> usize {
        counter_scratch_data()
            + decoded::counter_scratch_data()
            + crate::retained_metadata::retained_native_coordinator_counter_scratch_data()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<&[u8]>()
            + size_of::<usize>()
    }
}

// These are the actual nested portable DTO/Vec element classes of this closed
// coordinator. Extensions are String/Value maps, not Control grant caches.
pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::launch_decode::typed_slot;

/// Prices only the real permanent DTO; the old complete validator quote is
/// separately retained as work, never multiplied as persistent DTO backing.
/// The complete raw Value row retains every opaque subtree, string and tree;
/// known typed vectors add only their actual element layouts. Unsupported raw
/// shapes retain the original conservative bound and unchanged decoder grammar.
pub(super) fn backing(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(refused());
    }
    match typed_backing::arrays(bytes, maximum) {
        Ok(arrays) => sum(
            &[
                decoded::quote(
                    bytes,
                    size_of::<serde_json::Value>(),
                    size_of::<serde_json::Value>(),
                    maximum,
                )?
                .value_backing,
                arrays,
                size_of::<PacketNative5CoordinatorInstallation>(),
                size_of::<PacketConnectedHostSelection>(),
            ],
            maximum,
        ),
        // New fields or shapes never receive a guessed smaller slot. Preserve
        // the original conservative quote and let the unchanged DTO decoder
        // determine accepted grammar after genuine construction admission.
        Err(_) => conservative_backing(bytes, maximum),
    }
}

fn conservative_backing(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    // The installation's template and host.initial_node remain Value. Only
    // participants and the four actual host DTO fields own typed Vec elements.
    // Price a complete independent Value row as well, conservatively covering
    // every opaque subtree and owned-deserializer container rebuild.
    let mut retained = decoded::quote(
        bytes,
        size_of::<serde_json::Value>(),
        size_of::<serde_json::Value>(),
        maximum,
    )?
    .value_backing;
    let mut peers = Fields::array(field(bytes, "participants")?)?;
    let mut count = 0usize;
    while let Some(peer) = peers.next_value()? {
        count = count.checked_add(1).ok_or_else(refused)?;
        retained = sum(
            &[
                retained,
                decoded::quote(
                    peer,
                    size_of::<PacketControlSelection>(),
                    typed_slot(),
                    maximum,
                )?
                .typed_backing,
            ],
            maximum,
        )?;
    }
    peers.finish()?;
    let host = field(bytes, "host")?;
    for (name, root) in [
        ("descriptor", size_of::<NodeDescriptor>()),
        ("binding", size_of::<NodeBinding>()),
        ("owner", size_of::<OwnerBinding>()),
        ("prepared_token", size_of::<Id>()),
    ] {
        retained = sum(
            &[
                retained,
                decoded::quote(field(host, name)?, root, typed_slot(), maximum)?.typed_backing,
            ],
            maximum,
        )?;
    }
    let slots = count
        .checked_mul(4)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(refused)?;
    sum(
        &[
            retained,
            slots
                .checked_mul(size_of::<PacketControlSelection>())
                .ok_or_else(refused)?,
            size_of::<PacketNative5CoordinatorInstallation>(),
            size_of::<PacketConnectedHostSelection>(),
        ],
        maximum,
    )
}

fn typed(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    super::super::super::complete_restore::transfer::selected_native_dto_decode_storage_data(
        bytes,
        typed_slot(),
        maximum,
    )
}

fn field<'a>(bytes: &'a [u8], wanted: &str) -> Result<&'a [u8], ProviderError> {
    let mut fields = Fields::object(bytes)?;
    let mut found = None;
    while let Some((key, value)) = fields.pair()? {
        if plain_string(key)? == wanted && found.replace(value).is_some() {
            return Err(refused());
        }
    }
    fields.finish()?;
    found.ok_or_else(refused)
}

fn exact_fields(bytes: &[u8], names: &[&str]) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    if names.len() > 5 {
        return Err(refused());
    }
    let mut seen = [false; 5];
    while let Some((key, _)) = fields.pair()? {
        let key = plain_string(key)?;
        let index = names
            .iter()
            .position(|name| *name == key)
            .ok_or_else(refused)?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(refused());
        }
    }
    fields.finish()?;
    if seen[..names.len()].iter().any(|seen| !seen) {
        return Err(refused());
    }
    Ok(())
}

fn identity_rows(maximum: usize) -> Result<usize, ProviderError> {
    // The real validator's preceding3-native/4-world guards establish four
    // rows BEFORE it allocates these collections. Invalid larger input DTOs are
    // still counted by their full raw occurrence scan, or refused earlier.
    let mut collections = MetadataObserver::new();
    collections.tree::<Id, ()>(4)?;
    collections.tree::<Id, ()>(4)?;
    collections.vector::<serde_json::Value>(4)?; // identities
    collections.vector::<serde_json::Value>(4)?; // owner_rows
    collections.vector::<serde_json::Value>(4)?; // conflicts
    collections.vector::<OwnerBinding>(4)?;
    collections.tree::<Id, ()>(4)?; // host_configuration domains
    collections.vector::<serde_json::Value>(4)?; // host_configuration connections
    let backing = requested_metadata_backing_storage_data(&collections.finish())?;
    let mut identity = Projection::new(maximum)?;
    identity.add_object()?;
    for (key, width) in [("owner", 128), ("incarnation", 128), ("generation", 20)] {
        identity.add_field(key)?;
        identity.add_unescaped_ascii_extent(width)?;
    }
    let identity = identity.finish(maximum)?.requested_total()?;
    let mut state = Projection::new(maximum)?;
    state.add_object()?;
    for key in ["identity", "lifecycle", "operation", "domains"] {
        state.add_field(key)?;
    }
    state.add_value(&())?;
    state.add_string("Prepared")?;
    state.add_value(&())?;
    state.add_value(&())?;
    let state = state.finish(maximum)?.requested_total()?;
    let mut conflict = Projection::new(maximum)?;
    conflict.add_array_extent(2)?;
    conflict.add_unescaped_ascii_extent(128)?;
    conflict.add_array_extent(0)?;
    let conflict = conflict.finish(maximum)?.requested_total()?;
    // Four retained identity/row/conflict populations and independent JSON
    // comparisons at the end of validate_roster. Sum their phases, rather than
    // refund any original collection when its equal comparison is generated.
    let row = sum(&[identity, identity, state, conflict], maximum)?;
    sum(
        &[
            backing,
            row,
            row,
            row,
            row,
            row,
            row,
            row,
            row,
            3 * size_of::<std::collections::BTreeSet<Id>>(),
            4 * size_of::<Vec<serde_json::Value>>(),
            size_of::<Vec<OwnerBinding>>(),
        ],
        maximum,
    )
}

fn host_configuration_storage(
    host: &[u8],
    domains: &[u8],
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut items = Fields::array(domains)?;
    let mut count = 0usize;
    while items.next_value()?.is_some() {
        count = count.checked_add(1).ok_or_else(refused)?;
    }
    items.finish()?;
    // collect over a filter is not exact-sized: preserve the complete actual
    // input cardinality and geometric backing before the later len==1 check.
    let capacity = count
        .checked_mul(2)
        .and_then(|n| n.checked_add(4))
        .ok_or_else(refused)?;
    let mut vector = MetadataObserver::new();
    vector.vector::<&Id>(capacity)?;
    let backing = requested_metadata_backing_storage_data(&vector.finish())?;
    let mut value = Projection::new(maximum)?;
    value.add_object()?;
    for key in ["schema", "definition", "domains"] {
        value.add_field(key)?;
    }
    value.add_string("source-owned.host-scheduling-complete-configuration/2")?;
    value.add_value(&())?; // actual immutable definition reference counted below
    value.add_object()?;
    for key in ["coordinator", "connections"] {
        value.add_field(key)?;
    }
    value.add_unescaped_ascii_extent(128)?;
    value.add_array_extent(4)?;
    for _ in 0..4 {
        value.add_object()?;
        for key in ["connection", "domain"] {
            value.add_field(key)?;
            value.add_unescaped_ascii_extent(128)?;
        }
    }
    sum(
        &[
            backing,
            size_of::<Vec<&Id>>(),
            value.finish(maximum)?.requested_total()?,
            decode_value(field(field(host, "descriptor")?, "model_ref")?, maximum)?,
        ],
        maximum,
    )
}

/// Quotes complete selected data and all named validator phases before parsing.
pub(super) fn quote(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    if bytes.is_empty()
        || bytes.len()
            > crate::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
    {
        return Err(refused());
    }
    let mut total = decode_value(bytes, maximum)?;
    total = sum(
        &[
            total,
            size_of::<PacketNative5CoordinatorInstallation>(),
            size_of::<PacketConnectedHostSelection>(),
        ],
        maximum,
    )?;
    exact_fields(bytes, &["schema", "participants", "host", "template"])?;
    let participants = field(bytes, "participants")?;
    let host = field(bytes, "host")?;
    let template = field(bytes, "template")?;
    exact_fields(
        host,
        &[
            "descriptor",
            "binding",
            "owner",
            "prepared_token",
            "initial_node",
        ],
    )?;
    // The complete DTO decoder retains three selections, one host and a
    // Value template. Type only the actual DTO subtrees; preserve the complete
    // Value parser/container-rebuild quote for the whole raw input above.
    let mut peers = Fields::array(participants)?;
    let mut count = 0usize;
    while let Some(peer) = peers.next_value()? {
        count = count.checked_add(1).ok_or_else(refused)?;
        total = sum(&[total, typed(peer, maximum)?], maximum)?;
        // validate_roster holds independent OwnerBinding clones and creates
        // descriptor/binding comparison Values while prior rows stay live.
        let realized = field(peer, "realization")?;
        total = sum(
            &[
                total,
                typed(field(realized, "owner_bindings")?, maximum)?,
                decode_value(field(realized, "descriptors")?, maximum)?,
                decode_value(field(realized, "bindings")?, maximum)?,
            ],
            maximum,
        )?;
        let mut owners = Fields::array(field(realized, "owners")?)?;
        while let Some(owner) = owners.next_value()? {
            total = sum(
                &[
                    total,
                    decode_value(field(owner, "state_domain_ids")?, maximum)?,
                ],
                maximum,
            )?;
        }
        owners.finish()?;
    }
    peers.finish()?;
    if count != 3 {
        return Err(refused());
    }
    // Host.initial_node remains Value-typed. Its actual descriptor, binding,
    // OwnerBinding and prepared-token fields still undergo typed decoding.
    for name in ["descriptor", "binding", "owner", "prepared_token"] {
        total = sum(&[total, typed(field(host, name)?, maximum)?], maximum)?;
    }
    let host_domains = field(field(field(host, "owner")?, "owner")?, "state_domain_ids")?;
    total = sum(
        &[
            total,
            typed(field(host, "owner")?, maximum)?,
            decode_value(field(host, "descriptor")?, maximum)?,
            decode_value(field(host, "binding")?, maximum)?,
            decode_value(host_domains, maximum)?,
            host_configuration_storage(host, host_domains, maximum)?,
        ],
        maximum,
    )?;
    // The validator clones/decodes WorldBinding, activation scalars and policy
    // values separately. World stays live through both subordinate validators.
    let world = field(template, "world")?;
    total = sum(
        &[
            total,
            typed(world, maximum)?,
            typed(field(template, "activation")?, maximum)?,
            typed(field(template, "connections")?, maximum)?,
        ],
        maximum,
    )?;
    let world_projection = decode_value(world, maximum)?;
    // world.identity before the roster plus each of the3 native row identities.
    total = sum(
        &[
            total,
            world_projection,
            world_projection,
            world_projection,
            world_projection,
        ],
        maximum,
    )?;
    let mut nodes = Fields::array(field(template, "nodes")?)?;
    let mut node_count = 0usize;
    while let Some(node) = nodes.next_value()? {
        node_count = node_count.checked_add(1).ok_or_else(refused)?;
        total = sum(
            &[total, typed(field(node, "guarantees")?, maximum)?],
            maximum,
        )?;
    }
    nodes.finish()?;
    if node_count != 4 {
        return Err(refused());
    }
    total = sum(&[total,
        typed(field(field(host, "initial_node")?, "guarantees")?, maximum)?,
        identity_rows(maximum)?,
        crate::reference_packet::continuation_contracts::complete_coordinator_contract_storage_data(maximum)?], maximum)?;
    Ok(total)
}

pub(super) fn counter_scratch_data() -> usize {
    // Actual compiled type census, raw field/array cursors, live quote totals,
    // borrowed result references and nested collection/projection observers.
    expanded::counter_scratch_data()
        + crate::reference_packet::coordinator::PacketConnectedCoordinatorInstallation::borrowed_validation_counter_scratch_data()
        + typed_backing::counter_scratch_data()
        + crate::reference_packet::coordinator::packet_native5_coordinator_installation_counter_scratch_data()
        + size_of::<[usize; 29]>()
        + size_of::<[usize; 13]>()
        + size_of::<[&[u8]; 8]>()
        + 3 * size_of::<Fields<'_>>()
        + size_of::<[u8; 128]>()
        + size_of::<[bool; 5]>()
        + size_of::<MetadataObserver<'_>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + 3 * size_of::<Projection>()
        + 4 * size_of::<OriginalSerializationStorageData>()
        + 16 * size_of::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_complete_coordinator_quote_covers_owned_decode_and_exact_boundary() -> TestResult {
        let (_, _, local, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let bytes = original.bytes.as_slice();
        let quoted = quote(bytes, usize::MAX)?;
        let decoded = PacketNative5CoordinatorInstallation::decode(bytes, &local)?;
        let facts = crate::retained_metadata::observe_retained_native_coordinator(&decoded)?;
        let owned = requested_metadata_backing_storage_data(&facts)?;
        assert!(quoted >= owned + size_of::<PacketNative5CoordinatorInstallation>());
        assert_eq!(quote(bytes, quoted)?, quoted);
        assert!(quote(bytes, quoted - 1).is_err());
        Ok(())
    }

    #[test]
    fn actual_template_world_and_topology_are_counted_as_typed_validator_inputs() -> TestResult {
        let (_, _, local, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let bytes = original.bytes.as_slice();
        let template = field(bytes, "template")?;
        let world = field(template, "world")?;
        let decoded = PacketNative5CoordinatorInstallation::decode(bytes, &local)?;
        let world_value: WorldBinding = serde_json::from_value(decoded.template["world"].clone())?;
        let mut observed = MetadataObserver::new();
        let roundtrip = serde_json::to_value(&world_value)?;
        observed.observe(&roundtrip)?;
        assert!(
            typed(world, usize::MAX)?
                >= requested_metadata_backing_storage_data(&observed.finish())?
        );
        assert!(
            quote(bytes, usize::MAX)?
                >= typed(world, usize::MAX)? + typed(field(template, "connections")?, usize::MAX)?
        );
        Ok(())
    }

    #[test]
    fn closed_coordinator_fields_refuse_duplicates_and_unknown_dto_owners() {
        assert!(
            exact_fields(
                br#"{"schema":0,"participants":[],"host":{},"template":{}}"#,
                &["schema", "participants", "host", "template"]
            )
            .is_ok()
        );
        assert!(
            exact_fields(
                br#"{"schema":0,"schema":1,"participants":[],"host":{},"template":{}}"#,
                &["schema", "participants", "host", "template"]
            )
            .is_err()
        );
        assert!(
            exact_fields(
                br#"{"schema":0,"participants":[],"host":{},"template":{},"future_owner":{}}"#,
                &["schema", "participants", "host", "template"]
            )
            .is_err()
        );
    }
}
