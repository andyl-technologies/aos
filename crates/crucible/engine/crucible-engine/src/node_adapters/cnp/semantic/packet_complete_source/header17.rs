//! Preserves every outer Source selection and once fence in its actual edition.
//!
//! This header is one component of the complete Source17 graph. In particular,
//! an unbound outer Option and a bound empty selection have different histories:
//!
//! ```text
//! unbound = null; bound-empty = {"value":null}; selected = {"value":selection}
//! ```
//!
//! No scalar, historical declaration, or selection in this header issues a live
//! Source/Window claim or substitutes for the actual independently funded row.

use super::*;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRows,
};
use serde::{
    Serialize, Serializer,
    ser::{SerializeStruct, SerializeTuple},
};
use std::{cell::RefCell, mem::size_of};

pub(super) struct SourceHeader17<'a> {
    source: &'a PacketCompleteSemanticSource,
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    cells: [bool; 4],
}

impl PacketCompleteSemanticSource {
    /// Borrows the exact passive header under the same real Source read.
    ///
    /// # Errors
    /// Refuses a different creating process/thread. The actual Capture caller
    /// independently authenticates its SourceRead, SDK, supervisor and Window.
    pub(super) fn borrowed_settled17_header_data<'a>(
        &'a self,
        aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> Result<SourceHeader17<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_derivation_mechanism.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(SourceHeader17 {
            source: self,
            aliases,
            cells: header_cells_data(self),
        })
    }

    /// Counts actual header capacity rows without allocating an output bank.
    ///
    /// # Errors
    /// Refuses origin, unsupported field traversal, or checked row overflow.
    pub(super) fn settled17_header_metadata_demand_data(
        &self,
    ) -> Result<(usize, usize), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let mut total = (0usize, 0usize);
        if let Some((first, second)) = &self.ack_birth_input_banks {
            for demand in [
                OriginalRestoredOwnerCapacityRows(first).metadata_demand_data()?,
                OriginalRestoredOwnerCapacityRows(second).metadata_demand_data()?,
            ] {
                total.0 = total
                    .0
                    .checked_add(demand.0)
                    .ok_or(RuntimeError::ResourceLimit)?;
                total.1 = total
                    .1
                    .checked_add(demand.1)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(total)
    }

    /// Returns the independently live defining U64 decimal String bound.
    pub(super) const fn settled17_header_serialization_temporary_data() -> usize {
        20
    }

    /// Names fixed header/projection and checked serialization views.
    pub(super) fn settled17_header_counter_scratch_data() -> usize {
        template18::MECHANISM_GATE_CONTROLS
            + size_of::<SourceHeader17<'static>>()
            + size_of::<&Option<Box<ack_peer::NativeImport18BirthConstruction>>>()
            + size_of::<&SourceHeader17<'static>>()
            + size_of::<BoundSelection17<'static, ()>>()
            + size_of::<BirthBanks17<'static>>()
            + size_of::<Policy17<'static>>()
            + size_of::<[bool; 4]>() * 2
            + size_of::<Option<usize>>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

struct BoundSelection17<'a, T>(&'a Option<Option<T>>);

impl<T: Serialize> Serialize for BoundSelection17<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            None => serializer.serialize_none(),
            Some(value) => {
                let mut fields = serializer.serialize_struct("BoundSourceSelection17", 1)?;
                fields.serialize_field("value", value)?;
                fields.end()
            }
        }
    }
}

struct BirthBanks17<'a> {
    banks: &'a Option<(Vec<u8>, Vec<u8>)>,
    aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl Serialize for BirthBanks17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Some((first, second)) = self.banks else {
            return serializer.serialize_none();
        };
        let mut fields = serializer.serialize_tuple(2)?;
        fields.serialize_element(
            &OriginalRestoredOwnerCapacityRows(first).with_aliases(self.aliases),
        )?;
        fields.serialize_element(
            &OriginalRestoredOwnerCapacityRows(second).with_aliases(self.aliases),
        )?;
        fields.end()
    }
}

struct Policy17<'a>(&'a Option<invocation_snapshot::CoordinatorPolicy17>);

impl Serialize for Policy17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            None => serializer.serialize_none(),
            Some(invocation_snapshot::CoordinatorPolicy17::Attempted) => {
                let mut fields = serializer.serialize_struct("SourceCoordinatorPolicy17", 1)?;
                fields.serialize_field("kind", "attempted")?;
                fields.end()
            }
            Some(invocation_snapshot::CoordinatorPolicy17::Bound { maximum_records }) => {
                let mut fields = serializer.serialize_struct("SourceCoordinatorPolicy17", 2)?;
                fields.serialize_field("kind", "bound")?;
                fields.serialize_field("maximum_records", maximum_records)?;
                fields.end()
            }
        }
    }
}

impl Serialize for SourceHeader17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        self.source
            .storage_origin_with_error::<RuntimeError>()
            .map_err(S::Error::custom)?;
        if header_cells_data(self.source) != self.cells {
            return Err(S::Error::custom("Source header cell changed"));
        }
        if self.source.native_import18_derivation_mechanism.is_some()
            || self.source.native_import18_birth_construction.is_some()
            || self.source.native_import18_derivation.is_some()
            || self.source.native_import18_phase_bank_attempted.get()
            || self.source.native_import18_declaration.is_some()
            || self.source.original_coordinator_policy18.is_some()
        {
            return Err(S::Error::custom(
                "import18 Source requires its distinct history envelope",
            ));
        }
        let PacketCompleteSemanticSource {
            original,
            process: _,
            thread: _,
            capture_banks: _,
            capture_execution: _,
            preconstruction: _,
            effect_receiver: _,
            ack_emitter_selection,
            ack_peer_birth: _,
            ack_birth_attempted,
            native_import18_birth_construction: _,
            native_import18_derivation: _,
            native_import18_derivation_mechanism: _,
            ack_peer_association: _,
            restored_suffix_attempted: _,
            ack_codec_metadata_extent,
            native_ack_codec_metadata_extent,
            ack_birth_input_banks,
            complete_restore_selection,
            restore_input_emitter_selection,
            protocol_metadata_limits,
            capture_allocation_selection,
            fresh_restore_allocation_selection,
            original_extension_registry: _,
            registry_capture: _,
            registry_retention_attempted: _,
            registry_retention_failed: _,
            complete_bytes_launch_reserved: _,
            native_import18_declaration: _,
            native_import18_phase_bank_attempted: _,
            native_import18_phase_bank: _,
            native_import18_bank_attempted: _,
            native_import18_bank_reservation: _,
            native_import18_recipe: _,
            invocation_snapshot_declaration: _,
            original_coordinator_policy17,
            original_coordinator_policy18: _,
        } = self.source;
        let mut fields = serializer.serialize_struct("SourceOuterHeader17", 19)?;
        fields.serialize_field("schema", "source-private.source-restored-settled-header/17")?;
        fields.serialize_field("creator_role", "same-process-thread-retained-source")?;
        fields.serialize_field(
            "model",
            match original {
                CompletePacketOriginal::Producer(_) => "producer",
                CompletePacketOriginal::Reactive(_) => "reactive",
            },
        )?;
        fields.serialize_field("ack_birth_attempted", ack_birth_attempted)?;
        fields.serialize_field("restored_suffix_attempted", &self.cells[0])?;
        fields.serialize_field("registry_retention_attempted", &self.cells[1])?;
        fields.serialize_field("registry_retention_failed", &self.cells[2])?;
        fields.serialize_field("complete_bytes_launch_reserved", &self.cells[3])?;
        fields.serialize_field(
            "ack_emitter_selection",
            &BoundSelection17(ack_emitter_selection),
        )?;
        fields.serialize_field("ack_codec_metadata_extent", ack_codec_metadata_extent)?;
        fields.serialize_field(
            "native_ack_codec_metadata_extent",
            native_ack_codec_metadata_extent,
        )?;
        fields.serialize_field("ack_birth_input_banks", ack_birth_input_banks)?;
        fields.serialize_field(
            "ack_birth_input_banks_capacities",
            &BirthBanks17 {
                banks: ack_birth_input_banks,
                aliases: self.aliases,
            },
        )?;
        fields.serialize_field(
            "complete_restore_selection",
            &BoundSelection17(complete_restore_selection),
        )?;
        fields.serialize_field(
            "restore_input_emitter_selection",
            &BoundSelection17(restore_input_emitter_selection),
        )?;
        fields.serialize_field("protocol_metadata_limits", protocol_metadata_limits)?;
        fields.serialize_field(
            "capture_allocation_selection",
            &BoundSelection17(capture_allocation_selection),
        )?;
        fields.serialize_field(
            "fresh_restore_allocation_selection",
            &BoundSelection17(fresh_restore_allocation_selection),
        )?;
        fields.serialize_field(
            "coordinator_policy17",
            &Policy17(original_coordinator_policy17),
        )?;
        if header_cells_data(self.source) != self.cells {
            return Err(S::Error::custom("Source header cell changed"));
        }
        fields.end()
    }
}

fn header_cells_data(source: &PacketCompleteSemanticSource) -> [bool; 4] {
    [
        source.restored_suffix_attempted.get(),
        source.registry_retention_attempted.get(),
        source.registry_retention_failed.get(),
        source.complete_bytes_launch_reserved.get(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_binding_preserves_all_three_original_once_states() {
        let unbound: Option<Option<bool>> = None;
        let bound_empty = Some(None::<bool>);
        let selected = Some(Some(true));
        let values = [
            serde_json::to_value(BoundSelection17(&unbound)).unwrap(),
            serde_json::to_value(BoundSelection17(&bound_empty)).unwrap(),
            serde_json::to_value(BoundSelection17(&selected)).unwrap(),
        ];
        assert_eq!(values[0], serde_json::Value::Null);
        assert_eq!(values[1], serde_json::json!({"value":null}));
        assert_eq!(values[2], serde_json::json!({"value":true}));
    }
}

/// Checks the complete passive header grammar without constructing live state.
///
/// The parent separately authenticates the signed body, exact Source/model
/// installation, full alias graph, coordinator policy and actual current owner.
/// Numeric historical capacities never substitute for its new decoder budget.
///
/// # Errors
/// Refuses an unknown/missing field, collapsed outer binding, wrong model or
/// family, inconsistent actual byte-bank capacity rows, or unequal policy.
pub(super) fn validate_header17_data(
    value: &serde_json::Value,
    expected_model: PacketCompleteSourceRole,
    maximum_coordinator_records: usize,
) -> Result<(), RuntimeError> {
    use crucible_node_transport::{
        client::CanonicalAckCodecMetadataExtent,
        reference_packet::service::{
            PacketNative5AckEmitterSelection,
            capture_allocation::PacketNative5CaptureAllocationSelection,
            complete_restore::{
                PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            },
            fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        },
    };
    let fields = closed_object(
        value,
        &[
            "schema",
            "creator_role",
            "model",
            "ack_birth_attempted",
            "restored_suffix_attempted",
            "registry_retention_attempted",
            "registry_retention_failed",
            "complete_bytes_launch_reserved",
            "ack_emitter_selection",
            "ack_codec_metadata_extent",
            "native_ack_codec_metadata_extent",
            "ack_birth_input_banks",
            "ack_birth_input_banks_capacities",
            "complete_restore_selection",
            "restore_input_emitter_selection",
            "protocol_metadata_limits",
            "capture_allocation_selection",
            "fresh_restore_allocation_selection",
            "coordinator_policy17",
        ],
    )?;
    let model = match expected_model {
        PacketCompleteSourceRole::Producer => "producer",
        PacketCompleteSourceRole::Reactive => "reactive",
    };
    if fields["schema"].as_str() != Some("source-private.source-restored-settled-header/17")
        || fields["creator_role"].as_str() != Some("same-process-thread-retained-source")
        || fields["model"].as_str() != Some(model)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for name in [
        "ack_birth_attempted",
        "restored_suffix_attempted",
        "registry_retention_attempted",
        "registry_retention_failed",
        "complete_bytes_launch_reserved",
    ] {
        let _: bool = typed_data(&fields[name])?;
    }
    bound_selection_data::<PacketNative5AckEmitterSelection>(&fields["ack_emitter_selection"])?;
    bound_selection_data::<PacketNative5CompleteRestoreSelection>(
        &fields["complete_restore_selection"],
    )?;
    bound_selection_data::<PacketNative5RestoreInputEmitterSelection>(
        &fields["restore_input_emitter_selection"],
    )?;
    bound_selection_data::<PacketNative5CaptureAllocationSelection>(
        &fields["capture_allocation_selection"],
    )?;
    bound_selection_data::<PacketNative5FreshRestoreAllocationSelection>(
        &fields["fresh_restore_allocation_selection"],
    )?;
    let _: Option<CanonicalAckCodecMetadataExtent> =
        typed_data(&fields["ack_codec_metadata_extent"])?;
    let _: Option<CanonicalAckCodecMetadataExtent> =
        typed_data(&fields["native_ack_codec_metadata_extent"])?;
    let _: Option<
        crucible_node_transport::reference_packet::service::PacketNative5ProtocolMetadataLimits,
    > = typed_data(&fields["protocol_metadata_limits"])?;
    let policy = closed_object(
        &fields["coordinator_policy17"],
        &["kind", "maximum_records"],
    )?;
    if policy["kind"].as_str() != Some("bound")
        || typed_data::<usize>(&policy["maximum_records"])? != maximum_coordinator_records
        || maximum_coordinator_records < 2
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let banks = &fields["ack_birth_input_banks"];
    let capacities = &fields["ack_birth_input_banks_capacities"];
    if banks.is_null() {
        return if capacities.is_null() {
            Ok(())
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    }
    let banks = banks
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(RuntimeError::InvalidReceipt)?;
    let capacities = capacities
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(RuntimeError::InvalidReceipt)?;
    for (bank, rows) in banks.iter().zip(capacities) {
        let bank = bank.as_array().ok_or(RuntimeError::InvalidReceipt)?;
        for byte in bank {
            if byte.as_u64().is_none_or(|n| n > 255) {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        let rows = rows
            .as_array()
            .filter(|rows| rows.len() == 1)
            .ok_or(RuntimeError::InvalidReceipt)?;
        let row = closed_object(
            &rows[0],
            &[
                "kind",
                "length",
                "capacity",
                "element_bytes",
                "alignment",
                "shared_group",
            ],
        )?;
        if row["kind"].as_str() != Some("vector")
            || typed_data::<usize>(&row["length"])? != bank.len()
            || typed_data::<usize>(&row["capacity"])? < bank.len()
            || typed_data::<usize>(&row["element_bytes"])? != std::mem::size_of::<u8>()
            || typed_data::<usize>(&row["alignment"])? != std::mem::align_of::<u8>()
            || !row["shared_group"].is_null()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

fn bound_selection_data<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<(), RuntimeError> {
    if value.is_null() {
        return Ok(());
    }
    let fields = closed_object(value, &["value"])?;
    let _: Option<T> = typed_data(&fields["value"])?;
    Ok(())
}

fn typed_data<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<T, RuntimeError> {
    serde::Deserialize::deserialize(value).map_err(|_| RuntimeError::InvalidReceipt)
}

fn closed_object<'a>(
    value: &'a serde_json::Value,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, RuntimeError> {
    let object = value.as_object().ok_or(RuntimeError::InvalidReceipt)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(object)
}
