//! Projects closed native17 receipt/hash/result work before any formatter runs.
//!
//! Actual immutable owners supply every field. These projections create no DTO,
//! canonical bank, request hash, native grant or allocation credit.

use super::*;

fn fields(out: &mut Projection, names: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for name in names {
        out.add_field(name)?;
    }
    Ok(())
}

fn decimal(out: &mut Projection, value: U64) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(value.get().checked_ilog10().unwrap_or(0) as usize + 1)
}

fn exact_reference(out: &mut Projection, value: &ContentRef) -> Result<(), ProviderError> {
    let ContentRef {
        hash,
        length,
        media_type,
    } = value;
    fields(out, &["hash", "length", "media_type"])?;
    out.add_value(hash)?;
    decimal(out, *length)?;
    out.add_string(media_type)
}

pub(super) fn original_work_data(
    original: &Envelope,
    maximum: usize,
) -> Result<NativeSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    Observation17OriginalData::Actual(original).project(&mut out)?;
    // request_hash first owns this complete DOM before removing two fields and
    // adding request_origin. Independently cover that insertion and key/string.
    out.add_field("request_origin")?;
    out.add_string("controller")?;
    let mut storage = out.finish(maximum)?;
    storage.serializer_temporary_requested_bytes = 20;
    if storage.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(storage)
}

pub(super) fn owner_binding_work_data(
    binding: &crucible_node_contract::OwnerBinding,
    maximum: usize,
) -> Result<NativeSerializationStorageData, ProviderError> {
    let crucible_node_contract::OwnerBinding {
        schema_version,
        owner,
        owner_roles,
        node_bindings,
        ownership_ref,
        extensions,
    } = binding;
    let crucible_node_contract::OwnerRef {
        id,
        participant_ids,
        state_domain_ids,
    } = owner;
    let mut out = Projection::new(maximum)?;
    fields(
        &mut out,
        &[
            "schema_version",
            "owner",
            "owner_roles",
            "node_bindings",
            "ownership_ref",
            "extensions",
        ],
    )?;
    out.add_value(schema_version)?;
    fields(&mut out, &["id", "participant_ids", "state_domain_ids"])?;
    out.add_value(id)?;
    out.add_value(participant_ids)?;
    out.add_value(state_domain_ids)?;
    out.add_value(owner_roles)?;
    out.add_array_extent(node_bindings.len())?;
    for crucible_node_contract::NodeBindingRef {
        node_id,
        binding_hash,
        extensions,
    } in node_bindings
    {
        fields(&mut out, &["node_id", "binding_hash", "extensions"])?;
        out.add_value(node_id)?;
        out.add_value(binding_hash)?;
        out.add_value(extensions)?;
    }
    exact_reference(&mut out, ownership_ref)?;
    out.add_value(extensions)?;
    let mut storage = out.finish(maximum)?;
    storage.serializer_temporary_requested_bytes = 20;
    if storage.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(storage)
}

impl PacketControl {
    pub(super) fn project_observation17_result_data(
        &self,
        out: &mut Projection,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let [owner] = self.selection.realization.owners.as_slice() else {
            return Err(refused());
        };
        let active = self.active.as_ref().ok_or_else(refused)?;
        let request_id = original.request_id.0.as_ref().ok_or_else(refused)?;
        fields(
            out,
            &[
                "observations",
                "next_sequence",
                "complete",
                "inventory_hash",
            ],
        )?;
        out.add_array_extent(1)?;
        fields(
            out,
            &[
                "schema_version",
                "execution_owner_id",
                "owner_binding_hash",
                "world_binding_hash",
                "activation_id",
                "world_generation",
                "owner_generation",
                "operation_id",
                "grant_id",
                "first_sequence",
                "last_sequence",
                "events",
                "visibility",
                "measurement_ref",
                "extensions",
            ],
        )?;
        out.add_value(&1u16)?;
        out.add_value(&owner.id)?;
        geometry::hash(out, "cnp.owner-binding.v1")?;
        out.add_value(&self.selection.world)?;
        out.add_value(&active.activation_id)?;
        decimal(out, active.world_generation)?;
        decimal(out, binding.authority.owner_generation)?;
        out.add_value(request_id)?;
        out.add_value(&Option::<()>::None)?;
        out.add_unescaped_ascii_extent(1)?;
        out.add_unescaped_ascii_extent(1)?;
        out.add_array_extent(0)?;
        out.add_value(&Visibility::Staged)?;
        geometry::json_reference(out)?;
        out.add_object()?;
        out.add_unescaped_ascii_extent(1)?;
        out.add_value(&true)?;
        geometry::hash(out, "source-owned.packet-connected-inventory/4")
    }
}
