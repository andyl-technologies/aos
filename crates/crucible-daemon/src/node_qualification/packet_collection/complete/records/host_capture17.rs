//! Authenticates explicit Host17 capability before immutable World birth.
//!
//! Every actual native Source must select the same capture family. The original
//! two-format roster stays exact; Scope presence cannot advertise an extra codec.

use super::*;

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    crucible::node_contract::host_scheduling_restored_continuation_schema17_counter_scratch_data()
        + size_of::<[bool; 3]>()
        + size_of::<[&SchemaRef; 3]>()
        + size_of::<&crucible::node_contract::HostSchedulingSource>()
        + size_of::<&[SchemaRef]>()
        + size_of::<&[u8]>()
        + size_of::<Option<&Vec<u8>>>()
        + size_of::<Result<bool, crucible::node_contract::RuntimeError>>()
        + size_of::<Result<bool, QualificationError>>()
        + size_of::<Result<(), QualificationError>>()
}

pub(super) fn authenticate_formats_data(
    request: &PacketCompleteGraphRequest<'_>,
) -> Result<bool, QualificationError> {
    let mut selected = [false; 3];
    for (slot, source) in selected.iter_mut().zip(&request.roster.sources) {
        *slot = source
            .requires_restored_capture17_scope_data()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    }
    let selected = selected_family_data(selected)?;
    let host = request.host.selection();
    let formats = host.binding.compatibility.implementation.formats.as_slice();
    if !selected {
        // Preserve the original two-format comparison and its existing factory
        // work. No new17 schema or definition is constructed on this path.
        return Ok(formats
            == [
                crucible::node_contract::host_scheduling_complete_owner_preparation_schema()
                    .map_err(|error| QualificationError::Evidence(error.reason))?,
                crucible::node_contract::host_scheduling_complete_continuation_schema()
                    .map_err(|error| QualificationError::Evidence(error.reason))?,
            ]);
    }
    request
        .host
        .authenticate_complete_preparation_source(request.host.world())
        .map_err(|error| QualificationError::Evidence(error.reason))?;
    let [preparation, restored, original] = formats else {
        return Ok(false);
    };
    // The actual complete Source constructor already authenticated both original
    // full schemas and stores immutable selection. Its edition is authenticated
    // above; the new17 path does not regenerate those old schemas before credit.
    if preparation.id.as_str() != "source-owned.host-scheduling-complete-preparation/2"
        || preparation.version != 2
        || original.id.as_str() != "source-owned.host-scheduling-continuation/2"
        || original.version != 2
    {
        return Ok(false);
    }
    authenticate_definition_data(request.content, restored)?;
    Ok(true)
}

fn selected_family_data(selected: [bool; 3]) -> Result<bool, QualificationError> {
    if selected.iter().any(|value| *value != selected[0]) {
        return Err(refused());
    }
    Ok(selected[0])
}

#[cfg(test)]
fn expected_formats_data(selected: [bool; 3]) -> Result<Vec<SchemaRef>, QualificationError> {
    selected_family_data(selected)?;
    let mut formats = vec![
        crucible::node_contract::host_scheduling_complete_owner_preparation_schema()
            .map_err(|error| QualificationError::Evidence(error.reason))?,
        crucible::node_contract::host_scheduling_complete_continuation_schema()
            .map_err(|error| QualificationError::Evidence(error.reason))?,
    ];
    if selected[0] {
        formats.push(
            crucible::node_contract::host_scheduling_restored_continuation_schema17()
                .map_err(|error| QualificationError::Evidence(error.reason))?,
        );
    }
    // ImplementationIdentity requires lexical (schema ID, version) order.
    // The distinct /17 ID sorts before /2; appending would invalidate a binding.
    formats.sort_by(|left, right| (&left.id, left.version).cmp(&(&right.id, right.version)));
    Ok(formats)
}

fn authenticate_definition_data(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    schema: &SchemaRef,
) -> Result<(), QualificationError> {
    // This defining validator streams a fixed digest and compares borrowed
    // spelling; the compiled byte loan also creates no Vec or SchemaRef owner.
    crucible::node_contract::authenticate_host_scheduling_restored_continuation_schema17_data(
        schema,
    )
    .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    let bytes = content.get(&schema.definition).ok_or_else(refused)?;
    if bytes.as_slice()
        != crucible::node_contract::host_scheduling_restored_continuation_definition17_bytes_data()
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod controls {
    use super::*;

    #[test]
    fn exact_legacy_and_explicit_three_source_rosters_stay_distinct() {
        let old = expected_formats_data([false; 3]).unwrap();
        let new = expected_formats_data([true; 3]).unwrap();
        assert_eq!(new[0], old[0]);
        assert_eq!(new[2], old[1]);
        assert_eq!(new.len(), 3);
        assert_eq!(
            new[1].id.as_str(),
            "source-owned.host-scheduling-continuation/17"
        );
        for mask in 1..7 {
            let selected = std::array::from_fn(|index| mask & (1 << index) != 0);
            assert!(expected_formats_data(selected).is_err());
        }
    }

    #[test]
    fn advertised17_requires_the_full_exact_compiled_definition() {
        let mut content = BTreeMap::new();
        let schema =
            crucible::node_contract::host_scheduling_restored_continuation_schema17().unwrap();
        assert!(authenticate_definition_data(&content, &schema).is_err());
        content.insert(schema.definition.clone(), b"{}".to_vec());
        assert!(authenticate_definition_data(&content, &schema).is_err());
        content.insert(
            schema.definition.clone(),
            crucible::node_contract::host_scheduling_restored_continuation_definition17().unwrap(),
        );
        // Only literal metadata correspondence is checked; no source, World,
        // currentness or capture permission is created by this DATA control.
        assert!(authenticate_definition_data(&content, &schema).is_ok());
        let mut substituted = schema.clone();
        substituted.definition.length =
            crucible_node_contract::U64::new(schema.definition.length.get() + 1);
        content.insert(
            substituted.definition.clone(),
            crucible::node_contract::host_scheduling_restored_continuation_definition17_bytes_data(
            )
            .to_vec(),
        );
        assert!(authenticate_definition_data(&content, &substituted).is_err());
    }
}
