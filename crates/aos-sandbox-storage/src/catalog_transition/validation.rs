//! Canonical physical-state ordering, uniqueness, and cross-row validation.

use std::collections::BTreeSet;

use super::*;

pub(super) fn normalize_and_validate(
    state: &mut PhysicalStateWire,
    format: PhysicalStateFormatV1,
) -> Result<(), StorageStateError> {
    state.roots.sort();
    state.datasets.sort();
    state.snapshots.sort();
    state.holds.sort();
    state.tombstones.sort();
    let expected_version = match format {
        PhysicalStateFormatV1::LegacyV1 => LEGACY_FORMAT_VERSION,
        PhysicalStateFormatV1::ExecutionV2 => EXECUTION_FORMAT_VERSION,
    };
    if state.magic != STATE_MAGIC
        || state.version != expected_version
        || state.generation == 0
        || state.roots.len() > MAXIMUM_OBJECTS
        || state.datasets.len() > MAXIMUM_OBJECTS
        || state.snapshots.len() > MAXIMUM_OBJECTS
        || state.holds.len() > MAXIMUM_HOLDS
        || state.tombstones.len() > MAXIMUM_TOMBSTONES
        || !unique(state.roots.iter().map(|row| row.dataset_prefix.as_str()))
        || !unique(state.roots.iter().map(|row| row.guid))
        || !unique(state.datasets.iter().map(|row| row.name.as_str()))
        || !unique(state.datasets.iter().map(|row| row.guid))
        || !unique(state.snapshots.iter().map(|row| row.name.as_str()))
        || !unique(state.snapshots.iter().map(|row| row.guid))
        || !unique(
            state
                .holds
                .iter()
                .map(|row| (row.snapshot_name.as_str(), row.hold_id)),
        )
        || !unique(
            state
                .tombstones
                .iter()
                .map(|row| (row.kind, row.name.as_str())),
        )
        || !unique(state.tombstones.iter().map(|row| row.guid))
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let valid_name = |name: &str| !name.is_empty() && name.len() <= MAXIMUM_NAME_BYTES;
    if state
        .roots
        .iter()
        .any(|root| root.guid == 0 || !valid_name(&root.pool) || !valid_name(&root.dataset_prefix))
        || state
            .datasets
            .iter()
            .any(|row| row.guid == 0 || !valid_name(&row.name))
        || state.snapshots.iter().any(|row| {
            row.guid == 0
                || row.source_guid == 0
                || !valid_name(&row.name)
                || !valid_name(&row.source_name)
        })
        || state.holds.iter().any(|row| {
            row.snapshot_guid == 0 || row.hold_id == [0; 16] || !valid_name(&row.snapshot_name)
        })
        || state
            .tombstones
            .iter()
            .any(|row| row.guid == 0 || row.retired_by == [0; 16] || !valid_name(&row.name))
    {
        return Err(StorageStateError::CorruptRecord);
    }
    for hold in &state.holds {
        if !state.snapshots.iter().any(|snapshot| {
            snapshot.name == hold.snapshot_name && snapshot.guid == hold.snapshot_guid
        }) {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    for dataset in &state.datasets {
        if !state.roots.iter().any(|root| root == &dataset.root) {
            return Err(StorageStateError::CorruptRecord);
        }
        if let Some(origin) = &dataset.origin
            && !state
                .snapshots
                .iter()
                .any(|snapshot| snapshot.name == origin.name && snapshot.guid == origin.guid)
        {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    for snapshot in &state.snapshots {
        if !state.datasets.iter().any(|dataset| {
            dataset.name == snapshot.source_name && dataset.guid == snapshot.source_guid
        }) {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    let live_guids = state
        .roots
        .iter()
        .map(|row| row.guid)
        .chain(state.datasets.iter().map(|row| row.guid))
        .chain(state.snapshots.iter().map(|row| row.guid));
    if !unique(live_guids)
        || state.tombstones.iter().any(|tombstone| {
            state.roots.iter().any(|row| row.guid == tombstone.guid)
                || state.datasets.iter().any(|row| row.guid == tombstone.guid)
                || state.snapshots.iter().any(|row| row.guid == tombstone.guid)
        })
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let creating_operations = state
        .datasets
        .iter()
        .filter_map(|row| row.created_by)
        .chain(state.snapshots.iter().filter_map(|row| row.created_by));
    if creating_operations
        .clone()
        .any(|operation| operation == [0; 16])
        || !unique(creating_operations)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    if state.tombstones.iter().any(|tombstone| {
        state.datasets.iter().any(|row| row.name == tombstone.name)
            || state.snapshots.iter().any(|row| row.name == tombstone.name)
    }) {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

fn unique<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}
