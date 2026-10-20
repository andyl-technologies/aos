//! Canonical physical-state ordering, uniqueness, and cross-row validation.

use std::collections::BTreeSet;

use super::*;

pub(super) fn normalize_and_validate(
    state: &mut PhysicalStateWire,
) -> Result<(), StorageStateError> {
    state.roots.sort();
    state.datasets.sort();
    state.snapshots.sort();
    state.holds.sort();
    state.tombstones.sort();
    if state.magic != STATE_MAGIC
        || state.version != FORMAT_VERSION
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

// The same borrowed validator serves ordinary and selected preparation. These
// byte shapes cover its temporary trees and stable-sort work before entry;
// none of those scratch keys becomes a resident namespace entry.
pub(super) fn atomic_uniqueness_bytes_v1(
    source: &PhysicalStateWire,
    program: &crate::DormantAtomicDatasetSnapshotV1,
) -> Result<usize, aos_sandbox_core::AccountingError> {
    let extra_keys = program.member_count().checked_mul(4).ok_or_else(memory_overflow)?;
    uniqueness_bytes_v1(source, extra_keys)
}

pub(super) fn catalog_uniqueness_bytes_v1(
    source: &PhysicalStateWire,
    catalog: &ResolvedCatalogCommitmentV1,
) -> Result<usize, aos_sandbox_core::AccountingError> {
    // Preparation uses allow_seed=false: existing inputs are compared, and
    // only the actual postcondition can add the following rows/keys.
    let extra_keys = match catalog.plan() {
        CatalogPlanV1::CreateWorkspace { .. }
        | CatalogPlanV1::Clone { .. }
        | CatalogPlanV1::Snapshot { .. } => 4,
        CatalogPlanV1::HoldSnapshot { .. } => 1,
        CatalogPlanV1::DestroyDataset { .. }
        | CatalogPlanV1::DestroySnapshot { .. } => 2,
        CatalogPlanV1::ReleaseHold { .. } | CatalogPlanV1::SetQuota { .. } => 0,
    };
    uniqueness_bytes_v1(source, extra_keys)
}

pub(super) fn capture_uniqueness_bytes_v3(source: &PhysicalStateWire)
    -> Result<usize, aos_sandbox_core::AccountingError>
{
    // The dedicated dataset adds name/GUID/live-GUID/creator-operation keys
    // to the same eleven borrowed uniqueness scans; no new namespace exists.
    uniqueness_bytes_v1(source, 4)
}

fn memory_overflow() -> aos_sandbox_core::AccountingError {
    aos_sandbox_core::AccountingError::ArithmeticOverflow {
        dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
    }
}

fn uniqueness_bytes_v1(
    source: &PhysicalStateWire,
    extra_keys: usize,
) -> Result<usize, aos_sandbox_core::AccountingError> {
    // Count every key in all eleven scans, although their trees are consumed
    // sequentially. Names stay borrowed from the already-paid input graph.
    let keys = source.roots.len().checked_mul(3)
        .zip(source.datasets.len().checked_mul(4))
        .and_then(|(roots, datasets)| roots.checked_add(datasets))
        .zip(source.snapshots.len().checked_mul(4))
        .and_then(|(prior, snapshots)| prior.checked_add(snapshots))
        .and_then(|prior| prior.checked_add(source.holds.len()))
        .zip(source.tombstones.len().checked_mul(2))
        .and_then(|(prior, tombstones)| prior.checked_add(tombstones))
        .and_then(|prior| prior.checked_add(extra_keys))
        .ok_or_else(memory_overflow)?;
    // This is the largest actual borrowed key: (&str, hold_id). It also
    // bounds &str, GUID, operation ID and (object kind, &str) keys.
    let nodes = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
        (&str, [u8; 16]), (),
    >(keys).ok_or_else(memory_overflow)?;
    let headers = 11_usize.checked_mul(std::mem::size_of::<BTreeSet<(&str, [u8; 16])>>())
        .ok_or_else(memory_overflow)?;

    // Stable sorting can allocate a temporary row array. Sum the complete
    // row arrays, then double the bound; only one sort runs at a time. New
    // postcondition keys each cover a complete largest-row scratch operand.
    let rows = [
        (source.roots.len(), std::mem::size_of::<RootWire>()),
        (source.datasets.len(), std::mem::size_of::<DatasetWire>()),
        (source.snapshots.len(), std::mem::size_of::<SnapshotWire>()),
        (source.holds.len(), std::mem::size_of::<HoldWire>()),
        (source.tombstones.len(), std::mem::size_of::<TombstoneWire>()),
    ];
    let largest = rows.iter().map(|(_, width)| *width).max().unwrap_or(0);
    let scratch = rows.iter().try_fold(0_usize, |bytes, (count, width)| {
        count.checked_mul(*width).and_then(|row| bytes.checked_add(row))
    }).and_then(|bytes| {
        extra_keys.checked_mul(largest).and_then(|extra| bytes.checked_add(extra))
    }).and_then(|bytes| bytes.checked_mul(2)).ok_or_else(memory_overflow)?;
    nodes.checked_add(headers)
        .and_then(|bytes| bytes.checked_add(scratch))
        .ok_or_else(memory_overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> PhysicalCatalogState {
        let catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap()
    }

    #[test]
    fn borrowed_validator_keeps_canonical_order_and_first_duplicate_error() {
        let source = source();
        let mut state = source.wire.clone();
        state.datasets.reverse();
        state.roots.reverse();

        normalize_and_validate(&mut state).unwrap();

        assert_eq!(state, source.wire);
        state.roots.push(state.roots[0].clone());
        // A later invalid name does not change the existing first error.
        state.datasets[0].name.clear();
        assert!(matches!(normalize_and_validate(&mut state),
            Err(StorageStateError::CorruptRecord)));
        assert_eq!(state.roots.len(), source.wire.roots.len() + 1);
    }

    #[test]
    fn borrowed_scratch_bound_depends_on_rows_and_not_name_heap_copies() {
        let source = source();
        let bytes = uniqueness_bytes_v1(&source.wire, 0).unwrap();
        let mut longer = source.wire.clone();
        longer.roots[0].dataset_prefix.push_str("/longer-name");

        assert!(bytes > 0);
        assert_eq!(uniqueness_bytes_v1(&longer, 0).unwrap(), bytes);
        assert!(uniqueness_bytes_v1(&source.wire, 4).unwrap() > bytes);
        assert!(matches!(uniqueness_bytes_v1(&source.wire, usize::MAX),
            Err(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            })));
    }
}
