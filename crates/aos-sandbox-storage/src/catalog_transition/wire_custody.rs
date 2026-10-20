//! Conservative byte geometry for the existing catalog wire producers.
//!
//! These pure shapes are paid through the same genuine State context before
//! model construction. Wire models and serializer buffers keep ordinary local
//! ownership; no separate archive, parser or execution authority is created.

use super::*;

/// Describes reached model bytes and the existing logical entry bound.
pub(crate) struct CatalogWireGeometryV1 {
    pub(crate) memory: usize,
    pub(crate) metadata: usize,
}

fn overflow() -> aos_sandbox_core::AccountingError {
    aos_sandbox_core::AccountingError::ArithmeticOverflow {
        dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
    }
}

fn add(left: usize, right: usize) -> Result<usize, aos_sandbox_core::AccountingError> {
    left.checked_add(right).ok_or_else(overflow)
}

fn add_metadata(left: usize, right: usize) -> Result<usize, aos_sandbox_core::AccountingError> {
    left.checked_add(right).ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
        dimension: aos_sandbox_core::ResourceDimension::MetadataEntries,
    })
}

fn rows<T>(count: usize) -> Result<usize, aos_sandbox_core::AccountingError> {
    count.max(4).checked_mul(std::mem::size_of::<T>()).ok_or_else(overflow)
}

pub(super) fn persistent_geometry(state: &PhysicalCatalogState)
    -> Result<CatalogWireGeometryV1, aos_sandbox_core::AccountingError>
{
    let wire = &state.wire;
    let mut memory = add(std::mem::size_of::<PhysicalStateWireV1>(), wire.magic.len())?;
    // One logical entry per resident catalog row or metadata-map record.
    // DTO headers, optional bindings, fields, and temporary lookup keys create
    // no additional namespace entry; their complete bytes remain below.
    let mut metadata = 0_usize;
    memory = add(memory, rows::<RootWire>(wire.roots.len())?)?;
    for root in &wire.roots {
        memory = add(memory, add(root.pool.len(), root.dataset_prefix.len())?)?;
        metadata = add_metadata(metadata, 1)?;
    }
    memory = add(memory, rows::<DatasetWire>(wire.datasets.len())?)?;
    for dataset in &wire.datasets {
        let names = add(dataset.name.len(), add(dataset.root.pool.len(), dataset.root.dataset_prefix.len())?)?;
        memory = add(memory, add(names, dataset.origin.as_ref().map_or(0, |origin| origin.name.len()))?)?;
        metadata = add_metadata(metadata, 1)?;
    }
    memory = add(memory, rows::<SnapshotWireV1>(wire.snapshots.len())?)?;
    for snapshot in &wire.snapshots {
        memory = add(memory, add(snapshot.name.len(), snapshot.source_name.len())?)?;
        metadata = add_metadata(metadata, 1)?;
    }
    // Count the actual held metadata map once without allocating lookup keys.
    // Extra unmatched entries conservatively overcount rather than authorizing
    // any model; the ordinary semantic producer still performs its own checks.
    for record in state.snapshot_metadata.values() {
        memory = add(memory, record.record.len())?;
        metadata = add_metadata(metadata, 1)?;
    }
    memory = add(memory, rows::<HoldWire>(wire.holds.len())?)?;
    for hold in &wire.holds {
        memory = add(memory, hold.snapshot_name.len())?;
        metadata = add_metadata(metadata, 1)?;
    }
    memory = add(memory, rows::<TombstoneWire>(wire.tombstones.len())?)?;
    for tombstone in &wire.tombstones {
        memory = add(memory, tombstone.name.len())?;
        metadata = add_metadata(metadata, 1)?;
    }
    Ok(CatalogWireGeometryV1 { memory, metadata })
}

pub(super) fn transition_geometry_v1(payload: &TransitionPayload)
    -> Result<CatalogWireGeometryV1, aos_sandbox_core::AccountingError>
{
    let mut geometry = persistent_geometry(&payload.result_state)?;
    let header = std::mem::size_of::<TransitionPayloadV1>()
        .max(std::mem::size_of::<GroupTransitionPayloadV2>());
    geometry.memory = add(geometry.memory, add(header, TRANSITION_MAGIC.len())?)?;
    if let Some(group) = payload.group.as_ref() {
        geometry.memory = add(geometry.memory, rows::<u64>(group.member_guids.len())?)?;
    }
    Ok(geometry)
}

pub(super) fn reservation_geometry_v1(predecessor: &PhysicalCatalogState)
    -> Result<CatalogWireGeometryV1, aos_sandbox_core::AccountingError>
{
    let mut geometry = persistent_geometry(predecessor)?;
    let header = std::mem::size_of::<ReservationPayloadV1>()
        .max(std::mem::size_of::<GroupReservationPayloadV2>());
    geometry.memory = add(geometry.memory, add(header, RESERVATION_MAGIC.len())?)?;
    Ok(geometry)
}

pub(super) fn head_geometry_v1(payload: &HeadPayload)
    -> Result<CatalogWireGeometryV1, aos_sandbox_core::AccountingError>
{
    let mut geometry = match payload.genesis_state.as_ref() {
        Some(state) => persistent_geometry(state)?,
        None => CatalogWireGeometryV1 { memory: 0, metadata: 0 },
    };
    geometry.memory = add(geometry.memory,
        add(std::mem::size_of::<HeadPayloadV1>(), HEAD_MAGIC.len())?)?;
    Ok(geometry)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_geometry_preserves_actual_namespace_rows_without_field_fees() {
        let catalog = super::super::tests::catalog(7, "tank/aos/project/work");
        let state = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();
        let entries = state.wire.roots.len() + state.wire.datasets.len()
            + state.wire.snapshots.len() + state.wire.holds.len()
            + state.wire.tombstones.len() + state.snapshot_metadata.len();
        let geometry = persistent_geometry(&state).unwrap();

        assert!(geometry.memory > 0);
        assert!(entries > 0);
        assert_eq!(geometry.metadata, entries);
    }

    #[test]
    fn fixed_head_coordinates_create_no_namespace_entry() {
        let payload = HeadPayload {
            binding: BindingWire { generation: 7, digest: [4; 32] },
            operation_id: Some([5; 16]),
            transition_digest: Some([6; 32]),
            genesis_state: None,
        };

        let geometry = head_geometry_v1(&payload).unwrap();

        assert!(geometry.memory >= std::mem::size_of::<HeadPayloadV1>() + HEAD_MAGIC.len());
        assert_eq!(geometry.metadata, 0);
    }
}
