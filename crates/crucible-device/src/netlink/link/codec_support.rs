//! Exact-size and fallible-allocation support for directed-link snapshots.

use super::*;

pub(super) fn link_snapshot_configured(maximum: u64) -> usize {
    let hard = u64::try_from(HARD_LINK_SNAPSHOT_BYTES).unwrap_or(u64::MAX);
    usize::try_from(maximum.min(hard)).unwrap_or(usize::MAX)
}

pub(super) fn link_snapshot_resource(
    field: &'static str,
    current: usize,
    requested: usize,
    configured: usize,
    hard: usize,
) -> LinkSnapshotCodecError {
    LinkSnapshotCodecError::ResourceLimit {
        field,
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: u64::try_from(configured).unwrap_or(u64::MAX),
        hard: u64::try_from(hard).unwrap_or(u64::MAX),
    }
}

fn link_snapshot_add_length(
    length: &mut usize,
    requested: usize,
    configured: usize,
) -> Result<(), LinkSnapshotCodecError> {
    let total = length.checked_add(requested).ok_or_else(|| {
        link_snapshot_resource(
            "link snapshot bytes",
            *length,
            requested,
            configured,
            HARD_LINK_SNAPSHOT_BYTES,
        )
    })?;
    if total > configured || total > HARD_LINK_SNAPSHOT_BYTES {
        return Err(link_snapshot_resource(
            "link snapshot bytes",
            *length,
            requested,
            configured,
            HARD_LINK_SNAPSHOT_BYTES,
        ));
    }
    *length = total;
    Ok(())
}

fn link_snapshot_add_repeated_length(
    length: &mut usize,
    count: usize,
    item_bytes: usize,
    configured: usize,
) -> Result<(), LinkSnapshotCodecError> {
    let requested = count.checked_mul(item_bytes).ok_or_else(|| {
        link_snapshot_resource(
            "link snapshot bytes",
            *length,
            usize::MAX,
            configured,
            HARD_LINK_SNAPSHOT_BYTES,
        )
    })?;
    link_snapshot_add_length(length, requested, configured)
}

pub(super) fn link_snapshot_encoded_length(
    snapshot: &LinkSnapshot,
    maximum: u64,
) -> Result<usize, LinkSnapshotCodecError> {
    let configured = link_snapshot_configured(maximum);
    let mut length = 0;
    for fixed in [LINK_SNAPSHOT_MAGIC.len(), 8, 1, 4, 8, 8, 1, 8, 8, 8, 4] {
        link_snapshot_add_length(&mut length, fixed, configured)?;
    }
    link_snapshot_add_repeated_length(
        &mut length,
        snapshot.faults.bandwidth_bits_per_sec.len(),
        8,
        configured,
    )?;
    link_snapshot_add_length(&mut length, 16 + 4, configured)?;
    link_snapshot_add_repeated_length(
        &mut length,
        snapshot.faults.additional_loss.len(),
        16,
        configured,
    )?;
    link_snapshot_add_length(&mut length, 16 + 8 + 16 + 4, configured)?;
    for strategy in &snapshot.faults.corruption_strategies {
        let strategy_bytes = match strategy {
            LinkCorruptionStrategy::BitFlip { .. } => 1 + 4,
            LinkCorruptionStrategy::FieldMutation => 1,
            LinkCorruptionStrategy::Truncation { .. } => 1 + 8,
        };
        link_snapshot_add_length(&mut length, strategy_bytes, configured)?;
    }
    link_snapshot_add_length(&mut length, 4 + 1 + 8 + 4, configured)?;
    for pending in &snapshot.inflight {
        link_snapshot_add_length(&mut length, 8 + 4 + 4 + 4 + 1 + 4, configured)?;
        link_snapshot_add_length(&mut length, pending.response.payload.len(), configured)?;
    }
    Ok(length)
}

pub(super) fn link_snapshot_vector<T>(
    field: &'static str,
    count: usize,
) -> Result<Vec<T>, LinkSnapshotCodecError> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        link_snapshot_resource(
            field,
            0,
            count,
            HARD_LINK_SNAPSHOT_ENTRIES,
            HARD_LINK_SNAPSHOT_ENTRIES,
        )
    })?;
    Ok(values)
}
