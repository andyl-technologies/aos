//! Configuration validation and mapped-view construction.

use super::*;

pub(super) fn validate_config(
    config: &QemuQuantumShmemConfig,
) -> Result<(), QemuMappedQuantumShmemHotPathError> {
    if config.shift_bits >= 64 {
        return Err(QemuMappedQuantumShmemHotPathError::Quantum {
            source: QemuQuantumError::InvalidShift {
                shift_bits: config.shift_bits,
            },
        });
    }
    Ok(())
}

pub(super) fn mapped_view<'a>(
    region: &'a mut MappedSetupRegion,
    config: &QemuQuantumShmemConfig,
) -> Result<QemuQuantumShmemView<'a>, QemuMappedQuantumShmemHotPathError> {
    let pair = region
        .node_directed_ring_pair_mut(
            config.vm_slot,
            config.router_slot,
            config.vm_slot,
            config.vm_slot,
            config.router_slot,
        )
        .map_err(|source| QemuMappedQuantumShmemHotPathError::RegionAccess { source })?;
    let MappedNodeRingPairMut {
        node_slot,
        first,
        second,
    } = pair;
    let MappedDirectedRingMut {
        header: inbound_ring,
        entries: inbound_entries,
        ..
    } = first;
    let MappedDirectedRingMut {
        header: outbound_ring,
        entries: outbound_entries,
        ..
    } = second;
    QemuQuantumShmemView::new(
        node_slot,
        inbound_ring,
        inbound_entries,
        outbound_ring,
        outbound_entries,
    )
    .map_err(|source| QemuMappedQuantumShmemHotPathError::Quantum { source })
}
