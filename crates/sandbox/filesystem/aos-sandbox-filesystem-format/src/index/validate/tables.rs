//! Allocation-free canonical table sweeps and dense child coverage.
//!
//! Each table has exactly N-1 slots. Root exclusion and unique non-root IDs
//! therefore prove a bijection, including hash ties, without rebuilding either
//! table. Directory order also proves contiguous ordinals and sibling names.

use super::*;

pub(super) fn validate_lookup_table(
    bytes: &[u8],
    nodes: &[IndexNodeRecord<'_>],
    seen: &mut [u8],
) -> Result<(), IndexError> {
    require_slots(bytes, LOOKUP_SLOT_BYTES, nodes.len())?;
    seen.fill(0);
    let mut previous = None;
    for index in 0..nodes.len().saturating_sub(1) {
        let slot = read_lookup_slot(bytes, 0, index as u64)?;
        let node = mark_child(slot.record_id, nodes, seen)?;
        let key = (slot.parent, slot.name_hash, slot.record_id);
        if previous.is_some_and(|previous| previous >= key)
            || slot.parent != node.parent
            || slot.record_offset != node.record_offset
            || slot.name_hash != lookup_hash(node.parent, node.name)
        {
            return Err(IndexError::InvalidRecord);
        }
        previous = Some(key);
    }
    require_coverage(nodes.len(), seen)
}

pub(super) fn validate_directory_table(
    bytes: &[u8],
    root_nlink: u64,
    nodes: &[IndexNodeRecord<'_>],
    hardlinks: &std::collections::BTreeMap<ObjectDigest, Vec<IndexHardlinkMember>>,
    seen: &mut [u8],
    nlinks: &mut Vec<u64>,
) -> Result<(), IndexError> {
    require_slots(bytes, DIRECTORY_SLOT_BYTES, nodes.len())?;
    // Capacity was admitted and allocated before decoding the first record.
    if !nlinks.is_empty() || nlinks.capacity() < nodes.len() {
        return Err(IndexError::LimitExceeded);
    }
    nlinks.extend(
        nodes
            .iter()
            .map(|node| if node.directory { 2_u64 } else { 1_u64 }),
    );
    for node in nodes.iter().skip(1).filter(|node| node.directory) {
        let parent = usize::try_from(node.parent).map_err(|_| IndexError::InvalidRecord)?;
        let value = nlinks.get_mut(parent).ok_or(IndexError::InvalidRecord)?;
        *value = value.checked_add(1).ok_or(IndexError::LimitExceeded)?;
    }
    for members in hardlinks.values() {
        let count = u64::try_from(members.len()).map_err(|_| IndexError::LimitExceeded)?;
        for member in members {
            let index = usize::try_from(member.node).map_err(|_| IndexError::InvalidRecord)?;
            *nlinks.get_mut(index).ok_or(IndexError::InvalidRecord)? = count;
        }
    }
    if nlinks.first().copied() != Some(root_nlink) {
        return Err(IndexError::InvalidRecord);
    }

    seen.fill(0);
    let mut previous: Option<(u64, u32, u64, &[u8])> = None;
    for index in 0..nodes.len().saturating_sub(1) {
        let slot = read_directory_slot(bytes, 0, index as u64)?;
        let node = mark_child(slot.record_id, nodes, seen)?;
        let key = (slot.parent, node.sibling_ordinal, slot.record_id);
        if slot.parent != node.parent
            || slot.record_offset != node.record_offset
            || nlinks.get(slot.record_id as usize).copied() != Some(slot.nlink)
        {
            return Err(IndexError::InvalidRecord);
        }
        match previous {
            Some((parent, ordinal, id, name)) if parent == slot.parent => {
                if (parent, ordinal, id) >= key
                    || ordinal.checked_add(1) != Some(node.sibling_ordinal)
                    || name >= node.name
                {
                    return Err(IndexError::InvalidRecord);
                }
            }
            Some((parent, _, _, _)) => {
                if parent >= slot.parent || node.sibling_ordinal != 0 {
                    return Err(IndexError::InvalidRecord);
                }
            }
            None if node.sibling_ordinal != 0 => return Err(IndexError::InvalidRecord),
            None => {}
        }
        previous = Some((slot.parent, node.sibling_ordinal, slot.record_id, node.name));
    }
    require_coverage(nodes.len(), seen)
}

fn require_slots(bytes: &[u8], width: usize, records: usize) -> Result<(), IndexError> {
    let slots = records.checked_sub(1).ok_or(IndexError::InvalidRecord)?;
    if slots.checked_mul(width).ok_or(IndexError::LimitExceeded)? != bytes.len() {
        return Err(IndexError::InvalidHeader);
    }
    Ok(())
}

fn mark_child<'nodes, 'bytes>(
    id: u64,
    nodes: &'nodes [IndexNodeRecord<'bytes>],
    seen: &mut [u8],
) -> Result<&'nodes IndexNodeRecord<'bytes>, IndexError> {
    let index = usize::try_from(id).map_err(|_| IndexError::InvalidRecord)?;
    if index == 0 {
        return Err(IndexError::InvalidRecord);
    }
    let node = nodes.get(index).ok_or(IndexError::InvalidRecord)?;
    let byte = seen.get_mut(index / 8).ok_or(IndexError::InvalidRecord)?;
    let mask = 1 << (index % 8);
    if *byte & mask != 0 {
        return Err(IndexError::InvalidRecord);
    }
    *byte |= mask;
    Ok(node)
}

fn require_coverage(records: usize, seen: &[u8]) -> Result<(), IndexError> {
    for id in 1..records {
        if seen
            .get(id / 8)
            .is_none_or(|byte| byte & (1 << (id % 8)) == 0)
        {
            return Err(IndexError::InvalidRecord);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collision_nodes() -> Vec<IndexNodeRecord<'static>> {
        // A table-only same-name fixture supplies equal hashes without
        // claiming a discovered SHA-256 collision or valid sibling names.
        vec![
            IndexNodeRecord {
                parent: u64::MAX,
                depth: 0,
                sibling_ordinal: 0,
                directory: true,
                name: b"",
                record_offset: 248,
            },
            IndexNodeRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: 0,
                directory: false,
                name: b"same",
                record_offset: 400,
            },
            IndexNodeRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: 1,
                directory: false,
                name: b"same",
                record_offset: 500,
            },
        ]
    }

    #[test]
    fn lookup_hash_ties_use_id_order_and_still_require_bijection() {
        let nodes = collision_nodes();
        let first = LookupSlot {
            parent: 0,
            name_hash: lookup_hash(0, b"same"),
            record_offset: 400,
            record_id: 1,
        };
        let second = LookupSlot {
            record_offset: 500,
            record_id: 2,
            ..first
        };
        let mut seen = [0];
        let canonical = [encode_lookup_slot(first), encode_lookup_slot(second)].concat();
        validate_lookup_table(&canonical, &nodes, &mut seen).unwrap();
        assert_eq!(seen, [0b110]);

        for forged in [
            [encode_lookup_slot(second), encode_lookup_slot(first)].concat(),
            [encode_lookup_slot(first), encode_lookup_slot(first)].concat(),
            [
                encode_lookup_slot(LookupSlot {
                    record_id: 0,
                    ..first
                }),
                encode_lookup_slot(second),
            ]
            .concat(),
            [
                encode_lookup_slot(LookupSlot {
                    name_hash: [0; 32],
                    ..first
                }),
                encode_lookup_slot(second),
            ]
            .concat(),
        ] {
            assert!(matches!(
                validate_lookup_table(&forged, &nodes, &mut seen),
                Err(IndexError::InvalidRecord)
            ));
        }
        assert!(matches!(
            validate_lookup_table(&canonical[..LOOKUP_SLOT_BYTES], &nodes, &mut seen),
            Err(IndexError::InvalidHeader)
        ));
    }

    #[test]
    fn directory_sweep_rejects_equal_names_even_with_exact_slots() {
        let nodes = collision_nodes();
        let bytes = [
            encode_directory_slot(DirectorySlot {
                parent: 0,
                record_offset: 400,
                record_id: 1,
                nlink: 1,
            }),
            encode_directory_slot(DirectorySlot {
                parent: 0,
                record_offset: 500,
                record_id: 2,
                nlink: 1,
            }),
        ]
        .concat();
        let mut seen = [0];
        let mut nlinks = Vec::with_capacity(nodes.len());
        assert!(matches!(
            validate_directory_table(
                &bytes,
                2,
                &nodes,
                &std::collections::BTreeMap::new(),
                &mut seen,
                &mut nlinks
            ),
            Err(IndexError::InvalidRecord)
        ));
    }
}
