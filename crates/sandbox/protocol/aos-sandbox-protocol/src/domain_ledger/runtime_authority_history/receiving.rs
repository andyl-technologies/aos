//! Prices only the actual map/index backing of the sole Runtime namespace scan.
//!
//! Row decode/assignment/publication backing is supplied by the existing codec
//! suppliers. This helper observes ordered held keys before growth; it neither
//! parses records nor creates a validated namespace or live authority.

use super::*;
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1;
use std::collections::BTreeMap;
use std::mem::size_of;

/// Prices the exact map roster used by the complete Runtime history reader.
///
/// The caller supplies the actual materialized map in its native key order.
/// Binding histories form one outer sandbox entry and one inner revision entry
/// per held binding; heads and pending rows occupy their own actual indices.
/// Invalid key widths or checked overflow return `None` before model growth.
#[must_use]
pub fn namespace_scan_map_receiving_demand_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Option<ResourceVector> {
    let mut bindings = 0usize;
    let mut subjects = 0usize;
    let mut heads = 0usize;
    let mut pending = 0usize;
    let mut previous = None;
    for ((namespace, key), _) in state {
        if *namespace != RecordNamespace::RuntimeAuthority {
            continue;
        }
        if let Some(suffix) = key.strip_prefix(BINDING_PREFIX) {
            if key.len() != BINDING_KEY_BYTES {
                return None;
            }
            let sandbox: [u8; 16] = suffix.get(..16)?.try_into().ok()?;
            if previous != Some(sandbox) {
                subjects = subjects.checked_add(1)?;
                previous = Some(sandbox);
            }
            bindings = bindings.checked_add(1)?;
        } else if key.starts_with(CURRENT_PREFIX) {
            if key.len() != CURRENT_KEY_BYTES {
                return None;
            }
            heads = heads.checked_add(1)?;
        } else if key.starts_with(PENDING_PREFIX) {
            if key.len() != PENDING_KEY_BYTES {
                return None;
            }
            pending = pending.checked_add(1)?;
        } else {
            return None;
        }
    }
    let nodes = conservative_btree_node_bytes_v1::<
        [u8; 16],
        BTreeMap<u64, RuntimeAuthorityBindingV1>,
    >(subjects)?
    .checked_add(conservative_btree_node_bytes_v1::<
        u64,
        RuntimeAuthorityBindingV1,
    >(bindings)?)?
    .checked_add(conservative_btree_node_bytes_v1::<
        [u8; 16],
        RuntimeAuthorityHeadV1,
    >(heads)?)?
    .checked_add(conservative_btree_node_bytes_v1::<
        [u8; 16],
        RuntimeAuthorityPendingV1,
    >(pending)?)?;
    // A decoded/moved row overlaps its destination node; the current getter
    // additionally returns one actual binding beside the namespace scanner.
    let row = size_of::<RuntimeAuthorityBindingV1>()
        .max(size_of::<RuntimeAuthorityPendingV1>())
        .max(size_of::<RuntimeAuthorityHeadV1>());
    let bytes = nodes
        .checked_add(row.checked_mul(2)?)?
        .checked_add(size_of::<
            BTreeMap<[u8; 16], BTreeMap<u64, RuntimeAuthorityBindingV1>>,
        >())?
        .checked_add(size_of::<BTreeMap<[u8; 16], RuntimeAuthorityHeadV1>>())?
        .checked_add(size_of::<BTreeMap<[u8; 16], RuntimeAuthorityPendingV1>>())?
        // Runtime current/pending/binding lookups can hold the nested keys
        // while resolving their real operation/publication crosslink.
        .checked_add(
            PENDING_KEY_BYTES
                .checked_add(BINDING_KEY_BYTES)?
                .checked_add(CURRENT_KEY_BYTES)?,
        )?;
    let entries = subjects
        .checked_add(bindings)?
        .checked_add(heads)?
        .checked_add(pending)?;
    Some(
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::MetadataEntries, u64::try_from(entries).ok()?),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_key(sandbox: u8, revision: u64) -> Vec<u8> {
        let mut key = BINDING_PREFIX.to_vec();
        key.extend_from_slice(&[sandbox; 16]);
        key.extend_from_slice(&revision.to_be_bytes());
        key
    }

    #[test]
    fn nested_runtime_indices_charge_actual_subjects_and_revisions() {
        let mut rows = BTreeMap::new();
        let empty = namespace_scan_map_receiving_demand_v2(&rows).unwrap();
        assert_eq!(empty.get(D::MetadataEntries), 0);

        rows.insert(
            (RecordNamespace::RuntimeAuthority, binding_key(1, 1)),
            Vec::new(),
        );
        rows.insert(
            (RecordNamespace::RuntimeAuthority, binding_key(1, 2)),
            Vec::new(),
        );
        let one_subject = namespace_scan_map_receiving_demand_v2(&rows).unwrap();
        assert_eq!(one_subject.get(D::MetadataEntries), 3);

        rows.remove(&(RecordNamespace::RuntimeAuthority, binding_key(1, 2)));
        rows.insert(
            (RecordNamespace::RuntimeAuthority, binding_key(2, 1)),
            Vec::new(),
        );
        let two_subjects = namespace_scan_map_receiving_demand_v2(&rows).unwrap();
        assert_eq!(two_subjects.get(D::MetadataEntries), 4);
        assert!(two_subjects.get(D::MemoryBytes) > one_subject.get(D::MemoryBytes));
    }
}
