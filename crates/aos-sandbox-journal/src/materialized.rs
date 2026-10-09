//! Ordered materialized-map projection and mutation mechanics.
//!
//! Namespace values and borrowed mutations are nonauthorizing DATA. Domain
//! owners retain namespace decoding, duplicate-key admission, semantic changes,
//! and visibility. Projection compares every mutation with the original map;
//! applying mutations instead follows their supplied order.

use std::collections::BTreeMap;

use crate::framing::FrameError;

/// Borrows one namespace-key replacement or deletion without admitting it.
#[derive(Clone, Copy, Debug)]
pub struct RecordMutationRef<'a, N> {
    /// Carries the owner's namespace DATA without interpreting its meaning.
    pub namespace: N,
    /// Borrows the record's actual key bytes.
    pub key: &'a [u8],
    /// Borrows a PUT value, including an empty value, or represents a DELETE.
    pub value: Option<&'a [u8]>,
}

/// Projects the record count against the original, unmodified map.
///
/// Repeated keys are not normalized or admitted: each mutation independently
/// consults the original map. Domain owners separately validate transactions.
///
/// # Errors
///
/// Returns the existing materialized-record-count error on checked overflow.
pub fn projected_record_count<'a, N: Ord + Copy>(
    state: &BTreeMap<(N, Vec<u8>), Vec<u8>>,
    records: impl IntoIterator<Item = RecordMutationRef<'a, N>>,
) -> Result<usize, FrameError> {
    let mut entries = state.len();
    for record in records {
        let key = (record.namespace, record.key.to_vec());
        match (state.contains_key(&key), record.value.is_some()) {
            (false, true) => {
                entries = entries
                    .checked_add(1)
                    .ok_or(FrameError::LimitExceeded("materialized record count"))?;
            }
            (true, false) => entries = entries.saturating_sub(1),
            _ => {}
        }
    }
    Ok(entries)
}

/// Projects bounded key/value bytes and record count without changing the map.
///
/// Each mutation consults the original map. This preserves the owner's
/// projection recipe, not sequential accounting for arbitrary repeated keys.
/// It does not validate configuration or admit duplicate keys.
///
/// # Errors
///
/// Preserves checked count and byte overflow errors. After projection, rejects
/// excessive bytes before excessive record count.
///
/// # Panics
///
/// With overflow checks enabled, repeating existing-key deletions more times
/// than the original record count panics. Domain admission rejects duplicate
/// keys before using this projection; the existing subtraction is unchanged.
pub fn validate_change<'a, N: Ord + Copy>(
    state: &BTreeMap<(N, Vec<u8>), Vec<u8>>,
    current_bytes: usize,
    records: impl IntoIterator<Item = RecordMutationRef<'a, N>>,
    maximum_bytes: usize,
    maximum_records: usize,
) -> Result<usize, FrameError> {
    let mut bytes = current_bytes;
    let mut entries = state.len();
    for record in records {
        let key = (record.namespace, record.key.to_vec());
        let existing = state.get(&key);
        if let Some(value) = existing {
            bytes = bytes.saturating_sub(record.key.len().saturating_add(value.len()));
        }
        match record.value {
            Some(value) => {
                if existing.is_none() {
                    entries = entries
                        .checked_add(1)
                        .ok_or(FrameError::LimitExceeded("materialized record count"))?;
                }
                bytes = bytes
                    .checked_add(record.key.len())
                    .and_then(|size| size.checked_add(value.len()))
                    .ok_or(FrameError::LimitExceeded("materialized state bytes"))?;
            }
            None if existing.is_some() => entries -= 1,
            None => {}
        }
    }
    if bytes > maximum_bytes {
        return Err(FrameError::LimitExceeded("materialized state bytes"));
    }
    if entries > maximum_records {
        return Err(FrameError::LimitExceeded("materialized record count"));
    }
    Ok(bytes)
}

/// Copies one mutation's bytes into the map without applying domain semantics.
pub fn apply_mutation<N: Ord + Copy>(
    state: &mut BTreeMap<(N, Vec<u8>), Vec<u8>>,
    record: RecordMutationRef<'_, N>,
) {
    let composite_key = (record.namespace, record.key.to_vec());
    match record.value {
        Some(value) => {
            state.insert(composite_key, value.to_vec());
        }
        None => {
            state.remove(&composite_key);
        }
    }
}

/// Clones the existing map, then applies supplied mutations in order.
///
/// Domain owners perform any required validation before this whole-map copy.
/// This does not publish a state or update domain-specific indexes.
pub fn materialize_copy<'a, N: Ord + Copy>(
    state: &BTreeMap<(N, Vec<u8>), Vec<u8>>,
    records: impl IntoIterator<Item = RecordMutationRef<'a, N>>,
) -> BTreeMap<(N, Vec<u8>), Vec<u8>> {
    let mut after = state.clone();
    for record in records {
        apply_mutation(&mut after, record);
    }
    after
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation<'a>(key: &'a [u8], value: Option<&'a [u8]>) -> RecordMutationRef<'a, u8> {
        RecordMutationRef {
            namespace: 1,
            key,
            value,
        }
    }

    #[test]
    fn duplicate_new_puts_project_against_the_original_map() {
        let before = BTreeMap::new();
        let records = [
            mutation(b"k", Some(b"first")),
            mutation(b"k", Some(b"last")),
        ];

        let count = projected_record_count(&before, records).unwrap();
        let bytes = validate_change(&before, 0, records, usize::MAX, usize::MAX).unwrap();
        let after = materialize_copy(&before, records);

        assert_eq!(count, 2);
        assert_eq!(bytes, 11);
        assert_eq!(
            after,
            BTreeMap::from([((1, b"k".to_vec()), b"last".to_vec())])
        );
        assert!(before.is_empty());
    }

    #[test]
    fn duplicate_replacements_subtract_the_original_value_each_time() {
        let before = BTreeMap::from([((1, b"k".to_vec()), b"old".to_vec())]);
        let records = [
            mutation(b"k", Some(b"first")),
            mutation(b"k", Some(b"last")),
        ];

        let count = projected_record_count(&before, records).unwrap();
        let bytes = validate_change(&before, 4, records, usize::MAX, usize::MAX).unwrap();
        let after = materialize_copy(&before, records);

        assert_eq!(count, 1);
        assert_eq!(bytes, 7);
        assert_eq!(after.get(&(1, b"k".to_vec())), Some(&b"last".to_vec()));
        assert_eq!(before.get(&(1, b"k".to_vec())), Some(&b"old".to_vec()));
    }

    #[test]
    fn put_then_delete_does_not_change_original_map_projection() {
        let before = BTreeMap::new();
        let records = [mutation(b"k", Some(b"first")), mutation(b"k", None)];

        let count = projected_record_count(&before, records).unwrap();
        let bytes = validate_change(&before, 0, records, usize::MAX, usize::MAX).unwrap();
        let after = materialize_copy(&before, records);

        assert_eq!(count, 1);
        assert_eq!(bytes, 6);
        assert!(after.is_empty());
        assert!(before.is_empty());
    }

    #[test]
    fn duplicate_deletions_retain_original_map_accounting() {
        let before = BTreeMap::from([
            ((1, b"k".to_vec()), b"old".to_vec()),
            ((1, b"j".to_vec()), b"old".to_vec()),
        ]);
        let records = [mutation(b"k", None), mutation(b"k", None)];

        let count = projected_record_count(&before, records).unwrap();
        let bytes = validate_change(&before, 8, records, usize::MAX, usize::MAX).unwrap();
        let after = materialize_copy(&before, records);

        assert_eq!(count, 0);
        assert_eq!(bytes, 0);
        assert_eq!(
            after,
            BTreeMap::from([((1, b"j".to_vec()), b"old".to_vec())])
        );
        assert_eq!(before.len(), 2);

        assert_eq!(
            projected_record_count(&before, [mutation(b"k", None); 3]).unwrap(),
            0,
        );
    }

    #[test]
    fn byte_projection_preserves_saturation_overflow_and_refusal_order() {
        let before = BTreeMap::from([((1, b"k".to_vec()), b"old".to_vec())]);

        assert_eq!(
            validate_change(&before, 0, [mutation(b"k", Some(b""))], 1, 1).unwrap(),
            1,
        );
        assert!(matches!(
            validate_change(
                &before,
                usize::MAX,
                [mutation(b"new", Some(b""))],
                usize::MAX,
                usize::MAX
            ),
            Err(FrameError::LimitExceeded("materialized state bytes")),
        ));
        assert!(matches!(
            validate_change(&before, 4, [], 0, 0),
            Err(FrameError::LimitExceeded("materialized state bytes")),
        ));
        assert!(matches!(
            validate_change(&before, 4, [], 4, 0),
            Err(FrameError::LimitExceeded("materialized record count")),
        ));
    }

    #[test]
    fn ordered_mutations_preserve_namespaces_and_empty_puts() {
        let mut state = BTreeMap::from([((2, b"k".to_vec()), b"other".to_vec())]);

        apply_mutation(&mut state, mutation(b"k", Some(b"")));
        assert_eq!(state.get(&(1, b"k".to_vec())), Some(&Vec::new()));

        let after = materialize_copy(&state, [mutation(b"k", None), mutation(b"k", Some(b"new"))]);

        assert_eq!(after.get(&(1, b"k".to_vec())), Some(&b"new".to_vec()));
        assert_eq!(after.get(&(2, b"k".to_vec())), Some(&b"other".to_vec()));
        assert_eq!(state.get(&(1, b"k".to_vec())), Some(&Vec::new()));
    }
}
