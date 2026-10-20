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
    validate_change_engine(state, current_bytes, records, maximum_bytes, maximum_records, None)
}

/// Retains the actual current materialization lookup tuple on a failed step.
///
/// Positive lookup/iteration scratch retires at the original boundary; this
/// DATA supplies neither an admitted map, count nor a native mutation permit.
pub struct NativeMaterializedChangeOriginalsV1<N> {
    current_key: Option<(N, Vec<u8>)>,
    bytes: usize,
    entries: usize,
    attempted: bool,
    closed: bool,
}

impl<N> NativeMaterializedChangeOriginalsV1<N> {
    /// Creates empty fixed slots without allocation.
    pub const fn new() -> Self {
        Self { current_key: None, bytes: 0, entries: 0, attempted: false, closed: false }
    }

    /// Borrows the actual current tuple retained before a checked-step refusal.
    pub fn current_key(&self) -> Option<(&N, &[u8])> {
        self.current_key.as_ref().map(|(namespace, key)| (namespace, key.as_slice()))
    }

    /// Counts five fields plus the current tuple's namespace/key cells as DATA.
    pub const fn receiving_metadata_cells_v1() -> usize { 7 }
}

impl<N> Default for NativeMaterializedChangeOriginalsV1<N> {
    fn default() -> Self { Self::new() }
}

/// Runs the same projection while retaining the current failed lookup tuple.
///
/// # Errors
/// Preserves ordinary arithmetic/bounds error order; reentry refuses without
/// replacing the first tuple. The actual returned error belongs to the caller.
///
/// # Panics
/// Preserves ordinary duplicate-deletion count underflow behavior.
pub fn validate_change_retaining_v1<'a, N: Ord + Copy>(
    state: &BTreeMap<(N, Vec<u8>), Vec<u8>>,
    current_bytes: usize,
    records: impl IntoIterator<Item = RecordMutationRef<'a, N>>,
    maximum_bytes: usize,
    maximum_records: usize,
    original: &mut NativeMaterializedChangeOriginalsV1<N>,
) -> Result<usize, FrameError> {
    if original.attempted {
        original.closed = true;
        return Err(FrameError::MissingRetainedPayload);
    }
    original.attempted = true;
    validate_change_engine(state, current_bytes, records, maximum_bytes, maximum_records, Some(original))
}

fn validate_change_engine<'a, N: Ord + Copy>(
    state: &BTreeMap<(N, Vec<u8>), Vec<u8>>,
    current_bytes: usize,
    records: impl IntoIterator<Item = RecordMutationRef<'a, N>>,
    maximum_bytes: usize,
    maximum_records: usize,
    mut original: Option<&mut NativeMaterializedChangeOriginalsV1<N>>,
) -> Result<usize, FrameError> {
    let mut bytes = current_bytes;
    let mut entries = state.len();
    for record in records {
        let key = (record.namespace, record.key.to_vec());
        let existing = state.get(&key);
        let outcome = (|| {
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
            Ok(())
        })();
        if let Err(cause) = outcome {
            if let Some(original) = original.as_deref_mut() {
                original.current_key = Some(key);
                original.bytes = bytes;
                original.entries = entries;
            }
            return Err(cause);
        }
    }
    if let Some(original) = original.as_deref_mut() {
        original.bytes = bytes;
        original.entries = entries;
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

#[cfg(test)]
mod retaining_change_tests {
    use super::*;

    #[test]
    fn failed_checked_step_keeps_the_current_original_lookup_key_across_reentry() {
        let state = BTreeMap::new();
        let records = || [RecordMutationRef { namespace: 3_u8, key: b"key", value: Some(b"v") }];
        let ordinary = validate_change(&state, usize::MAX, records(), usize::MAX, usize::MAX);
        let mut original = NativeMaterializedChangeOriginalsV1::new();
        let retained = validate_change_retaining_v1(
            &state, usize::MAX, records(), usize::MAX, usize::MAX, &mut original,
        );

        assert_eq!(ordinary.unwrap_err().to_string(), retained.unwrap_err().to_string());
        assert_eq!(original.current_key(), Some((&3, b"key".as_slice())));
        let key = original.current_key().unwrap().1.as_ptr();
        assert!(validate_change_retaining_v1(
            &state, 0, records(), usize::MAX, usize::MAX, &mut original,
        ).is_err());
        assert_eq!(original.current_key().unwrap().1.as_ptr(), key);
        assert_eq!(original.bytes, usize::MAX);
        assert_eq!(original.entries, 1);
    }
}
