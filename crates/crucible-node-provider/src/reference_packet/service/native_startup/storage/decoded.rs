//! Separates closed native decoded backing from parser and canonical work.
//!
//! This bounded occurrence walk creates no JSON or typed owner. Only actual
//! native constructor DTOs use its compiled element roster; generic restore
//! accounting and arbitrary raw framing retain their independent old bounds.

use super::*;
use serde_json::Value;

#[derive(Clone, Copy)]
pub(super) struct DecodedStorage {
    pub(super) value_backing: usize,
    pub(super) typed_backing: usize,
    pub(super) work: usize,
}

impl DecodedStorage {
    pub(super) fn total(self, maximum: usize) -> Result<usize, ProviderError> {
        sum(
            &[self.value_backing, self.typed_backing, self.work],
            maximum,
        )
    }
}

fn tree_node() -> Result<usize, ProviderError> {
    crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<String, Value>()
}

/// Counts actual raw occurrences before any later DTO cardinality validation.
///
/// Every string/map is conservatively retained even when it is a discarded
/// field name. Only array elements own independently allocated typed slots:
/// nested structs are inline in their actual root or Vec element. Unknown
/// Value extensions retain complete DOM geometry. Empty object roots and
/// minimum/spare array capacities are independent explicit terms.
pub(super) fn quote(
    bytes: &[u8],
    root: usize,
    element: usize,
    maximum: usize,
) -> Result<DecodedStorage, ProviderError> {
    if bytes.is_empty() || bytes.len() > maximum || root == 0 || element == 0 {
        return Err(refused());
    }
    let mut stack = [0u8; 64];
    let mut depth = 0usize;
    let mut cursor = 0usize;
    let mut strings = 0usize;
    let mut maps = 0usize;
    let mut slots = 0usize;
    let sort_node = crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<Vec<u16>, (&str, &Value)>()?;
    // Final ordered tree plus independent collect-Vec growth and stable-sort
    // heap coexist. A second pinned node dominates four input slots and one
    // sort slot per entry; fixed4096-byte sort workspace stays separate below.
    let sort_slot = size_of::<(Vec<u16>, (&str, &Value))>();
    if size_of::<usize>() != 8 || sort_slot.checked_mul(5).ok_or_else(refused)? > sort_node {
        return Err(refused());
    }
    let mut canonical = bytes.len().checked_mul(8).ok_or_else(refused)?;
    while let Some(&byte) = bytes.get(cursor) {
        if b" \t\r\n,:".contains(&byte) {
            cursor += 1;
            continue;
        }
        let closes = byte == b'}' || byte == b']';
        if !closes && depth > 0 && stack[depth - 1] == b'[' {
            slots = slots.checked_add(4).ok_or_else(refused)?;
        }
        match byte {
            b'{' | b'[' => {
                *stack.get_mut(depth).ok_or_else(refused)? = byte;
                depth += 1;
                if byte == b'{' {
                    maps = maps.checked_add(1).ok_or_else(refused)?;
                } else {
                    slots = slots.checked_add(4).ok_or_else(refused)?;
                }
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(refused)?;
                if stack[depth] != if byte == b'}' { b'{' } else { b'[' } {
                    return Err(refused());
                }
                cursor += 1;
            }
            b'"' => {
                cursor += 1;
                let start = cursor;
                loop {
                    let next = *bytes.get(cursor).ok_or_else(refused)?;
                    cursor += 1;
                    if next == b'\\' {
                        bytes.get(cursor).ok_or_else(refused)?;
                        cursor += 1;
                    } else if next == b'"' {
                        break;
                    }
                }
                let encoded = cursor - start - 1;
                // This also covers growable base64 Bytes decoding from the
                // borrowed string, and preserves both key/value string banks.
                strings = sum(
                    &[strings, encoded.checked_mul(8).ok_or_else(refused)?, 32],
                    maximum,
                )?;
                let mut next = cursor;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') {
                    maps = maps.checked_add(1).ok_or_else(refused)?;
                    canonical = sum(
                        &[
                            canonical,
                            encoded.checked_mul(8).ok_or_else(refused)?,
                            sort_node.checked_mul(2).ok_or_else(refused)?,
                            16,
                        ],
                        maximum,
                    )?;
                }
                canonical = sum(
                    &[canonical, encoded.checked_mul(24).ok_or_else(refused)?, 264],
                    maximum,
                )?;
            }
            _ => {
                let start = cursor;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| !b" \t\r\n,:]}".contains(byte))
                {
                    cursor += 1;
                }
                if cursor == start {
                    return Err(refused());
                }
            }
        }
    }
    if depth != 0 {
        return Err(refused());
    }
    let map_backing = maps.checked_mul(tree_node()?).ok_or_else(refused)?;
    let value_backing = sum(
        &[
            strings,
            map_backing,
            slots.checked_mul(size_of::<Value>()).ok_or_else(refused)?,
            size_of::<Value>(),
        ],
        maximum,
    )?;
    let typed_backing = sum(
        &[
            strings,
            map_backing,
            slots.checked_mul(element).ok_or_else(refused)?,
            root,
        ],
        maximum,
    )?;
    // Container rebuilding from owned Value can coexist with the original
    // subtree. Keep both DOMs; canonical sorting/output is separate work.
    // These are explicit standard-library local banks, not compiler frames.
    // A single sort owns one aligned4096 workspace,66 one-word run records,
    //66 desired-depth bytes, insertion temporary/CopyOnDrop and heap header.
    let sort_alignment = align_of::<(Vec<u16>, (&str, &Value))>();
    let sort_workspace = ((4096 + sort_alignment - 1) & !(sort_alignment - 1))
        + size_of::<[usize; 66]>()
        + size_of::<[u8; 66]>()
        + sort_slot
        + 3 * size_of::<usize>()
        + size_of::<Vec<(Vec<u16>, (&str, &Value))>>();
    let work = sum(
        &[
            value_backing,
            value_backing,
            typed_backing,
            canonical,
            sort_workspace,
        ],
        maximum,
    )?;
    let result = DecodedStorage {
        value_backing,
        typed_backing,
        work,
    };
    result.total(maximum)?;
    Ok(result)
}

pub(super) const fn counter_scratch_data() -> usize {
    // Scanner totals/cursors, source/target widths, largest checked sum
    // array, live result/backing locals, and the nested checked-sum views.
    size_of::<[u8; 64]>()
        + size_of::<DecodedStorage>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 7]>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 4]>()
        + size_of::<&[u8]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn native_value_backing_covers_empty_maps_dense_arrays_and_independent_clones() -> TestResult {
        for input in [
            b"{}".as_slice(),
            b"[]",
            br#"{"a":{},"b":[{},{},"x",1,2],"c":"\uD834\uDD1E"}"#,
        ] {
            let actual: Value = serde_json::from_slice(input)?;
            let independent = actual.clone();
            let mut observer = MetadataObserver::new();
            observer.observe(&actual)?;
            let backing = requested_metadata_backing_storage_data(&observer.finish())?;
            let mut cloned = MetadataObserver::new();
            cloned.observe(&independent)?;
            let clone_backing = requested_metadata_backing_storage_data(&cloned.finish())?;
            let row = quote(input, size_of::<Value>(), size_of::<Value>(), usize::MAX)?;
            assert!(row.value_backing >= backing);
            assert!(row.typed_backing >= clone_backing);
            let exact = row.total(usize::MAX)?;
            assert_eq!(
                quote(input, size_of::<Value>(), size_of::<Value>(), exact)?.total(exact)?,
                exact
            );
            assert!(quote(input, size_of::<Value>(), size_of::<Value>(), exact - 1).is_err());
        }
        Ok(())
    }

    #[test]
    fn actual_coordinator_backing_covers_the_retained_dto_without_validator_work() -> TestResult {
        use crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation;
        let (_, _, local, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let actual =
            PacketNative5CoordinatorInstallation::decode(original.bytes.as_slice(), &local)?;
        let facts = crate::retained_metadata::observe_retained_native_coordinator(&actual)?;
        let observed = requested_metadata_backing_storage_data(&facts)?;
        let backing = coordinator_decode::backing(original.bytes.as_slice(), usize::MAX)?;
        assert!(backing >= observed + size_of::<PacketNative5CoordinatorInstallation>());
        assert!(coordinator_decode::quote(original.bytes.as_slice(), usize::MAX)? > backing);
        assert!(quote(b"{}", usize::MAX, usize::MAX, usize::MAX).is_err());
        Ok(())
    }
}
