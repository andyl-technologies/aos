//! Reconstructs checked compact byte groups as independently owned content data.
//!
//! A complete borrowed cursor pass precedes every owning allocation. Each first
//! group receives one original-capacity Vec; aliases clone that same Rc. Logical
//! limits, incomplete transfers and nonrenewing credit remain unchanged. Edition7
//! omits metadata String capacities, so this data constructor is not complete
//! allocation-state restoration and cannot install a controller or source.

use super::compact_cursor::{
    BorrowedContentReference, BorrowedContentRow, CompactContentLimits, ContentGroupKind,
    ValidatedCompactContent,
};
use super::{ClientContent, Transfer};
use crate::ProviderError;
use crucible_node_format::{ContentRef, HashRef, Id};
use std::{collections::BTreeMap, rc::Rc};

impl ClientContent {
    /// Reconstructs explicit edition-eight data with original metadata capacities.
    ///
    /// Full borrowed byte/alias and metadata-capacity admission precedes every
    /// owner allocation. Each original String and first-group byte bank receives
    /// one exact-capacity allocation; aliases reuse the original reconstructed Rc.
    /// Tree/control-block/allocator layout and the complete native source/factory
    /// peak remain separately admitted. This data constructor installs no state.
    ///
    /// # Errors
    /// Refuses malformed data, insufficient credit, allocation/capacity mismatch,
    /// unavailable aliases or changed complete content hashes.
    pub fn decode_compact_metadata8_data(
        input: &[u8],
        limits: super::compact_metadata8::CompactMetadata8Limits,
    ) -> Result<Self, ProviderError> {
        let plan = super::compact_metadata8::ValidatedCompactMetadata8::validate(input, limits)?;
        let data = plan.data();
        let mut transfer_groups = empty_group_rows(data.transfer_count())?;
        let mut object_groups = empty_group_rows(data.object_count())?;
        let mut transfers = BTreeMap::new();
        let mut objects = BTreeMap::new();

        for (index, (row, capacities)) in data.transfers().zip(plan.transfer_metadata()).enumerate()
        {
            let row = row?;
            let capacities = capacities?;
            let reference = own_reference_capacities(row.reference, capacities)?;
            let bytes = own_group(&row, &transfer_groups, &object_groups)?;
            let complete = row
                .complete
                .ok_or(ProviderError::Frame("compact transfer completion absent"))?;
            if complete {
                reference.verify(bytes.as_slice())?;
            }
            if row.payload.is_some() {
                transfer_groups[index] = Some(bytes.clone());
            }
            let key = Id::new(own_original_string(row.key, capacities[0])?)?;
            transfers.insert(
                key,
                Transfer {
                    reference,
                    bytes,
                    complete,
                },
            );
        }

        for (index, (row, capacities)) in data.objects().zip(plan.object_metadata()).enumerate() {
            let row = row?;
            let capacities = capacities?;
            let reference = own_reference_capacities(row.reference, capacities)?;
            let bytes = own_group(&row, &transfer_groups, &object_groups)?;
            reference.verify(bytes.as_slice())?;
            if row.payload.is_some() {
                object_groups[index] = Some(bytes.clone());
            }
            objects.insert(
                own_original_string(row.key, capacities[0])?,
                (reference, bytes),
            );
        }
        let original = data.stored_limits();
        Ok(Self {
            maximum_bytes: original.maximum_bytes,
            maximum_objects: original.maximum_objects,
            maximum_chunk: original.maximum_chunk,
            reserved: data.reserved(),
            transfers,
            objects,
        })
    }

    /// Reconstructs validated byte and alias data without installing native state.
    ///
    /// All lexical fields, row counts and first-group capacities are admitted
    /// before allocation. Original byte capacities, reference values, aliases,
    /// completion flags and reserved credit are preserved; metadata strings get
    /// independent bounded copies because their original capacities are absent.
    /// The caller precharges the cursor's fixed scratch, two row-index vectors,
    /// Rc owners, metadata strings and tree storage in addition to byte groups.
    /// This method does not establish a complete native/factory memory peak.
    ///
    /// # Errors
    /// Refuses invalid input/allowances, allocation failure, changed complete
    /// content hashes, inconsistent aliases or an allocator capacity mismatch.
    pub fn decode_compact_protocol_data(
        input: &[u8],
        limits: CompactContentLimits,
    ) -> Result<Self, ProviderError> {
        let plan = ValidatedCompactContent::validate(input, limits)?;
        let mut transfer_groups = empty_group_rows(plan.transfer_count())?;
        let mut object_groups = empty_group_rows(plan.object_count())?;
        let mut transfers = BTreeMap::new();
        let mut objects = BTreeMap::new();

        for (index, row) in plan.transfers().enumerate() {
            let row = row?;
            let reference = own_reference(row.reference)?;
            let bytes = own_group(&row, &transfer_groups, &object_groups)?;
            let complete = row
                .complete
                .ok_or(ProviderError::Frame("compact transfer completion absent"))?;
            if complete {
                reference.verify(bytes.as_slice())?;
            }
            if row.payload.is_some() {
                transfer_groups[index] = Some(bytes.clone());
            }
            let key = Id::new(own_string(row.key)?)?;
            transfers.insert(
                key,
                Transfer {
                    reference,
                    bytes,
                    complete,
                },
            );
        }

        for (index, row) in plan.objects().enumerate() {
            let row = row?;
            let reference = own_reference(row.reference)?;
            let bytes = own_group(&row, &transfer_groups, &object_groups)?;
            reference.verify(bytes.as_slice())?;
            if row.payload.is_some() {
                object_groups[index] = Some(bytes.clone());
            }
            objects.insert(own_string(row.key)?, (reference, bytes));
        }

        let original = plan.stored_limits();
        Ok(Self {
            maximum_bytes: original.maximum_bytes,
            maximum_objects: original.maximum_objects,
            maximum_chunk: original.maximum_chunk,
            reserved: plan.reserved(),
            transfers,
            objects,
        })
    }
}

fn empty_group_rows(count: usize) -> Result<Vec<Option<Rc<Vec<u8>>>>, ProviderError> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)
        .map_err(|_| ProviderError::ResourceExhausted("compact group index rows"))?;
    if rows.capacity() != count {
        return Err(ProviderError::ResourceExhausted(
            "compact group index capacity",
        ));
    }
    rows.resize_with(count, || None);
    Ok(rows)
}

fn own_group(
    row: &BorrowedContentRow<'_>,
    transfers: &[Option<Rc<Vec<u8>>>],
    objects: &[Option<Rc<Vec<u8>>>],
) -> Result<Rc<Vec<u8>>, ProviderError> {
    if let Some(payload) = &row.payload {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(row.capacity)
            .map_err(|_| ProviderError::ResourceExhausted("compact original group capacity"))?;
        if bytes.capacity() != row.capacity {
            return Err(ProviderError::ResourceExhausted(
                "compact original group allocation differs",
            ));
        }
        payload.fill_preowned(&mut bytes)?;
        return Ok(Rc::new(bytes));
    }
    let roster = match row.edge.kind {
        ContentGroupKind::Transfer => transfers,
        ContentGroupKind::Object => objects,
    };
    let original = roster
        .get(row.edge.index)
        .and_then(Option::as_ref)
        .ok_or(ProviderError::Frame("compact original group unavailable"))?;
    if original.capacity() != row.capacity {
        return Err(ProviderError::Frame(
            "compact original alias capacity differs",
        ));
    }
    Ok(original.clone())
}

fn own_string(value: &str) -> Result<String, ProviderError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| ProviderError::ResourceExhausted("compact bounded metadata string"))?;
    owned.push_str(value);
    Ok(owned)
}

fn own_reference(reference: BorrowedContentReference<'_>) -> Result<ContentRef, ProviderError> {
    let mut media_type = String::new();
    media_type
        .try_reserve_exact(reference.media_type_length())
        .map_err(|_| ProviderError::ResourceExhausted("compact bounded media type"))?;
    for byte in reference.media_type_bytes() {
        media_type.push(char::from(byte));
    }
    Ok(ContentRef {
        hash: HashRef {
            algorithm: own_string("blake3-256")?,
            domain: own_string("cnp.blob.v1")?,
            digest: own_string(reference.digest())?,
        },
        length: crucible_node_format::U64::new(reference.length()),
        media_type,
    })
}

fn own_original_string(value: &str, capacity: usize) -> Result<String, ProviderError> {
    if capacity < value.len() {
        return Err(ProviderError::Frame(
            "compact original String capacity too small",
        ));
    }
    let mut owned = String::new();
    owned
        .try_reserve_exact(capacity)
        .map_err(|_| ProviderError::ResourceExhausted("compact original String capacity"))?;
    if owned.capacity() != capacity {
        return Err(ProviderError::ResourceExhausted(
            "compact original String allocation differs",
        ));
    }
    owned.push_str(value);
    Ok(owned)
}

fn own_reference_capacities(
    reference: BorrowedContentReference<'_>,
    capacities: [usize; 5],
) -> Result<ContentRef, ProviderError> {
    let mut media_type = own_original_string("", capacities[4])?;
    if media_type.capacity() < reference.media_type_length() {
        return Err(ProviderError::Frame(
            "compact original media capacity too small",
        ));
    }
    for byte in reference.media_type_bytes() {
        media_type.push(char::from(byte));
    }
    Ok(ContentRef {
        hash: HashRef {
            algorithm: own_original_string("blake3-256", capacities[1])?,
            domain: own_original_string("cnp.blob.v1", capacities[2])?,
            digest: own_original_string(reference.digest(), capacities[3])?,
        },
        length: crucible_node_format::U64::new(reference.length()),
        media_type,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn compact_owning_content_preserves_real_aliases_distinct_equal_groups_and_empty_spare() {
        let mut first = Vec::with_capacity(64);
        first.extend_from_slice(b"same");
        let mut second = Vec::with_capacity(96);
        second.extend_from_slice(b"same");
        let first = Rc::new(first);
        let second = Rc::new(second);
        let reference = canonical::content_ref(b"same", "application/octet-stream").unwrap();
        let mut original = ClientContent::new(1024, 8, 256).unwrap();
        original.reserved = 12;
        original.transfers.insert(
            Id::new("first").unwrap(),
            Transfer {
                reference: reference.clone(),
                bytes: first.clone(),
                complete: true,
            },
        );
        original.transfers.insert(
            Id::new("second").unwrap(),
            Transfer {
                reference: reference.clone(),
                bytes: second,
                complete: true,
            },
        );
        original
            .objects
            .insert(reference.hash.digest.clone(), (reference, first));
        let empty_reference = canonical::content_ref(b"", "application/octet-stream").unwrap();
        original.objects.insert(
            empty_reference.hash.digest.clone(),
            (empty_reference, Rc::new(Vec::with_capacity(32))),
        );
        let encoded = serde_json::to_vec(&original.original_compact_protocol_view()).unwrap();
        let limits = CompactContentLimits {
            max_input_bytes: encoded.len(),
            max_rows: 4,
            max_groups: 3,
            max_first_group_capacity_bytes: 192,
        };

        let recovered = ClientContent::decode_compact_protocol_data(&encoded, limits).unwrap();
        assert_eq!(recovered.reserved, 12);
        assert_eq!(
            serde_json::to_vec(&recovered.original_compact_protocol_view()).unwrap(),
            encoded
        );
        let first = &recovered
            .transfers
            .get(&Id::new("first").unwrap())
            .unwrap()
            .bytes;
        let second = &recovered
            .transfers
            .get(&Id::new("second").unwrap())
            .unwrap()
            .bytes;
        assert!(!Rc::ptr_eq(first, second));
        assert_eq!(first.capacity(), 64);
        assert_eq!(second.capacity(), 96);
        let alias = recovered
            .objects
            .values()
            .find(|(_, bytes)| !bytes.is_empty())
            .unwrap();
        assert!(Rc::ptr_eq(first, &alias.1));
        let empty = recovered
            .objects
            .values()
            .find(|(_, bytes)| bytes.is_empty())
            .unwrap();
        assert_eq!(empty.1.capacity(), 32);
        let insufficient = CompactContentLimits {
            max_first_group_capacity_bytes: 191,
            ..limits
        };
        assert!(ClientContent::decode_compact_protocol_data(&encoded, insufficient).is_err());
    }

    #[test]
    fn compact_owning_content_refuses_changed_complete_hash_and_retains_partial_transfer_credit() {
        let reference = canonical::content_ref(b"complete", "application/octet-stream").unwrap();
        let mut original = ClientContent::new(1024, 4, 256).unwrap();
        original.reserved = 8;
        let mut partial = Vec::with_capacity(32);
        partial.extend_from_slice(b"com");
        original.transfers.insert(
            Id::new("partial").unwrap(),
            Transfer {
                reference,
                bytes: Rc::new(partial),
                complete: false,
            },
        );
        let encoded = serde_json::to_vec(&original.original_compact_protocol_view()).unwrap();
        let limits = CompactContentLimits {
            max_input_bytes: encoded.len(),
            max_rows: 1,
            max_groups: 1,
            max_first_group_capacity_bytes: 32,
        };
        let recovered = ClientContent::decode_compact_protocol_data(&encoded, limits).unwrap();
        assert_eq!(recovered.reserved, 8);
        let transfer = recovered.transfers.values().next().unwrap();
        assert!(!transfer.complete);
        assert_eq!(transfer.bytes.as_slice(), b"com");
        assert_eq!(transfer.bytes.capacity(), 32);

        let wrong = canonical::content_ref(b"wrong", "application/octet-stream").unwrap();
        let mut changed = ClientContent::new(1024, 4, 256).unwrap();
        changed.reserved = 5;
        changed.transfers.insert(
            Id::new("changed").unwrap(),
            Transfer {
                reference: wrong,
                bytes: Rc::new(b"other".to_vec()),
                complete: true,
            },
        );
        let encoded = serde_json::to_vec(&changed.original_compact_protocol_view()).unwrap();
        let limits = CompactContentLimits {
            max_input_bytes: encoded.len(),
            max_rows: 1,
            max_groups: 1,
            max_first_group_capacity_bytes: 5,
        };
        assert!(ClientContent::decode_compact_protocol_data(&encoded, limits).is_err());
    }
}
