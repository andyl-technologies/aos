//! Reconstructs only historical Bytes backing at its exact recorded capacity.
//!
//! The borrowed pass checks the actual unpadded URL-safe encoding with fixed
//! scratch. The build pass reserves the recorded Vec once and decodes in place.
//! This primitive creates DATA only; whole-family admission remains external.

use super::*;
use base64::Engine;
use crucible_node_contract::Bytes;
use std::mem::{align_of, size_of};

impl HistoricalType for Bytes {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<u8>(),
            align_of::<u8>(),
        )?;
        let encoded = plain_string(input)?.as_bytes();
        let mut decoded_bytes = 0usize;
        let mut scratch = [0u8; 3];
        for chunk in encoded.chunks(4) {
            let initialized = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode_slice(chunk, &mut scratch)
                .map_err(|_| invalid())?;
            decoded_bytes = decoded_bytes.checked_add(initialized).ok_or_else(invalid)?;
            if decoded_bytes > capacity {
                return Err(invalid());
            }
        }
        ledger.native17_target_vector_data::<u8>(capacity)?;
        if !build {
            return Ok(None);
        }

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| credit())?;
        if bytes.capacity() != capacity {
            return Err(credit());
        }
        bytes.resize(decoded_bytes, 0);
        let initialized = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut bytes)
            .map_err(|_| invalid())?;
        if initialized != decoded_bytes {
            return Err(invalid());
        }
        Ok(Some(Bytes::new(bytes)))
    }
}

/// Names fixed input, exact output, validation scratch and fallible-result views.
pub(crate) fn historical_bytes_counter_scratch_data() -> usize {
    size_of::<&mut Ledger<'static, 'static, 'static>>()
        + 3 * size_of::<&[u8]>()
        + size_of::<&str>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<&base64::engine::general_purpose::GeneralPurpose>()
        + size_of::<crate::retained_metadata::records::MetadataCapacityRecord>()
        + size_of::<
            Option<
                Result<crate::retained_metadata::records::MetadataCapacityRecord, ProviderError>,
            >,
        >()
        + size_of::<&mut [u8]>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<bool>()
        + size_of::<std::slice::Chunks<'static, u8>>()
        + size_of::<Option<&[u8]>>()
        + size_of::<[u8; 3]>()
        + 3 * size_of::<usize>()
        + size_of::<Option<usize>>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, base64::DecodeSliceError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Bytes>()
        + size_of::<Option<Bytes>>()
        + size_of::<Result<Option<Bytes>, ProviderError>>()
}

// crucible-lint: allow panic-shortcut -- actual Bytes/capacity roundtrips are test observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual historical encoding and allocation observations"
)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    };

    #[test]
    fn historical_bytes_preserves_actual_spare_capacity_without_encoding_copy() {
        let mut backing = Vec::with_capacity(31);
        backing.extend_from_slice(b"actual payload");
        let original = Bytes::new(backing);
        let input = serde_json::to_vec(&original).unwrap();
        let mut bank = MetadataRecordBank::reserve(1).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        observer.observe(&original).unwrap();
        let facts = observer.finish();
        let raw = serde_json::to_vec(&bank).unwrap();
        let rows =
            ValidatedMetadataRecords::validate(&raw, 1, facts.vector_capacity_bytes).unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 128,
            maximum_nodes: 8,
            maximum_depth: 8,
            maximum_owned_backing_bytes: facts.vector_capacity_bytes,
            maximum_tree_entries: 0,
        };
        let mut borrowed = Ledger::new(rows.rows(), limits);
        assert!(borrowed.read::<Bytes>(&input, false).unwrap().is_none());
        assert!(borrowed.rows.next().is_none());

        let mut build = Ledger::new(rows.rows(), limits);
        let restored = build.read::<Bytes>(&input, true).unwrap().unwrap();
        assert_eq!(restored, original);
        assert_eq!(
            restored.allocation_capacity(),
            original.allocation_capacity()
        );
        assert!(build.rows.next().is_none());
    }

    #[test]
    fn historical_bytes_rejects_small_capacity_and_noncanonical_encoding_in_preflight() {
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 128,
            maximum_nodes: 8,
            maximum_depth: 8,
            maximum_owned_backing_bytes: 32,
            maximum_tree_entries: 0,
        };
        let rows = ValidatedMetadataRecords::validate(br#"[["vector",1,1,1]]"#, 1, 1).unwrap();
        let mut ledger = Ledger::new(rows.rows(), limits);
        assert!(ledger.read::<Bytes>(br#""YWJj""#, false).is_err());
        for malformed in [
            br#""Y""#.as_slice(),
            br#""Zh""#,
            br#""Zg==""#,
            br#""+/8""#,
            br#""\u005a g""#,
        ] {
            let rows =
                ValidatedMetadataRecords::validate(br#"[["vector",32,1,1]]"#, 1, 32).unwrap();
            let mut ledger = Ledger::new(rows.rows(), limits);
            assert!(ledger.read::<Bytes>(malformed, false).is_err());
        }
    }
}
