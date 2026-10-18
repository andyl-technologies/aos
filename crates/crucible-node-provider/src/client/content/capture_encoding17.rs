//! Bounds future encoded receiver custody, including original alias metadata.
//!
//! A provider original can append at most once. Existing unfinished aliases may
//! split during append, so their complete logical lengths are counted again.
//! This is an encoded growth bound; no byte capacity or content quota is minted.

use super::*;
use crate::client::history_encoding17 as json;

impl ClientContent {
    pub(in crate::client) fn capture_history_encoded_growth_data(
        &self,
        maximum_mutating_provider_originals: usize,
        frame: usize,
    ) -> Result<usize, ProviderError> {
        let chunk = self.maximum_chunk.min(frame);
        let appended =
            json::multiply(maximum_mutating_provider_originals, chunk)?.min(self.maximum_bytes);
        let unfinished = self
            .transfers
            .values()
            .filter(|transfer| !transfer.complete)
            .try_fold(0usize, |sum, transfer| json::add(sum, transfer.bytes.len()))?;
        let payload = json::compact_bytes(json::add(unfinished, appended)?)?;
        let rows = maximum_mutating_provider_originals.min(self.maximum_objects);
        let reference = json::content_reference()?;
        let alias = json::array(1, json::literal("transfer")?)?
            .checked_add(json::DECIMAL + 1)
            .ok_or_else(json::exhausted)?;
        let metadata = json::array(5, json::DECIMAL)?;

        // New transfer/object rows keep independent keys/fullrefs and capacity
        // rows, even when their Rc payload aliases. Repeated payload is bounded
        // separately below without assuming equality identifies allocations.
        let transfer = json::array(1, json::string(128)?)?;
        let transfer = [reference, alias, json::DECIMAL, 5, 4]
            .into_iter()
            .try_fold(transfer, |sum, width| json::add(sum, json::add(width, 1)?))?;
        let object = json::array(1, 66)?;
        let object = [reference, alias, json::DECIMAL, 4]
            .into_iter()
            .try_fold(object, |sum, width| json::add(sum, json::add(width, 1)?))?;
        let new_rows = json::multiply(
            rows,
            json::add(json::add(transfer, object)?, json::multiply(2, metadata)?)?,
        )?;

        // Inserting sorted keys can change old alias ordinals. Existing mutable
        // byte-bank capacity decimals can also grow, without growing metadata
        // strings. Count complete old alias/capacity rows rather than borrowing
        // their already-encoded digits from the independently funded baseline.
        let existing = json::add(self.transfers.len(), self.objects.len())?;
        let changed_rows = json::multiply(
            existing,
            json::add(json::add(alias, json::DECIMAL)?, metadata)?,
        )?;
        // Two conservative serialized views cover any transfer/object payload
        // edge arrangement, including equal distinct allocations. Per-bank
        // compact headers/chunk rounding are priced once for every possible row.
        let banks = json::add(existing, json::multiply(2, rows)?)?;
        let headers = json::multiply(banks, 64 + 4 + 3)?;
        [
            json::multiply(2, payload)?,
            headers,
            new_rows,
            changed_rows,
            json::DECIMAL,
        ]
        .into_iter()
        .try_fold(0, json::add)
    }

    pub(in crate::client) fn capture_history_encoding_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<std::collections::btree_map::Values<'static, Id, Transfer>>()
            + std::mem::size_of::<[usize; 5]>() * 2
            + std::mem::size_of::<std::array::IntoIter<usize, 5>>()
            + json::counter_scratch_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{Bytes, Extensions, canonical};

    #[test]
    fn actual_receiver_partial_completion_and_alias_metadata_fit_encoded_growth()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut content = ClientContent::new(65_536, 16, 3073)?;
        let payload = vec![255u8; 6147];
        let reference = canonical::content_ref(&payload, "application/json")?;
        let transfer = Id::new("encoded-growth-real-transfer")?;
        content.begin(&BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: reference.clone(),
            extensions: Extensions::new(),
        })?;
        content.chunk(&BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(0),
            bytes: Bytes::new(payload[..3073].to_vec()),
            extensions: Extensions::new(),
        })?;
        let before = serde_json::to_vec(&content.original_compact_metadata8_view())?;
        let quote = content.capture_history_encoded_growth_data(4, 65_536)?;

        content.chunk(&BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(3073),
            bytes: Bytes::new(payload[3073..6146].to_vec()),
            extensions: Extensions::new(),
        })?;
        content.chunk(&BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(6146),
            bytes: Bytes::new(payload[6146..].to_vec()),
            extensions: Extensions::new(),
        })?;
        content.finish(&BlobFinishRequest {
            transfer_id: transfer.clone(),
            extensions: Extensions::new(),
        })?;
        let after = serde_json::to_vec(&content.original_compact_metadata8_view())?;
        assert!(after.len().saturating_sub(before.len()) <= quote);
        assert_eq!(content.get(&reference)?, payload);
        assert!(Rc::ptr_eq(
            &content
                .transfers
                .get(&transfer)
                .ok_or("missing transfer")?
                .bytes,
            &content
                .objects
                .get(&reference.hash.digest)
                .ok_or("missing object")?
                .1,
        ));
        let pointer = content.get(&reference)?.as_ptr();
        content.finish(&BlobFinishRequest {
            transfer_id: transfer,
            extensions: Extensions::new(),
        })?;
        assert_eq!(content.get(&reference)?.as_ptr(), pointer);
        assert_eq!(
            serde_json::to_vec(&content.original_compact_metadata8_view())?,
            after
        );
        Ok(())
    }

    #[test]
    fn existing_unfinished_shared_payload_split_is_independently_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut content = ClientContent::new(65_536, 16, 3073)?;
        let reference = canonical::content_ref(b"abcdefgh", "application/json")?;
        let first = Id::new("first")?;
        content.begin(&BlobBeginRequest {
            transfer_id: first.clone(),
            content: reference.clone(),
            extensions: Extensions::new(),
        })?;
        content.chunk(&BlobChunkRequest {
            transfer_id: first.clone(),
            offset: U64::new(0),
            bytes: Bytes::new(b"abcd".to_vec()),
            extensions: Extensions::new(),
        })?;
        // Preserve an actual parent-owned Rc alias as inert receiver DATA. An
        // append exercises defining Rc::make_mut and must price both groups.
        let alias = Rc::clone(&content.transfers.get(&first).ok_or("missing first")?.bytes);
        content.transfers.insert(
            Id::new("second")?,
            Transfer {
                reference: reference.clone(),
                bytes: alias,
                complete: false,
            },
        );
        let before = serde_json::to_vec(&content.original_compact_metadata8_view())?;
        let quote = content.capture_history_encoded_growth_data(1, 65_536)?;
        content.chunk(&BlobChunkRequest {
            transfer_id: first.clone(),
            offset: U64::new(4),
            bytes: Bytes::new(b"efgh".to_vec()),
            extensions: Extensions::new(),
        })?;
        let after = serde_json::to_vec(&content.original_compact_metadata8_view())?;
        assert!(after.len().saturating_sub(before.len()) <= quote);
        assert!(!Rc::ptr_eq(
            &content.transfers.get(&first).ok_or("missing first")?.bytes,
            &content
                .transfers
                .get(&Id::new("second")?)
                .ok_or("missing second")?
                .bytes,
        ));
        assert!(
            content
                .capture_history_encoded_growth_data(usize::MAX, usize::MAX)
                .is_err()
        );
        Ok(())
    }
}
