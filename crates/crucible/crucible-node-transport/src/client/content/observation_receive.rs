//! Quotes actual immutable-content receiver ceilings for first-Observe suffixes.
//!
//! The generic receiver can retain unexpected or incomplete transfers while
//! waiting for the promised root. Existing byte/object ceilings remain exact;
//! this independent prospective row counts both real Rc views conservatively.
//! Current allocations remain independently visible to the owning census.

use super::*;
use crate::retained_metadata::requested_storage::{shared_header_storage_data, tree_storage_data};
use std::mem::{align_of, size_of};

impl ClientContent {
    pub(in crate::client) fn observation_receive_content_storage_data(
        &self,
        reference_backing: usize,
        maximum_new_requests: usize,
        maximum_wire_chunk: usize,
    ) -> Result<(usize, usize), ProviderError> {
        self.observation_receive_content_storage_for_limits_data(
            reference_backing,
            maximum_new_requests,
            maximum_wire_chunk,
            self.maximum_bytes,
            self.maximum_objects,
        )
    }

    pub(in crate::client) fn observation_receive_capture_content_storage_data(
        &self,
        reference_backing: usize,
        maximum_new_requests: usize,
        maximum_wire_chunk: usize,
        capacity: &capture_capacity::CaptureContentCapacityData,
    ) -> Result<(usize, usize), ProviderError> {
        self.authenticate_capture_capacity_data(capacity)?;
        self.observation_receive_content_storage_for_limits_data(
            reference_backing,
            maximum_new_requests,
            maximum_wire_chunk,
            capacity.byte_ceiling(),
            capacity.object_ceiling(),
        )
    }

    fn observation_receive_content_storage_for_limits_data(
        &self,
        reference_backing: usize,
        maximum_new_requests: usize,
        maximum_wire_chunk: usize,
        maximum_bytes: usize,
        maximum_objects: usize,
    ) -> Result<(usize, usize), ProviderError> {
        // A reserved length is numeric quota, not a Vec allocation. Every
        // append requires one newly journaled provider BlobChunk original.
        // Cached ACK replay returns before content mutation; a retained Chunk
        // without its ACK can only replay its original offset and bytes. Thus
        // each immutable request identity can append at most once.
        let chunk = self.maximum_chunk.min(maximum_wire_chunk);
        let future_bytes = mul(maximum_new_requests, chunk)?.min(maximum_bytes);
        let unfinished_bytes = self
            .transfers
            .values()
            .filter(|transfer| !transfer.complete)
            .try_fold(0usize, |sum, transfer| add(sum, transfer.bytes.len()))?;
        // Reallocation may copy existing unfinished bytes. Completed buffers
        // cannot append. Sum geometric Vec requests, including the nonzero
        // minimum for every possible bank; both Rc views remain visible to the
        // conservative census even when they share one immutable allocation.
        let possible_bytes = add(unfinished_bytes, future_bytes)?;
        let one_view = add(mul(2, possible_bytes)?, mul(8, maximum_objects)?)?;
        let both_views = mul(2, one_view)?;
        let headers = mul(
            mul(2, maximum_objects)?,
            add(
                size_of::<Vec<u8>>(),
                shared_header_storage_data(1, align_of::<Vec<u8>>())?,
            )?,
        )?;
        let reference_and_keys = mul(maximum_objects, add(mul(2, reference_backing)?, 128 + 64)?)?;
        let transfers = tree_storage_data(
            1,
            maximum_objects,
            size_of::<Id>() + size_of::<Transfer>(),
            align_of::<(Id, Transfer)>(),
        )?;
        let objects = tree_storage_data(
            1,
            maximum_objects,
            size_of::<String>() + size_of::<(ContentRef, Rc<Vec<u8>>)>(),
            align_of::<(String, (ContentRef, Rc<Vec<u8>>))>(),
        )?;
        let retained = [both_views, headers, reference_and_keys, transfers, objects]
            .into_iter()
            .try_fold(0, add)?;
        // The old buffer can coexist with its new request during one Chunk's
        // reallocation. Hash verification has an independent full reference.
        let transient = add(one_view, reference_backing)?;
        Ok((retained, transient))
    }

    pub(in crate::client) const fn observation_receive_maximum_chunk_data(&self) -> usize {
        self.maximum_chunk
    }

    pub(in crate::client) const fn observation_receive_content_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<[usize; 5]>()
            + size_of::<std::collections::btree_map::Values<'static, Id, Transfer>>()
            + size_of::<Option<&Transfer>>()
            + size_of::<[usize; 8]>()
            + size_of::<[usize; 7]>() * 2
            + size_of::<&capture_capacity::CaptureContentCapacityData>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<Result<(usize, usize), ProviderError>>()
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right)
        .ok_or(ProviderError::ResourceExhausted(
            "first Observe receiver content projection",
        ))
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right)
        .ok_or(ProviderError::ResourceExhausted(
            "first Observe receiver content projection",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Bytes, Extensions, canonical};

    #[test]
    fn incomplete_reserved_content_and_actual_alias_views_fit_without_refunding_current_storage() {
        let mut content = ClientContent::new(32, 4, 3).unwrap();
        let reference = canonical::content_ref(b"abcdef", "application/json").unwrap();
        let id = Id::new("retained-first-observe-transfer").unwrap();
        content
            .begin(&BlobBeginRequest {
                transfer_id: id.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        let initial = content
            .observation_receive_content_storage_data(4096, 4, 3)
            .unwrap();
        for (offset, bytes) in [(0, &b"abc"[..]), (3, &b"def"[..])] {
            content
                .chunk(&BlobChunkRequest {
                    transfer_id: id.clone(),
                    offset: U64::new(offset),
                    bytes: Bytes::new(bytes.to_vec()),
                    extensions: Extensions::new(),
                })
                .unwrap();
        }
        content
            .finish(&BlobFinishRequest {
                transfer_id: id,
                extensions: Extensions::new(),
            })
            .unwrap();
        assert!(
            initial.0
                >= content
                    .observation_receive_content_storage_data(4096, 4, 3)
                    .unwrap()
                    .0
        );
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        content.observe_owned_metadata(&mut observer).unwrap();
        let actual =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())
                .unwrap();
        assert!(actual <= initial.0, "actual {actual}, quoted {}", initial.0);
        assert_eq!(content.get(&reference).unwrap(), b"abcdef");
        assert!(
            content
                .observation_receive_content_storage_data(usize::MAX, 4, 3)
                .is_err()
        );
    }
}
