//! Derives the four additional immutable output reservations for Capture17.
//!
//! These counters are inert until the admitted SDK construction installs its
//! one-use Capture owner. Existing objects, transfers, aliases and consumed
//! reservations remain owned; no existing allowance is recycled.

use super::*;

/// Binds prospective output capacity to the exact current content counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::client) struct CaptureContentCapacityData {
    current: [usize; 7],
    bytes: usize,
    objects: usize,
}

impl CaptureContentCapacityData {
    /// Returns the old byte allowance plus all four maximum output lengths.
    pub(in crate::client) const fn byte_ceiling(self) -> usize {
        self.bytes
    }

    /// Returns the old object allowance plus four distinct output slots.
    pub(in crate::client) const fn object_ceiling(self) -> usize {
        self.objects
    }
}

impl ClientContent {
    fn capture_capacity_counters(&self) -> Result<[usize; 7], ProviderError> {
        let unfinished = self
            .transfers
            .values()
            .filter(|transfer| !transfer.complete)
            .try_fold(0usize, |sum, transfer| {
                sum.checked_add(transfer.bytes.len()).ok_or_else(refused)
            })?;

        Ok([
            self.maximum_bytes,
            self.maximum_objects,
            self.maximum_chunk,
            self.reserved,
            self.transfers.len(),
            self.objects.len(),
            unfinished,
        ])
    }

    /// Derives additional capacity for four outputs while retaining all old credit.
    ///
    /// # Errors
    /// Refuses arithmetic overflow or absolute byte/object limits.
    pub(in crate::client) fn capture_capacity_data(
        &self,
        output_lengths: [usize; 4],
    ) -> Result<CaptureContentCapacityData, ProviderError> {
        let growth = output_lengths.into_iter().try_fold(0usize, |sum, length| {
            sum.checked_add(length).ok_or_else(refused)
        })?;
        let bytes = self
            .maximum_bytes
            .checked_add(growth)
            .filter(|value| *value <= 512 * 1024 * 1024)
            .ok_or_else(refused)?;
        let objects = self
            .maximum_objects
            .checked_add(output_lengths.len())
            .filter(|value| *value <= 4096)
            .ok_or_else(refused)?;

        Ok(CaptureContentCapacityData {
            current: self.capture_capacity_counters()?,
            bytes,
            objects,
        })
    }

    /// Checks the exact current limits, consumed credit and mutable payload extent.
    ///
    /// # Errors
    /// Refuses a changed content counter or overflowing partial-transfer extent.
    pub(in crate::client) fn authenticate_capture_capacity_data(
        &self,
        capacity: &CaptureContentCapacityData,
    ) -> Result<(), ProviderError> {
        if self.capture_capacity_counters()? != capacity.current {
            return Err(refused());
        }
        Ok(())
    }

    /// Applies a separately admitted extension without moving content allocations.
    ///
    /// # Errors
    /// Refuses stale counters before changing either finite ceiling.
    pub(in crate::client) fn retain_capture_capacity_data(
        &mut self,
        capacity: &CaptureContentCapacityData,
    ) -> Result<(), ProviderError> {
        self.authenticate_capture_capacity_data(capacity)?;
        // Every checked scalar and current-state comparison precedes mutation.
        self.maximum_bytes = capacity.bytes;
        self.maximum_objects = capacity.objects;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("settled Capture content capacity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Bytes, Extensions, canonical};

    fn complete(content: &mut ClientContent, id: &str, bytes: &[u8]) -> ContentRef {
        let reference = canonical::content_ref(bytes, "application/octet-stream").unwrap();
        let transfer_id = Id::new(id).unwrap();
        content
            .begin(&BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })
            .unwrap();
        content
            .chunk(&BlobChunkRequest {
                transfer_id: transfer_id.clone(),
                offset: U64::new(0),
                bytes: Bytes::new(bytes.to_vec()),
                extensions: Extensions::new(),
            })
            .unwrap();
        content
            .finish(&BlobFinishRequest {
                transfer_id,
                extensions: Extensions::new(),
            })
            .unwrap();
        reference
    }

    #[test]
    fn four_outputs_preserve_consumed_reservations_aliases_and_exact_limits() {
        let mut content = ClientContent::new(3, 1, 8).unwrap();
        let original = complete(&mut content, "original", b"old");
        let pointer = content.get(&original).unwrap().as_ptr();
        let capacity = content.capture_capacity_data([1, 2, 3, 4]).unwrap();
        assert!(content.preflight_capacity(4, 10).is_err());

        content.retain_capture_capacity_data(&capacity).unwrap();

        content.preflight_capacity(4, 10).unwrap();
        assert!(content.preflight_capacity(5, 10).is_err());
        assert!(content.preflight_capacity(4, 11).is_err());
        assert_eq!(content.reserved, 3);
        assert_eq!(content.maximum_chunk, 8);
        assert_eq!(content.get(&original).unwrap().as_ptr(), pointer);
        let transfer = &content.transfers[&Id::new("original").unwrap()];
        assert!(Rc::ptr_eq(
            &transfer.bytes,
            &content.objects[&original.hash.digest].1
        ));

        for (id, bytes) in [
            ("snapshot", &b"a"[..]),
            ("control", &b"bb"[..]),
            ("anchor", &b"ccc"[..]),
            ("after", &b"dddd"[..]),
        ] {
            let reference = complete(&mut content, id, bytes);
            assert_eq!(content.get(&reference).unwrap(), bytes);
        }
        assert_eq!(content.reserved, 13);
        assert_eq!(content.objects.len(), 5);
        assert!(content.preflight_capacity(1, 1).is_err());
        assert!(content.retain_capture_capacity_data(&capacity).is_err());
        assert_eq!(content.get(&original).unwrap().as_ptr(), pointer);
    }

    #[test]
    fn prospective_receiver_and_history_quotes_equal_the_installed_limits() {
        let mut content = ClientContent::new(1, 1, 8).unwrap();
        let original = complete(&mut content, "original", b"x");
        let capacity = content.capture_capacity_data([2, 3, 4, 5]).unwrap();
        let old = content
            .observation_receive_content_storage_data(4096, 32, 65536)
            .unwrap();
        let prospective = content
            .observation_receive_capture_content_storage_data(4096, 32, 65536, &capacity)
            .unwrap();
        let old_encoding = content
            .capture_history_encoded_growth_data(32, 65536)
            .unwrap();
        let encoding = content
            .capture_history_encoded_growth_with_capacity_data(32, 65536, &capacity)
            .unwrap();
        assert!(prospective.0 > old.0);
        assert!(prospective.1 > old.1);
        assert!(encoding > old_encoding);

        content.retain_capture_capacity_data(&capacity).unwrap();

        assert_eq!(
            prospective,
            content
                .observation_receive_content_storage_data(4096, 32, 65536)
                .unwrap()
        );
        assert_eq!(
            encoding,
            content
                .capture_history_encoded_growth_data(32, 65536)
                .unwrap()
        );
        assert_eq!(content.get(&original).unwrap(), b"x");
    }

    #[test]
    fn changed_partial_transfer_refuses_stale_capacity_without_mutation() {
        let mut content = ClientContent::new(8, 2, 8).unwrap();
        let transfer_id = Id::new("incomplete").unwrap();
        content
            .begin(&BlobBeginRequest {
                transfer_id: transfer_id.clone(),
                content: canonical::content_ref(b"abcdef", "application/octet-stream").unwrap(),
                extensions: Extensions::new(),
            })
            .unwrap();
        let capacity = content.capture_capacity_data([1; 4]).unwrap();
        content
            .chunk(&BlobChunkRequest {
                transfer_id,
                offset: U64::new(0),
                bytes: Bytes::new(b"abc".to_vec()),
                extensions: Extensions::new(),
            })
            .unwrap();
        let before = serde_json::to_vec(&content.protocol_view()).unwrap();

        assert!(content.retain_capture_capacity_data(&capacity).is_err());
        assert!(
            content
                .observation_receive_capture_content_storage_data(4096, 8, 65536, &capacity)
                .is_err()
        );

        assert_eq!(
            serde_json::to_vec(&content.protocol_view()).unwrap(),
            before
        );
    }

    #[test]
    fn overflow_and_absolute_caps_refuse_before_changing_content() {
        for (bytes, objects, outputs) in [
            (512 * 1024 * 1024 - 4, 4092, [1; 4]),
            (512 * 1024 * 1024 - 3, 4092, [1; 4]),
            (8, 4093, [1; 4]),
            (8, 1, [usize::MAX, 1, 1, 1]),
        ] {
            let content = ClientContent::new(bytes, objects, 8).unwrap();
            let before = serde_json::to_vec(&content.protocol_view()).unwrap();
            assert_eq!(
                content.capture_capacity_data(outputs).is_ok(),
                bytes == 512 * 1024 * 1024 - 4
            );
            assert_eq!(
                serde_json::to_vec(&content.protocol_view()).unwrap(),
                before
            );
        }
    }
}
