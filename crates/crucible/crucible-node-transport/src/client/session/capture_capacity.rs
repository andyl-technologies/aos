//! Prices the additional journal and four output reservations for Capture17.
//!
//! The construction row prices all receiver allocations under these future
//! counters. Only its retained one-use Capture assignment applies them; a DATA
//! quote alone grants no Source action or additional original namespace.

use super::*;
use crate::client::content::capture_capacity::CaptureContentCapacityData;

/// Binds prospective byte ceilings to the current unrecycled custody counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::client) struct CaptureCapacityData {
    current: [usize; 5],
    journal: usize,
    content: CaptureContentCapacityData,
}

impl CaptureCapacityData {
    /// Borrows the independently derived four-output content reservation.
    pub(in crate::client) const fn content(&self) -> &CaptureContentCapacityData {
        &self.content
    }
}

impl ClientCustody {
    fn capture_capacity_counters(&self) -> [usize; 5] {
        [
            self.maximum_requests,
            self.maximum_bytes,
            self.retained_bytes,
            self.controller.len(),
            self.provider.len(),
        ]
    }

    /// Derives future journal sides and four output reservations without effects.
    ///
    /// # Errors
    /// Refuses exhausted namespaces, arithmetic overflow or absolute byte/object caps.
    pub(in crate::client) fn capture_capacity_data(
        &self,
        outgoing: usize,
        incoming: usize,
        frame: usize,
        output_lengths: [usize; 4],
    ) -> Result<CaptureCapacityData, ProviderError> {
        if outgoing
            > self
                .maximum_requests
                .checked_sub(self.controller.len())
                .ok_or_else(refused)?
            || incoming
                != self
                    .maximum_requests
                    .checked_sub(self.provider.len())
                    .ok_or_else(refused)?
        {
            return Err(refused());
        }
        // Each future original retains its request and first response. Existing
        // unanswered originals may still acquire their first response without
        // consuming another namespace entry. Cached ACK replay adds no journal.
        let unanswered = self
            .originals()
            .filter(|original| original.response.is_none())
            .count();
        let sides = outgoing
            .checked_add(incoming)
            .and_then(|value| value.checked_mul(2))
            .and_then(|value| value.checked_add(unanswered))
            .ok_or_else(refused)?;
        // Journal debit measures normalized canonical JSON, not literal wire
        // length. In particular, numeric details can expand during JCS output.
        let canonical = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(frame)?
            .maximum_canonical_encoded_bytes;
        let growth = sides.checked_mul(canonical).ok_or_else(refused)?;
        let journal = self
            .maximum_bytes
            .checked_add(growth)
            .filter(|value| *value <= 512 * 1024 * 1024)
            .ok_or_else(refused)?;
        let content = self.content.capture_capacity_data(output_lengths)?;

        Ok(CaptureCapacityData {
            current: self.capture_capacity_counters(),
            journal,
            content,
        })
    }

    /// Checks that the quote still names the same consumed counters and limits.
    ///
    /// # Errors
    /// Refuses changed journal or content counters, including partial-transfer growth.
    pub(in crate::client) fn authenticate_capture_capacity_data(
        &self,
        capacity: &CaptureCapacityData,
    ) -> Result<(), ProviderError> {
        if self.capture_capacity_counters() != capacity.current {
            return Err(refused());
        }
        self.content
            .authenticate_capture_capacity_data(&capacity.content)
    }

    /// Applies a construction's quota extension after its once owner is retained.
    ///
    /// # Errors
    /// Refuses stale counters before changing either journal or content capacity.
    pub(in crate::client) fn retain_capture_capacity_data(
        &mut self,
        capacity: &CaptureCapacityData,
    ) -> Result<(), ProviderError> {
        self.authenticate_capture_capacity_data(capacity)?;
        self.content
            .retain_capture_capacity_data(&capacity.content)?;
        // No callback or fallible work follows the content counter mutation.
        self.maximum_bytes = capacity.journal;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("settled Capture journal capacity")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_and_content_grow_independently_without_recycling_consumed_bytes() {
        let mut custody = ClientCustody::new(8, ClientContent::new(16, 1, 8).unwrap()).unwrap();
        custody.retained_bytes = 7;
        let capacity = custody
            .capture_capacity_data(3, 8, 64, [1, 2, 3, 4])
            .unwrap();

        custody.retain_capture_capacity_data(&capacity).unwrap();

        let canonical = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(64).unwrap().maximum_canonical_encoded_bytes;
        let journal = 16 + 22 * canonical;
        assert_eq!(custody.byte_reservations(), (journal, 26));
        assert_eq!(custody.retained_bytes, 7);
        assert_eq!(custody.maximum_requests(), 8);
        custody.ensure_journal_room(journal - 7).unwrap();
        assert!(custody.ensure_journal_room(journal - 6).is_err());
        custody.content().preflight_capacity(5, 26).unwrap();
        assert!(custody.content().preflight_capacity(6, 26).is_err());
        assert!(custody.retain_capture_capacity_data(&capacity).is_err());
    }

    #[test]
    fn normalized_numeric_details_use_canonical_extent_instead_of_wire_length() {
        use crucible_node_format::canonical;

        let wire = br#"{"details":[1e20,1e20,1e20,1e20]}"#;
        let value = canonical::parse_json(wire, wire.len()).unwrap();
        let normalized = canonical::canonical_json(&value).unwrap();
        assert!(normalized.len() > wire.len());
        let mut custody = ClientCustody::new(2, ClientContent::new(1, 1, 8).unwrap()).unwrap();
        let capacity = custody
            .capture_capacity_data(0, 2, wire.len(), [1; 4])
            .unwrap();

        custody.retain_capture_capacity_data(&capacity).unwrap();

        let all_sides = 4 * normalized.len();
        assert!(all_sides > 1 + 4 * wire.len());
        custody.ensure_journal_room(all_sides).unwrap();
        assert_eq!(custody.maximum_requests(), 2);
    }

    #[test]
    fn stale_consumption_and_content_changes_leave_both_quotas_intact() {
        let mut custody = ClientCustody::new(8, ClientContent::new(16, 1, 8).unwrap()).unwrap();
        let capacity = custody.capture_capacity_data(3, 8, 64, [1; 4]).unwrap();
        custody.retained_bytes = 1;
        let before = serde_json::to_vec(&custody.protocol_view()).unwrap();

        assert!(custody.retain_capture_capacity_data(&capacity).is_err());

        assert_eq!(
            serde_json::to_vec(&custody.protocol_view()).unwrap(),
            before
        );
        custody.retained_bytes = 0;
        custody
            .content
            .install(
                crucible_node_format::canonical::content_ref(b"new", "application/octet-stream")
                    .unwrap(),
                b"new".to_vec(),
            )
            .unwrap();
        let before = serde_json::to_vec(&custody.protocol_view()).unwrap();
        assert!(custody.retain_capture_capacity_data(&capacity).is_err());
        assert_eq!(
            serde_json::to_vec(&custody.protocol_view()).unwrap(),
            before
        );
    }

    #[test]
    fn invalid_namespace_or_either_absolute_limit_leaves_the_custody_unchanged() {
        for (bytes, objects, outgoing, incoming, frame) in [
            (512 * 1024 * 1024 - 10, 1, 3, 8, 64),
            (16, 4093, 3, 8, 64),
            (16, 1, 9, 8, 64),
            (16, 1, 3, 7, 64),
            (16, 1, 3, 8, usize::MAX),
        ] {
            let custody =
                ClientCustody::new(8, ClientContent::new(bytes, objects, 8).unwrap()).unwrap();
            let before = serde_json::to_vec(&custody.protocol_view()).unwrap();

            assert!(
                custody
                    .capture_capacity_data(outgoing, incoming, frame, [1; 4])
                    .is_err()
            );

            assert_eq!(
                serde_json::to_vec(&custody.protocol_view()).unwrap(),
                before
            );
        }
    }
}
