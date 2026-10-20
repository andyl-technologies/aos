//! Reports the exact current host encoding in its actual precharged banks.
//!
//! These data facts describe one borrowed state. They do not predict a later
//! Capture suffix, bind an operational cut or grant semantic/archive authority.

use super::*;

/// Describes the exact current complete host view and its retained bank layouts.
///
/// A later protocol operation can change these values. The source separately
/// admits future windows and rechecks the actual settled owner before adoption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalOwned11StateQuote {
    /// Counts actual capacity rows required by the complete typed walk.
    pub required_record_rows: usize,
    /// Counts actual shared backing views required by the alias walk.
    pub required_alias_rows: usize,
    /// Counts actual nodes visited by the bounded typed walk.
    pub observed_nodes: usize,
    /// Counts exact bytes from the same wrapper and data tuple as capture.
    pub encoded_extent: usize,
    /// Describes the actual independent encoded and literal-copy banks.
    pub snapshot_allocation: ProtocolSnapshotAllocationFacts,
    /// Describes the actual populated metadata-record bank.
    pub metadata_allocation: MetadataRecordAllocationFacts,
    /// Describes the actual populated alias and temporary lookup banks.
    pub alias_allocation: MetadataAliasAllocationFacts,
    /// Describes the same current original literal bank and its counters.
    pub original_storage: OriginalProtocolStorageFacts,
}

impl ProtocolSnapshotReservation {
    pub(crate) fn quote_original_host_owned11<T: Serialize>(
        &mut self,
        data: &T,
        original_storage: OriginalProtocolStorageFacts,
        walk: impl FnOnce(&mut crate::retained_metadata::MetadataObserver) -> Result<(), ProviderError>,
    ) -> Result<OriginalOwned11StateQuote, ProviderError> {
        let quote = self.quote_original_native_owned11(data, walk)?;
        Ok(OriginalOwned11StateQuote {
            required_record_rows: quote.required_record_rows,
            required_alias_rows: quote.required_alias_rows,
            observed_nodes: quote.observed_nodes,
            encoded_extent: quote.encoded_extent,
            snapshot_allocation: self.original_allocation_facts()?,
            metadata_allocation: self.original_metadata_record_allocation_facts()?.ok_or(
                ProviderError::Correlation("host quote original record bank absent"),
            )?,
            alias_allocation: self.original_alias_allocation_facts()?.ok_or(
                ProviderError::Correlation("host quote original alias bank absent"),
            )?,
            original_storage,
        })
    }
}

// crucible-lint: allow panic-shortcut -- Host quote controls deliberately panic on broken exact-bank invariants.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "checks real precharged data-bank boundaries"
)]
mod tests {
    use super::*;
    use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};

    fn walk(
        observer: &mut MetadataObserver,
        text: &String,
        shared: &Rc<u64>,
    ) -> Result<(), ProviderError> {
        observer.observe(text)?;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, shared.as_ref())
    }

    #[test]
    fn host_quote_counts_same_encoder_without_binding_or_copying_literals() {
        let text = String::from("actual borrowed host data");
        let shared = Rc::new(7u64);
        let original =
            crate::transport::original_frames::OriginalFrameReservation::reserve(64, 4).unwrap();
        let original_facts = original.storage_facts(65536);
        let mut reservation =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let before = reservation.original_allocation_facts().unwrap();
        let quote = reservation
            .quote_original_host_owned11(&text, original_facts, |observer| {
                walk(observer, &text, &shared)
            })
            .unwrap();

        assert_eq!(quote.required_record_rows, 2);
        assert_eq!(quote.required_alias_rows, 1);
        assert_eq!(quote.metadata_allocation.retained_rows, 2);
        assert_eq!(quote.alias_allocation.retained_rows, 1);
        assert_eq!(quote.original_storage, original_facts);
        assert_eq!(quote.snapshot_allocation, before);
        assert!(reservation.issuer.is_none() && reservation.bytes.is_empty());
        assert_eq!(reservation.literal.as_ref().unwrap().frames().count(), 0);
        reservation.encode_owned11(&text).unwrap();
        assert_eq!(reservation.bytes.len(), quote.encoded_extent);
        assert_eq!(reservation.bytes.capacity(), before.encoded_capacity);
    }

    #[test]
    fn host_quote_exact_encoding_limit_and_short_rows_retain_preowned_banks() {
        let text = String::from("host quote limit data");
        let shared = Rc::new(9u64);
        let original =
            crate::transport::original_frames::OriginalFrameReservation::reserve(64, 4).unwrap();
        let original_facts = original.storage_facts(65536);
        let mut measuring =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let quote = measuring
            .quote_original_host_owned11(&text, original_facts, |observer| {
                walk(observer, &text, &shared)
            })
            .unwrap();
        let mut exact =
            ProtocolSnapshotReservation::reserve_complete_owned11(quote.encoded_extent, 64, 4, 2)
                .unwrap();
        let exact_quote = exact
            .quote_original_host_owned11(&text, original_facts, |observer| {
                walk(observer, &text, &shared)
            })
            .unwrap();
        exact.encode_owned11(&text).unwrap();
        assert_eq!(exact.bytes.len(), exact_quote.encoded_extent);

        let mut short = ProtocolSnapshotReservation::reserve_complete_owned11(
            quote.encoded_extent - 1,
            64,
            4,
            2,
        )
        .unwrap();
        let before = short.bytes.as_ptr();
        assert!(
            short
                .quote_original_host_owned11(&text, original_facts, |observer| walk(
                    observer, &text, &shared
                ),)
                .is_err()
        );
        assert!(short.bytes.is_empty() && short.issuer.is_none());
        assert_eq!(short.bytes.as_ptr(), before);
        assert_eq!(short.owned11_records.as_ref().unwrap().rows().len(), 2);

        let mut short_rows =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 1).unwrap();
        assert!(
            short_rows
                .quote_original_host_owned11(&text, original_facts, |observer| walk(
                    observer, &text, &shared
                ),)
                .is_err()
        );
        assert_eq!(short_rows.owned11_records.as_ref().unwrap().rows().len(), 1);
        assert!(short_rows.bytes.is_empty() && short_rows.issuer.is_none());
    }
}
