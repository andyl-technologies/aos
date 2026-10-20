//! Quotes the actual native owned-eleven walk in its precharged original banks.
//!
//! The native SDK caller authenticates its original actor, installed source,
//! service loan and exact cut before invoking this data producer. The quote
//! creates no permit. It records actual rows, counts the exact encoder wrapper,
//! and retains partial banks on refusal without binding or publishing bytes.

use super::*;
use crate::retained_metadata::MetadataObserver;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeProtocolMetadataQuote {
    pub(crate) required_record_rows: usize,
    pub(crate) frame_bank_views: usize,
    pub(crate) required_alias_rows: usize,
    pub(crate) maximum_existing_alias_row_encoded_bytes: usize,
    pub(crate) observed_nodes: usize,
    pub(crate) encoded_extent: usize,
    pub(crate) selected_rows: usize,
    pub(crate) record_capacity: usize,
    pub(crate) record_bytes: usize,
    pub(crate) alias_row_capacity: usize,
    pub(crate) alias_lookup_capacity: usize,
    pub(crate) alias_row_bytes: usize,
    pub(crate) alias_lookup_bytes: usize,
}

impl ProtocolSnapshotReservation {
    pub(crate) fn quote_original_native_owned11<T: Serialize>(
        &mut self,
        data: &T,
        walk: impl FnOnce(&mut MetadataObserver) -> Result<(), ProviderError>,
    ) -> Result<NativeProtocolMetadataQuote, ProviderError> {
        self.quote_original_native_owned11_facts(data, walk)
            .map(|(quote, _)| quote)
    }

    /// Counts the same populated wrapper before selected native12 copies.
    ///
    /// The caller admits the actual serializer/Bytes counter phase first.
    /// Ordinary owned11 callers keep their existing one-extent-count path.
    pub(crate) fn quote_original_native_owned11_with_serialization_data<T: Serialize>(
        &mut self,
        data: &T,
        walk: impl FnOnce(&mut MetadataObserver) -> Result<(), ProviderError>,
        maximum_requested_bytes: usize,
    ) -> Result<
        (
            NativeProtocolMetadataQuote,
            crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
        ),
        ProviderError,
    > {
        let (quote, facts) = self.quote_original_native_owned11_facts(data, walk)?;
        let records = self
            .owned11_records
            .as_ref()
            .ok_or(ProviderError::Correlation("native record bank absent"))?;
        let aliases = self
            .owned11_aliases
            .as_ref()
            .ok_or(ProviderError::Correlation("native alias bank absent"))?;
        let view = ("source-private.cnp-protocol/11", data, records, aliases);
        let serialization =
            crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
                &view,
                facts,
                maximum_requested_bytes,
            )?;
        Ok((quote, serialization))
    }

    fn quote_original_native_owned11_facts<T: Serialize>(
        &mut self,
        data: &T,
        walk: impl FnOnce(&mut MetadataObserver) -> Result<(), ProviderError>,
    ) -> Result<
        (
            NativeProtocolMetadataQuote,
            crate::retained_metadata::RetainedProtocolMetadataFacts,
        ),
        ProviderError,
    > {
        if !self.unused_for_after_preflight() || !self.uses_owned11_encoding() {
            return Err(ProviderError::Correlation(
                "native metadata quote requires unused born banks",
            ));
        }
        let records = self
            .owned11_records
            .as_mut()
            .ok_or(ProviderError::Correlation("native record bank absent"))?;
        let aliases = self
            .owned11_aliases
            .as_mut()
            .ok_or(ProviderError::Correlation("native alias bank absent"))?;
        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        walk(&mut observer)?;
        let facts = observer.finish();
        let alias = aliases.allocation_facts();
        if records.rows().len() != facts.capacity_records
            || aliases.retained_rows() != facts.shared_backing_views
            || records.maximum_rows() != alias.maximum_rows
        {
            return Err(ProviderError::Correlation(
                "native metadata traversal bank correspondence",
            ));
        }
        // This is the exact encode_owned11 wrapper and actual completed rows,
        // not a selected byte ceiling or a prediction of later suffix traffic.
        let view = ("source-private.cnp-protocol/11", data, &*records, &*aliases);
        let encoded_extent = crate::connection::serialized_credit(&view, self.maximum)?;
        Ok((
            NativeProtocolMetadataQuote {
                required_record_rows: facts.capacity_records,
                frame_bank_views: aliases.retained_rows_of_kind(
                    crate::retained_metadata::aliases::MetadataSharedKind::FrameBank,
                ),
                required_alias_rows: facts.shared_backing_views,
                maximum_existing_alias_row_encoded_bytes: aliases
                    .maximum_existing_kind_row_encoding_data()?,
                observed_nodes: facts.observed_nodes,
                encoded_extent,
                selected_rows: records.maximum_rows(),
                record_capacity: records.capacity_rows(),
                record_bytes: records.allocated_bytes(),
                alias_row_capacity: alias.row_capacity,
                alias_lookup_capacity: alias.lookup_capacity,
                alias_row_bytes: alias.row_bytes,
                alias_lookup_bytes: alias.lookup_bytes,
            },
            facts,
        ))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "real precharged metadata bank boundary assertions"
)]
mod tests {
    use super::*;
    use crate::retained_metadata::aliases::MetadataSharedKind;
    use std::rc::Rc;

    fn walk(
        observer: &mut MetadataObserver,
        text: &String,
        shared: &Rc<u64>,
    ) -> Result<(), ProviderError> {
        observer.observe(text)?;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, shared.as_ref())
    }

    #[test]
    fn selected_serializer_events_cover_actual_populated_wrapper_without_binding() {
        let text = String::from("same original wrapper");
        let shared = Rc::new(7u64);
        let mut bank =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let (quote, serialization) = bank
            .quote_original_native_owned11_with_serialization_data(
                &text,
                |observer| walk(observer, &text, &shared),
                1024 * 1024,
            )
            .unwrap();
        assert!(bank.bytes.is_empty() && bank.issuer.is_none());
        assert_eq!(quote.required_record_rows, 2);
        assert_eq!(quote.required_alias_rows, 1);
        bank.encode_owned11(&text).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bank.bytes).unwrap();
        let encoded_tree =
            crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
                &value,
                Default::default(),
                1024 * 1024,
            )
            .unwrap();

        assert_eq!(
            serialization.serialized_value_nodes,
            encoded_tree.serialized_value_nodes
        );
        assert_eq!(
            serialization.serialized_capacity_records,
            encoded_tree.serialized_capacity_records
        );
        assert!(serialization.maximum_encoded_bytes >= bank.bytes.len());
        assert_eq!(quote.encoded_extent, bank.bytes.len());
    }

    #[test]
    fn selected_serializer_storage_refusal_retains_same_actual_unbound_rows() {
        let text = String::from("same original wrapper");
        let shared = Rc::new(7u64);
        let mut bank =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let original_pointer = bank.bytes.as_ptr();

        assert!(
            bank.quote_original_native_owned11_with_serialization_data(
                &text,
                |observer| walk(observer, &text, &shared),
                1,
            )
            .is_err()
        );

        assert_eq!(bank.bytes.as_ptr(), original_pointer);
        assert!(bank.bytes.is_empty() && bank.issuer.is_none());
        assert_eq!(bank.owned11_records.as_ref().unwrap().rows().len(), 2);
        assert_eq!(bank.owned11_aliases.as_ref().unwrap().retained_rows(), 1);
    }

    #[test]
    fn exact_metadata_rows_admit_and_one_short_retains_partial_original_bank() {
        let mut text = String::with_capacity(17);
        text.push_str("original");
        let shared = Rc::new(3u64);
        let mut exact =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let before = exact.original_allocation_facts().unwrap();
        let quote = exact
            .quote_original_native_owned11(&text, |observer| walk(observer, &text, &shared))
            .unwrap();
        assert_eq!(quote.required_record_rows, 2);
        assert_eq!(quote.required_alias_rows, 1);
        assert_eq!(quote.selected_rows, 2);
        exact.encode_owned11(&text).unwrap();
        assert_eq!(exact.bytes.len(), quote.encoded_extent);
        assert_eq!(exact.bytes.capacity(), before.encoded_capacity);

        let mut short =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 1).unwrap();
        let pointer = short.bytes.as_ptr();
        assert!(
            short
                .quote_original_native_owned11(&text, |observer| walk(observer, &text, &shared))
                .is_err()
        );
        assert_eq!(short.owned11_records.as_ref().unwrap().rows().len(), 1);
        assert_eq!(short.bytes.as_ptr(), pointer);
        assert!(short.bytes.is_empty() && short.issuer.is_none());
    }

    #[test]
    fn exact_encoded_quote_matches_encoder_and_one_byte_short_publishes_nothing() {
        let text = String::from("same original metadata");
        let shared = Rc::new(9u64);
        let mut measuring =
            ProtocolSnapshotReservation::reserve_complete_owned11(4096, 64, 4, 2).unwrap();
        let quote = measuring
            .quote_original_native_owned11(&text, |observer| walk(observer, &text, &shared))
            .unwrap();
        let mut exact =
            ProtocolSnapshotReservation::reserve_complete_owned11(quote.encoded_extent, 64, 4, 2)
                .unwrap();
        let exact_quote = exact
            .quote_original_native_owned11(&text, |observer| walk(observer, &text, &shared))
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
        assert!(
            short
                .quote_original_native_owned11(&text, |observer| walk(observer, &text, &shared))
                .is_err()
        );
        assert_eq!(short.owned11_records.as_ref().unwrap().rows().len(), 2);
        assert!(short.bytes.is_empty() && short.issuer.is_none());
    }
}
