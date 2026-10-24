//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, Import17, import_fields17,
};

import_fields17!(HistoricalNativeState => HistoricalNativeHeap17, "source-private.current-import-historical-native-state/17", {
    connection: HistoricalNativeConnection,
    blobs: HistoricalNativeBlobReceiver,
    service: HistoricalNativeService,
    capture_allocation: Option<super::super::capture_owner::HistoricalNativeCaptureAllocationOwner>,
});

import_fields17!(SealedHistoricalNativeState => HistoricalSealedNativeImport17, "source-private.current-import-sealed-historical-native-state/17", {
    reference: crucible_node_format::ContentRef,
    encoded: Vec<u8>,
    historical: Option<HistoricalNativeState>,
    correlation_capacity_span: (usize, usize),
    complete: bool,
});

impl SealedHistoricalNativeState {
    /// Borrows the initialized current heap, including failed reconstruction.
    pub(crate) fn borrowed_current17_data(
        &self,
    ) -> Result<impl serde::Serialize + '_, crate::ProviderError> {
        Ok(BorrowedImport17(self))
    }
    /// Walks actual current retained backing without requiring completion.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), crate::ProviderError> {
        self.observe_current(observer)
    }
}

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeState>()
        + std::mem::size_of::<HistoricalNativeHeap17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeState>>()
        + std::mem::size_of::<Result<Option<HistoricalNativeHeap17>, crate::ProviderError>>()
        + std::mem::size_of::<SealedHistoricalNativeState>()
        + std::mem::size_of::<HistoricalSealedNativeImport17>()
        + std::mem::size_of::<BorrowedImport17<'static, SealedHistoricalNativeState>>()
        + std::mem::size_of::<Result<Option<HistoricalSealedNativeImport17>, crate::ProviderError>>(
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, ValidatedMetadataRecords},
    };

    #[test]
    fn incomplete_owner_preserves_encoded_spare_bank_without_decoded_root() {
        let mut encoded = Vec::with_capacity(89);
        encoded.extend_from_slice(b"partial-import");
        let reference = crucible_node_format::ContentRef {
            hash: crucible_node_format::canonical::hash("cnp.blob.v1", &encoded).unwrap(),
            length: crucible_node_format::U64::new(encoded.len() as u64),
            media_type: "application/x-native-import-test".to_owned(),
        };
        let owner = SealedHistoricalNativeState {
            reference,
            encoded,
            historical: None,
            correlation_capacity_span: (7, 11),
            complete: false,
        };
        let input = serde_json::to_vec(&owner.borrowed_current17_data().unwrap()).unwrap();
        let mut bank = MetadataRecordBank::reserve(32).unwrap();
        let mut observer = MetadataObserver::recording(&mut bank);
        owner
            .observe_current17_metadata_data(&mut observer)
            .unwrap();
        let _ = observer.finish();
        let rows = serde_json::to_vec(&bank).unwrap();
        let records = ValidatedMetadataRecords::validate(&rows, 32, 65536).unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 65536,
            maximum_nodes: 1024,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 65536,
            maximum_tree_entries: 1024,
        };
        let mut passive = Ledger::new(records.rows(), limits);
        assert!(
            passive
                .read::<HistoricalSealedNativeImport17>(&input, false)
                .unwrap()
                .is_none()
        );
        assert!(passive.rows.next().is_none());
        let mut building = Ledger::new(records.rows(), limits);
        let historical = building
            .read::<HistoricalSealedNativeImport17>(&input, true)
            .unwrap()
            .unwrap();
        assert_eq!(historical.encoded, owner.encoded);
        assert_eq!(historical.encoded.capacity(), owner.encoded.capacity());
        assert!(historical.historical.is_none());
        assert_eq!(historical.correlation_capacity_span, (7, 11));
        assert!(!historical.complete);
        assert!(building.rows.next().is_none());
    }
}
