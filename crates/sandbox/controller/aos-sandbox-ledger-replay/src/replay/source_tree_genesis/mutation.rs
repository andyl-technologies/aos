//! Keeps the original Source genesis mutation comparison and COMMIT DATA.
//!
//! Error-only parameters preserve native owning categories before parking.
//! No supplied schema, callback, writer or currentness grant enters this work.

use super::*;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use crate::replay::hierarchy_records::HierarchyProtectedRecordKindV1;

// This is a pure model destination, never an append permission or IO borrower.
/// Keeps the original complete Source genesis mutation comparison DATA.
pub struct SourceGenesisMutationOriginalsV1<
    E = JournalError,
    H = DomainLedgerDataError,
    R = crate::genesis::SourceGenesisReceiptDataErrorV1,
> {
    pub parser: SourceGenesisRowsOriginalsV1<E, R>,
    pub rows: Option<SourceGenesisRowsV1>,
    pub receipt: Option<SourceTreeGenesisReceiptV1>,
    pub receipt_decode: Option<crate::genesis::SourceGenesisReceiptDecodeOriginalsV1<R>>,
    pub pending: Option<SourceGenesisPendingV1>,
    pub ack: Option<SourceGenesisAckV1>,
    pub key: Option<aos_sandbox_protocol::domain_ledger::records::DomainKeyDecodeCaptureV1<crate::replay::hierarchy_records::HierarchyProtectedJournalSchemaV1>>,
    pub predecessor: super::super::source_tree_successor::SourceGenesisPredecessorOriginalsV1<E, H, R>,
    pub classification: super::classification::SourceGenesisProtectedRecordScanOriginalsV1<E>,
    pub result: Option<Result<(), E>>,
    pub closed: Option<E>,
    pub entered: bool,
}

impl<E, H, R> SourceGenesisMutationOriginalsV1<E, H, R>
where
    E: From<JournalError> + std::error::Error + 'static,
    H: From<DomainLedgerDataError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
{
    /// Creates an inert original comparison destination.
    pub fn new() -> Self {
        Self {
            parser: SourceGenesisRowsOriginalsV1::new(), rows: None, receipt: None, receipt_decode: None,
            pending: None, ack: None, key: None,
            predecessor: super::super::source_tree_successor::SourceGenesisPredecessorOriginalsV1::new(),
            classification: super::classification::SourceGenesisProtectedRecordScanOriginalsV1::new(),
            result: None, closed: None, entered: false,
        }
    }

    /// Runs the original selected genesis mutation comparison once.
    ///
    /// # Errors
    /// Rejects repeated or inconsistent comparison work, or geometry overflow.
    pub fn observe_once(
        &mut self,
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        transition: SourceGenesisTransitionV1,
    ) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.result = Some(require_no_mutation_engine(state, transaction, transition, Some(self)));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(E::from(JournalError::ProtectedBoundary)) }
    }

    /// Borrows the first original comparison or parser cause.
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.parser.cause()
            .or_else(|| self.receipt_decode.as_ref().and_then(|capture| capture.failure()))
            .or_else(|| self.predecessor.cause())
            .or_else(|| self.classification.cause())
            .or_else(|| self.key.as_ref().and_then(|key| key.failure()).map(|cause| cause as _))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Returns the original fixed comparison construction footprint.
    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
        use aos_sandbox_protocol::domain_ledger::records::DomainKeyDecodeCaptureV1;
        use super::super::source_tree_successor::SourceGenesisPredecessorOriginalsV1;
        use std::mem::size_of;
        type KeyCapture = DomainKeyDecodeCaptureV1<crate::replay::hierarchy_records::HierarchyProtectedJournalSchemaV1>;
        type ReceiptCapture<R> = crate::genesis::SourceGenesisReceiptDecodeOriginalsV1<R>;
        let (receipt_bytes, receipt_cells) = ReceiptCapture::<R>::fixed_footprint_v1()?;
        let (parser_bytes, parser_cells) = SourceGenesisRowsOriginalsV1::<E, R>::fixed_footprint_v1()?;
        let (classification_bytes, classification_cells) = super::classification::SourceGenesisProtectedRecordScanOriginalsV1::<E>::fixed_footprint_v1()?;
        let (predecessor_bytes, predecessor_cells) = SourceGenesisPredecessorOriginalsV1::<E, H, R>::fixed_footprint_v1()?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(fixed_row_decode_peak_bytes_v1::<E>()?)?
            .checked_add(receipt_bytes.checked_sub(size_of::<ReceiptCapture<R>>().checked_mul(2)?)?)?
            .checked_add(size_of::<Option<&mut Option<ReceiptCapture<R>>>>())?
            .checked_add(classification_bytes.checked_sub(size_of::<super::classification::SourceGenesisProtectedRecordScanOriginalsV1>().checked_mul(2)?)?)?
            .checked_add(parser_bytes.checked_sub(size_of::<SourceGenesisRowsOriginalsV1<E, R>>().checked_mul(2)?)?)?
            .checked_add(predecessor_bytes.checked_sub(size_of::<SourceGenesisPredecessorOriginalsV1<E, H, R>>().checked_mul(2)?)?)?
            .checked_add(KeyCapture::receiving_construction_bytes_v1()?.checked_sub(size_of::<KeyCapture>().checked_mul(2)?)?)?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisRowsV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceTreeGenesisReceiptV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisPendingV1>>())?
            .checked_add(size_of::<CaptureOnDropV1<'static, SourceGenesisAckV1>>())?
            .checked_add(RECEIPT_PREFIX.len().checked_add(16)?)?
            .checked_add(ACK_PREFIX.len().checked_add(16)?)?
            .checked_add(size_of::<Vec<u8>>().checked_mul(3)?)?
            .checked_add(size_of::<(RecordNamespace, Vec<u8>)>())?
            .checked_add(size_of::<[HierarchyProtectedRecordKindV1; 2]>())?
            .checked_add(size_of::<std::iter::Zip<std::slice::Iter<'static, JournalRecord>, std::array::IntoIter<HierarchyProtectedRecordKindV1, 2>>>())?
            .checked_add(size_of::<Option<(&'static JournalRecord, HierarchyProtectedRecordKindV1)>>())?
            .checked_add(size_of::<Option<&'static mut Self>>())?
            .checked_add(size_of::<Option<&'static mut SourceGenesisRowsOriginalsV1<E, R>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceGenesisRowsV1>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceTreeGenesisReceiptV1>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceGenesisPendingV1>>>())?
            .checked_add(size_of::<Option<&'static mut Option<SourceGenesisAckV1>>>())?
            .checked_add(size_of::<Option<&'static mut Option<KeyCapture>>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut SourceGenesisPredecessorOriginalsV1<E, H, R>>>())?
            .checked_add(size_of::<Option<&'static mut super::classification::SourceGenesisProtectedRecordScanOriginalsV1>>())?;
        // Twelve actual outer slots, nested receipt/parser/predecessor/key/classifier destinations,
        // four two-field guards, returned genesis roots3, ten optional loans,
        // three comparison Vecs and their name tuple2, plus required-kind
        // array2, the zip iterator4 and its current optional pair3.
        let cells = 11usize.checked_add(receipt_cells)?.checked_add(parser_cells)?.checked_add(predecessor_cells)?.checked_add(classification_cells)?
            .checked_add(KeyCapture::receiving_metadata_cells_v1())?.checked_add(4 * 2 + 3 + 10 + 3 + 2 + 2 + 4 + 3)?;
        Some((bytes, cells))
    }
}


impl<E, H, R> SourceGenesisMutationOriginalsV1<E, H, R>
where
    E: From<JournalError> + std::error::Error + 'static,
    H: From<DomainLedgerDataError> + std::error::Error + 'static,
    R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static,
{
    /// Bounds the actual held and proposed row/backing peak.
    ///
    /// # Errors
    /// Rejects repeated or inconsistent comparison work, or geometry overflow.
    pub fn dynamic_demand_v1(
        state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: Option<&JournalTransaction>,
    ) -> Result<aos_sandbox_model::ResourceVector, E> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use std::mem::size_of;
        let overflow = || E::from(JournalError::LimitExceeded("Source genesis mutation geometry"));
        let mut count = 0usize;
        let mut encoded = 0usize;
        for ((_, key), value) in state {
            if key.starts_with(KEY_FAMILY_PREFIX) {
                count = count.checked_add(1).ok_or_else(overflow)?;
                encoded = encoded.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(overflow)?;
            }
        }
        fn nodes<T>(count: usize) -> Option<usize> {
            size_of::<T>().checked_mul(11)?.checked_add(size_of::<usize>().checked_mul(12)?)?.checked_mul(count)
        }
        let mut bytes = nodes::<(ProjectId, SourceTreeGenesisReceiptV1)>(count)
            .and_then(|bytes| bytes.checked_add(nodes::<(ProjectId, SourceGenesisAckV1)>(count)?))
            .and_then(|bytes| bytes.checked_add(encoded)).ok_or_else(overflow)?;
        for record in transaction.into_iter().flat_map(|transaction| transaction.records()) {
            // The required pair key decoder and the pre-existing classifier
            // share the two-copy canonical key recipe; a required-name probe
            // adds its actual third key copy. The single
            // proposed genesis receipt owns its actual supplied value bytes.
            bytes = bytes.checked_add(record.key().len().checked_mul(3).ok_or_else(overflow)?)
                .and_then(|bytes| bytes.checked_add(record.value().map_or(0, <[u8]>::len))).ok_or_else(overflow)?;
        }
        let (classification_bytes, classification_cells) = super::classification::SourceGenesisProtectedRecordScanOriginalsV1::<E>::backing_footprint_v1(
            transaction.map_or(0, |transaction| transaction.records().len()),
        ).ok_or_else(overflow)?;
        bytes = bytes.checked_add(classification_bytes).ok_or_else(overflow)?;
        let cells = count.checked_mul(2 + 1).and_then(|cells| cells.checked_add(classification_cells)).ok_or_else(overflow)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| overflow())?))
    }
}
