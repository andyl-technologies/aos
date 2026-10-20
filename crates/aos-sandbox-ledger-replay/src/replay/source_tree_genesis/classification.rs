//! Retains ignored key-decoder work without changing the protected-key classifier.

use super::*;
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
use crate::replay::hierarchy_records::{HierarchyProtectedJournalKeyV1, HierarchyProtectedRecordKindV1};
use aos_sandbox_protocol::domain_ledger::records::DomainKeyDecodeCaptureV1;
use std::collections::TryReserveError;
use std::mem::size_of;

pub type HierarchyKeyCaptureV1 = DomainKeyDecodeCaptureV1<crate::replay::hierarchy_records::HierarchyProtectedJournalSchemaV1>;

pub struct SourceGenesisProtectedRecordScanOriginalsV1<E = JournalError> {
    pub keys: Vec<HierarchyKeyCaptureV1>,
    pub current: Option<HierarchyKeyCaptureV1>,
    pub allocation: Option<Result<(), TryReserveError>>,
    pub result: Option<Result<bool, E>>,
    pub closed: Option<E>,
    pub entered: bool,
}

impl<E: From<JournalError> + std::error::Error + 'static> SourceGenesisProtectedRecordScanOriginalsV1<E> {
    pub const fn new() -> Self {
        Self {
            keys: Vec::new(),
            current: None,
            allocation: None,
            result: None,
            closed: None,
            entered: false,
        }
    }

    pub fn observe_once(
        &mut self,
        records: &[JournalRecord],
        rows: &SourceGenesisRowsV1,
    ) -> Result<bool, E> {
        if self.entered {
            self.closed.get_or_insert(E::from(JournalError::ProtectedBoundary));
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        self.entered = true;
        self.allocation = Some(self.keys.try_reserve_exact(records.len()));
        self.result = Some(if matches!(self.allocation, Some(Ok(()))) {
            Ok(self.scan(records, rows))
        } else {
            Err(E::from(JournalError::LimitExceeded("Source genesis classifier originals")))
        });
        match &self.result {
            Some(Ok(protected)) => Ok(*protected),
            _ => Err(E::from(JournalError::ProtectedBoundary)),
        }
    }

    fn scan(&mut self, records: &[JournalRecord], rows: &SourceGenesisRowsV1) -> bool {
        for record in records {
            let protected = protected_record_engine(record, rows, Some(&mut self.current));
            if let Some(original) = self.current.take() {
                // This moves the actual ignored failure or completed key into
                // already-funded/reserved storage; no additional decoder runs.
                self.keys.push(original);
            }
            if protected {
                return true;
            }
        }
        false
    }

    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Individual key errors are FALSE classifier DATA in the existing
        // grammar, so they cannot mask the actual mutation refusal or a later
        // semantic error. They remain resident in keys, with their raw prefix.
        self.allocation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub fn fixed_footprint_v1() -> Option<(usize, usize)> {
        let key_extra = HierarchyKeyCaptureV1::receiving_construction_bytes_v1()?
            .checked_sub(size_of::<HierarchyKeyCaptureV1>().checked_mul(2)?)?;
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(key_extra)?
            .checked_add(size_of::<std::slice::Iter<'static, JournalRecord>>())?
            .checked_add(size_of::<Option<HierarchyKeyCaptureV1>>())?
            .checked_add(size_of::<&'static mut Self>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&'static mut Option<HierarchyKeyCaptureV1>>>())?
            .checked_add(size_of::<Result<bool, E>>())?
            .checked_add(size_of::<&'static [JournalRecord]>().checked_mul(2)?)?
            .checked_add(size_of::<&'static SourceGenesisRowsV1>().checked_mul(2)?)?
            .checked_add(size_of::<&'static JournalRecord>())?
            .checked_add(size_of::<Option<(usize, usize)>>())?
            .checked_add(size_of::<usize>().checked_mul(3)?)?
            .checked_add(size_of::<bool>())?;
        // Six owner fields; current concrete key controls; iterator2 and
        // take carrier; three mutable engine loans; five input/iteration
        // borrows; dynamic width argument/two named widths +returned tuple;
        // whole scan result and its classification bool.
        let cells = 6usize.checked_add(HierarchyKeyCaptureV1::receiving_metadata_cells_v1())?
            .checked_add(2 + 1 + 3 + 5 + 3 + 1 + 1 + 1)?;
        Some((bytes, cells))
    }

    pub fn backing_footprint_v1(records: usize) -> Option<(usize, usize)> {
        // At most one actual key destination per reached input record. Its
        // byte copies are already covered by the caller's three key-width
        // lanes; this adds the concrete resident destinations and their cells.
        let bytes = records.checked_mul(size_of::<HierarchyKeyCaptureV1>())?;
        let cells = records.checked_mul(HierarchyKeyCaptureV1::receiving_metadata_cells_v1())?;
        Some((bytes, cells))
    }
}


pub fn protected_record(record: &JournalRecord, rows: &SourceGenesisRowsV1) -> bool {
    protected_record_engine(record, rows, None)
}

pub fn protected_record_engine(
    record: &JournalRecord,
    rows: &SourceGenesisRowsV1,
    originals: Option<&mut Option<HierarchyKeyCaptureV1>>,
) -> bool {
    if record.key().starts_with(KEY_FAMILY_PREFIX) {
        return true;
    }
    if record.namespace() != RecordNamespace::DesiredState {
        return false;
    }
    let ordinary_key;
    let key = match originals {
        Some(slot) => {
            *slot = Some(HierarchyKeyCaptureV1::new());
            let Some(capture) = slot.as_mut() else { return false; };
            if aos_sandbox_protocol::domain_ledger::records::decode_domain_key_retaining_v1(record.key(), capture).is_err() {
                return false;
            }
            let Some(key) = capture.key() else { return false; };
            key
        }
        None => {
            let Ok(key) = HierarchyProtectedJournalKeyV1::decode(record.key()) else {
                return false;
            };
            ordinary_key = key;
            &ordinary_key
        }
    };
    if !matches!(
        key.kind(),
        HierarchyProtectedRecordKindV1::Tree | HierarchyProtectedRecordKindV1::TreeLineage
    ) {
        return false;
    }
    key.identity()
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .map(ProjectId::from_bytes)
        .is_some_and(|project| rows.receipts.contains_key(&project))
}
