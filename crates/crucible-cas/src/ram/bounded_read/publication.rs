//! Single-use readback of a bounded publication through the same owning Work.
//!
//! Receipt validation precedes each authenticated read. A Packed leaf borrows
//! one current pinned generation and one bounded last-pack cache; it retains
//! every full ContentId/EOF/schema check and closes the view before acceptance.

use super::*;
use crate::content_store::{ContentId, PutReceipt};
use crate::ram::codec::{
    MAX_PUBLICATION_BATCH_OBJECTS, PreparedEnvelopeRead, prepare_envelope_read,
    read_envelope_using, read_prepared_envelope_using,
};

#[derive(Clone, Copy)]
pub(super) struct Readback<'read> {
    store: &'read crate::ram::RamStore,
    expected: &'read [Option<(ContentId, u64)>; MAX_PUBLICATION_BATCH_OBJECTS],
    receipts: &'read [PutReceipt],
}

impl Readback<'_> {
    fn entry(&self, index: usize) -> Result<(ContentId, u64), RamStoreError> {
        self.expected
            .iter()
            .flatten()
            .nth(index)
            .copied()
            .ok_or(RamStoreError::Invalid("RAM publication readback entry"))
    }

    fn validate(&self, index: usize) -> Result<ContentId, RamStoreError> {
        let (id, length) = self.entry(index)?;
        let receipt = self.receipts.get(index).ok_or(RamStoreError::Invalid(
            "RAM publication batch receipt count",
        ))?;
        self.store.validate_receipt(receipt, id, length)?;
        Ok(id)
    }

    pub(super) fn execute_existing(&self, work: &mut Work<'_>) -> Result<ReadValue, RamStoreError> {
        for index in 0..self.receipts.len() {
            let id = self.validate(index)?;
            // A forwarded leaf must not stand in for the original facade.
            // Ordinary reads retain every Graph/physical/namespace check.
            drop(self.store.read_envelope(id, work)?);
        }
        Ok(ReadValue::Publication)
    }
}

pub(in crate::ram) fn read_publication(
    store: &crate::ram::RamStore,
    expected: &[Option<(ContentId, u64)>; MAX_PUBLICATION_BATCH_OBJECTS],
    receipts: &[PutReceipt],
    work: &mut Work<'_>,
) -> Result<(), RamStoreError> {
    if let Some(first) = work.account.read_failure() {
        return Err(first.into());
    }
    if receipts.len() != expected.iter().flatten().count() {
        return Err(RamStoreError::Invalid(
            "RAM publication batch receipt count",
        ));
    }
    if receipts.is_empty() {
        return Ok(());
    }
    let readback = Readback {
        store,
        expected,
        receipts,
    };
    // Preserve the first receipt's refusal before any new control debit or
    // view effects. Later receipts still validate just before their own read.
    readback.validate(0)?;
    let bytes = std::mem::size_of::<ReadState>()
        .checked_add(std::mem::size_of::<BoundedReadRequest<'_, '_>>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Readback<'_>>()))
        .and_then(|bytes| {
            std::mem::size_of::<PreparedEnvelopeRead>()
                .checked_mul(2)
                .and_then(|prepared| bytes.checked_add(prepared))
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RamStoreError::Limit("RAM publication readback control"))?;
    let _credit = work
        .original()
        .reserve_scratch_bytes(bytes)
        .map_err(crate::ram::codec_ownership::admission)?;
    let mut state = ReadState {
        phase: ReadPhase::Ready,
        pending: Cell::new(None),
    };
    let mut request = BoundedReadRequest {
        work,
        task: ReadTask::Publication(readback),
        state: &mut state,
        physical: None,
        inventory_admission: None,
    };
    let provider = store.backend.read_bounded_with_boundary(&mut request);
    match request.finish(provider).map_err(RamStoreError::from)? {
        ReadValue::Publication => Ok(()),
        _ => unreachable!("publication readback retains its own terminal outcome"),
    }
}

impl BoundedReadRequest<'_, '_> {
    pub(super) fn execute_packed_publication(
        &mut self,
        backend: &crate::content_store::PackedBlobBackend,
    ) -> Result<(), StoreError> {
        match self.state.phase {
            ReadPhase::Ready => {}
            ReadPhase::Failed => return Err(self.first_failure()),
            _ => {
                return Err(StoreError::Unsupported {
                    capability: "bounded-read-request-already-used",
                });
            }
        }
        if let Some(first) = self.work.account.read_failure() {
            self.state.phase = ReadPhase::Failed;
            return Err(first);
        }
        let ReadTask::Publication(readback) = self.task else {
            return Err(StoreError::Unsupported {
                capability: "not-publication-readback",
            });
        };
        self.state.phase = ReadPhase::Active;
        let physical = self.physical;
        let admission = self.inventory_admission;
        let result = (|| {
            let first_id = readback.validate(0)?;
            // This is the SAME first record's child account. Carry it through
            // view creation and consume it for the first body; no extra child
            // ledger is created merely to perform a preflight.
            let first = prepare_envelope_read(first_id, self.work)?;
            self.work.checked(|original, boundary| {
                if let Some(admit) = admission {
                    admit(first_id)?;
                }
                crate::content_store::checked_reader::check(original, boundary)?;
                verify_physical(original, physical)
            })?;
            let view = self.work.checked(|original, boundary| {
                let mut checked = || {
                    crate::content_store::checked_reader::check(original, boundary)?;
                    verify_physical(original, physical)
                };
                crate::content_store::PackedReadView::begin(backend, original, &mut checked)
            })?;
            let mut reader = self.work.checked(|original, boundary| {
                let mut checked = || {
                    crate::content_store::checked_reader::check(original, boundary)?;
                    verify_physical(original, physical)
                };
                view.reader(backend, original, &mut checked)
            })?;
            let selected = Cell::new(None);
            let mut source =
                |original: &crate::owned_decode::DecodeBudget,
                 id,
                 boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
                    selected.set(Some(id));
                    if let Some(admit) = admission {
                        admit(id)?;
                    }
                    reader.lookup(backend, original, id, boundary)
                };
            let mut verify = |original: &crate::owned_decode::DecodeBudget| {
                if let (Some(admit), Some(id)) = (admission, selected.get()) {
                    admit(id)?;
                }
                verify_physical(original, physical)
            };
            drop(read_prepared_envelope_using(
                first,
                self.work,
                true,
                &mut source,
                &mut verify,
            )?);
            for index in 1..readback.receipts.len() {
                let id = readback.validate(index)?;
                drop(read_envelope_using(
                    id,
                    self.work,
                    true,
                    &mut source,
                    &mut verify,
                )?);
            }
            Ok::<(), RamStoreError>(())
        })();
        // Reader, pack pin, index snapshot and both locks have closed before
        // this final original/physical cut and before the receipt is accepted.
        let result = result.and_then(|()| {
            self.work.checked(|original, boundary| {
                crate::content_store::checked_reader::check(original, boundary)?;
                verify_physical(original, physical)
            })
        });
        match result {
            Ok(()) => {
                self.state.pending.set(Some(Ok(ReadValue::Publication)));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            Err(error) => {
                self.state.phase = ReadPhase::Failed;
                Err(self.work.account.fail_read(error))
            }
        }
    }
}

#[cfg(test)]
mod tests;
