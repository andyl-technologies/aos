//! Retains completed consuming-pin rows and the current unfinished pin's fields.

use super::*;

#[derive(Default)]
struct PinReadAttempt {
    id: Option<u64>,
    owner: Option<Id>,
    owner_attempt: <Id as Native17Build>::Attempt,
    schema: Option<ContentRef>,
    schema_attempt: <ContentRef as Native17Build>::Attempt,
    phase: Option<HistoricalNativePinPhase>,
    receipt: Option<Option<ContentRef>>,
    receipt_attempt: <Option<ContentRef> as Native17Build>::Attempt,
}

#[derive(Default)]
pub(super) struct PinsReadAttempt {
    rows: BTreeMap<u64, HistoricalNativeBlobPin>,
    children: Vec<PinReadAttempt>,
    completed: bool,
    moved: bool,
}

impl PinsReadAttempt {
    pub(super) fn read_into_data(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        facts: &mut BlobReadFacts,
    ) -> Result<(), ProviderError> {
        let count = rows(ledger, facts)?;
        ledger.native17_target_vector_data::<PinReadAttempt>(count)?;
        self.children
            .try_reserve_exact(count)
            .map_err(|_| exhausted())?;
        if self.children.capacity() != count {
            return Err(exhausted());
        }
        let mut fields = Fields::array(input)?;
        let mut previous = None;
        while let Some(item) = fields.next_value()? {
            if self.children.len() == count {
                return Err(invalid());
            }
            self.children.push(Default::default());
            let child = self.children.last_mut().ok_or_else(invalid)?;
            let mut pin = Fields::array(item)?;
            let id = ledger
                .read::<U64>(next(&mut pin)?, true)?
                .ok_or_else(invalid)?
                .get();
            child.id = Some(id);
            if id == 0 || previous.is_some_and(|previous| previous >= id) {
                return Err(invalid());
            }
            previous = Some(id);
            owned::<Id>(
                next(&mut pin)?,
                ledger,
                &mut child.owner_attempt,
                &mut child.owner,
            )?;
            owned::<ContentRef>(
                next(&mut pin)?,
                ledger,
                &mut child.schema_attempt,
                &mut child.schema,
            )?;
            child.phase = Some(phase(next(&mut pin)?)?);
            owned::<Option<ContentRef>>(
                next(&mut pin)?,
                ledger,
                &mut child.receipt_attempt,
                &mut child.receipt,
            )?;
            pin.finish()?;
            if child.owner.is_none() || child.schema.is_none() || child.receipt.is_none() {
                return Err(invalid());
            }
            let phase = child.phase.ok_or_else(invalid)?;
            self.rows.insert(
                id,
                HistoricalNativeBlobPin {
                    owner: child.owner.take().ok_or_else(invalid)?,
                    schema: child.schema.take().ok_or_else(invalid)?,
                    phase,
                    receipt: child.receipt.take().ok_or_else(invalid)?,
                },
            );
        }
        fields.finish()?;
        if self.children.len() != count {
            return Err(invalid());
        }
        self.completed = true;
        Ok(())
    }

    pub(super) fn preflight_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        facts: &mut BlobReadFacts,
    ) -> Result<(), ProviderError> {
        let count = rows(ledger, facts)?;
        ledger.native17_target_vector_data::<PinReadAttempt>(count)?;
        let mut fields = Fields::array(input)?;
        let mut actual = 0usize;
        let mut previous = None;
        while let Some(item) = fields.next_value()? {
            actual = actual
                .checked_add(1)
                .filter(|actual| *actual <= count)
                .ok_or_else(invalid)?;
            let mut pin = Fields::array(item)?;
            let id = ledger
                .read::<U64>(next(&mut pin)?, true)?
                .ok_or_else(invalid)?
                .get();
            if id == 0 || previous.is_some_and(|previous| previous >= id) {
                return Err(invalid());
            }
            previous = Some(id);
            Id::preflight_data(next(&mut pin)?, ledger)?;
            ContentRef::preflight_data(next(&mut pin)?, ledger)?;
            phase(next(&mut pin)?)?;
            <Option<ContentRef> as Native17Build>::preflight_data(next(&mut pin)?, ledger)?;
            pin.finish()?;
        }
        fields.finish()?;
        if actual != count {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn completed_data(&self) -> bool {
        self.completed
    }

    pub(super) fn take_output_data(&mut self) -> Option<BTreeMap<u64, HistoricalNativeBlobPin>> {
        if !self.completed || self.moved {
            return None;
        }
        self.moved = true;
        Some(std::mem::take(&mut self.rows))
    }

    pub(super) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if !self.moved {
            observe_pins(&self.rows, observer)?;
        }
        observer.vector::<PinReadAttempt>(self.children.capacity())?;
        for child in &self.children {
            if let Some(value) = &child.owner {
                Id::observe_output_data(value, observer)?;
            }
            Id::observe_attempt_data(&child.owner_attempt, observer)?;
            if let Some(value) = &child.schema {
                ContentRef::observe_output_data(value, observer)?;
            }
            ContentRef::observe_attempt_data(&child.schema_attempt, observer)?;
            if let Some(value) = &child.receipt {
                <Option<ContentRef> as Native17Build>::observe_output_data(value, observer)?;
            }
            <Option<ContentRef> as Native17Build>::observe_attempt_data(
                &child.receipt_attempt,
                observer,
            )?;
        }
        Ok(())
    }
}

fn rows(
    ledger: &mut Ledger<'_, '_, '_>,
    facts: &mut BlobReadFacts,
) -> Result<usize, ProviderError> {
    let (_, _, alignment) = crate::blob::original_blob_alignment17_data();
    let count = ledger.row_aligned(
        MetadataRecordKind::Tree,
        crate::blob::original_blob_layouts().pin_tree,
        alignment,
    )?;
    facts.tree_data(count, ledger)?;
    facts.payload_data::<u64, HistoricalNativeBlobPin>(count)?;
    ledger.native17_target_tree_data::<u64, HistoricalNativeBlobPin>(count)?;
    Ok(count)
}

fn phase(input: &[u8]) -> Result<HistoricalNativePinPhase, ProviderError> {
    match plain_string(input)? {
        "held" => Ok(HistoricalNativePinPhase::Held),
        "quarantined" => Ok(HistoricalNativePinPhase::Quarantined),
        "settled" => Ok(HistoricalNativePinPhase::Settled),
        _ => Err(invalid()),
    }
}

pub(crate) fn observe_pins(
    pins: &BTreeMap<u64, HistoricalNativeBlobPin>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.tree::<u64, HistoricalNativeBlobPin>(pins.len())?;
    for pin in pins.values() {
        Id::observe_output_data(&pin.owner, observer)?;
        ContentRef::observe_output_data(&pin.schema, observer)?;
        <Option<ContentRef> as Native17Build>::observe_output_data(&pin.receipt, observer)?;
    }
    Ok(())
}
