//! Retains exact native Blob DATA fields in the caller's typed attempt.

use super::*;
/// Keeps one native record and each current nested transfer/pin partial.
#[derive(Default)]
pub(super) struct RecordReadAttempt {
    pub(super) key: KeyReadAttempt,
    content: Option<ContentRef>,
    content_attempt: <ContentRef as Native17Build>::Attempt,
    bytes: Option<HistoricalByteBank17>,
    bytes_attempt: <HistoricalByteBank17 as Native17Build>::Attempt,
    chunks: ChunksReadAttempt,
    retirement: RetirementReadAttempt,
    pins: PinsReadAttempt,
    completed: Option<HistoricalNativeBlobRecord>,
    length: Option<usize>,
    verified: Option<bool>,
    quarantined: Option<bool>,
    exposed: Option<bool>,
    charged: Option<bool>,
}

impl RecordReadAttempt {
    pub(super) fn read_into_data<'input>(
        &mut self,
        input: &'input [u8],
        ledger: &mut Ledger<'_, '_, '_>,
        facts: &mut BlobReadFacts,
    ) -> Result<TransferKeyOrder<'input>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let order = self.key.read_into_data(next(&mut fields)?, ledger)?;
        owned::<ContentRef>(
            next(&mut fields)?,
            ledger,
            &mut self.content_attempt,
            &mut self.content,
        )?;
        self.length = ledger.read::<usize>(next(&mut fields)?, true)?;
        owned::<HistoricalByteBank17>(
            next(&mut fields)?,
            ledger,
            &mut self.bytes_attempt,
            &mut self.bytes,
        )?;
        self.chunks
            .read_into_data(next(&mut fields)?, ledger, facts)?;
        self.verified = ledger.read::<bool>(next(&mut fields)?, true)?;
        self.quarantined = ledger.read::<bool>(next(&mut fields)?, true)?;
        self.exposed = ledger.read::<bool>(next(&mut fields)?, true)?;
        self.retirement.read_into_data(next(&mut fields)?, ledger)?;
        self.pins
            .read_into_data(next(&mut fields)?, ledger, facts)?;
        self.charged = ledger.read::<bool>(next(&mut fields)?, true)?;
        fields.finish()?;
        if self.content.is_none()
            || self.bytes.is_none()
            || !self.chunks.completed
            || self.retirement.output_data().is_none()
            || !self.pins.completed_data()
        {
            return Err(invalid());
        }
        let length = self.length.ok_or_else(invalid)?;
        let verified = self.verified.ok_or_else(invalid)?;
        let quarantined = self.quarantined.ok_or_else(invalid)?;
        let exposed = self.exposed.ok_or_else(invalid)?;
        let charged = self.charged.ok_or_else(invalid)?;
        self.completed = Some(HistoricalNativeBlobRecord {
            content: self.content.take().ok_or_else(invalid)?,
            bytes: self.bytes.take().ok_or_else(invalid)?.0,
            chunks: self.chunks.take_output_data().ok_or_else(invalid)?,
            retirement: self.retirement.take_output_data().ok_or_else(invalid)?,
            pins: self.pins.take_output_data().ok_or_else(invalid)?,
            length,
            verified,
            quarantined,
            exposed,
            charged,
        });
        Ok(order)
    }
    pub(super) fn preflight_data<'input>(
        input: &'input [u8],
        ledger: &mut Ledger<'_, '_, '_>,
        facts: &mut BlobReadFacts,
    ) -> Result<TransferKeyOrder<'input>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let order = KeyReadAttempt::preflight_data(next(&mut fields)?, ledger)?;
        ContentRef::preflight_data(next(&mut fields)?, ledger)?;
        ledger.read::<usize>(next(&mut fields)?, false)?;
        HistoricalByteBank17::preflight_data(next(&mut fields)?, ledger)?;
        ChunksReadAttempt::preflight_data(next(&mut fields)?, ledger, facts)?;
        for _ in 0..3 {
            ledger.read::<bool>(next(&mut fields)?, false)?;
        }
        RetirementReadAttempt::preflight_data(next(&mut fields)?, ledger)?;
        PinsReadAttempt::preflight_data(next(&mut fields)?, ledger, facts)?;
        ledger.read::<bool>(next(&mut fields)?, false)?;
        fields.finish()?;
        Ok(order)
    }
    pub(super) fn completed_data(&self) -> Option<&HistoricalNativeBlobRecord> {
        self.completed.as_ref()
    }
    #[cfg(test)]
    pub(super) fn partial_bytes_data(&self) -> Option<&Vec<u8>> {
        self.bytes.as_ref().map(|bank| &bank.0)
    }
    #[cfg(test)]
    pub(super) fn partial_chunks_data(&self) -> &BTreeMap<usize, usize> {
        &self.chunks.rows
    }
    pub(super) fn take_output_data(&mut self) -> Option<HistoricalNativeBlobRecord> {
        self.completed.take()
    }
    pub(super) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.key.observe_attempt_data(observer)?;
        if let Some(value) = &self.completed {
            observe_record(value, observer)?;
        }
        if let Some(value) = &self.content {
            ContentRef::observe_output_data(value, observer)?;
        }
        ContentRef::observe_attempt_data(&self.content_attempt, observer)?;
        if let Some(value) = &self.bytes {
            HistoricalByteBank17::observe_output_data(value, observer)?;
        }
        HistoricalByteBank17::observe_attempt_data(&self.bytes_attempt, observer)?;
        self.chunks.observe_attempt_data(observer)?;
        self.retirement.observe_attempt_data(observer)?;
        self.pins.observe_attempt_data(observer)
    }
}

#[derive(Default)]
struct ChunksReadAttempt {
    rows: BTreeMap<usize, usize>,
    completed: bool,
    moved: bool,
}
impl ChunksReadAttempt {
    fn read_into_data(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        facts: &mut BlobReadFacts,
    ) -> Result<(), ProviderError> {
        let count = chunk_rows(ledger, facts)?;
        let mut fields = Fields::array(input)?;
        let mut actual = 0usize;
        let mut previous = None;
        while let Some(item) = fields.next_value()? {
            actual = actual
                .checked_add(1)
                .filter(|actual| *actual <= count)
                .ok_or_else(invalid)?;
            let mut pair = Fields::array(item)?;
            let offset = ledger
                .read::<usize>(next(&mut pair)?, true)?
                .ok_or_else(invalid)?;
            let length = ledger
                .read::<usize>(next(&mut pair)?, true)?
                .ok_or_else(invalid)?;
            pair.finish()?;
            if length == 0
                || previous.is_some_and(|value| value >= offset)
                || offset.checked_add(length).is_none()
            {
                return Err(invalid());
            }
            previous = Some(offset);
            self.rows.insert(offset, length);
        }
        fields.finish()?;
        if actual != count {
            return Err(invalid());
        }
        self.completed = true;
        Ok(())
    }
    fn preflight_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        facts: &mut BlobReadFacts,
    ) -> Result<(), ProviderError> {
        let count = chunk_rows(ledger, facts)?;
        let mut fields = Fields::array(input)?;
        let mut actual = 0usize;
        let mut previous = None;
        while let Some(item) = fields.next_value()? {
            actual = actual
                .checked_add(1)
                .filter(|actual| *actual <= count)
                .ok_or_else(invalid)?;
            let mut pair = Fields::array(item)?;
            let offset = ledger
                .read::<usize>(next(&mut pair)?, true)?
                .ok_or_else(invalid)?;
            let length = ledger
                .read::<usize>(next(&mut pair)?, true)?
                .ok_or_else(invalid)?;
            pair.finish()?;
            if length == 0
                || previous.is_some_and(|value| value >= offset)
                || offset.checked_add(length).is_none()
            {
                return Err(invalid());
            }
            previous = Some(offset);
        }
        fields.finish()?;
        if actual != count {
            return Err(invalid());
        }
        Ok(())
    }
    fn take_output_data(&mut self) -> Option<BTreeMap<usize, usize>> {
        if !self.completed || self.moved {
            return None;
        }
        self.moved = true;
        Some(std::mem::take(&mut self.rows))
    }
    fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if !self.moved {
            observer.tree::<usize, usize>(self.rows.len())?;
        }
        Ok(())
    }
}
fn chunk_rows(
    ledger: &mut Ledger<'_, '_, '_>,
    facts: &mut BlobReadFacts,
) -> Result<usize, ProviderError> {
    let count = ledger.row_aligned(
        MetadataRecordKind::Tree,
        size_of::<usize>() * 2,
        align_of::<usize>(),
    )?;
    facts.tree_data(count, ledger)?;
    ledger.native17_target_tree_data::<usize, usize>(count)?;
    Ok(count)
}

pub(crate) fn observe_record(
    value: &HistoricalNativeBlobRecord,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    ContentRef::observe_output_data(&value.content, observer)?;
    observer.vector::<u8>(value.bytes.capacity())?;
    observer.tree::<usize, usize>(value.chunks.len())?;
    observe_retirement(&value.retirement, observer)?;
    observe_pins(&value.pins, observer)
}
