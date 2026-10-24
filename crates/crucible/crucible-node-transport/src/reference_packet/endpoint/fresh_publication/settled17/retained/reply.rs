//! Retains reply DOM, evidence rows and unfinished reference/byte-bank children.

use super::*;

type ReplyBody = serde_json::Map<String, serde_json::Value>;
type Evidence = (ContentRef, Vec<u8>);

/// Keeps the exact native evidence row's two independent reconstructed children.
#[derive(Default)]
struct EvidenceReadAttempt {
    reference: Option<ContentRef>,
    reference_attempt: <ContentRef as Native17Build>::Attempt,
    bytes: Option<HistoricalByteBank17>,
    bytes_attempt: <HistoricalByteBank17 as Native17Build>::Attempt,
}

/// Keeps partial reply fields and every evidence row before later failures.
#[derive(Default)]
pub(crate) struct HistoricalFreshReply17ReadAttempt {
    started: bool,
    completed: Option<HistoricalFreshReply17>,
    body: Option<ReplyBody>,
    body_attempt: <ReplyBody as Native17Build>::Attempt,
    evidence: Vec<Evidence>,
    children: Vec<EvidenceReadAttempt>,
    evidence_moved: bool,
}

impl Native17Build for HistoricalFreshReply17 {
    type Attempt = HistoricalFreshReply17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started {
            return Err(ProviderError::Conflict(
                "native17 Fresh reply already attempted",
            ));
        }
        attempt.started = true;
        let mut fields = Fields::object(input)?;
        ReplyBody::read_into_data(fields.named("body")?, ledger, &mut attempt.body_attempt)?;
        attempt.body =
            Some(ReplyBody::take_output_data(&mut attempt.body_attempt).ok_or_else(invalid)?);
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<Evidence>(),
            align_of::<Evidence>(),
        )?;
        let evidence_input = fields.named("evidence")?;
        let count = evidence_count(evidence_input)?;
        if count > capacity {
            return Err(invalid());
        }
        ledger.native17_target_vector_data::<Evidence>(capacity)?;
        ledger.native17_target_vector_data::<EvidenceReadAttempt>(count)?;
        attempt
            .evidence
            .try_reserve_exact(capacity)
            .map_err(|_| exhausted())?;
        if attempt.evidence.capacity() != capacity {
            return Err(exhausted());
        }
        attempt
            .children
            .try_reserve_exact(count)
            .map_err(|_| exhausted())?;
        if attempt.children.capacity() != count {
            return Err(exhausted());
        }
        let mut sequence = Fields::array(evidence_input)?;
        while let Some(raw) = sequence.next_value()? {
            if attempt.children.len() == count {
                return Err(invalid());
            }
            attempt.children.push(Default::default());
            let child = attempt.children.last_mut().ok_or_else(invalid)?;
            let mut pair = Fields::array(raw)?;
            ContentRef::read_into_data(
                pair.next_value()?.ok_or_else(invalid)?,
                ledger,
                &mut child.reference_attempt,
            )?;
            child.reference = Some(
                ContentRef::take_output_data(&mut child.reference_attempt).ok_or_else(invalid)?,
            );
            HistoricalByteBank17::read_into_data(
                pair.next_value()?.ok_or_else(invalid)?,
                ledger,
                &mut child.bytes_attempt,
            )?;
            child.bytes = Some(
                HistoricalByteBank17::take_output_data(&mut child.bytes_attempt)
                    .ok_or_else(invalid)?,
            );
            pair.finish()?;
            if child.reference.is_none() || child.bytes.is_none() {
                return Err(invalid());
            }
            attempt.evidence.push((
                child.reference.take().ok_or_else(invalid)?,
                child.bytes.take().ok_or_else(invalid)?.0,
            ));
        }
        sequence.finish()?;
        fields.finish()?;
        if attempt.children.len() != count || attempt.body.is_none() {
            return Err(invalid());
        }
        // All grammar and capacity checks have completed before either move.
        attempt.completed = Some(Self {
            body: attempt.body.take().ok_or_else(invalid)?,
            evidence: std::mem::take(&mut attempt.evidence),
        });
        attempt.evidence_moved = true;
        Ok(())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut fields = Fields::object(input)?;
        ReplyBody::preflight_data(fields.named("body")?, ledger)?;
        let capacity = ledger.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<Evidence>(),
            align_of::<Evidence>(),
        )?;
        let evidence = fields.named("evidence")?;
        let count = evidence_count(evidence)?;
        if count > capacity {
            return Err(invalid());
        }
        ledger.native17_target_vector_data::<Evidence>(capacity)?;
        ledger.native17_target_vector_data::<EvidenceReadAttempt>(count)?;
        let mut sequence = Fields::array(evidence)?;
        while let Some(raw) = sequence.next_value()? {
            let mut pair = Fields::array(raw)?;
            ContentRef::preflight_data(pair.next_value()?.ok_or_else(invalid)?, ledger)?;
            HistoricalByteBank17::preflight_data(pair.next_value()?.ok_or_else(invalid)?, ledger)?;
            pair.finish()?;
        }
        sequence.finish()?;
        fields.finish()
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        if let Some(body) = &attempt.body {
            ReplyBody::observe_output_data(body, observer)?;
        }
        ReplyBody::observe_attempt_data(&attempt.body_attempt, observer)?;
        if !attempt.evidence_moved {
            observe_evidence(&attempt.evidence, observer)?;
        }
        observer.vector::<EvidenceReadAttempt>(attempt.children.capacity())?;
        for child in &attempt.children {
            if let Some(value) = &child.reference {
                ContentRef::observe_output_data(value, observer)?;
            }
            ContentRef::observe_attempt_data(&child.reference_attempt, observer)?;
            if let Some(value) = &child.bytes {
                HistoricalByteBank17::observe_output_data(value, observer)?;
            }
            HistoricalByteBank17::observe_attempt_data(&child.bytes_attempt, observer)?;
        }
        Ok(())
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        ReplyBody::observe_output_data(&value.body, observer)?;
        observe_evidence(&value.evidence, observer)
    }
}

fn evidence_count(input: &[u8]) -> Result<usize, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut count = 0usize;
    while fields.next_value()?.is_some() {
        count = count.checked_add(1).ok_or_else(invalid)?;
    }
    fields.finish()?;
    Ok(count)
}

fn observe_evidence(
    evidence: &Vec<Evidence>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    observer.vector::<Evidence>(evidence.capacity())?;
    for (reference, bytes) in evidence {
        ContentRef::observe_output_data(reference, observer)?;
        observer.vector::<u8>(bytes.capacity())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
