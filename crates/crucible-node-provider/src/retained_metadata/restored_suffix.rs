//! Counts separate ordinary suffix terminal backing, including failed partials.
//!
//! Full raw result/error maps and typed method children own independent banks.
//! This walker has no live-protocol predicate and does not grant execution or
//! waive Source origin checks. Unknown typed families refuse instead of zero.

use super::*;
use crate::bodies::*;

pub(crate) fn response(
    response: &ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let ResponseBody { shape, result } = response;
    super::capture_data::observe_response_shape(shape, observer)?;
    match result {
        None => Ok(()),
        Some(MethodResult::BeginAccepted(value)) => observer.observe(value),
        Some(MethodResult::Poll(value)) => observer.observe(value),
        Some(MethodResult::Observe(value)) => observer.observe(value),
        Some(MethodResult::Input(value)) => observer.observe(value),
        Some(MethodResult::ExactRun(value) | MethodResult::BoundarySettle(value)) => {
            let ExactRunResult {
                grant_id,
                reached,
                stop_reason: _,
                stop_receipt,
                observation_batch,
                pending_inventory,
                next_attention,
            } = value;
            observer.observe(grant_id)?;
            observer.observe(reached)?;
            observer.observe(stop_receipt)?;
            observer.observe(observation_batch)?;
            observer.observe(pending_inventory)?;
            observe_bound(next_attention, observer)
        }
        Some(MethodResult::Retire(value)) => {
            let RetireResult {
                retired_request_ids,
                retired_operation_ids,
            } = value;
            observer.observe(retired_request_ids)?;
            observer.observe(retired_operation_ids)
        }
        Some(MethodResult::BlobBegin(value)) => observer.observe(&value.transfer_id),
        Some(MethodResult::BlobChunk(value)) => observer.observe(&value.transfer_id),
        Some(MethodResult::BlobFinish(value)) => {
            observer.observe(&value.transfer_id)?;
            observer.observe(&value.content)
        }
        Some(
            MethodResult::Hello(_)
            | MethodResult::Discover(_)
            | MethodResult::Realize(_)
            | MethodResult::Admit(_)
            | MethodResult::Activate(_)
            | MethodResult::Cancel(_)
            | MethodResult::QuantumClose(_)
            | MethodResult::WorldActivate(_)
            | MethodResult::Abort(_)
            | MethodResult::Release(_)
            | MethodResult::QuantumBegin(_)
            | MethodResult::Pause(_)
            | MethodResult::Capture(_)
            | MethodResult::PrepareRestore(_)
            | MethodResult::Shutdown(_),
        ) => Err(ProviderError::Correlation(
            "retained suffix response family differs",
        )),
    }
}

// The kind and position are inline. The optional full ContentRef retains its
// actual String capacities even in malformed or failed response partials.
fn observe_bound(bound: &Bound, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
    let Bound {
        kind,
        position,
        evidence,
    } = bound;
    match kind {
        BoundKind::At | BoundKind::After | BoundKind::NoneUntilActivation | BoundKind::Unknown => {}
    }
    observer.observe(position)?;
    observer.observe(evidence)
}

pub(crate) const fn counter_scratch_data() -> usize {
    size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<(&ResponseBody, &ResponseShape, &Option<MethodResult>)>()
        + size_of::<(
            &Id,
            &Position,
            &ContentRef,
            &ContentRef,
            &ContentRef,
            &Bound,
        )>()
        + size_of::<(&Vec<Id>, &Vec<Id>)>()
        + size_of::<(
            &OperationState,
            &serde_json::Map<String, Value>,
            &Extensions,
        )>()
        + size_of::<(&OperationState, &ErrorRecord, &Extensions)>()
        + size_of::<(&BoundKind, &Option<Position>, &Option<ContentRef>)>()
        + size_of::<&Bound>()
        + size_of::<&BoundKind>()
        + size_of::<&Option<Position>>()
        + size_of::<&Option<ContentRef>>()
        + size_of::<&ExactRunResult>()
        + size_of::<&RetireResult>()
        + size_of::<&BeginAccepted>()
        + size_of::<&PollResult>()
        + size_of::<&ObserveResult>()
        + size_of::<&InputResult>()
        + size_of::<&BlobBeginResult>()
        + size_of::<&BlobChunkResult>()
        + size_of::<&BlobFinishResult>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_walk_keeps_every_variant_and_actual_evidence_spare_backing() {
        let mut evidence = canonical::content_ref(b"bound evidence", "application/json").unwrap();
        evidence.hash.algorithm.reserve(31);
        evidence.hash.domain.reserve(37);
        evidence.hash.digest.reserve(41);
        evidence.media_type.reserve(43);
        let expected = evidence.hash.algorithm.capacity()
            + evidence.hash.domain.capacity()
            + evidence.hash.digest.capacity()
            + evidence.media_type.capacity();

        for kind in [
            BoundKind::At,
            BoundKind::After,
            BoundKind::NoneUntilActivation,
            BoundKind::Unknown,
        ] {
            let bound = Bound {
                kind,
                position: if matches!(kind, BoundKind::At | BoundKind::After) {
                    Some(Position::new(Tick::new(3), U64::new(2), Phase::Reaction))
                } else {
                    None
                },
                evidence: if kind == BoundKind::Unknown {
                    None
                } else {
                    Some(evidence.clone())
                },
            };
            // Re-reserve the actual child after Clone, which may discard spare.
            let mut bound = bound;
            if let Some(reference) = &mut bound.evidence {
                reference.hash.algorithm.reserve(31);
                reference.hash.domain.reserve(37);
                reference.hash.digest.reserve(41);
                reference.media_type.reserve(43);
            }
            let actual = bound.evidence.as_ref().map_or(0, |reference| {
                reference.hash.algorithm.capacity()
                    + reference.hash.domain.capacity()
                    + reference.hash.digest.capacity()
                    + reference.media_type.capacity()
            });
            let mut observer = MetadataObserver::new();
            observe_bound(&bound, &mut observer).unwrap();
            assert_eq!(observer.facts.string_capacity_bytes, actual);
            assert_eq!(
                observer.facts.string_banks,
                if kind == BoundKind::Unknown { 0 } else { 4 }
            );
            if kind != BoundKind::Unknown {
                assert!(actual >= expected);
            }
        }

        // Raw partial custody counts evidence even when semantic validation
        // would reject this kind/field combination. It does not bless the bound.
        let partial = Bound {
            kind: BoundKind::Unknown,
            position: None,
            evidence: Some(evidence),
        };
        let mut observer = MetadataObserver::new();
        observe_bound(&partial, &mut observer).unwrap();
        assert_eq!(observer.facts.string_capacity_bytes, expected);
        assert!(partial.validate().is_err());
    }
}
