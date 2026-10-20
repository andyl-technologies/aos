//! Typed action/evidence reducers that couple physical observations to state.

use super::*;

pub(super) fn validate_scrub_component(
    payload: &CacheAtomicObjectPayloadV1,
) -> Result<(), RecoveryError> {
    let Some(scrub) = &payload.scrub else {
        return if payload.record.kind == CacheRecordKindV1::Scrub {
            Err(RecoveryError::PayloadMismatch)
        } else {
            Ok(())
        };
    };
    scrub
        .evidence
        .validate()
        .map_err(|_| RecoveryError::PayloadMismatch)?;
    if payload.record.kind != CacheRecordKindV1::Scrub {
        return Ok(());
    }
    let expected_scope = CacheAuthorityScopeV1::new(
        payload.plan.partition,
        scrub_subject(
            &payload.plan.descriptor,
            scrub.evidence.before_validation,
            scrub.evidence.after_validation,
            scrub.evidence.content_digest,
        ),
        Some(scrub.evidence.operation),
        scrub.prior_catalog.digest,
        scrub.prior_catalog.root_custody,
        scrub.prior_catalog.generation,
        scrub.evidence.authority_scope.valid_until(),
    )?;
    if scrub.evidence.operation != payload.record.operation
        || scrub.evidence.catalog_digest != scrub.prior_catalog.digest
        || scrub.evidence.authority_scope != expected_scope
        || scrub.evidence.authority_record != payload.record.authority
        || scrub.evidence.digest != payload.record.evidence
        || scrub.prior_catalog.partition != payload.plan.partition
        || scrub.prior_catalog.descriptor != payload.plan.descriptor
        || scrub.resulting_catalog.partition != payload.plan.partition
        || scrub.resulting_catalog.descriptor != payload.plan.descriptor
        || payload.catalog.as_ref() != Some(&scrub.resulting_catalog)
        || payload.record.amount != scrub.resulting_catalog.generation
    {
        return Err(RecoveryError::PayloadMismatch);
    }
    let observations_match = scrub_observations_match(&scrub.prior_catalog, scrub.evidence);
    let expected_result = match payload.record.state {
        1 if scrub.prior_catalog.presence == CatalogPresenceV1::Committed && observations_match => {
            scrub.prior_catalog.clone()
        }
        2 if scrub.prior_catalog.presence == CatalogPresenceV1::Committed
            && !observations_match =>
        {
            scrub
                .prior_catalog
                .clone()
                .transition(CatalogPresenceV1::Quarantined)
                .map_err(|_| RecoveryError::PayloadMismatch)?
        }
        3 if scrub.prior_catalog.presence == CatalogPresenceV1::Quarantined
            && observations_match =>
        {
            scrub
                .prior_catalog
                .clone()
                .transition(CatalogPresenceV1::Committed)
                .map_err(|_| RecoveryError::PayloadMismatch)?
        }
        _ => return Err(RecoveryError::PayloadMismatch),
    };
    if scrub.resulting_catalog != expected_result {
        return Err(RecoveryError::PayloadMismatch);
    }
    Ok(())
}

fn scrub_observations_match(entry: &CatalogEntryV1, evidence: ScrubEvidenceV1) -> bool {
    let observed = evidence.after_validation;
    observed == evidence.before_validation
        && observed.backing == entry.backing
        && observed.root_custody == entry.root_custody
        && observed.root_generation == entry.root_generation
        && observed.canonical_name == entry.canonical_name
        && observed.size == entry.descriptor.encoded_size()
        && observed.seal == entry.seal
        && evidence.content_digest == entry.descriptor.digest()
        && observed.read_only
        && observed.confined_resolution
}
