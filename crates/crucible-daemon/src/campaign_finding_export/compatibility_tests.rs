//! Compatibility projections of complete retained request/response bytes.
//!
//! CFXT framing is test-only: it labels collection lengths and canonical bodies,
//! without introducing a production export format or materialization authority.

// crucible-lint: allow panic-shortcut -- bounded fixture projections localize retained-proof failures.
#![allow(clippy::expect_used)]

use super::*;

/// Projects the exact bounded canonical bodies for the fixed parent fixture.
pub(crate) fn retained_response_material(export: &GuardedCampaignFindingExport) -> Vec<u8> {
    let mut bytes = b"CFXT\0\0\0\x01".to_vec();
    frame(
        &mut bytes,
        &u64::try_from(export.query_pages.len())
            .expect("bounded query pages")
            .to_le_bytes(),
    );
    for page in &export.query_pages {
        frame(&mut bytes, &page.request.canonical_bytes());
        frame(&mut bytes, &page.response.canonical_bytes());
    }
    frame(
        &mut bytes,
        &u64::try_from(export.findings.len())
            .expect("bounded findings")
            .to_le_bytes(),
    );
    for finding in &export.findings {
        frame(&mut bytes, &finding.request().canonical_bytes());
        frame(&mut bytes, &finding.response().canonical_bytes());
        for object in finding.objects() {
            frame(&mut bytes, &object.request().canonical_bytes());
            frame(&mut bytes, &object.response().canonical_bytes());
        }
        for occurrence in finding.occurrences() {
            frame(&mut bytes, &occurrence.request().canonical_bytes());
            frame(&mut bytes, &occurrence.response().canonical_bytes());
            for object in occurrence.objects() {
                frame(&mut bytes, &object.request().canonical_bytes());
                frame(&mut bytes, &object.response().canonical_bytes());
            }
            if let Some(replays) = occurrence.triage_replays() {
                for replay in [
                    replays.minimization_original(),
                    replays.minimization_selected(),
                    replays.verification_original(),
                    replays.verification_selected(),
                ] {
                    for segment in replay.segments() {
                        frame(&mut bytes, &segment.request().canonical_bytes());
                        frame(&mut bytes, &segment.response().canonical_bytes());
                    }
                }
            }
        }
    }
    bytes
}

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("bounded canonical body")
            .to_le_bytes(),
    );
    output.extend_from_slice(bytes);
}

/// Reopens retained bytes and checks original request bindings after teardown.
pub(crate) fn validate_retained_responses_for_test(export: &GuardedCampaignFindingExport) {
    for page in &export.query_pages {
        let bytes = page.response.canonical_bytes();
        let reopened = QueryCampaignFindingsResponse::from_canonical_bytes(&bytes)
            .expect("retained full query body");
        reopened
            .validate_for(&page.request)
            .expect("original request binding and Merkle proof");
        assert_eq!(reopened, page.response);
        assert_eq!(reopened.canonical_bytes(), bytes);

        let changed = QueryCampaignFindingsRequest::new(
            page.request.principal().clone(),
            CampaignName::new("different-export-context").expect("different campaign"),
            page.request.snapshot(),
            page.request.after(),
            page.request.limit(),
        )
        .expect("well-formed different context");
        assert!(reopened.validate_for(&changed).is_err());
    }
}

#[test]
fn original_export_byte_and_exchange_caps_keep_exact_error_identity() {
    let mut bytes = FindingExportBudget::new().expect("finite original deadline");
    bytes
        .retain_exchange(MAX_FINDING_EXPORT_BYTES, 0)
        .expect("exact byte ceiling");
    let error = bytes
        .retain_exchange(0, 1)
        .expect_err("one byte beyond ceiling");
    let legacy: crate::GuardedDefaultCampaignInvariantError = error;
    assert_eq!(
        legacy,
        GuardedDefaultCampaignInvariantError::FindingExportLimit
    );
    assert_eq!(
        legacy.to_string(),
        "final finding proof export exceeded its fixed bound"
    );

    let mut exchanges = FindingExportBudget::new().expect("finite original deadline");
    exchanges.exchanges = MAX_FINDING_EXPORT_EXCHANGES;
    assert_eq!(
        exchanges.retain_exchange(0, 0),
        Err(GuardedDefaultCampaignInvariantError::FindingExportLimit)
    );
}

#[test]
fn original_export_overflow_and_deadline_refusals_remain_closed() {
    let mut overflow = FindingExportBudget::new().expect("finite original deadline");
    overflow.bytes = usize::MAX;
    assert_eq!(
        overflow.retain_exchange(1, 0),
        Err(GuardedDefaultCampaignInvariantError::FindingExportLimit)
    );

    let expired = FindingExportBudget {
        deadline: ProcessDeadline::after(Duration::ZERO).expect("zero original deadline"),
        bytes: 0,
        exchanges: 0,
    };
    let error = expired.check().expect_err("expired original budget");
    assert_eq!(
        error,
        GuardedDefaultCampaignInvariantError::FindingExportDeadline
    );
    assert_eq!(
        error.to_string(),
        "final finding proof export exceeded its finite deadline"
    );
}
