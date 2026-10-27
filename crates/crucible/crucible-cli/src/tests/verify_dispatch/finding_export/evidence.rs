//! Evidence-store capture, publication, and rewriting helpers for finding
//! export tests.
//!
//! Tamper cases edit stored record and chunk text directly, then re-hash every
//! enclosing object, so a rejection proves authentication rather than a broken
//! content address.

use super::*;

/// Captures one finding through the checked client into `store`.
pub(super) fn capture_finding<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: &str,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
    report: Option<TriageFindingEvidence>,
    store: &crucible_engine::LocalDagStore,
) -> Result<crucible_engine::ContentHash, Box<dyn Error>>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    use crate::cli_triage_debug::campaign_evidence::{
        CampaignFindingCaptureScope, capture_campaign_triage_finding,
        capture_campaign_triage_finding_from_service, find_campaign_finding_membership,
    };

    let scope = CampaignFindingCaptureScope {
        principal: crucible_campaign::CampaignPrincipal::new(principal)?,
        campaign: crucible_campaign::CampaignName::new("cli-campaign-findings-finding-export")?,
        snapshot,
        finding,
    };
    let membership = find_campaign_finding_membership(client, &scope)?;
    Ok(match report {
        Some(report) => {
            capture_campaign_triage_finding(client, &scope, &membership, report, store)?
        }
        None => capture_campaign_triage_finding_from_service(client, &scope, &membership, store)?,
    })
}

/// Reads one stored evidence text blob.
fn stored_text(
    store: &crucible_engine::LocalDagStore,
    key: crucible_engine::ContentHash,
) -> Result<String, Box<dyn Error>> {
    Ok(String::from_utf8(std::fs::read(store.object_path(&key))?)?)
}

/// Returns `field` from a record, or from its first occurrence chunk.
pub(super) fn stored_field(
    store: &crucible_engine::LocalDagStore,
    record: crucible_engine::ContentHash,
    field: &str,
) -> Result<String, Box<dyn Error>> {
    let find = |text: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{field}=")).map(str::to_owned))
    };
    let record_text = stored_text(store, record)?;
    if let Some(value) = find(&record_text) {
        return Ok(value);
    }
    let chunk = first_chunk_key(&record_text)?;
    find(&stored_text(store, chunk)?)
        .ok_or_else(|| std::io::Error::other(format!("missing evidence field {field}")).into())
}

fn first_chunk_key(record_text: &str) -> Result<crucible_engine::ContentHash, Box<dyn Error>> {
    let chunk = record_text
        .lines()
        .find_map(|line| line.strip_prefix("occurrence_chunk.0="))
        .ok_or_else(|| std::io::Error::other("record has no occurrence chunk"))?;
    parse_hash(chunk)
}

pub(super) fn parse_hash(hex: &str) -> Result<crucible_engine::ContentHash, Box<dyn Error>> {
    Ok(crucible_engine::ContentAddressedBlobRef::parse("evidence hash", &format!("blake3:{hex}"))?.hash())
}

/// Rewrites a record's first chunk and stores the re-hashed chunk and record.
pub(super) fn rewrite_first_chunk(
    store: &crucible_engine::LocalDagStore,
    record: crucible_engine::ContentHash,
    rewrite: impl FnOnce(&str) -> String,
) -> Result<crucible_engine::ContentHash, Box<dyn Error>> {
    let record_text = stored_text(store, record)?;
    let chunk = first_chunk_key(&record_text)?;
    let rewritten = rewrite(&stored_text(store, chunk)?);
    let rewritten_chunk = store.put(rewritten.as_bytes())?;
    assert_ne!(rewritten_chunk, chunk);
    let rewritten_record = record_text.replacen(&chunk.to_hex(), &rewritten_chunk.to_hex(), 1);
    Ok(store.put(rewritten_record.as_bytes())?)
}

/// Re-points a ledger manifest from one record to another.
pub(super) fn ledger_with_record(
    ledger: &[u8],
    record: crucible_engine::ContentHash,
    replacement: crucible_engine::ContentHash,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(std::str::from_utf8(ledger)?
        .replacen(&record.to_hex(), &replacement.to_hex(), 1)
        .into_bytes())
}

/// Publishes a model reproduction's schedule segments before its record.
pub(super) fn publish_reproduction_segments(
    repository: &crucible_campaign::CampaignRepository,
    artifact: &crucible_engine::ReproductionArtifact,
) -> Result<(), Box<dyn Error>> {
    let segments = crucible_engine::SharedSegmentStore::new();
    let manifest = artifact.schedule().write_segments(&segments)?;
    for segment in manifest.segments() {
        let bytes = crucible_engine::SegmentSource::segment(&segments, segment.id)?;
        repository.publish_reproduction_payload_segment(
            crucible_campaign::ReproductionPayloadSegment::new(segment.id, segment.encoded_bytes)?,
            &bytes,
        )?;
    }
    Ok(())
}
