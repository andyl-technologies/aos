//! Authenticated campaign finding, occurrence, and replay-set validation.
//!
//! Authentication is a fold over one finding's evidence record. Finding-level
//! exchanges are checked first; occurrences are then authenticated one at a
//! time with only the page cursor, the position, and two bundle flags carried
//! between them. No complete occurrence or proof set is ever resident; within
//! an occurrence, one triage replay is reassembled at a time.

use super::super::record::{
    CampaignFindingEvidenceRecord, CampaignOccurrenceExchanges, MAX_OCCURRENCES_PER_CHUNK,
    TRIAGE_REPLAY_ROLES, read_occurrence_chunk,
};
use super::super::reproduction::{
    authenticate_finding_reproduction, authenticate_occurrence_reproduction,
};
use super::super::store::CampaignExchangeRef;
use super::super::triage_segments::authenticate_occurrence_triage_log_segments;
use super::*;

/// Largest reassembled triage replay transfer accepted for one role.
const MAX_TRIAGE_REPLAY_TRANSFER_BYTES: usize = 256 * 1024 * 1024;

/// Finding-level campaign records recovered from authenticated responses.
pub(crate) struct AuthenticatedCampaignFindingHead {
    pub(crate) finding: crucible_campaign::Finding,
    pub(crate) observation: crucible_campaign::Observation,
    pub(crate) reproduction: crucible_campaign::ReproductionArtifact,
    pub(crate) minimized_reproduction: Option<crucible_campaign::ReproductionArtifact>,
    /// Crucible artifact decoded from the reproduction's authenticated segments.
    pub(crate) reproduction_artifact: crucible_engine::ReproductionArtifact,
    /// Crucible artifact of the minimized reproduction, present with it.
    pub(crate) minimized_artifact: Option<crucible_engine::ReproductionArtifact>,
}

/// Everything one occurrence authentication reads besides its own exchanges.
#[derive(Clone, Copy)]
pub(crate) struct CampaignFindingAuthenticationContext<'a> {
    /// Finding position in its ledger, used only in diagnostics.
    pub(crate) index: usize,
    pub(crate) record: &'a CampaignFindingEvidenceRecord,
    pub(crate) finding: &'a crucible_campaign::Finding,
    /// Report projection whose discovery path and fingerprint frame replays.
    pub(crate) template: &'a TriageFindingEvidence,
    pub(crate) evidence: &'a crucible_engine::LocalDagStore,
}

/// How an occurrence page request's cursor is checked.
#[derive(Clone, Copy)]
pub(crate) enum OccurrenceCursorCheck {
    /// The request must continue the chain at exactly this cursor.
    Chained(Option<crucible_campaign::CampaignHash>),
    /// The chain was authenticated when the ledger loaded; a later on-demand
    /// read of the same content-addressed occurrence does not repeat it.
    Loaded,
}

/// Bundle identity and continuation cursor of one authenticated occurrence.
pub(crate) struct AuthenticatedCampaignOccurrence {
    pub(crate) bundle: crucible_campaign::FindingCandidateBundleId,
    pub(crate) next_after: Option<crucible_campaign::CampaignHash>,
}

/// Authenticates the membership and finding-object exchanges of one record.
///
/// # Errors
///
/// Returns an error when a request names another campaign dependency, a
/// response fails its checked binding, or the finding is not admitted.
pub(crate) fn authenticate_campaign_finding_head(
    index: usize,
    evidence: &crucible_engine::LocalDagStore,
    record: &CampaignFindingEvidenceRecord,
) -> Result<AuthenticatedCampaignFindingHead, CliError> {
    let expected_finding_id = record.finding;
    let membership_request = decode_request(
        evidence,
        record.membership,
        crucible_campaign::QueryCampaignFindingsRequest::from_canonical_bytes,
        index,
        "membership",
    )?;
    if membership_request.campaign() != &record.campaign
        || membership_request.snapshot() != record.snapshot
    {
        return Err(artifact_error(format!(
            "finding {index} membership request names another campaign snapshot"
        )));
    }
    let object_request = |exchange: CampaignExchangeRef,
                          kind: crucible_campaign::CampaignFindingObjectKind,
                          label: &str| {
        let request = decode_request(
            evidence,
            exchange,
            crucible_campaign::GetCampaignFindingObjectRequest::from_canonical_bytes,
            index,
            label,
        )?;
        if request.campaign() != &record.campaign
            || request.snapshot() != record.snapshot
            || request.finding() != expected_finding_id
            || request.kind() != kind
        {
            return Err(artifact_error(format!(
                "finding {index} {label} request names another campaign dependency"
            )));
        }
        Ok(request)
    };
    let observation_request = object_request(
        record.observation,
        crucible_campaign::CampaignFindingObjectKind::Observation,
        "object",
    )?;
    let reproduction_request = object_request(
        record.reproduction,
        crucible_campaign::CampaignFindingObjectKind::Reproduction,
        "object",
    )?;
    let minimized_request = record
        .minimized
        .map(|exchange| {
            object_request(
                exchange,
                crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction,
                "minimized",
            )
        })
        .transpose()?;

    let client = crucible_campaign::CampaignClient::new(StoredCampaignFindingService::for_finding(
        evidence, record,
    ));
    let membership = client
        .query_campaign_findings(&membership_request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign membership proof was rejected: {error}"
            ))
        })?;
    let finding = membership
        .entries()
        .iter()
        .find(|finding| finding.id() == Ok(expected_finding_id))
        .cloned()
        .ok_or_else(|| {
            artifact_error(format!(
                "finding {index} is not admitted by the campaign snapshot"
            ))
        })?;

    let observation = match client
        .get_campaign_finding_object(&observation_request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign observation proof was rejected: {error}"
            ))
        })?
        .object()
    {
        crucible_campaign::CampaignFindingObject::Observation(observation) => observation.clone(),
        _ => {
            return Err(artifact_error(format!(
                "finding {index} campaign observation proof has the wrong object kind"
            )));
        }
    };
    let reproduction = match client
        .get_campaign_finding_object(&reproduction_request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign reproduction proof was rejected: {error}"
            ))
        })?
        .object()
    {
        crucible_campaign::CampaignFindingObject::Reproduction(reproduction) => {
            reproduction.clone()
        }
        _ => {
            return Err(artifact_error(format!(
                "finding {index} campaign reproduction proof has the wrong object kind"
            )));
        }
    };
    let minimized_reproduction = minimized_request
        .map(|request| {
            match client
                .get_campaign_finding_object(&request)
                .map_err(|error| {
                    artifact_error(format!(
                        "finding {index} minimized reproduction proof was rejected: {error}"
                    ))
                })?
                .object()
            {
                crucible_campaign::CampaignFindingObject::MinimizedReproduction(reproduction) => {
                    Ok(reproduction.clone())
                }
                _ => Err(artifact_error(format!(
                    "finding {index} minimized campaign proof has the wrong object kind"
                ))),
            }
        })
        .transpose()?;

    let reproduction_artifact = authenticate_finding_reproduction(
        evidence,
        record,
        false,
        &reproduction,
        record.reproduction_segments,
    )?;
    let minimized_artifact = match (&minimized_reproduction, record.minimized_segments) {
        (Some(minimized), Some(segments)) => Some(authenticate_finding_reproduction(
            evidence, record, true, minimized, segments,
        )?),
        (None, None) => None,
        _ => {
            return Err(artifact_error(format!(
                "finding {index} minimized reproduction and its segment list disagree"
            )));
        }
    };

    Ok(AuthenticatedCampaignFindingHead {
        finding,
        observation,
        reproduction,
        minimized_reproduction,
        reproduction_artifact,
        minimized_artifact,
    })
}

/// Authenticates every occurrence of one finding as a fold over its chunks.
///
/// `on_replay` receives each occurrence's four native replays, one at a time,
/// in [`TRIAGE_REPLAY_ROLES`] order. Uniqueness of candidate bundles needs no
/// resident set: each page request continues at the previous page's
/// exclusive cursor, and the checked Merkle scan proof admits only strictly
/// later index keys, so a bundle cannot recur in an authenticated chain.
///
/// # Errors
///
/// Returns an error when the record lists another occurrence count, a page
/// breaks the canonical chain, any occurrence fails authentication, or the
/// chain omits the finding's representative or latest candidate bundle.
pub(crate) fn authenticate_campaign_occurrences(
    context: CampaignFindingAuthenticationContext<'_>,
    on_replay: &mut dyn FnMut(
        u64,
        crucible_campaign::CampaignFindingTriageReplayRole,
        crucible_engine::FailureTriageReplayEvidence,
    ) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let index = context.index;
    let record = context.record;
    let expected_count = u64::from(context.finding.candidate_occurrence_count());
    if record.occurrence_count != expected_count {
        return Err(artifact_error(format!(
            "finding {index} does not retain one proof page per candidate occurrence"
        )));
    }

    let mut after = None;
    let mut seen_candidate = false;
    let mut seen_latest = false;
    let mut page = 0_u64;
    for (chunk_index, chunk) in (0_u64..).zip(&record.chunks) {
        let first = chunk_index * MAX_OCCURRENCES_PER_CHUNK;
        let occurrences = read_occurrence_chunk(
            context.evidence,
            *chunk,
            first,
            record.chunk_len(chunk_index)?,
        )?;
        for exchanges in &occurrences {
            let occurrence = authenticate_campaign_occurrence(
                context,
                page,
                exchanges,
                OccurrenceCursorCheck::Chained(after),
                on_replay,
            )?;
            seen_candidate |= occurrence.bundle == context.finding.candidate_bundle();
            seen_latest |= occurrence.bundle == context.finding.latest_candidate_bundle();
            after = occurrence.next_after;
            if after.is_none() && page + 1 != expected_count {
                return Err(artifact_error(format!(
                    "finding {index} occurrence pages claim an early end of index"
                )));
            }
            page += 1;
        }
    }
    if page != expected_count || after.is_some() || !seen_candidate || !seen_latest {
        return Err(artifact_error(format!(
            "finding {index} occurrence proof chain is incomplete"
        )));
    }
    Ok(())
}

/// Authenticates one occurrence and decodes its native replays.
///
/// Returns the occurrence's bundle identity and the cursor the next page
/// request must continue from.
///
/// # Errors
///
/// Returns an error when a request names another dependency, a response
/// fails its checked binding or disagrees with the finding, or a replay is
/// incomplete, reordered, substituted, or semantically unbound.
pub(crate) fn authenticate_campaign_occurrence(
    context: CampaignFindingAuthenticationContext<'_>,
    page: u64,
    exchanges: &CampaignOccurrenceExchanges,
    cursor: OccurrenceCursorCheck,
    on_replay: &mut dyn FnMut(
        u64,
        crucible_campaign::CampaignFindingTriageReplayRole,
        crucible_engine::FailureTriageReplayEvidence,
    ) -> Result<(), CliError>,
) -> Result<AuthenticatedCampaignOccurrence, CliError> {
    let index = context.index;
    let record = context.record;
    let finding = context.finding;
    let expected_finding_id = record.finding;

    let page_request = decode_request(
        context.evidence,
        exchanges.page,
        crucible_campaign::QueryCampaignFindingOccurrencesRequest::from_canonical_bytes,
        index,
        "occurrence page",
    )?;
    let after_matches = match cursor {
        OccurrenceCursorCheck::Chained(after) => page_request.after() == after,
        OccurrenceCursorCheck::Loaded => true,
    };
    if page_request.campaign() != &record.campaign
        || page_request.snapshot() != record.snapshot
        || page_request.finding() != expected_finding_id
        || !after_matches
        || page_request.limit()
            != crucible_campaign::MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS
    {
        return Err(artifact_error(format!(
            "finding {index} occurrence page {page} request breaks the canonical page chain"
        )));
    }
    let client = crucible_campaign::CampaignClient::new(
        StoredCampaignFindingService::for_occurrence(context.evidence, exchanges),
    );
    let response = client
        .query_campaign_finding_occurrences(&page_request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} occurrence page {page} proof was rejected: {error}"
            ))
        })?;
    if response.finding() != finding || response.entries().len() != 1 {
        return Err(artifact_error(format!(
            "finding {index} occurrence page {page} has an incomplete body"
        )));
    }
    let bundle = response
        .entries()
        .first()
        .map(crucible_campaign::CampaignFindingOccurrence::bundle)
        .ok_or_else(|| artifact_error("campaign occurrence page has no candidate bundle"))?;
    let bundle_id = bundle.id().map_err(|error| {
        artifact_error(format!(
            "finding {index} occurrence page {page} bundle ID is invalid: {error}"
        ))
    })?;

    let mut objects = Vec::with_capacity(3);
    for (exchange, kind) in [
        (
            exchanges.observation,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Observation,
        ),
        (
            exchanges.reproduction,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Reproduction,
        ),
        (
            exchanges.minimized,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
        ),
    ] {
        let request = decode_request(
            context.evidence,
            exchange,
            crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::from_canonical_bytes,
            index,
            "occurrence object",
        )?;
        if request.campaign() != &record.campaign
            || request.snapshot() != record.snapshot
            || request.finding() != expected_finding_id
            || request.bundle() != bundle_id
            || request.kind() != kind
        {
            return Err(artifact_error(format!(
                "finding {index} occurrence page {page} object request names another dependency"
            )));
        }
        let object_response = client
            .get_campaign_finding_occurrence_object(&request)
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} occurrence page {page} object proof was rejected: {error}"
                ))
            })?;
        if object_response.finding() != finding
            || object_response.bundle() != bundle
            || object_response.object().kind() != kind
        {
            return Err(artifact_error(format!(
                "finding {index} occurrence page {page} object proof disagrees with its bundle"
            )));
        }
        objects.push(object_response);
    }
    let reproduction = match objects.get(1).map(|response| response.object()) {
        Some(crucible_campaign::CampaignFindingOccurrenceObject::Reproduction(reproduction)) => {
            reproduction
        }
        _ => {
            return Err(artifact_error(
                "campaign occurrence reproduction proof has another object kind",
            ));
        }
    };
    let minimized = match objects.get(2).map(|response| response.object()) {
        Some(crucible_campaign::CampaignFindingOccurrenceObject::MinimizedReproduction(
            reproduction,
        )) => reproduction,
        _ => {
            return Err(artifact_error(
                "campaign occurrence minimized proof has another object kind",
            ));
        }
    };

    let minimization = minimized.minimization().ok_or_else(|| {
        artifact_error(format!(
            "finding {index} occurrence page {page} minimized reproduction has no trace"
        ))
    })?;
    let signature_replays = bundle.signature_minimization();
    let validated_replays = crucible_campaign::FindingSignatureMinimizationEvidence::new(
        finding.signature(),
        minimization,
        signature_replays.minimization_pass().to_vec(),
        signature_replays.verification_pass().to_vec(),
    )
    .map_err(|error| {
        artifact_error(format!(
            "finding {index} occurrence page {page} replay evidence is invalid: {error}"
        ))
    })?;
    if bundle.signature() != finding.signature() || &validated_replays != signature_replays {
        return Err(artifact_error(format!(
            "finding {index} occurrence page {page} disagrees with its finding"
        )));
    }

    // Both reproductions' segments are authenticated for every occurrence,
    // so no captured evidence goes unchecked.
    let original_artifact = authenticate_occurrence_reproduction(
        context.evidence,
        record,
        bundle_id,
        false,
        reproduction,
        exchanges.reproduction_segments,
    )?;
    let selected_artifact = authenticate_occurrence_reproduction(
        context.evidence,
        record,
        bundle_id,
        true,
        minimized,
        exchanges.minimized_segments,
    )?;

    match (&exchanges.triage, bundle.triage_evidence()) {
        (Some(roles), Some(evidence_set)) => {
            let original = campaign_model_finding_reproduction(
                &context.template.finding,
                reproduction,
                original_artifact,
            )?;
            let selected = campaign_model_finding_reproduction(
                &context.template.finding,
                minimized,
                selected_artifact,
            )?;
            for ((role, _), exchanges) in TRIAGE_REPLAY_ROLES.iter().zip(roles) {
                let evidence_id = triage_role_evidence(&evidence_set, *role);
                let replay = authenticate_campaign_triage_replay(
                    context,
                    TriageReplayPosition {
                        page,
                        bundle: bundle_id,
                        role: *role,
                        evidence: evidence_id,
                    },
                    &exchanges.segments,
                    &client,
                )?;
                let log_segments = authenticate_occurrence_triage_log_segments(
                    context.evidence,
                    record,
                    bundle_id,
                    *role,
                    &replay,
                    exchanges.log_segments,
                )?;
                let (reproduction, model_finding) = if triage_role_is_selected(*role) {
                    (minimized, selected.clone())
                } else {
                    (reproduction, original.clone())
                };
                let native = decode_campaign_triage_replay_record(
                    &replay,
                    reproduction,
                    model_finding,
                    log_segments,
                )?;
                drop(replay);
                on_replay(page, *role, native)?;
            }
        }
        (None, None) => {}
        _ => {
            return Err(artifact_error(format!(
                "finding {index} occurrence page {page} triage replay set disagrees with its bundle"
            )));
        }
    }

    Ok(AuthenticatedCampaignOccurrence {
        bundle: bundle_id,
        next_after: response.next_after(),
    })
}

/// Occurrence, bundle, role, and evidence one replay transfer must name.
#[derive(Clone, Copy)]
struct TriageReplayPosition {
    page: u64,
    bundle: crucible_campaign::FindingCandidateBundleId,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
}

/// Authenticates one role's ordered segment transcript and reassembles it.
///
/// Only this replay's envelopes are resident while it is reassembled.
fn authenticate_campaign_triage_replay(
    context: CampaignFindingAuthenticationContext<'_>,
    position: TriageReplayPosition,
    segments: &[CampaignExchangeRef],
    client: &crucible_campaign::CampaignClient<StoredCampaignFindingService>,
) -> Result<crucible_campaign::FindingTriageReplayEvidence, CliError> {
    let finding_index = context.index;
    let TriageReplayPosition {
        page: page_index,
        bundle,
        role,
        evidence,
    } = position;
    let record = context.record;
    let fetch = |exchange: CampaignExchangeRef| {
        let request = decode_request(
            context.evidence,
            exchange,
            crucible_campaign::GetCampaignFindingTriageReplaySegmentRequest::from_canonical_bytes,
            finding_index,
            "triage replay segment",
        )?;
        let response = client
            .get_campaign_finding_triage_replay_segment(&request)
            .map_err(|error| {
                artifact_error(format!(
                    "finding {finding_index} occurrence page {page_index} triage replay segment proof was rejected: {error}"
                ))
            })?;
        Ok::<_, CliError>((request, response))
    };

    let first = segments.first().copied().ok_or_else(|| {
        artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} has an empty triage replay transfer"
        ))
    })?;
    let (_, first_response) = fetch(first)?;
    let description = first_response.description().clone();
    drop(first_response);
    if description.evidence() != evidence {
        return Err(artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} triage replay description names another evidence record"
        )));
    }

    let mut expected_segments = 0_usize;
    let mut total_envelope_bytes = 0_usize;
    for object in description.objects() {
        let object_bytes = usize::try_from(object.stored_envelope_bytes()).map_err(|_| {
            artifact_error(format!(
                "finding {finding_index} occurrence page {page_index} triage replay envelope length is invalid"
            ))
        })?;
        total_envelope_bytes = total_envelope_bytes
            .checked_add(object_bytes)
            .ok_or_else(|| artifact_error("campaign triage replay transfer size overflows"))?;
        expected_segments = expected_segments
            .checked_add(
                usize::try_from(object_segment_count(object.stored_envelope_bytes())?).map_err(
                    |_| artifact_error("campaign triage replay segment count is invalid"),
                )?,
            )
            .ok_or_else(|| artifact_error("campaign triage replay segment count overflows"))?;
    }
    if total_envelope_bytes > MAX_TRIAGE_REPLAY_TRANSFER_BYTES
        || segments.len() != expected_segments
    {
        return Err(artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} triage replay transfer bounds are invalid"
        )));
    }

    let mut envelopes = Vec::with_capacity(description.objects().len());
    let mut remaining = segments.iter().copied();
    for object in description.objects() {
        let object_bytes = usize::try_from(object.stored_envelope_bytes())
            .map_err(|_| artifact_error("campaign triage replay envelope length is invalid"))?;
        let mut envelope = Vec::with_capacity(object_bytes);
        for segment_index in 0..object_segment_count(object.stored_envelope_bytes())? {
            let exchange = remaining.next().ok_or_else(|| {
                artifact_error("campaign triage replay transfer ended before its description")
            })?;
            let (request, response) = fetch(exchange)?;
            if request.campaign() != &record.campaign
                || request.snapshot() != record.snapshot
                || request.finding() != record.finding
                || request.bundle() != bundle
                || request.role() != role
                || request.evidence() != evidence
                || request.object_ordinal() != object.ordinal()
                || request.object() != object.content()
                || request.segment_index() != segment_index
                || response.description() != &description
            {
                return Err(artifact_error(format!(
                    "finding {finding_index} occurrence page {page_index} triage replay segment is reordered or substituted"
                )));
            }
            envelope.extend_from_slice(response.range_bytes());
        }
        if envelope.len() != object_bytes {
            return Err(artifact_error(format!(
                "finding {finding_index} occurrence page {page_index} triage replay envelope is incomplete"
            )));
        }
        envelopes.push(envelope);
    }

    let replay = crucible_campaign::FindingTriageReplayEvidence::from_storage_envelopes(
        &description,
        &envelopes,
    )
    .map_err(|error| {
        artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} triage replay storage proof is invalid: {error}"
        ))
    })?;
    if replay.id().ok() != Some(evidence) {
        return Err(artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} triage replay identity changed during reassembly"
        )));
    }
    Ok(replay)
}

/// Reads and decodes one stored request blob.
fn decode_request<T>(
    evidence: &crucible_engine::LocalDagStore,
    exchange: CampaignExchangeRef,
    decode: impl FnOnce(&[u8]) -> Result<T, crucible_campaign::CampaignCodecError>,
    index: usize,
    label: &str,
) -> Result<T, CliError> {
    decode(&exchange.read_request(evidence)?).map_err(|error| {
        artifact_error(format!(
            "finding {index} {label} request is invalid: {error}"
        ))
    })
}

fn triage_role_is_selected(role: crucible_campaign::CampaignFindingTriageReplayRole) -> bool {
    matches!(
        role,
        crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected
            | crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected
    )
}

/// Checks that finding-level records agree with each other and the report.
///
/// # Errors
///
/// Returns an error when any identity, configuration, fingerprint, payload,
/// or failure kind disagrees.
pub(crate) fn validate_campaign_triage_finding(
    index: usize,
    expected_finding_id: crucible_campaign::FindingId,
    item: &CampaignTriageFindingEvidence,
) -> Result<(), CliError> {
    let finding_id = item
        .finding
        .id()
        .map_err(|error| artifact_error(format!("finding {index} ID is invalid: {error}")))?;
    let observation_id = item.observation.id().map_err(|error| {
        artifact_error(format!(
            "finding {index} observation ID is invalid: {error}"
        ))
    })?;
    let reproduction_id = item.reproduction.id().map_err(|error| {
        artifact_error(format!(
            "finding {index} reproduction ID is invalid: {error}"
        ))
    })?;
    let minimized_id = item
        .minimized_reproduction
        .as_ref()
        .map(crucible_campaign::ReproductionArtifact::id)
        .transpose()
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} minimized reproduction ID is invalid: {error}"
            ))
        })?;
    let report_fingerprint =
        crucible_campaign::CampaignHash::from_bytes(item.report.finding.finding_fingerprint.bytes);
    let report_configuration =
        crucible_campaign::CampaignHash::from_bytes(item.report.finding.configuration.bytes);
    let report_failure_matches = match (item.finding.signature().kind(), &item.report.failure) {
        (
            crucible_campaign::FindingKind::PropertyViolation,
            crucible_model::FailureClusterReportFailure::Property(property),
        ) => {
            item.finding.signature().property() == Some(property.violation.assertion.name.as_str())
        }
        (
            crucible_campaign::FindingKind::Timeout,
            crucible_model::FailureClusterReportFailure::Timeout(_),
        ) => true,
        _ => false,
    };
    if finding_id != expected_finding_id
        || item.finding.observation() != observation_id
        || item.finding.reproduction() != reproduction_id
        || item.finding.minimized() != minimized_id
        || item.reproduction.configuration() != item.observation.child()
        || item.reproduction.configuration_artifact() != item.observation.child_content()
        || item.reproduction.finding_fingerprint() != item.finding.signature().fingerprint()
        || item.reproduction.finding_fingerprint() != report_fingerprint
        || item.reproduction.configuration().as_hash() != report_configuration
        || crucible_daemon::crucible_reproduction_payload(&item.report.finding.artifact)
            .ok()
            .as_ref()
            != Some(item.reproduction.reproduction_payload())
        || !report_failure_matches
    {
        return Err(artifact_error(format!(
            "finding {index} campaign records disagree with their report projection"
        )));
    }
    Ok(())
}
