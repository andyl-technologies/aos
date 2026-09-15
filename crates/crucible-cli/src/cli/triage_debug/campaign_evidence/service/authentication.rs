//! Authenticated campaign finding, occurrence, and replay-set validation.

use super::*;

pub(crate) fn authenticate_campaign_triage_finding(
    index: usize,
    expected_finding_id: crucible_campaign::FindingId,
    item: &CampaignTriageFindingEvidence,
) -> Result<(), CliError> {
    if item.membership.request.campaign() != &item.campaign
        || item.membership.request.snapshot() != item.snapshot
    {
        return Err(artifact_error(format!(
            "finding {index} membership request names another campaign snapshot"
        )));
    }
    for (proof, kind) in [
        (
            &item.observation_proof,
            crucible_campaign::CampaignFindingObjectKind::Observation,
        ),
        (
            &item.reproduction_proof,
            crucible_campaign::CampaignFindingObjectKind::Reproduction,
        ),
    ] {
        if proof.request.campaign() != &item.campaign
            || proof.request.snapshot() != item.snapshot
            || proof.request.finding() != expected_finding_id
            || proof.request.kind() != kind
        {
            return Err(artifact_error(format!(
                "finding {index} object request names another campaign dependency"
            )));
        }
    }
    if let Some(proof) = &item.minimized_reproduction_proof
        && (proof.request.campaign() != &item.campaign
            || proof.request.snapshot() != item.snapshot
            || proof.request.finding() != expected_finding_id
            || proof.request.kind()
                != crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction)
    {
        return Err(artifact_error(format!(
            "finding {index} minimized request names another campaign dependency"
        )));
    }
    let mut objects = vec![
        item.observation_proof.clone(),
        item.reproduction_proof.clone(),
    ];
    objects.extend(item.minimized_reproduction_proof.iter().cloned());
    let occurrences = item
        .occurrence_proofs
        .iter()
        .map(|proof| proof.page.clone())
        .collect();
    let mut occurrence_objects = Vec::new();
    let mut triage_segments = Vec::new();
    for proof in &item.occurrence_proofs {
        occurrence_objects.extend([
            proof.observation.clone(),
            proof.reproduction.clone(),
            proof.minimized_reproduction.clone(),
        ]);
        if let Some(triage) = &proof.triage_evidence {
            for replay in [
                &triage.minimization_original,
                &triage.minimization_selected,
                &triage.verification_original,
                &triage.verification_selected,
            ] {
                triage_segments.extend(replay.segments.iter().cloned());
            }
        }
    }
    let client = crucible_campaign::CampaignClient::new(ImportedCampaignFindingService {
        membership: item.membership.clone(),
        objects,
        occurrences,
        occurrence_objects,
        triage_segments,
    });
    let membership = client
        .query_campaign_findings(&item.membership.request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign membership proof was rejected: {error}"
            ))
        })?;
    let authenticated_finding = membership
        .entries()
        .iter()
        .find(|finding| finding.id() == Ok(expected_finding_id))
        .ok_or_else(|| {
            artifact_error(format!(
                "finding {index} is not admitted by the campaign snapshot"
            ))
        })?;
    if authenticated_finding != &item.finding {
        return Err(artifact_error(format!(
            "finding {index} body differs from its admitted campaign member"
        )));
    }

    let observation = client
        .get_campaign_finding_object(&item.observation_proof.request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign observation proof was rejected: {error}"
            ))
        })?;
    let crucible_campaign::CampaignFindingObject::Observation(observation) = observation.object()
    else {
        return Err(artifact_error(format!(
            "finding {index} campaign observation proof has the wrong object kind"
        )));
    };
    if observation != &item.observation {
        return Err(artifact_error(format!(
            "finding {index} observation differs from its campaign proof"
        )));
    }

    let reproduction = client
        .get_campaign_finding_object(&item.reproduction_proof.request)
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} campaign reproduction proof was rejected: {error}"
            ))
        })?;
    let crucible_campaign::CampaignFindingObject::Reproduction(reproduction) =
        reproduction.object()
    else {
        return Err(artifact_error(format!(
            "finding {index} campaign reproduction proof has the wrong object kind"
        )));
    };
    if reproduction != &item.reproduction {
        return Err(artifact_error(format!(
            "finding {index} reproduction differs from its campaign proof"
        )));
    }

    let proved_minimized = item
        .minimized_reproduction_proof
        .as_ref()
        .map(|proof| {
            client
                .get_campaign_finding_object(&proof.request)
                .map_err(|error| {
                    artifact_error(format!(
                        "finding {index} minimized reproduction proof was rejected: {error}"
                    ))
                })
        })
        .transpose()?;
    match (
        proved_minimized.as_ref(),
        item.minimized_reproduction.as_ref(),
    ) {
        (Some(response), Some(expected)) => {
            let crucible_campaign::CampaignFindingObject::MinimizedReproduction(actual) =
                response.object()
            else {
                return Err(artifact_error(format!(
                    "finding {index} minimized campaign proof has the wrong object kind"
                )));
            };
            if actual != expected {
                return Err(artifact_error(format!(
                    "finding {index} minimized reproduction differs from its campaign proof"
                )));
            }
        }
        (None, None) => {}
        _ => {
            return Err(artifact_error(format!(
                "finding {index} minimized reproduction is missing its campaign proof"
            )));
        }
    }
    authenticate_campaign_occurrences(index, expected_finding_id, item, &client)
}

fn authenticate_campaign_occurrences(
    index: usize,
    expected_finding_id: crucible_campaign::FindingId,
    item: &CampaignTriageFindingEvidence,
    client: &crucible_campaign::CampaignClient<ImportedCampaignFindingService>,
) -> Result<(), CliError> {
    let expected_count = usize::try_from(item.finding.candidate_occurrence_count())
        .map_err(|_| artifact_error(format!("finding {index} occurrence count is invalid")))?;
    if expected_count == 0 {
        if item.finding.candidate_bundle().is_some() || !item.occurrence_proofs.is_empty() {
            return Err(artifact_error(format!(
                "finding {index} has inconsistent candidate occurrence evidence"
            )));
        }
        return Ok(());
    }
    if item.occurrence_proofs.len() != expected_count {
        return Err(artifact_error(format!(
            "finding {index} does not retain one proof page per candidate occurrence"
        )));
    }

    let mut after = None;
    let mut bundle_ids = BTreeSet::new();
    for (page, occurrence_proof) in item.occurrence_proofs.iter().enumerate() {
        let page_proof = &occurrence_proof.page;
        if page_proof.request.campaign() != &item.campaign
            || page_proof.request.snapshot() != item.snapshot
            || page_proof.request.finding() != expected_finding_id
            || page_proof.request.after() != after
            || page_proof.request.limit()
                != crucible_campaign::MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS
        {
            return Err(artifact_error(format!(
                "finding {index} occurrence page {page} request breaks the canonical page chain"
            )));
        }
        let response = client
            .query_campaign_finding_occurrences(&page_proof.request)
            .map_err(|error| {
                artifact_error(format!(
                    "finding {index} occurrence page {page} proof was rejected: {error}"
                ))
            })?;
        if response.finding() != &item.finding || response.entries().len() != 1 {
            return Err(artifact_error(format!(
                "finding {index} occurrence page {page} has an incomplete body"
            )));
        }
        let bundle = campaign_occurrence_bundle(occurrence_proof)?;
        let bundle_id = bundle.id().map_err(|error| {
            artifact_error(format!(
                "finding {index} occurrence page {page} bundle ID is invalid: {error}"
            ))
        })?;

        let object_proofs = [
            (
                &occurrence_proof.observation,
                crucible_campaign::CampaignFindingOccurrenceObjectKind::Observation,
            ),
            (
                &occurrence_proof.reproduction,
                crucible_campaign::CampaignFindingOccurrenceObjectKind::Reproduction,
            ),
            (
                &occurrence_proof.minimized_reproduction,
                crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
            ),
        ];
        match (&occurrence_proof.triage_evidence, bundle.triage_evidence()) {
            (Some(triage), Some(evidence)) => {
                let context = CampaignTriageReplayAuthenticationContext {
                    finding_index: index,
                    page_index: page,
                    item,
                    finding: expected_finding_id,
                    bundle: bundle_id,
                };
                authenticate_campaign_triage_replay(
                    context,
                    crucible_campaign::CampaignFindingTriageReplayRole::MinimizationOriginal,
                    evidence.minimization_original(),
                    &triage.minimization_original,
                    client,
                )?;
                authenticate_campaign_triage_replay(
                    context,
                    crucible_campaign::CampaignFindingTriageReplayRole::MinimizationSelected,
                    evidence.minimization_selected(),
                    &triage.minimization_selected,
                    client,
                )?;
                authenticate_campaign_triage_replay(
                    context,
                    crucible_campaign::CampaignFindingTriageReplayRole::VerificationOriginal,
                    evidence.verification_original(),
                    &triage.verification_original,
                    client,
                )?;
                authenticate_campaign_triage_replay(
                    context,
                    crucible_campaign::CampaignFindingTriageReplayRole::VerificationSelected,
                    evidence.verification_selected(),
                    &triage.verification_selected,
                    client,
                )?;
            }
            (None, None) => {}
            _ => {
                return Err(artifact_error(format!(
                    "finding {index} occurrence page {page} triage replay set disagrees with its bundle"
                )));
            }
        }
        for (object_proof, kind) in object_proofs {
            if object_proof.request.campaign() != &item.campaign
                || object_proof.request.snapshot() != item.snapshot
                || object_proof.request.finding() != expected_finding_id
                || object_proof.request.bundle() != bundle_id
                || object_proof.request.kind() != kind
            {
                return Err(artifact_error(format!(
                    "finding {index} occurrence page {page} object request names another dependency"
                )));
            }
            let object_response = client
                .get_campaign_finding_occurrence_object(&object_proof.request)
                .map_err(|error| {
                    artifact_error(format!(
                        "finding {index} occurrence page {page} object proof was rejected: {error}"
                    ))
                })?;
            if object_response.finding() != &item.finding
                || object_response.bundle() != bundle
                || object_response.object().kind() != kind
            {
                return Err(artifact_error(format!(
                    "finding {index} occurrence page {page} object proof disagrees with its bundle"
                )));
            }
        }

        let minimized = campaign_occurrence_minimized_reproduction(occurrence_proof)?;
        let minimization = minimized.minimization().ok_or_else(|| {
            artifact_error(format!(
                "finding {index} occurrence page {page} minimized reproduction has no trace"
            ))
        })?;
        let signature_replays = bundle.signature_minimization();
        let validated_replays = crucible_campaign::FindingSignatureMinimizationEvidence::new(
            item.finding.signature(),
            minimization,
            signature_replays.minimization_pass().to_vec(),
            signature_replays.verification_pass().to_vec(),
        )
        .map_err(|error| {
            artifact_error(format!(
                "finding {index} occurrence page {page} replay evidence is invalid: {error}"
            ))
        })?;
        if bundle.signature() != item.finding.signature()
            || &validated_replays != signature_replays
            || !bundle_ids.insert(bundle_id)
        {
            return Err(artifact_error(format!(
                "finding {index} occurrence page {page} disagrees with its finding"
            )));
        }
        after = response.next_after();
        if after.is_none() && page + 1 != expected_count {
            return Err(artifact_error(format!(
                "finding {index} occurrence pages claim an early end of index"
            )));
        }
    }
    if after.is_some()
        || item
            .finding
            .candidate_bundle()
            .is_none_or(|bundle| !bundle_ids.contains(&bundle))
        || item
            .finding
            .latest_candidate_bundle()
            .is_none_or(|bundle| !bundle_ids.contains(&bundle))
    {
        return Err(artifact_error(format!(
            "finding {index} occurrence proof chain is incomplete"
        )));
    }
    Ok(())
}

fn authenticate_campaign_triage_replay(
    context: CampaignTriageReplayAuthenticationContext<'_>,
    role: crucible_campaign::CampaignFindingTriageReplayRole,
    evidence: crucible_campaign::FindingTriageReplayEvidenceId,
    proof: &CampaignFindingTriageReplayProof,
    client: &crucible_campaign::CampaignClient<ImportedCampaignFindingService>,
) -> Result<crucible_campaign::FindingTriageReplayEvidence, CliError> {
    let CampaignTriageReplayAuthenticationContext {
        finding_index,
        page_index,
        item,
        finding,
        bundle,
    } = context;
    let first = proof.segments.first().ok_or_else(|| {
        artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} has an empty triage replay transfer"
        ))
    })?;
    let description = first.response.description().clone();
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
        let count = object
            .stored_envelope_bytes()
            .checked_add(crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES - 1)
            .ok_or_else(|| artifact_error("campaign triage segment count overflows"))?
            / crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES;
        expected_segments =
            expected_segments
                .checked_add(usize::try_from(count).map_err(|_| {
                    artifact_error("campaign triage replay segment count is invalid")
                })?)
                .ok_or_else(|| artifact_error("campaign triage replay segment count overflows"))?;
    }
    if total_envelope_bytes > 256 * 1024 * 1024 || proof.segments.len() != expected_segments {
        return Err(artifact_error(format!(
            "finding {finding_index} occurrence page {page_index} triage replay transfer bounds are invalid"
        )));
    }

    let mut envelopes = Vec::with_capacity(description.objects().len());
    let mut segment_position = 0;
    for object in description.objects() {
        let object_bytes = usize::try_from(object.stored_envelope_bytes())
            .map_err(|_| artifact_error("campaign triage replay envelope length is invalid"))?;
        let mut envelope = Vec::with_capacity(object_bytes);
        let segment_count = object
            .stored_envelope_bytes()
            .checked_add(crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES - 1)
            .ok_or_else(|| artifact_error("campaign triage segment count overflows"))?
            / crucible_campaign::MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES;
        for segment_index in 0..u32::try_from(segment_count)
            .map_err(|_| artifact_error("campaign triage segment count is invalid"))?
        {
            let segment = proof.segments.get(segment_position).ok_or_else(|| {
                artifact_error("campaign triage replay transfer ended before its description")
            })?;
            let request = &segment.request;
            if request.campaign() != &item.campaign
                || request.snapshot() != item.snapshot
                || request.finding() != finding
                || request.bundle() != bundle
                || request.role() != role
                || request.evidence() != evidence
                || request.object_ordinal() != object.ordinal()
                || request.object() != object.content()
                || request.segment_index() != segment_index
                || segment.response.description() != &description
            {
                return Err(artifact_error(format!(
                    "finding {finding_index} occurrence page {page_index} triage replay segment is reordered or substituted"
                )));
            }
            let response = client
                .get_campaign_finding_triage_replay_segment(request)
                .map_err(|error| {
                    artifact_error(format!(
                        "finding {finding_index} occurrence page {page_index} triage replay segment proof was rejected: {error}"
                    ))
                })?;
            if response != segment.response {
                return Err(artifact_error(format!(
                    "finding {finding_index} occurrence page {page_index} triage replay segment response was substituted"
                )));
            }
            envelope.extend_from_slice(response.range_bytes());
            segment_position += 1;
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
    for occurrence in campaign_occurrences(item) {
        let _ = campaign_occurrence_native_triage_replays(occurrence, &item.report)?;
    }
    if finding_id != expected_finding_id
        || item.finding.observation() != observation_id
        || item.finding.reproduction() != reproduction_id
        || item.finding.minimized() != minimized_id
        || item.reproduction.configuration() != item.observation.child()
        || item.reproduction.configuration_artifact() != item.observation.child_content()
        || item.reproduction.finding_fingerprint() != item.finding.signature().fingerprint()
        || item.reproduction.finding_fingerprint() != report_fingerprint
        || item.reproduction.configuration().as_hash() != report_configuration
        || item.reproduction.payload() != item.report.finding.artifact.to_compact_binary()
        || !report_failure_matches
    {
        return Err(artifact_error(format!(
            "finding {index} campaign records disagree with their report projection"
        )));
    }
    Ok(())
}
