//! Campaign service capture and offline proof authentication.

use super::*;

// crucible-lint: allow rust-allow -- the durable finding producer consumes this staged export boundary in the integration stack.
#[allow(dead_code)]
pub(crate) fn capture_campaign_triage_finding<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding_id: crucible_campaign::FindingId,
    report: TriageFindingEvidence,
) -> Result<CampaignTriageFindingEvidence, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let mut after = None;
    let (membership, finding) = loop {
        let request = crucible_campaign::QueryCampaignFindingsRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            after,
            crucible_campaign::MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
        )
        .map_err(|error| artifact_error(format!("build campaign finding query: {error}")))?;
        let response = client
            .query_campaign_findings(&request)
            .map_err(|error| artifact_error(format!("query campaign finding evidence: {error}")))?;
        let finding = response
            .entries()
            .iter()
            .find(|finding| finding.id() == Ok(finding_id))
            .cloned();
        if let Some(finding) = finding {
            break (
                CampaignFindingsMembershipProof { request, response },
                finding,
            );
        }
        after = response.next_after();
        if after.is_none() {
            return Err(artifact_error(
                "campaign snapshot does not retain the requested finding",
            ));
        }
    };

    let observation_proof = capture_campaign_finding_object(
        client,
        principal.clone(),
        campaign.clone(),
        snapshot,
        finding_id,
        crucible_campaign::CampaignFindingObjectKind::Observation,
    )?;
    let reproduction_proof = capture_campaign_finding_object(
        client,
        principal.clone(),
        campaign.clone(),
        snapshot,
        finding_id,
        crucible_campaign::CampaignFindingObjectKind::Reproduction,
    )?;
    let minimized_reproduction_proof = finding
        .minimized()
        .map(|_| {
            capture_campaign_finding_object(
                client,
                principal.clone(),
                campaign.clone(),
                snapshot,
                finding_id,
                crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction,
            )
        })
        .transpose()?;
    let observation = match observation_proof.response.object() {
        crucible_campaign::CampaignFindingObject::Observation(value) => value.clone(),
        _ => return Err(artifact_error("campaign returned another observation kind")),
    };
    let reproduction = match reproduction_proof.response.object() {
        crucible_campaign::CampaignFindingObject::Reproduction(value) => value.clone(),
        _ => {
            return Err(artifact_error(
                "campaign returned another reproduction kind",
            ));
        }
    };
    let minimized_reproduction = minimized_reproduction_proof
        .as_ref()
        .map(|proof| match proof.response.object() {
            crucible_campaign::CampaignFindingObject::MinimizedReproduction(value) => {
                Ok(value.clone())
            }
            _ => Err(artifact_error(
                "campaign returned another minimized reproduction kind",
            )),
        })
        .transpose()?;

    let mut occurrence_proofs = Vec::new();
    let mut occurrence_after = None;
    while occurrence_proofs.len()
        < usize::try_from(finding.candidate_occurrence_count())
            .map_err(|_| artifact_error("campaign finding occurrence count is invalid"))?
    {
        let request = crucible_campaign::QueryCampaignFindingOccurrencesRequest::new(
            principal.clone(),
            campaign.clone(),
            snapshot,
            finding_id,
            occurrence_after,
            crucible_campaign::MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS,
        )
        .map_err(|error| artifact_error(format!("build campaign occurrence query: {error}")))?;
        let response = client
            .query_campaign_finding_occurrences(&request)
            .map_err(|error| artifact_error(format!("query campaign occurrence: {error}")))?;
        let bundle = response
            .entries()
            .first()
            .ok_or_else(|| artifact_error("campaign occurrence query ended before its count"))?
            .bundle();
        let bundle_id = bundle.id().map_err(|error| {
            artifact_error(format!("campaign occurrence bundle ID is invalid: {error}"))
        })?;
        let observation = capture_campaign_finding_occurrence_object(
            client,
            principal.clone(),
            campaign.clone(),
            snapshot,
            finding_id,
            bundle_id,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Observation,
        )?;
        let reproduction = capture_campaign_finding_occurrence_object(
            client,
            principal.clone(),
            campaign.clone(),
            snapshot,
            finding_id,
            bundle_id,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::Reproduction,
        )?;
        let minimized_reproduction = capture_campaign_finding_occurrence_object(
            client,
            principal.clone(),
            campaign.clone(),
            snapshot,
            finding_id,
            bundle_id,
            crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
        )?;
        let triage_evidence = bundle
            .triage_evidence()
            .map(|_| {
                Ok::<_, CliError>(CampaignFindingOccurrenceTriageProof {
                    minimization_original: capture_campaign_finding_occurrence_object(
                        client,
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        finding_id,
                        bundle_id,
                        crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence,
                    )?,
                    minimization_selected: capture_campaign_finding_occurrence_object(
                        client,
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        finding_id,
                        bundle_id,
                        crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence,
                    )?,
                    verification_original: capture_campaign_finding_occurrence_object(
                        client,
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        finding_id,
                        bundle_id,
                        crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence,
                    )?,
                    verification_selected: capture_campaign_finding_occurrence_object(
                        client,
                        principal.clone(),
                        campaign.clone(),
                        snapshot,
                        finding_id,
                        bundle_id,
                        crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence,
                    )?,
                })
            })
            .transpose()?;
        occurrence_after = response.next_after();
        occurrence_proofs.push(CampaignFindingOccurrenceProof {
            page: CampaignFindingOccurrencesProof { request, response },
            observation,
            reproduction,
            minimized_reproduction,
            triage_evidence,
        });
    }

    let evidence = CampaignTriageFindingEvidence {
        campaign,
        snapshot,
        membership,
        observation_proof,
        reproduction_proof,
        minimized_reproduction_proof,
        occurrence_proofs,
        finding,
        observation,
        reproduction,
        minimized_reproduction,
        report,
    };
    authenticate_campaign_triage_finding(0, finding_id, &evidence)?;
    validate_campaign_triage_finding(0, finding_id, &evidence)?;
    Ok(evidence)
}

// crucible-lint: allow rust-allow -- this helper is reachable through the staged campaign finding export boundary.
#[allow(dead_code)]
fn capture_campaign_finding_object<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
    kind: crucible_campaign::CampaignFindingObjectKind,
) -> Result<CampaignFindingObjectProof, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
        principal, campaign, snapshot, finding, kind,
    )
    .map_err(|error| artifact_error(format!("build campaign finding object query: {error}")))?;
    let response = client
        .get_campaign_finding_object(&request)
        .map_err(|error| artifact_error(format!("query campaign finding object: {error}")))?;
    Ok(CampaignFindingObjectProof { request, response })
}

// crucible-lint: allow rust-allow -- this helper is reachable through the staged campaign finding export boundary.
#[allow(dead_code, clippy::too_many_arguments)]
fn capture_campaign_finding_occurrence_object<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    campaign: crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
    bundle: crucible_campaign::FindingCandidateBundleId,
    kind: crucible_campaign::CampaignFindingOccurrenceObjectKind,
) -> Result<CampaignFindingOccurrenceObjectProof, CliError>
where
    S: crucible_campaign::CampaignFindingOccurrenceService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let request = crucible_campaign::GetCampaignFindingOccurrenceObjectRequest::new(
        principal, campaign, snapshot, finding, bundle, kind,
    )
    .map_err(|error| artifact_error(format!("build campaign occurrence object query: {error}")))?;
    let response = client
        .get_campaign_finding_occurrence_object(&request)
        .map_err(|error| artifact_error(format!("query campaign occurrence object: {error}")))?;
    Ok(CampaignFindingOccurrenceObjectProof { request, response })
}

#[derive(Clone)]
struct ImportedCampaignFindingService {
    membership: CampaignFindingsMembershipProof,
    objects: Vec<CampaignFindingObjectProof>,
    occurrences: Vec<CampaignFindingOccurrencesProof>,
    occurrence_objects: Vec<CampaignFindingOccurrenceObjectProof>,
}

impl crucible_campaign::CampaignFindingOccurrenceService for ImportedCampaignFindingService {
    fn query_campaign_finding_occurrences(
        &self,
        request: &crucible_campaign::QueryCampaignFindingOccurrencesRequest,
    ) -> Result<crucible_campaign::QueryCampaignFindingOccurrencesResponse, Self::Error> {
        self.occurrences
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &crucible_campaign::GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        self.occurrence_objects
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }
}

macro_rules! reject_imported_campaign_service_operations {
    ($($method:ident($request:ty) -> $response:ty;)*) => {
        $(
            fn $method(&self, _request: &$request) -> Result<$response, Self::Error> {
                Err(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
            }
        )*
    };
}

impl crucible_campaign::CampaignService for ImportedCampaignFindingService {
    type Error = crucible_campaign::CampaignServiceFailure;

    reject_imported_campaign_service_operations! {
        list_campaigns(crucible_campaign::ListCampaignsRequest) -> crucible_campaign::ListCampaignsResponse;
        create_campaign(crucible_campaign::CreateCampaignRequest) -> crucible_campaign::CreateCampaignResponse;
        derive_campaign(crucible_campaign::DeriveCampaignRequest) -> crucible_campaign::DeriveCampaignResponse;
        get_campaign(crucible_campaign::GetCampaignRequest) -> crucible_campaign::GetCampaignResponse;
        get_campaign_status(crucible_campaign::GetCampaignStatusRequest) -> crucible_campaign::GetCampaignStatusResponse;
        query_campaign_report(crucible_campaign::QueryCampaignReportRequest) -> crucible_campaign::QueryCampaignReportResponse;
        get_campaign_snapshot(crucible_campaign::GetCampaignSnapshotRequest) -> crucible_campaign::GetCampaignSnapshotResponse;
        watch_campaign(crucible_campaign::WatchCampaignRequest) -> crucible_campaign::WatchCampaignResponse;
        query_campaign_graph(crucible_campaign::QueryCampaignGraphRequest) -> crucible_campaign::QueryCampaignGraphResponse;
        get_campaign_graph_object(crucible_campaign::GetCampaignGraphObjectRequest) -> crucible_campaign::GetCampaignGraphObjectResponse;
        query_campaign_choices(crucible_campaign::QueryCampaignChoicesRequest) -> crucible_campaign::QueryCampaignChoicesResponse;
        query_campaign_frontier(crucible_campaign::QueryCampaignFrontierRequest) -> crucible_campaign::QueryCampaignFrontierResponse;
        explain_campaign_attempt(crucible_campaign::ExplainCampaignAttemptRequest) -> crucible_campaign::ExplainCampaignAttemptResponse;
        get_campaign_planner_rankings(crucible_campaign::GetCampaignPlannerRankingsRequest) -> crucible_campaign::GetCampaignPlannerRankingsResponse;
        get_campaign_frontier_object(crucible_campaign::GetCampaignFrontierObjectRequest) -> crucible_campaign::GetCampaignFrontierObjectResponse;
        get_campaign_choice_object(crucible_campaign::GetCampaignChoiceObjectRequest) -> crucible_campaign::GetCampaignChoiceObjectResponse;
        apply_campaign_command(crucible_campaign::ApplyCampaignCommandRequest) -> crucible_campaign::ApplyCampaignCommandResponse;
        pin_campaign(crucible_campaign::PinCampaignRequest) -> crucible_campaign::PinCampaignResponse;
        submit_discovery_request(crucible_campaign::SubmitCampaignDiscoveryRequest) -> crucible_campaign::SubmitCampaignDiscoveryResponse;
        submit_branch_request(crucible_campaign::SubmitCampaignBranchRequest) -> crucible_campaign::SubmitCampaignBranchResponse;
    }

    fn query_campaign_findings(
        &self,
        request: &crucible_campaign::QueryCampaignFindingsRequest,
    ) -> Result<crucible_campaign::QueryCampaignFindingsResponse, Self::Error> {
        if request != &self.membership.request {
            return Err(crucible_campaign::CampaignServiceFailure::ProtocolViolation);
        }
        Ok(self.membership.response.clone())
    }

    fn get_campaign_finding_object(
        &self,
        request: &crucible_campaign::GetCampaignFindingObjectRequest,
    ) -> Result<crucible_campaign::GetCampaignFindingObjectResponse, Self::Error> {
        self.objects
            .iter()
            .find(|proof| &proof.request == request)
            .map(|proof| proof.response.clone())
            .ok_or(crucible_campaign::CampaignServiceFailure::ProtocolViolation)
    }
}

pub(super) fn authenticate_campaign_triage_finding(
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
    for proof in &item.occurrence_proofs {
        occurrence_objects.extend([
            proof.observation.clone(),
            proof.reproduction.clone(),
            proof.minimized_reproduction.clone(),
        ]);
        if let Some(triage) = &proof.triage_evidence {
            occurrence_objects.extend([
                triage.minimization_original.clone(),
                triage.minimization_selected.clone(),
                triage.verification_original.clone(),
                triage.verification_selected.clone(),
            ]);
        }
    }
    let client = crucible_campaign::CampaignClient::new(ImportedCampaignFindingService {
        membership: item.membership.clone(),
        objects,
        occurrences,
        occurrence_objects,
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

        let mut object_proofs = vec![
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
            (Some(triage), Some(_)) => object_proofs.extend([
                (
                    &triage.minimization_original,
                    crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence,
                ),
                (
                    &triage.minimization_selected,
                    crucible_campaign::CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence,
                ),
                (
                    &triage.verification_original,
                    crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence,
                ),
                (
                    &triage.verification_selected,
                    crucible_campaign::CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence,
                ),
            ]),
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

pub(super) fn validate_campaign_triage_finding(
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
