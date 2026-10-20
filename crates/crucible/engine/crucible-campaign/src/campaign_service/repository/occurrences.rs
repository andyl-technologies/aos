//! Authenticated finding-occurrence queries over the repository service.

use super::*;

impl<A> CampaignFindingOccurrenceService for RepositoryCampaignService<'_, A>
where
    A: CampaignPrincipalAuthorizer,
{
    fn query_campaign_finding_occurrences(
        &self,
        request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::QueryCampaignFindingOccurrences,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (finding, finding_proof) = self
            .repository
            .finding_with_proof(head.snapshot().roots().findings, request.finding())?;
        let occurrence_root = finding.candidate_occurrences();
        let limit = usize::try_from(request.limit()).map_err(|_| {
            CampaignRepositoryError::InvalidRequest {
                reason: "campaign-finding-occurrence-query-page-size-is-invalid",
            }
        })?;
        let (page, occurrence_proof) = self.repository.scan_finding_candidate_occurrences_page(
            occurrence_root,
            request.after(),
            limit,
        )?;
        let entries = page
            .entries()
            .iter()
            .map(|(_, object)| {
                let bundle = self.repository.load_finding_candidate_bundle(
                    FindingCandidateBundleId::from_content_id(*object)?,
                )?;
                Ok(CampaignFindingOccurrence::new(bundle))
            })
            .collect::<Result<Vec<_>, CampaignRepositoryError>>()?;
        Ok(QueryCampaignFindingOccurrencesResponse::new(
            request,
            head.snapshot().clone(),
            finding,
            entries,
            page.next_after(),
            finding_proof,
            occurrence_proof,
        )?)
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignFindingOccurrenceObject,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }
        let (finding, finding_proof) = self
            .repository
            .finding_with_proof(head.snapshot().roots().findings, request.finding())?;
        let occurrence_root = finding.candidate_occurrences();
        let (bundle, occurrence_proof) = self
            .repository
            .finding_candidate_bundle_with_proof(occurrence_root, request.bundle())?;
        let object = match request.kind() {
            CampaignFindingOccurrenceObjectKind::Observation => {
                CampaignFindingOccurrenceObject::Observation(
                    self.repository.load_observation(bundle.observation())?,
                )
            }
            CampaignFindingOccurrenceObjectKind::Reproduction => {
                CampaignFindingOccurrenceObject::Reproduction(
                    self.repository
                        .load_reproduction_artifact(bundle.reproduction())?,
                )
            }
            CampaignFindingOccurrenceObjectKind::MinimizedReproduction => {
                CampaignFindingOccurrenceObject::MinimizedReproduction(
                    self.repository
                        .load_reproduction_artifact(bundle.minimized())?,
                )
            }
            CampaignFindingOccurrenceObjectKind::MinimizationOriginalTriageEvidence => {
                let evidence =
                    bundle
                        .triage_evidence()
                        .ok_or(CampaignRepositoryError::InvalidRequest {
                            reason: "campaign-finding-candidate-has-no-triage-evidence",
                        })?;
                CampaignFindingOccurrenceObject::MinimizationOriginalTriageEvidence(
                    self.repository
                        .load_finding_triage_replay_evidence(evidence.minimization_original())?,
                )
            }
            CampaignFindingOccurrenceObjectKind::MinimizationSelectedTriageEvidence => {
                let evidence =
                    bundle
                        .triage_evidence()
                        .ok_or(CampaignRepositoryError::InvalidRequest {
                            reason: "campaign-finding-candidate-has-no-triage-evidence",
                        })?;
                CampaignFindingOccurrenceObject::MinimizationSelectedTriageEvidence(
                    self.repository
                        .load_finding_triage_replay_evidence(evidence.minimization_selected())?,
                )
            }
            CampaignFindingOccurrenceObjectKind::VerificationOriginalTriageEvidence => {
                let evidence =
                    bundle
                        .triage_evidence()
                        .ok_or(CampaignRepositoryError::InvalidRequest {
                            reason: "campaign-finding-candidate-has-no-triage-evidence",
                        })?;
                CampaignFindingOccurrenceObject::VerificationOriginalTriageEvidence(
                    self.repository
                        .load_finding_triage_replay_evidence(evidence.verification_original())?,
                )
            }
            CampaignFindingOccurrenceObjectKind::VerificationSelectedTriageEvidence => {
                let evidence =
                    bundle
                        .triage_evidence()
                        .ok_or(CampaignRepositoryError::InvalidRequest {
                            reason: "campaign-finding-candidate-has-no-triage-evidence",
                        })?;
                CampaignFindingOccurrenceObject::VerificationSelectedTriageEvidence(
                    self.repository
                        .load_finding_triage_replay_evidence(evidence.verification_selected())?,
                )
            }
        };
        Ok(GetCampaignFindingOccurrenceObjectResponse::new(
            request,
            head.snapshot().clone(),
            finding,
            bundle,
            object,
            finding_proof,
            occurrence_proof,
        )?)
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
        self.authorizer.authorize(
            request.principal(),
            CampaignServiceOperation::GetCampaignFindingTriageReplaySegment,
            request.campaign(),
            request.request_digest(),
        )?;
        let head = self.repository.head(request.campaign().as_str())?;
        if head.snapshot_id() != request.snapshot() {
            return Err(CampaignRepositoryError::Stale {
                expected: request.snapshot(),
                current: head.snapshot_id(),
            }
            .into());
        }

        let (finding, finding_proof) = self
            .repository
            .finding_with_proof(head.snapshot().roots().findings, request.finding())?;
        let occurrence_root = finding.candidate_occurrences();
        let (bundle, occurrence_proof) = self
            .repository
            .finding_candidate_bundle_with_proof(occurrence_root, request.bundle())?;
        if request.role().evidence(&bundle) != Some(request.evidence()) {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-finding-triage-replay-role-evidence-mismatch",
            }
            .into());
        }

        let description = self
            .repository
            .describe_finding_triage_replay_storage(request.evidence())?;
        let range = description.segment_range(
            request.object_ordinal(),
            request.object(),
            request.segment_index(),
        )?;
        let range_bytes = self.repository.read_finding_triage_replay_storage_range(
            request.evidence(),
            request.object_ordinal(),
            range,
        )?;
        Ok(GetCampaignFindingTriageReplaySegmentResponse::new(
            request,
            head.snapshot().clone(),
            finding,
            bundle,
            description,
            range_bytes,
            crate::CampaignFindingTriageReplayProofs::new(finding_proof, occurrence_proof),
        )?)
    }
}
