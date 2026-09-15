//! Typed record-body and authenticated child-table validation.

use super::*;

impl ObjectEnvelope {
    pub(super) fn validate_record_body(&self) -> Result<(), CampaignCodecError> {
        if matches!(
            self.record_kind,
            CampaignRecordKind::Policy
                | CampaignRecordKind::Fact
                | CampaignRecordKind::Snapshot
                | CampaignRecordKind::BudgetLedger
                | CampaignRecordKind::PlannerCandidateBudget
                | CampaignRecordKind::BranchPath
                | CampaignRecordKind::BranchRequest
                | CampaignRecordKind::Attempt
                | CampaignRecordKind::AttemptAdmission
                | CampaignRecordKind::MeasurementSet
                | CampaignRecordKind::Observation
                | CampaignRecordKind::ObjectiveEvaluation
                | CampaignRecordKind::RankingExplanation
                | CampaignRecordKind::ReproductionArtifact
                | CampaignRecordKind::Finding
                | CampaignRecordKind::FindingCandidateBundle
                | CampaignRecordKind::FindingTriageReplayEvidence
                | CampaignRecordKind::FindingTriageReplayEvidenceChunk
                | CampaignRecordKind::PlannerCandidateGuidance
                | CampaignRecordKind::PlannerBeamCandidate
                | CampaignRecordKind::ArchiveManifest
                | CampaignRecordKind::ArchiveInventoryPage
        ) {
            let version = self
                .envelope
                .body()
                .get(..std::mem::size_of::<u32>())
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                .ok_or(CampaignCodecError::Truncated)?;
            if version != self.envelope.schema_version() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "versioned campaign body and envelope versions differ",
                });
            }
        }
        let expected = expected_children(self.record_kind, self.envelope.body())?;
        if expected != *self.envelope.children() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "campaign record child table disagrees with its body",
            });
        }
        Ok(())
    }
}

fn expected_children(
    kind: CampaignRecordKind,
    body: &[u8],
) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
    match kind {
        CampaignRecordKind::BudgetLedger => {
            let ledger = crate::CampaignBudgetLedger::from_canonical_bytes(body)?;
            content_children(ledger.content_children())
        }
        CampaignRecordKind::Lineage => {
            let value = CampaignLineage::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Policy => {
            let value = CampaignPolicy::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Snapshot => {
            snapshot_children(&CampaignSnapshot::from_canonical_bytes(body)?)
        }
        CampaignRecordKind::Fact => fact_children(&CampaignFact::from_canonical_bytes(body)?),
        CampaignRecordKind::PlanningView => {
            let value = codec::decode::<CampaignPlanningView>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerEngine => {
            codec::decode::<PlannerEngine>(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::PolicyArtifact => {
            let value = codec::decode::<PolicyArtifact>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerState => {
            let value = codec::decode::<PlannerState>(body)?;
            content_children([("engine", value.engine().content_id())])
        }
        CampaignRecordKind::PlannerInvocation => {
            let value = codec::decode::<PlannerInvocation>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ChoiceDomain => {
            ChoiceDomain::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::SelectableDeclaration => {
            SelectableDeclaration::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::ChoiceOpportunity => {
            let value = codec::decode::<ChoiceOpportunity>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ChoiceGroup => {
            let value = codec::decode::<ChoiceGroup>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Selection => {
            let value = Selection::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::CandidateGeneratorSpec => {
            let value = crate::CandidateGeneratorSpec::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ScenarioArtifact => {
            ScenarioArtifact::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::ConfigurationArtifact => {
            let value = ConfigurationArtifact::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::BranchRequest => {
            let value = BranchRequest::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Proposal => {
            let value = Proposal::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::BranchPath => {
            codec::decode::<BranchPath>(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::Attempt => {
            let value = codec::decode::<Attempt>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::AttemptAdmission => {
            let value = codec::decode::<AttemptAdmission>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerStep => {
            let value = PlannerStep::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ExpansionState => {
            let value = codec::decode::<ExpansionState>(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ContinuationProjection => {
            let value = ContinuationProjection::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ExpansionCredit => {
            let value = ExpansionCredit::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::MeasurementSet => {
            let value = MeasurementSet::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PropertyVerdictSet => {
            let value = PropertyVerdictSet::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::CoverageProjection => {
            let value = CoverageProjection::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Observation => {
            let value = Observation::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ObjectiveEvaluation => {
            let value = ObjectiveEvaluation::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::RankingExplanation => {
            let value = RankingExplanation::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::SurvivorSelection => {
            let value = SurvivorSelection::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::RetainedPlannerRequest => {
            let value = PlannerRequest::from_canonical_bytes(body)?;
            content_children(value.content_children()?)
        }
        CampaignRecordKind::ReproductionArtifact => {
            let value = ReproductionArtifact::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::Finding => {
            let value = Finding::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::FindingCandidateBundle => {
            let value = FindingCandidateBundle::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::FindingTriageReplayEvidence => {
            content_children(FindingTriageReplayEvidence::storage_content_children(body)?)
        }
        CampaignRecordKind::FindingTriageReplayEvidenceChunk => {
            crate::finding_triage_evidence::validate_finding_triage_replay_chunk_body(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::PlannerCandidateGuidance => {
            let value = crate::PlannerCandidateGuidance::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerCandidateBudget => {
            let value = crate::PlannerCandidateBudget::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerBeamCandidate => {
            let value = crate::PlannerBeamCandidate::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::PlannerSearchCandidate => {
            let value = crate::PlannerSearchCandidate::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ArchiveManifest => {
            let value = CampaignArchiveManifest::from_canonical_bytes(body)?;
            content_children(value.content_children())
        }
        CampaignRecordKind::ArchiveInventoryPage => {
            CampaignArchiveInventoryPage::from_canonical_bytes(body)?;
            Ok(BTreeSet::new())
        }
        CampaignRecordKind::MerkleNode => Err(CampaignCodecError::InvalidValue {
            reason: "opaque campaign record requires its owning validator",
        }),
    }
}

pub(super) fn snapshot_children(
    snapshot: &CampaignSnapshot,
) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
    let roots = snapshot.roots();
    let mut children = vec![
        ("lineage", snapshot.lineage().content_id()),
        ("active-policy", snapshot.active_policy().content_id()),
        ("root.graph", roots.graph),
        ("root.exploration", roots.exploration),
        ("root.observations", roots.observations),
        ("root.corpus", roots.corpus),
        ("root.coverage", roots.coverage),
        ("root.findings", roots.findings),
        ("root.pins", roots.pins),
        ("root.accounting", roots.accounting),
        ("root.coordination", roots.coordination),
    ];
    if let Some(parent) = snapshot.parent() {
        children.push(("parent", parent.content_id()));
    }
    if let Some(transition) = snapshot.transition() {
        children.push(("transition", transition.content_id()));
    }
    children.push(("budget-ledger", snapshot.budget_ledger().content_id()));
    content_children(children)
}

pub(super) fn fact_children(
    fact: &CampaignFact,
) -> Result<BTreeSet<ContentChild>, CampaignCodecError> {
    let children = match fact {
        CampaignFact::CampaignDerived(derivation) => vec![
            ("source-snapshot", derivation.source().content_id()),
            ("active-policy", derivation.active_policy().content_id()),
        ],
        CampaignFact::ChoiceOpportunityDiscovered {
            parent,
            opportunity,
            ..
        } => vec![
            ("parent-configuration", parent.content_id()),
            ("choice-opportunity", opportunity.content_id()),
        ],
        CampaignFact::BranchRequestAccepted { request: id, .. } => {
            vec![("branch-request", id.content_id())]
        }
        CampaignFact::PlannerAdvanced(id) => vec![("planner-step", id.content_id())],
        CampaignFact::ProposalIssued(id) => vec![("proposal", id.content_id())],
        CampaignFact::AttemptAdmitted(admission) => {
            vec![("attempt-admission", admission.content_id())]
        }
        CampaignFact::AttemptClosed { attempt, .. } => vec![("attempt", attempt.content_id())],
        CampaignFact::ObservationCredited(id) => {
            vec![("observation", id.content_id())]
        }
        CampaignFact::FindingPublished(id) => vec![("finding", id.content_id())],
        CampaignFact::ObjectiveEvaluationPublished(id) => {
            vec![("objective-evaluation", id.content_id())]
        }
        CampaignFact::PolicyActivated(activation) => vec![
            ("prior-policy", activation.prior().content_id()),
            ("next-policy", activation.next().content_id()),
        ],
        CampaignFact::BudgetGranted(_) | CampaignFact::PinChanged(_) => Vec::new(),
        CampaignFact::PinCommandAccepted(request) => {
            vec![("expected-snapshot", request.expected_snapshot.content_id())]
        }
        CampaignFact::DiscoveryRequested(request) => vec![
            ("expected-snapshot", request.expected_snapshot.content_id()),
            ("configuration", request.configuration.content_id()),
        ],
        CampaignFact::SavepointCaptureRequested(request) => vec![
            ("expected-snapshot", request.expected_snapshot.content_id()),
            ("attempt", request.attempt.content_id()),
            ("configuration", request.configuration.content_id()),
        ],
        CampaignFact::SavepointCaptureResolved(resolution) => vec![
            (
                "expected-snapshot",
                resolution.expected_snapshot.content_id(),
            ),
            ("capture-request", resolution.request.content_id()),
        ],
        CampaignFact::SavepointContinuationSelected(selection) => vec![
            (
                "expected-snapshot",
                selection.expected_snapshot.content_id(),
            ),
            ("capture-request", selection.request.content_id()),
            ("ready-resolution", selection.ready.content_id()),
            ("continuation-attempt", selection.continuation.content_id()),
        ],
        CampaignFact::ControlRequested(request) => {
            let mut values = vec![("expected-snapshot", request.expected_snapshot.content_id())];
            if let CampaignControlAction::ActivatePolicy(policy) = &request.action {
                values.push(("requested-policy", policy.content_id()));
            }
            values
        }
    };
    content_children(children)
}

pub(crate) fn content_children<I, R>(
    children: I,
) -> Result<BTreeSet<ContentChild>, CampaignCodecError>
where
    I: IntoIterator<Item = (R, ContentId)>,
    R: Into<String>,
{
    children
        .into_iter()
        .map(|(role, id)| ContentChild::new(role, id).map_err(CampaignCodecError::from))
        .collect()
}
