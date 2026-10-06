//! Cold ancestry validation across retained planner requests.

use super::*;
use crucible_campaign::{CampaignBudgetLedger, CampaignStoreError, ObjectEnvelope};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, PutReceipt,
    StoreError,
};

struct FaultingBlobBackend {
    inner: Arc<MemoryBlobBackend>,
    corrupted: ContentId,
}

impl ImmutableBlobBackend for FaultingBlobBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        if id == self.corrupted {
            return Err(StoreError::Corrupt { id });
        }
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        if id == self.corrupted {
            return Err(StoreError::Corrupt { id });
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

fn issued_campaign(
    label: &str,
    attempts: usize,
) -> Result<(GateFixture, crucible_campaign::PlannerStepResult), Box<dyn Error>> {
    let fixture = GateFixture::new(
        label,
        CampaignMode::Strict,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let head = fixture.create_funded_running(label, &BTreeMap::new(), attempts as u64)?;
    let (domain, alternatives) = discrete_domain(label, attempts)?;
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Discrete(alternatives[0]),
        CandidateSource::finite(
            alternatives
                .iter()
                .copied()
                .map(ChoiceValue::Discrete)
                .collect(),
        )?,
        BranchRequestCause::Operator(command_id(label, "request")),
        label,
        BranchBudget::new(attempts as u64, attempts as u64)?,
    )?;
    discover_and_submit(&fixture, label, head.snapshot_id(), &request)?;

    let mut planner = planner_driver(&fixture)?;
    let mut last = None;
    for _ in 0..attempts {
        let CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::Issue { .. },
        } = planner.step(label)?
        else {
            return Err("planner did not issue an attempt".into());
        };
        last = Some(result);
    }
    Ok((fixture, last.ok_or("planner issued no steps")?))
}

fn reopened_repository(
    fixture: &GateFixture,
    blobs: Arc<dyn ImmutableBlobBackend>,
) -> Result<CampaignRepository, CampaignRepositoryError> {
    CampaignRepository::with_component_authorities(
        blobs,
        fixture.refs.clone(),
        fixture.planner_authority.clone(),
        fixture.debugger_authority.clone(),
    )
}

#[test]
fn cold_reopen_matches_snapshot_and_rejects_corrupt_planner_inputs() -> Result<(), Box<dyn Error>> {
    let campaign = "cold-validation-integrity";
    let (fixture, last) = issued_campaign(campaign, 3)?;
    let expected_head = fixture.repository.head(campaign)?;
    let expected_page = fixture
        .repository
        .project_claimable_attempts(campaign, None, 7)?;

    let reopened = reopened_repository(&fixture, fixture.blobs.clone())?;
    assert_eq!(reopened.head(campaign)?, expected_head);
    assert_eq!(
        reopened.project_claimable_attempts(campaign, None, 7)?,
        expected_page
    );

    let step = fixture
        .repository
        .load_planner_step_at(last.new_snapshot, last.step)?;
    let request = fixture.repository.load_planner_request(step.request())?;
    let ledger_id = expected_head.snapshot().budget_ledger().content_id();
    let ledger_bytes = fixture.blobs.read(ledger_id, None)?.read_all(64 * 1024)?;
    let ledger_envelope = ObjectEnvelope::from_canonical_bytes(&ledger_bytes)?;
    let ledger = CampaignBudgetLedger::from_canonical_bytes(ledger_envelope.body())?;
    for corrupted in [
        step.request().content_id(),
        request.invocation_id()?.content_id(),
        ledger.request_admissions(),
    ] {
        let faulty = reopened_repository(
            &fixture,
            Arc::new(FaultingBlobBackend {
                inner: fixture.blobs.clone(),
                corrupted,
            }),
        )?;
        let outcome = faulty.project_claimable_attempts(campaign, None, 7);
        assert!(
            matches!(
                &outcome,
                Err(
                    CampaignRepositoryError::Store(StoreError::Corrupt { id })
                        | CampaignRepositoryError::Merkle(CampaignStoreError::Store(
                            StoreError::Corrupt { id }
                        ))
                ) if *id == corrupted
            ),
            "corruption at {corrupted} was not rejected as corrupt: {outcome:?}"
        );
    }
    Ok(())
}
