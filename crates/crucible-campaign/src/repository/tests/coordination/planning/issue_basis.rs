//! Operation-local Issue basis authentication and reproducible immutable-read evidence.

use super::*;
use crucible_cas::content_store::{BackendCapabilities, ByteRange, PutReceipt};

const CAMPAIGN: &str = "issue-basis-vector";

#[derive(Clone, Copy)]
enum PublicationFault {
    PartialWrite,
    ReceiptMismatch,
}

struct BasisBackend {
    inner: Arc<MemoryBlobBackend>,
    reads: Mutex<BTreeMap<ContentId, usize>>,
    fault: Mutex<Option<ContentId>>,
    publication_fault: Mutex<Option<PublicationFault>>,
    failed_publication: Mutex<Vec<ContentId>>,
}

impl ImmutableBlobBackend for BasisBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        *self
            .reads
            .lock()
            .expect("read counts")
            .entry(id)
            .or_default() += 1;
        if *self.fault.lock().expect("fault lock") == Some(id) {
            return Ok(BlobHandle::from_bytes(b"corrupt immutable basis".to_vec()));
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }

    fn put_many_if_absent(
        &self,
        objects: &[(ContentId, BlobHandle)],
    ) -> Result<Vec<PutReceipt>, StoreError> {
        // Exercise the enlarged publication beyond its former 32-object boundary.
        let fault = if objects.len() > 32 {
            self.publication_fault
                .lock()
                .expect("publication fault")
                .take()
        } else {
            None
        };
        if matches!(fault, Some(PublicationFault::PartialWrite)) {
            for (id, source) in &objects[..33] {
                self.inner.put_if_absent(*id, source)?;
                self.failed_publication
                    .lock()
                    .expect("published prefix")
                    .push(*id);
            }
            return Err(StoreError::InvalidComposition {
                reason: "injected-partial-batch-publication",
            });
        }

        let mut receipts = self.inner.put_many_if_absent(objects)?;
        if matches!(fault, Some(PublicationFault::ReceiptMismatch)) {
            *self.failed_publication.lock().expect("published batch") =
                objects.iter().map(|(id, _)| *id).collect();
            receipts[0].id = receipts[1].id;
        }
        Ok(receipts)
    }
}

struct IssueFixture {
    repository: CampaignRepository,
    backend: Arc<BasisBackend>,
    snapshot: CampaignSnapshotId,
    invocation: PlannerInvocationId,
    domain: ChoiceDomainId,
    step: PlannerStepProposal,
    usage: PlanningUsage,
}

fn issue_fixture() -> IssueFixture {
    let (original, lineage, policy, inner) = counted_fixture();
    let backend = Arc::new(BasisBackend {
        inner,
        reads: Mutex::new(BTreeMap::new()),
        fault: Mutex::new(None),
        publication_fault: Mutex::new(None),
        failed_publication: Mutex::new(Vec::new()),
    });
    let repository = CampaignRepository::new(backend.clone(), original.refs.clone());
    let campaign = CAMPAIGN;
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create Issue fixture");
    let alternatives = (0_u64..16)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "test.finite-vector-closure",
                &index.to_be_bytes(),
            ));
            (
                id,
                DiscreteAlternative::new(id, format!("choice-{index}"), None)
                    .expect("discrete alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let values = alternatives
        .keys()
        .copied()
        .map(ChoiceValue::Discrete)
        .collect::<Vec<_>>();
    let domain = ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("domain"));
    let declaration = SelectableDeclaration::new(
        "product.network.retry",
        ChoiceSource::Workload {
            producer: "finite-vector-closure".to_owned(),
        },
        domain.clone(),
        values.first().expect("first finite choice").clone(),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"finite-vector-scheduler"),
            producer: CampaignHash::derive("test", b"finite-vector-producer"),
        },
        campaign,
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(lineage.genesis()),
            lineage.genesis_content(),
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
        ),
        CandidateSource::finite(values.iter().cloned().collect()).expect("finite source"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"finite-vector-request",
        ))),
        BranchBudget::new(16, 16).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("finite request");
    let requested = repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &request)
        .expect("submit finite request");

    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, _) =
        planner_basis(&repository, campaign, requested.new_snapshot, state.clone());
    let invocation = repository
        .prepare_planner_invocation(
            campaign,
            requested.new_snapshot,
            &engine,
            &artifact,
            &state,
            None,
            16,
            PlanningBudget::new(1, 16, 16, 8192, 100).expect("vector planning budget"),
        )
        .expect("vector invocation");
    let proposals = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            Proposal::new(
                request.branch_point(),
                request.id().expect("request id"),
                request.domain(),
                value,
                policy.id().expect("policy id"),
                Some(invocation.id().expect("invocation id")),
                u64::try_from(index + 1).expect("proposal ordinal"),
                invocation.input_view(),
            )
            .expect("ordered finite proposal")
        })
        .collect::<Vec<_>>();
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 16,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 18,
    };
    let step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next state"),
        usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                request.branch_point(),
                request.id().expect("request id"),
            ),
            branch_requests: Vec::new(),
            proposals: proposals.clone(),
        },
    )
    .expect("vector Issue");
    IssueFixture {
        repository,
        backend,
        snapshot: requested.new_snapshot,
        invocation: invocation.id().expect("invocation id"),
        domain: request.domain(),
        step,
        usage,
    }
}

fn journal_bytes(repository: &CampaignRepository, head: CampaignSnapshotId) -> Vec<Vec<u8>> {
    let mut journal = Vec::new();
    let mut current = Some(head);
    while let Some(id) = current {
        let loaded = repository
            .read_snapshot(id.content_id())
            .expect("journal snapshot");
        journal.push(loaded.envelope.canonical_bytes());
        if let Some(fact) = loaded.snapshot.transition() {
            journal.push(
                repository
                    .read_envelope(fact.content_id())
                    .expect("journal fact")
                    .canonical_bytes(),
            );
        }
        current = loaded.snapshot.parent();
    }
    journal
}

#[test]
fn issue_basis_preserves_complete_journal_and_output_identity() {
    let first = issue_fixture();
    let second = issue_fixture();
    first.backend.reads.lock().expect("read counts").clear();
    let accepted = first
        .repository
        .accept_planner_step(CAMPAIGN, first.snapshot, &first.step, first.usage)
        .expect("first Issue");
    let counts = first.backend.reads.lock().expect("read counts").clone();
    let repeated = second
        .repository
        .accept_planner_step(CAMPAIGN, second.snapshot, &second.step, second.usage)
        .expect("independent Issue");
    assert_eq!(accepted, repeated);
    assert_eq!(
        journal_bytes(&first.repository, accepted.new_snapshot),
        journal_bytes(&second.repository, repeated.new_snapshot)
    );

    let hot = first
        .repository
        .load_planner_step_at(accepted.new_snapshot, accepted.step)
        .expect("hot Issue");
    let cold = CampaignRepository::new(first.backend.clone(), first.repository.refs.clone());
    assert_eq!(
        cold.head(CAMPAIGN).expect("cold head").snapshot_id(),
        accepted.new_snapshot
    );
    assert_eq!(
        cold.load_planner_step_at(accepted.new_snapshot, accepted.step)
            .expect("cold Issue"),
        hot
    );
    assert_eq!(
        (hot.accounting().proposals, hot.accounting().attempts),
        (16, 16)
    );
    let mut journal_material = Vec::new();
    for bytes in journal_bytes(&first.repository, accepted.new_snapshot) {
        journal_material.extend_from_slice(
            &u64::try_from(bytes.len())
                .expect("journal length")
                .to_be_bytes(),
        );
        journal_material.extend_from_slice(&bytes);
    }
    eprintln!(
        "issue-basis-evidence snapshot={} step={} journal={} reads={} invocation_reads={} domain_reads={} proposals=16 attempts=16",
        accepted.new_snapshot.content_id(),
        accepted.step.content_id(),
        CampaignHash::derive("test.issue-basis.journal", &journal_material),
        counts.values().sum::<usize>(),
        counts
            .get(&first.invocation.content_id())
            .copied()
            .unwrap_or_default(),
        counts
            .get(&first.domain.content_id())
            .copied()
            .unwrap_or_default()
    );
}

#[test]
fn next_issue_operation_reauthenticates_missing_and_corrupt_basis() {
    let fixture = issue_fixture();
    let accepted = fixture
        .repository
        .accept_planner_step(CAMPAIGN, fixture.snapshot, &fixture.step, fixture.usage)
        .expect("warm Issue");
    let objects = fixture.backend.inner.object_count().expect("object count");
    let journal = journal_bytes(&fixture.repository, accepted.new_snapshot);

    for target in [fixture.invocation.content_id(), fixture.domain.content_id()] {
        for corrupt in [false, true] {
            let original = fixture
                .backend
                .inner
                .read(target, None)
                .expect("stored basis");
            if corrupt {
                *fixture.backend.fault.lock().expect("fault lock") = Some(target);
            } else {
                let mut fence = fixture
                    .backend
                    .inner
                    .acquire_inventory_fence()
                    .expect("fixture inventory fence");
                fence
                    .delete_candidate(target)
                    .expect("delete immutable basis");
            }
            assert!(
                fixture
                    .repository
                    .accept_planner_step(CAMPAIGN, fixture.snapshot, &fixture.step, fixture.usage)
                    .is_err(),
                "next operation accepted missing/corrupt basis {target}"
            );
            *fixture.backend.fault.lock().expect("fault lock") = None;
            fixture
                .backend
                .inner
                .put_if_absent(target, &original)
                .expect("restore basis");
            assert_eq!(
                fixture
                    .repository
                    .head(CAMPAIGN)
                    .expect("unchanged head")
                    .snapshot_id(),
                accepted.new_snapshot
            );
            assert_eq!(
                fixture
                    .backend
                    .inner
                    .object_count()
                    .expect("unchanged object count"),
                objects
            );
            assert_eq!(
                journal_bytes(&fixture.repository, accepted.new_snapshot),
                journal
            );
            let replay = fixture
                .repository
                .accept_planner_step(CAMPAIGN, fixture.snapshot, &fixture.step, fixture.usage)
                .expect("restored authenticated basis");
            assert!(replay.replayed);
            assert_eq!(replay.new_snapshot, accepted.new_snapshot);
            assert_eq!(replay.step, accepted.step);
        }
    }
}

#[test]
fn enlarged_issue_publication_preserves_head_after_partial_write_or_bad_receipt() {
    for fault in [
        PublicationFault::PartialWrite,
        PublicationFault::ReceiptMismatch,
    ] {
        let fixture = issue_fixture();
        let control = issue_fixture();
        let before = journal_bytes(&fixture.repository, fixture.snapshot);
        *fixture
            .backend
            .publication_fault
            .lock()
            .expect("publication fault") = Some(fault);

        let rejected = fixture.repository.accept_planner_step(
            CAMPAIGN,
            fixture.snapshot,
            &fixture.step,
            fixture.usage,
        );
        assert!(
            rejected.is_err(),
            "accepted invalid publication: {rejected:?}"
        );
        assert!(
            fixture
                .backend
                .publication_fault
                .lock()
                .expect("consumed fault")
                .is_none()
        );
        let published = fixture
            .backend
            .failed_publication
            .lock()
            .expect("published prefix");
        assert_eq!(
            published.len(),
            match fault {
                PublicationFault::PartialWrite => 33,
                PublicationFault::ReceiptMismatch => 64,
            }
        );
        for id in published.iter().copied() {
            assert!(
                fixture
                    .backend
                    .inner
                    .contains(id)
                    .expect("published object exists")
            );
        }
        drop(published);
        assert_eq!(
            fixture
                .repository
                .head(CAMPAIGN)
                .expect("unchanged head")
                .snapshot_id(),
            fixture.snapshot
        );
        assert_eq!(journal_bytes(&fixture.repository, fixture.snapshot), before);

        let cold =
            CampaignRepository::new(fixture.backend.clone(), fixture.repository.refs.clone());
        assert_eq!(
            cold.head(CAMPAIGN)
                .expect("cold unchanged head")
                .snapshot_id(),
            fixture.snapshot
        );
        let retried = cold
            .accept_planner_step(CAMPAIGN, fixture.snapshot, &fixture.step, fixture.usage)
            .expect("retry authentic partial publication");
        let expected = control
            .repository
            .accept_planner_step(CAMPAIGN, control.snapshot, &control.step, control.usage)
            .expect("independent complete publication");
        assert_eq!(retried, expected);
        assert_eq!(
            journal_bytes(&cold, retried.new_snapshot),
            journal_bytes(&control.repository, expected.new_snapshot)
        );
    }
}
