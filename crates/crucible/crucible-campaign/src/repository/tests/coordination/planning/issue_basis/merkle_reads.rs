//! Independent bounded Issue passes, authentic read work, and publication refusal.

use super::*;
use crate::repository::planner_issue::{PlannerIssueBasis, PlannerIssueProjection};

fn with_basis<T>(fixture: &IssueFixture, action: impl FnOnce(&PlannerIssueBasis<'_>) -> T) -> T {
    let snapshot = fixture
        .repository
        .read_snapshot(fixture.snapshot.content_id())
        .expect("stored snapshot");
    let invocation = fixture
        .repository
        .load_planner_invocation(fixture.invocation)
        .expect("authenticated invocation");
    let PlannerProposalDisposition::Issue {
        selected,
        branch_requests,
        proposals,
    } = fixture.step.disposition()
    else {
        panic!("fixture must be a genuine Issue");
    };
    assert_eq!(proposals.len(), 16);
    let basis = fixture
        .repository
        .planner_issue_basis(
            &snapshot,
            &invocation,
            *selected,
            branch_requests,
            proposals,
        )
        .expect("authenticated Issue basis");
    action(&basis)
}

fn read_counts(backend: &BasisBackend) -> (usize, usize) {
    let counts = backend.reads.lock().expect("read counts");
    let merkle = counts
        .iter()
        .filter(|(id, _)| id.kind() == ObjectKind::MerkleNode)
        .map(|(_, count)| count)
        .sum();
    (counts.values().sum(), merkle)
}

fn assert_projection_equal(left: &PlannerIssueProjection, right: &PlannerIssueProjection) {
    assert_eq!(left.exploration, right.exploration);
    assert_eq!(left.accounting, right.accounting);
    assert_eq!(left.branch_requests, right.branch_requests);
    assert_eq!(left.proposals, right.proposals);
    assert_eq!(left.attempts, right.attempts);
    assert_eq!(left.deduplicated, right.deduplicated);
    assert_eq!(left.simple_finite_issue, right.simple_finite_issue);
}

fn queue(repository: &CampaignRepository) -> Vec<AttemptId> {
    let mut cursor = None;
    let mut attempts = Vec::new();
    for _ in 0..4096 {
        let page = repository
            .project_claimable_attempts(CAMPAIGN, cursor, 1)
            .expect("genuine accounting page");
        attempts.extend_from_slice(page.attempts());
        match page.next() {
            Some(next) => cursor = Some(next),
            None => return attempts,
        }
    }
    panic!("sixteen-admission queue must reach EOF under the bound");
}

#[test]
fn separate_issue_read_custody_reduces_node_reads_and_preserves_sixteen_admissions() {
    let original = issue_fixture();
    let candidate = issue_fixture();
    let (old_preflight, old_publication, old_preflight_reads, old_publication_reads) =
        with_basis(&original, |basis| {
            original.backend.reads.lock().expect("counts").clear();
            let preflight = original
                .repository
                .uncached_issue_preflight_for_test(basis)
                .expect("original preflight projection");
            let preflight_reads = read_counts(&original.backend);

            original.backend.reads.lock().expect("counts").clear();
            let publication = original
                .repository
                .uncached_issue_publication_for_test(basis)
                .expect("original durable publication projection");
            let publication_reads = read_counts(&original.backend);
            (preflight, publication, preflight_reads, publication_reads)
        });
    let (new_preflight, new_publication, new_preflight_reads, new_publication_reads) =
        with_basis(&candidate, |basis| {
            candidate.backend.reads.lock().expect("counts").clear();
            let preflight = candidate
                .repository
                .preflight_planner_issue(basis)
                .expect("bounded preflight");
            let preflight_reads = read_counts(&candidate.backend);

            candidate.backend.reads.lock().expect("counts").clear();
            let publication = candidate
                .repository
                .publish_planner_issue(basis, &preflight)
                .expect("independent bounded publication");
            let publication_reads = read_counts(&candidate.backend);
            (preflight, publication, preflight_reads, publication_reads)
        });
    assert_projection_equal(&old_preflight, &new_preflight);
    assert_projection_equal(&old_publication, &new_publication);
    assert_eq!(new_publication.attempts, 16);
    assert_eq!(new_publication.proposals.len(), 16);
    assert_eq!(new_publication.deduplicated, 0);
    assert!(new_preflight_reads.1 < old_preflight_reads.1);
    assert!(new_publication_reads.1 < old_publication_reads.1);
    eprintln!(
        "issue-node-read-custody: preflight_original={old_preflight_reads:?} preflight_bounded={new_preflight_reads:?} publication_original={old_publication_reads:?} publication_bounded={new_publication_reads:?} proposals=16 attempts=16"
    );

    let first = original
        .repository
        .accept_planner_step(CAMPAIGN, original.snapshot, &original.step, original.usage)
        .expect("accept original canonical output");
    let second = candidate
        .repository
        .accept_planner_step(
            CAMPAIGN,
            candidate.snapshot,
            &candidate.step,
            candidate.usage,
        )
        .expect("accept candidate canonical output");
    assert_eq!(first, second);
    assert_eq!(
        journal_bytes(&original.repository, first.new_snapshot),
        journal_bytes(&candidate.repository, second.new_snapshot)
    );
    let hot = queue(&candidate.repository);
    assert_eq!(hot.len(), 16);
    assert_eq!(hot, queue(&original.repository));
    let cold =
        CampaignRepository::new(candidate.backend.clone(), candidate.repository.refs.clone());
    assert_eq!(
        cold.head(CAMPAIGN)
            .expect("fresh validated head")
            .snapshot_id(),
        second.new_snapshot
    );
    assert_eq!(queue(&cold), hot);
}

fn inject_node_fault(fixture: &IssueFixture, target: ContentId, corrupt: bool) -> BlobHandle {
    let original = fixture
        .backend
        .inner
        .read(target, None)
        .expect("original node");
    if corrupt {
        *fixture.backend.fault.lock().expect("fault") = Some(target);
    } else {
        let mut fence = fixture
            .backend
            .inner
            .acquire_inventory_fence()
            .expect("private inventory fence");
        fence.delete_candidate(target).expect("remove target node");
    }
    original
}

fn restore_node(fixture: &IssueFixture, target: ContentId, original: &BlobHandle) {
    *fixture.backend.fault.lock().expect("fault") = None;
    fixture
        .backend
        .inner
        .put_if_absent(target, original)
        .expect("restore node");
}

#[test]
fn preflight_refuses_missing_or_corrupt_prior_nodes_without_ref_promotion() {
    for accounting in [false, true] {
        for corrupt in [false, true] {
            let fixture = issue_fixture();
            with_basis(&fixture, |basis| {
                let snapshot = fixture
                    .repository
                    .read_snapshot(fixture.snapshot.content_id())
                    .expect("authenticated original snapshot");
                let roots = snapshot.snapshot.roots();
                let target = if accounting {
                    roots.accounting
                } else {
                    roots.exploration
                };
                let count = fixture.backend.inner.object_count().expect("object count");
                let original = inject_node_fault(&fixture, target, corrupt);
                fixture.backend.reads.lock().expect("counts").clear();

                let rejected = fixture.repository.preflight_planner_issue(basis);
                assert!(rejected.is_err());
                assert!(
                    fixture
                        .backend
                        .reads
                        .lock()
                        .expect("reads")
                        .get(&target)
                        .copied()
                        .unwrap_or_default()
                        > 0
                );

                restore_node(&fixture, target, &original);
                assert_eq!(
                    fixture
                        .backend
                        .inner
                        .object_count()
                        .expect("unchanged objects"),
                    count
                );
                assert_eq!(
                    fixture
                        .repository
                        .head(CAMPAIGN)
                        .expect("unchanged head")
                        .snapshot_id(),
                    fixture.snapshot
                );
            });
        }
    }
}

#[test]
fn publication_reauthenticates_a_node_removed_or_corrupted_after_preflight() {
    for accounting in [false, true] {
        for corrupt in [false, true] {
            let fixture = issue_fixture();
            with_basis(&fixture, |basis| {
                let prepared = fixture
                    .repository
                    .preflight_planner_issue(basis)
                    .expect("successful preflight");
                assert_eq!(prepared.attempts, 16);
                let snapshot = fixture
                    .repository
                    .read_snapshot(fixture.snapshot.content_id())
                    .expect("authenticated original snapshot");
                let roots = snapshot.snapshot.roots();
                let target = if accounting {
                    roots.accounting
                } else {
                    roots.exploration
                };
                let prior_reads = fixture
                    .backend
                    .reads
                    .lock()
                    .expect("reads")
                    .get(&target)
                    .copied()
                    .unwrap_or_default();
                assert!(prior_reads > 0);
                let original = inject_node_fault(&fixture, target, corrupt);
                fixture.backend.reads.lock().expect("counts").clear();

                assert!(
                    fixture
                        .repository
                        .publish_planner_issue(basis, &prepared)
                        .is_err()
                );
                assert!(
                    fixture
                        .backend
                        .reads
                        .lock()
                        .expect("reads")
                        .get(&target)
                        .copied()
                        .unwrap_or_default()
                        > 0
                );

                restore_node(&fixture, target, &original);
                assert_eq!(
                    fixture
                        .repository
                        .head(CAMPAIGN)
                        .expect("unchanged head")
                        .snapshot_id(),
                    fixture.snapshot
                );
                let published = fixture
                    .repository
                    .publish_planner_issue(basis, &prepared)
                    .expect("fresh restored publication");
                assert_eq!(published.attempts, 16);
                assert_eq!(published.proposals, prepared.proposals);
            });
        }
    }
}
