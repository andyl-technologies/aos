//! Ordered frontier pages, mixed request schemas, and forged index rejection.

use super::*;

#[test]
fn indexed_pages_match_legacy_order_across_request_schemas_and_restart() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    repository
        .create("scan-order", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let mut expected = BTreeSet::new();
    for branch in 0..2 {
        let template = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            &format!("scan-branch-{branch}"),
        );
        // Insert versions and causes in reverse order, not in scan order.
        for schema in (1_u32..=4).rev() {
            for cause in (0..3).rev() {
                let request = BranchRequest::new(
                    template.branch_point(),
                    template.parent(),
                    template.opportunity(),
                    template.domain(),
                    template.source().clone(),
                    BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                        CampaignHash::derive(
                            "scan-order",
                            format!("{branch}-{schema}-{cause}").as_bytes(),
                        ),
                    )),
                    template.budget(),
                    template.stop().clone(),
                )
                .expect("request");
                let mut bytes = request.canonical_bytes();
                bytes[..4].copy_from_slice(&schema.to_be_bytes());
                let request =
                    BranchRequest::from_canonical_bytes(&bytes).expect("retained request schema");
                let head = repository.head("scan-order").expect("head");
                repository
                    .submit_known_branch_request("scan-order", head.snapshot_id(), &request)
                    .expect("request transition");
                expected.insert(PlanningScanPosition::new(
                    request.branch_point(),
                    request.id().expect("request id"),
                ));
            }
        }
    }
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let head = cold.head("scan-order").expect("cold indexed head");
    let view = head.snapshot().planning_view();
    for limit in [1, 3, 7] {
        let mut after = None;
        let mut seen = Vec::new();
        loop {
            let page = cold
                .planner_scan_page(&view, after, limit)
                .expect("indexed page");
            let mut legacy = cold
                .legacy_planner_scan_positions(&view, after, limit as usize + 1)
                .expect("legacy order");
            let complete = legacy.len() <= limit as usize;
            if !complete {
                legacy.pop_last();
            }
            assert_eq!(page.positions(), legacy.keys().copied().collect::<Vec<_>>());
            assert_eq!(page.complete(), complete);
            seen.extend_from_slice(page.positions());
            if complete {
                break;
            }
            after = page.positions().last().copied();
        }
        assert_eq!(seen, expected.iter().copied().collect::<Vec<_>>());
    }

    let mut roots = head.snapshot().roots();
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            planner_scan_index_anchor_key(),
            MerkleMap::empty_content_id().expect("empty"),
        )
        .expect("forge incomplete index")
        .content_id();
    let forged = CampaignSnapshot::successor(
        head.snapshot().parent().expect("parent"),
        head.snapshot().lineage(),
        head.snapshot().active_policy(),
        roots,
        head.snapshot().transition().expect("transition"),
    )
    .expect("forged snapshot")
    .with_budget_ledger(head.snapshot().budget_ledger().expect("ledger"));
    let forged_id = repository
        .put_snapshot(&forged)
        .expect("publish forged snapshot");
    let before = blobs.object_count().expect("objects");
    assert!(matches!(
        cold.validate_complete_head(forged_id),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-transition-exploration-root-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        before
    );
}
