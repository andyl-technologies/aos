//! Ordered current-request frontier pages and forged index rejection.

use super::*;

#[test]
fn indexed_pages_match_canonical_order_across_request_shapes_and_restart() {
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
        // Insert distinct causes in reverse order, not in scan order.
        for variant in (2_u32..=4).rev() {
            for cause in (0..3).rev() {
                let request = BranchRequest::new(
                    BranchRequest::identity(
                        template.branch_point(),
                        template.parent(),
                        template.opportunity(),
                        template.domain(),
                    ),
                    template.source().clone(),
                    BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                        CampaignHash::derive(
                            "scan-order",
                            format!("{branch}-{variant}-{cause}").as_bytes(),
                        ),
                    )),
                    template.budget(),
                    template.stop().clone(),
                )
                .expect("request");
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
        let opportunity = repository
            .load_choice_opportunity(template.opportunity())
            .expect("scenario-default opportunity");
        let scenario_default = BranchRequest::new(
            BranchRequest::identity(
                template.branch_point(),
                template.parent(),
                template.opportunity(),
                template.domain(),
            ),
            CandidateSource::finite(BTreeSet::from([opportunity.default().clone()]))
                .expect("scenario-default source"),
            BranchRequestCause::ScenarioDefault(policy.id().expect("policy id")),
            BranchBudget::new(1, 1).expect("scenario-default budget"),
            StopCondition::NextChoice,
        )
        .expect("scenario-default request");
        assert_eq!(
            scenario_default
                .id()
                .expect("scenario-default request id")
                .content_id()
                .schema_version(),
            crate::exploration::BRANCH_REQUEST_SCHEMA_VERSION
        );
        let head = repository.head("scan-order").expect("head");
        repository
            .submit_known_branch_request("scan-order", head.snapshot_id(), &scenario_default)
            .expect("scenario-default request transition");
        expected.insert(PlanningScanPosition::new(
            scenario_default.branch_point(),
            scenario_default.id().expect("scenario-default request id"),
        ));
    }
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let head = cold.head("scan-order").expect("cold indexed head");
    let view = head.snapshot().planning_view();
    let index = cold
        .merkle
        .get(view.exploration(), planner_scan_index_anchor_key())
        .expect("planner index lookup")
        .expect("planner index anchor");
    for position in &expected {
        let request = position.source().content_id();
        let branch = cold
            .merkle
            .get(index, position.branch_point().as_hash())
            .expect("branch lookup")
            .expect("indexed branch");
        assert_eq!(
            cold.merkle
                .get(branch, CampaignHash::from_bytes(request.digest()))
                .expect("request lookup"),
            Some(request)
        );
    }

    for limit in [1, 3, 7] {
        let mut after = None;
        let mut seen = Vec::new();
        loop {
            let page = cold
                .planner_scan_page(&view, after, limit)
                .expect("indexed page");
            seen.extend_from_slice(page.positions());
            if page.complete() {
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
        head.snapshot().budget_ledger(),
    )
    .expect("forged snapshot");
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
