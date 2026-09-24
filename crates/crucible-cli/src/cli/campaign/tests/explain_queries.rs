//! Authenticated campaign explanation query and rendering tests.

use super::*;

#[test]
fn planner_attempt_explanations_render_guidance_and_accounting() {
    macro_rules! stored_id {
        ($type:ident, $tag:literal, $kind:expr, $version:expr, $label:literal) => {
            $type::parse(&format!(
                concat!($tag, "@{}"),
                ContentId::for_bytes($kind, $version, $label.as_bytes()).encode()
            ))
            .expect(concat!("valid ", $tag))
        };
    }

    let selected = PlanningScanPosition::new(
        BranchPointId::from_hash(hash("planner-explanation-branch-point")),
        stored_id!(
            BranchRequestId,
            "crucible.campaign.branch-request",
            ObjectKind::CampaignFact,
            CampaignRecordKind::BranchRequest.schema_version(),
            "planner-explanation-request"
        ),
    );
    let step = PlannerStep::new(
        None,
        stored_id!(
            PlannerInvocationId,
            "crucible.campaign.planner-invocation",
            ObjectKind::Policy,
            2,
            "planner-explanation-invocation"
        ),
        stored_id!(
            RetainedPlannerRequestId,
            "crucible.campaign.retained-planner-request",
            ObjectKind::Policy,
            1,
            "planner-explanation-retained-request"
        ),
        hash("planner-explanation-request-digest"),
        policy("planner-explanation-policy"),
        stored_id!(
            PlannerEngineId,
            "crucible.campaign.planner-engine",
            ObjectKind::Policy,
            1,
            "planner-explanation-engine"
        ),
        stored_id!(
            PolicyArtifactId,
            "crucible.campaign.policy-artifact",
            ObjectKind::Policy,
            1,
            "planner-explanation-policy-artifact"
        ),
        stored_id!(
            CampaignViewId,
            "crucible.campaign.planning-view",
            ObjectKind::CampaignFact,
            1,
            "planner-explanation-view"
        ),
        PlannerDisposition::Issue {
            selected,
            issued_branch_requests: Vec::new(),
            issued_proposals: vec![stored_id!(
                ProposalId,
                "crucible.campaign.proposal",
                ObjectKind::CampaignFact,
                CampaignRecordKind::Proposal.schema_version(),
                "planner-explanation-proposal"
            )],
        },
        stored_id!(
            PlannerStateId,
            "crucible.campaign.planner-state",
            ObjectKind::Policy,
            1,
            "planner-explanation-state"
        ),
        PlanningUsage {
            branch_requests: 0,
            proposals: 1,
            input_objects: 12,
            input_bytes: 34_567,
            fuel: 890,
        },
        PlanningAccounting {
            branch_requests: 0,
            proposals: 1,
            attempts: 1,
            deduplicated: 0,
            input_objects: 12,
            input_bytes: 34_567,
            fuel: 890,
        },
        GuidanceEvidence::new(BTreeMap::from([
            (String::from("exploration"), 125_000),
            (String::from("novelty"), 750_000),
        ]))
        .expect("valid planner guidance evidence"),
    )
    .expect("valid planner explanation step");

    let explained =
        explain::explained_planner_decision(&step).expect("authenticated planner explanation");
    let value = serde_json::to_value(explained).expect("planner explanation JSON");

    assert_eq!(
        value["selected_branch_point"],
        selected.branch_point().to_string()
    );
    assert_eq!(value["selected_source"], selected.source().to_string());
    assert_eq!(value["guidance_terms_micros"]["exploration"], 125_000);
    assert_eq!(value["guidance_terms_micros"]["novelty"], 750_000);
    assert_eq!(value["accounting"]["attempts"], 1);
    assert_eq!(value["accounting"]["input_bytes"], 34_567);
    assert_eq!(value["accounting"]["fuel"], 890);
}
