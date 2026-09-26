//! Ordered finite-vector admission through the canonical frontier driver.

use super::*;

#[test]
fn finite_frontier_issues_one_ordered_bounded_vector() -> Result<(), Box<dyn Error>> {
    let fixture = GateFixture::new(
        "finite-vector-issue",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let campaign = "finite-vector-issue";
    let head = fixture.create_funded_running(campaign, &BTreeMap::new(), 16)?;
    let domain = integer_domain(15)?;
    let values = (0..16_u64)
        .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)))
        .collect::<BTreeSet<_>>();
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        CandidateSource::finite(values.clone())?,
        BranchRequestCause::Operator(command_id(campaign, "request")),
        campaign,
        BranchBudget::new(16, 16)?,
    )?;
    let requested = discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;
    let (engine, artifact, initial_state) = fixture
        .repository
        .publish_canonical_frontier_planner_basis()?
        .into_parts();
    let low_fuel = fixture.repository.prepare_planner_invocation(
        campaign,
        requested.new_snapshot,
        &engine,
        &artifact,
        &initial_state,
        None,
        16,
        PlanningBudget::new(1, 16, 64, 64 * 1024, 2)?,
    )?;
    let low_fuel_request = fixture
        .repository
        .build_planner_request(requested.new_snapshot, low_fuel.id()?)?;
    let mut pure = CanonicalFrontierPlanner;
    let low_fuel_output = pure.plan(&low_fuel_request)?;
    let PlannerProposalDisposition::Issue { proposals, .. } =
        low_fuel_output.proposal().disposition()
    else {
        return Err("low-fuel finite frontier did not issue".into());
    };
    assert_eq!(proposals.len(), 1);

    let mut driver = planner_driver_with_proposal_limit(&fixture, 16)?;

    let CampaignPlannerStepOutcome::Advanced {
        result,
        disposition: PlannerDisposition::Issue {
            issued_proposals, ..
        },
        ..
    } = driver.step(campaign)?
    else {
        return Err("finite frontier did not issue its ordered vector".into());
    };
    assert_ne!(result.new_snapshot, requested.new_snapshot);
    assert_eq!(issued_proposals.len(), 16);
    for (index, proposal_id) in issued_proposals.into_iter().enumerate() {
        let proposal = fixture.repository.load_proposal(proposal_id)?;
        assert_eq!(proposal.ordinal(), index as u64 + 1);
        assert_eq!(
            proposal.value(),
            values.iter().nth(index).ok_or("missing value")?
        );
    }
    let mut cursor = None;
    let mut claimable_count = 0;
    loop {
        let page = fixture
            .repository
            .project_claimable_attempts(campaign, cursor, 32)?;
        claimable_count += page.attempts().len();
        cursor = page.next();
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(claimable_count, 16);
    Ok(())
}
