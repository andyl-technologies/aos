//! Checked Mirror replay of a canonical finite-expansion projection.

use super::*;

#[test]
fn checked_mirror_archive_replays_finite_expansion_state() {
    const NAME: &str = "checked-expansion-archive";

    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded(NAME, &lineage, &policy, &BTreeMap::new())
        .expect("create finite-expansion campaign");
    let model = ProbabilityModelId::from_hash(CampaignHash::derive(
        "test.checked-expansion-model.v1",
        b"network retry",
    ));
    let request = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        NAME,
        model,
        BTreeMap::from([
            (ChoiceValue::Boolean(false), 1),
            (ChoiceValue::Boolean(true), 3),
        ]),
    );
    assert_eq!(request.source().model_prior(), Some(model));

    let discovered = repository
        .discover_choice_opportunity(
            NAME,
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover modeled opportunity");
    let requested = repository
        .submit_branch_request(NAME, discovered.new_snapshot, &request)
        .expect("submit modeled branch request");
    let state_id = repository
        .project_finite_expansion(requested.new_snapshot, request.branch_point(), None, 10)
        .expect("project finite expansion");
    let state = repository
        .load_expansion_state(state_id)
        .expect("load canonical expansion state");

    assert_eq!(state.id().expect("canonical expansion state ID"), state_id);
    assert_eq!(state.source_snapshot(), requested.new_snapshot);
    assert_eq!(state.branch_point(), request.branch_point());
    assert_eq!(
        state
            .continuations()
            .get(&request.id().expect("branch request ID")),
        Some(&ContinuationState::Ready)
    );
    assert_eq!(state.continuations().len(), 1);
    assert_eq!(state.statistics().admitted_children, 0);

    assert_checked_archive(&repository, requested.new_snapshot, [state_id.content_id()]);
}
