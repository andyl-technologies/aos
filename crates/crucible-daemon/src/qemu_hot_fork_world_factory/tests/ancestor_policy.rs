//! The ancestor suffix policy: bounds, pause mode, and its decision allowlist.
//!
//! Policy is pure over the attempt input and the recorded schedule, so these
//! tests build schedules directly rather than driving a lifecycle.

use crucible::{
    NetworkFaultPhase, NetworkFaultSelectable, SignalFaultCampaignReplayPlan, VirtualTime,
};

use super::super::ancestor::{
    MAX_ANCESTOR_SUFFIX_DECISIONS, MAX_ANCESTOR_SUFFIX_SELECTIONS, ancestor_suffix_refusal,
    configuration_carried_decision,
};
use super::ancestor_runner::{Edge, override_decision, provenance, rng_step, step, suffix_case};
use super::*;
use crate::managed_qemu_hot_fork_source_world_pool::test_support::scheduler_selection_for_test;

/// A scenario with network fault choices and no guest selectables.
fn network_scenario() -> ScenarioDefForm {
    let scenario = test_execution_scenario();
    let selectables = ScenarioSelectables::new(
        scenario.world(),
        ScenarioSelectableLimits::default(),
        vec![NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    scenario
        .with_selectables(selectables)
        .expect("attach network selectables")
}

/// A schedule whose suffix opens with a network fault branch at the root
/// `anchor`, then continues past it, the shape of an anchor's descendants.
struct NetworkSuffix {
    scenario: ScenarioDefForm,
    anchor: Configuration,
    branch: crucible::NetworkFaultCampaignBranch,
    target: Configuration,
}

fn network_suffix() -> NetworkSuffix {
    let scenario = network_scenario();
    let genesis = Configuration::genesis(scenario.scenario_def());
    let anchor = rng_step(&genesis, "policy-network-root", 3);
    let selectable = NetworkFaultSelectable::next(
        &scenario,
        &anchor,
        NetworkFaultPhase::First,
        VirtualTime { ticks: 100 },
        &[],
    )
    .expect("network choice resolves")
    .expect("network choice is offered");
    let value = NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)
        .expect("network fault value");
    let branch = selectable
        .resolve_branch(
            &selectable
                .branch_selection(value)
                .expect("network branch selection"),
        )
        .expect("network fault branch");
    let after = rng_step(branch.selected(), "policy-after-fault", 1);
    let target = rng_step(&after, "policy-after-fault", 2);
    NetworkSuffix {
        scenario,
        anchor,
        branch,
        target,
    }
}

/// Discovers `target` with exactly `branches` recorded as network replay.
fn input_with_network_branches(
    suffix: &NetworkSuffix,
    target: &Configuration,
    branches: Vec<crucible::NetworkFaultCampaignBranch>,
) -> CrucibleAttemptExecution {
    let replay = SignalFaultCampaignReplayPlan::empty(target.clone())
        .with_network_branches(branches)
        .expect("network replay plan");
    execution_input_for_scenario_configuration(suffix.scenario.clone(), target.clone())
        .with_test_signal_fault_replay(replay)
}

/// The attempt's own edge qualifies only as a guest selection; a scheduler
/// producer's selection is not on the allowlist.
#[test]
fn suffix_policy_admits_a_guest_edge_and_refuses_an_unlisted_one() {
    for (edge, expected) in [
        (Edge::Guest, None),
        (Edge::Scheduler, Some("unlisted-selection")),
    ] {
        let case = suffix_case(edge);
        let parent_len = case.parent.schedule.len();

        assert_eq!(
            configuration_carried_decision(&case.input, &case.selected, parent_len, parent_len),
            expected
        );
    }
}

/// A recorded network fault branch inside the suffix is crossed at its park;
/// the same decision without its recorded branch is refused.
#[test]
fn suffix_policy_crosses_a_recorded_network_fault_branch() {
    let suffix = network_suffix();
    let from = suffix.anchor.schedule.len();
    let end = suffix.target.schedule.len();

    let recorded =
        input_with_network_branches(&suffix, &suffix.target, vec![suffix.branch.clone()]);
    assert_eq!(
        configuration_carried_decision(&recorded, &suffix.target, from, end),
        None
    );

    let unrecorded = input_with_network_branches(&suffix, &suffix.target, Vec::new());
    assert_eq!(
        configuration_carried_decision(&unrecorded, &suffix.target, from, end),
        Some("unlisted-selection")
    );
}

/// Scheduler producer selections and overrides in a suffix are refused by
/// name; deterministic RNG draws pass.
#[test]
fn suffix_policy_refuses_unlisted_suffix_decisions_by_name() {
    let suffix = network_suffix();
    let from = suffix.anchor.schedule.len();
    let produced = step(
        &suffix.target,
        Decision::Selection(scheduler_selection_for_test(
            &suffix.scenario,
            "policy.scheduler",
        )),
    );
    let overridden = step(&suffix.target, override_decision("policy"));
    let drawn = rng_step(&suffix.target, "policy-draw", 9);

    let cases = [
        (produced, Some("unlisted-selection")),
        (overridden, Some("override-decision")),
        (drawn, None),
    ];
    for (target, expected) in cases {
        let input = input_with_network_branches(&suffix, &target, vec![suffix.branch.clone()]);
        assert_eq!(
            configuration_carried_decision(&input, &target, from, target.schedule.len()),
            expected
        );
    }
}

/// A recorded selection in a declared guest domain is answered at the
/// guest's request, so it qualifies inside the suffix.
#[test]
fn suffix_policy_admits_a_recorded_guest_selection() {
    let case = suffix_case(Edge::Guest);
    let declaration = guest_selectable_declaration();
    let pending = branch_replay_guest_pending(&declaration, "policy-suffix");
    let discovery = crate::guest_selectable::resolve_guest_selectable(
        case.input.lineage().scenario(),
        case.input.scenario(),
        pending.node(),
        pending.pending(),
    )
    .expect("resolve suffix guest opportunity");
    let selection = Selection::new(
        discovery.opportunity(),
        discovery.domain(),
        ChoiceValue::Boolean(false),
        SelectionOrigin::Default,
    )
    .expect("recorded guest selection");
    let chosen = step(
        &case.anchor,
        Decision::Selection(SelectionDecision::new(&selection)),
    );
    let target = rng_step(&chosen, "policy-after-guest", 4);

    assert_eq!(
        configuration_carried_decision(
            &case.input,
            &target,
            case.anchor.schedule.len(),
            target.schedule.len()
        ),
        None
    );
}

#[test]
fn suffix_policy_accepts_replay_only_decisions_and_names_each_refusal() {
    let case = suffix_case(Edge::Guest);
    let pause =
        crate::qemu_campaign_lifecycle::replay_pauses_before_live_network_choice(&case.selected);
    assert_eq!(
        ancestor_suffix_refusal(
            &case.input,
            &case.parent,
            &case.selected,
            &provenance(&case.anchor, Some(pause))
        ),
        None
    );

    let refusals = [
        (
            provenance(&case.parent, Some(pause)),
            "ancestor-not-strict-prefix",
        ),
        (
            provenance(&case.anchor, Some(!pause)),
            "ancestor-pause-mode-mismatch",
        ),
        (
            provenance(&case.anchor, None),
            "ancestor-pause-mode-mismatch",
        ),
    ];
    for (provenance, expected) in refusals {
        assert_eq!(
            ancestor_suffix_refusal(&case.input, &case.parent, &case.selected, &provenance),
            Some(expected)
        );
    }

    // A configuration-served decision anywhere in the range refuses it.
    let overridden = step(&case.anchor, override_decision("suffix"));
    let parent = rng_step(&overridden, "ancestor-after-override", 1);
    assert_eq!(
        configuration_carried_decision(
            &case.input,
            &parent,
            case.anchor.schedule.len(),
            parent.schedule.len()
        ),
        Some("override-decision")
    );
    assert_eq!(
        configuration_carried_decision(
            &case.input,
            &case.selected,
            case.anchor.schedule.len(),
            case.parent.schedule.len()
        ),
        None
    );
}

#[test]
fn suffix_policy_bounds_decisions_and_selections() {
    let case = suffix_case(Edge::Scheduler);
    let pause =
        crate::qemu_campaign_lifecycle::replay_pauses_before_live_network_choice(&case.selected);

    let mut long = case.anchor.clone();
    for value in 0..=u64::try_from(MAX_ANCESTOR_SUFFIX_DECISIONS).expect("bound fits") {
        long = rng_step(&long, "ancestor-long-suffix", value);
    }
    assert_eq!(
        ancestor_suffix_refusal(
            &case.input,
            &long,
            &long,
            &provenance(&case.anchor, Some(pause))
        ),
        Some("ancestor-suffix-too-long")
    );

    let scenario = case.input.scenario().clone();
    let mut chosen = case.anchor.clone();
    for index in 0..=MAX_ANCESTOR_SUFFIX_SELECTIONS {
        let name = format!("ancestor.selection-{index}");
        chosen = step(
            &chosen,
            Decision::Selection(
                crate::managed_qemu_hot_fork_source_world_pool::test_support::scheduler_selection_for_test(
                    &scenario, &name,
                ),
            ),
        );
    }
    assert_eq!(
        ancestor_suffix_refusal(
            &case.input,
            &chosen,
            &chosen,
            &provenance(&case.anchor, Some(pause))
        ),
        Some("ancestor-suffix-too-many-selections")
    );
}
