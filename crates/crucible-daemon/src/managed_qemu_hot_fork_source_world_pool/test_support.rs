//! Source-world fixtures paused at a published, non-genesis boundary.
//!
//! Published-root admission rejects worlds with an empty schedule, so tests
//! that retain thin-attempt worlds need a scripted world that has recorded
//! scheduler selections before it was prepared as a source.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failures.
#![allow(clippy::expect_used)]

use crucible_api::vm_lifecycle::{
    ProductionVmHotForkSourceWorld,
    prepared_multi_node_hot_fork_source_world_after_selections_for_scenario_for_test,
};
use crucible_campaign::{
    BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ScenarioDefId, SelectableDeclaration, Selection,
    SelectionOrigin,
};
use crucible_qemu::{QemuTestHotForkOutcome, scripted_hot_fork_source_for_test};

/// Builds a built-in crash-restart world paused after one scheduler selection.
///
/// `name` names the selectable, so distinct names produce distinct boundary
/// configurations.
pub(crate) fn advanced_published_root_source_for_test(
    name: &str,
) -> ProductionVmHotForkSourceWorld {
    published_root_source_after_selections_for_test(&[name])
}

/// Builds a built-in crash-restart world paused after one selection per name.
///
/// Every prefix of `names` names an ancestor boundary of the world, so worlds
/// built from prefixes of one list are strict schedule ancestors of each other.
pub(crate) fn published_root_source_after_selections_for_test(
    names: &[&str],
) -> ProductionVmHotForkSourceWorld {
    let scenario = crucible::crash_restart_scenario()
        .expect("built-in scenario")
        .scenario;
    let selections = names
        .iter()
        .map(|name| scheduler_selection_for_test(&scenario, name))
        .collect();

    let node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let (_nodes, source) =
        prepared_multi_node_hot_fork_source_world_after_selections_for_scenario_for_test(
            &scenario,
            vec![node],
            selections,
        )
        .expect("advanced source world");
    source
}

/// Builds a default scheduler selection of a selectable named `name`.
pub(crate) fn scheduler_selection_for_test(
    scenario: &crucible::ScenarioDefForm,
    name: &str,
) -> crucible::SelectionDecision {
    let scenario_id =
        ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.scenario_def().id().bytes));
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        name,
        ChoiceSource::Scheduler {
            producer: String::from("published-root"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(std::collections::BTreeSet::new()).expect("choice class"),
        std::collections::BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        scenario_id,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("published-root-scheduler", name.as_bytes()),
            producer: CampaignHash::derive("published-root-producer", name.as_bytes()),
        },
        name,
        None,
    )
    .expect("choice opportunity");
    // The default value keeps the recorded selection valid for its domain.
    let selection = Selection::new(
        &opportunity,
        &domain,
        ChoiceValue::Boolean(false),
        SelectionOrigin::Default,
    )
    .expect("recorded selection");
    crucible::SelectionDecision::new(&selection)
}
