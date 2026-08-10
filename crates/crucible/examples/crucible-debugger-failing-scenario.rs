//! Emits a deliberately failing scenario for hands-on debugger exercises.
//!
//! A database cluster starts normally, while the scenario incorrectly requires
//! `db-0` to remain crashed. The resulting assertion failure is small and
//! deterministic, but still requires the operator to compare the assertion,
//! event history, and live VM state to identify the scenario-authoring error.

use std::error::Error;

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, EventGraph, NodeId, NodeLifecycle, Plan,
    Predicate, Properties, Property, ScenarioDefForm, Seed,
};

fn main() -> Result<(), Box<dyn Error>> {
    print!("{}", failing_scenario()?.to_canonical_toml()?);
    Ok(())
}

fn failing_scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    let base = crucible::crash_restart_scenario()?.scenario;
    let world = base.world().clone();
    let suspect = NodeId {
        name: String::from("db-0"),
    };
    let assertion_id = AssertionId::from_name("suspect-must-crash");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion_id.clone(),
            message: String::from("db-0 must remain crashed"),
            property: Property::Always {
                predicate: Predicate::node_state(suspect, NodeLifecycle::Crashed),
            },
        }],
    )?;
    let assertion_ids = vec![assertion_id.clone()];
    let graph = EventGraph::builder()
        .event("fail-on-inverted-expectation")
        .when(Predicate::assertion_state(
            assertion_id,
            AssertionPhase::Violated,
        ))
        .action(Action::fail("db-0 did not crash"))
        .build_with_assertions_for_world(assertion_ids.clone(), &world)?;
    let plan = Plan::from_event_graph_with_assertions_for_world(&world, assertion_ids, graph)?;
    Ok(ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(0xdeb6),
        0,
    )?)
}
