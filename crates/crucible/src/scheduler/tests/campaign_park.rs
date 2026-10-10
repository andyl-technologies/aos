//! Campaign-marker parks for staggered all-VM atomic boundaries.

use super::*;

fn vm(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn runnable(name: &str, counter: u64) -> SchedulerScenarioNode {
    test_scenario_node(
        name,
        counter,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    )
}

fn logical_time(scheduler: &SingleScheduler, name: &str) -> u64 {
    let node = scheduler
        .nodes
        .iter()
        .find(|node| node.id.node.name == name)
        .unwrap_or_else(|| panic!("test node `{name}` should exist"));
    scheduler
        .node_current_time(node)
        .unwrap_or_else(|error| panic!("test node time should project: {error}"))
        .ticks
}

fn candidate_names(scheduler: &SingleScheduler) -> Vec<String> {
    scheduler
        .advance_candidates()
        .unwrap_or_else(|error| panic!("candidates should project: {error}"))
        .into_iter()
        .map(|candidate| scheduler.nodes[candidate.index].id.node.name.clone())
        .collect()
}

#[test]
fn parked_vm_leaves_runs_frontier_and_quiescence() {
    let mut scheduler = test_scheduler(vec![runnable("a", 20), runnable("b", 40)], Vec::new());
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 20 });

    scheduler
        .park_campaign_marker_node(&vm("a"))
        .unwrap_or_else(|error| panic!("live VM should park: {error}"));

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });
    assert_eq!(scheduler.campaign_parked_nodes(), vec![vm("a")]);
    assert_eq!(candidate_names(&scheduler), vec![String::from("b")]);
    let quiescence = scheduler
        .quiescence()
        .unwrap_or_else(|error| panic!("quiescence should project: {error}"));
    assert!(!quiescence.blockers.iter().any(|blocker| matches!(
        blocker,
        SchedulerQuiescenceBlocker::RunnableNode { node } if node.node.name == "a"
    )));
    assert!(matches!(
        scheduler.checkpoint(),
        Err(SingleSchedulerCheckpointError::Transient)
    ));
    assert!(scheduler.park_campaign_marker_node(&vm("a")).is_err());
}

#[test]
fn staggered_parks_join_the_latest_park_and_keep_timer_durations() {
    let timed = test_scenario_node(
        "a",
        20,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 25 },
        },
    );
    let mut scheduler = test_scheduler(
        vec![timed, runnable("b", 30), runnable("c", 40)],
        Vec::new(),
    );

    for name in ["a", "b", "c"] {
        scheduler
            .park_campaign_marker_node(&vm(name))
            .unwrap_or_else(|error| panic!("VM `{name}` should park: {error}"));
    }
    // The last live participant defined the retained frontier.
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });

    let joined = scheduler
        .join_campaign_parks_to_frontier()
        .unwrap_or_else(|error| panic!("all-parked world should join: {error}"));

    assert_eq!(joined, vec![vm("a"), vm("b"), vm("c")]);
    assert!(!scheduler.has_campaign_parks());
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });
    for name in ["a", "b", "c"] {
        assert_eq!(logical_time(&scheduler, name), 40);
    }
    // Physical counters stay at each park; only the logical clock moves.
    assert_eq!(scheduler.nodes[0].counter, NodeCounter { ticks: 20 });
    assert_eq!(
        scheduler.nodes[0].exact_local_event,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { ticks: 45 },
        }
    );
    assert!(scheduler.checkpoint().is_ok());
}

#[test]
fn all_parked_join_advances_to_a_park_ahead_of_the_frontier() {
    let mut scheduler = test_scheduler(vec![runnable("a", 50), runnable("b", 30)], Vec::new());

    scheduler
        .park_campaign_marker_node(&vm("a"))
        .unwrap_or_else(|error| panic!("leading VM should park: {error}"));
    scheduler
        .park_campaign_marker_node(&vm("b"))
        .unwrap_or_else(|error| panic!("trailing VM should park: {error}"));
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 30 });

    scheduler
        .join_campaign_parks_to_frontier()
        .unwrap_or_else(|error| panic!("all-parked world should join: {error}"));

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 50 });
    assert_eq!(logical_time(&scheduler, "a"), 50);
    assert_eq!(logical_time(&scheduler, "b"), 50);
}

#[test]
fn join_with_a_live_peer_rejects_a_park_beyond_the_frontier() {
    let mut scheduler = test_scheduler(vec![runnable("a", 50), runnable("b", 30)], Vec::new());
    scheduler
        .park_campaign_marker_node(&vm("a"))
        .unwrap_or_else(|error| panic!("leading VM should park: {error}"));

    assert!(scheduler.join_campaign_parks_to_frontier().is_err());

    assert_eq!(scheduler.campaign_parked_nodes(), vec![vm("a")]);
    assert_eq!(logical_time(&scheduler, "a"), 50);
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 30 });
}
