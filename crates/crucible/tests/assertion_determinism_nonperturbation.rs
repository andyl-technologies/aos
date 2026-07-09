//! Checks T-ASRT-13 assertion determinism and non-perturbation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, AssertionRunVerdict, ConditionLeaf, GuestAssertionDetail,
    GuestAssertionKind, GuestAssertionMarker, HostAssertionEvaluator, HostAssertionPredicate,
    Icount, LintedHostAssertionOracle, NodeId, NodeTemplate, ObservableEvent, ObservedState,
    OfflineAssertionChecker, Predicate, Properties, Property, ReadyPoint, RecordedAssertionLog,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode, lint_host_assertion_harness_source,
};

#[cfg(feature = "test-double")]
use crucible::{AdvanceOutcome, Backend, BackendInput, ExecutionHorizon, SimBackend};

#[derive(Clone, Debug, Default)]
struct DeterministicOracle;

impl HostAssertionPredicate for DeterministicOracle {
    fn leaf_is_true(&self, _observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => {
                assert!(nodes.is_empty());
                matches!(name, "host-always" | "host-hit")
            }
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

fn linted_host_oracle<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    crucible::test_support::unchecked_host_assertion_oracle_for_test(oracle)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn assertion(id: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: format!("assertion {id}"),
        property,
    }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    World::from_nodes(vec![ready_node("guest")]).expect("assertion determinism world should build")
}

fn properties(world: &World) -> Properties {
    Properties::from_assertions_for_world(
        world,
        vec![
            assertion(
                "m-host-always",
                Property::Always {
                    predicate: Predicate::named("host-always"),
                },
            ),
            assertion(
                "z-host-sometimes",
                Property::Sometimes {
                    predicate: Predicate::named("host-hit"),
                },
            ),
        ],
    )
    .expect("assertion determinism properties should validate")
}

fn guest_marker() -> GuestAssertionMarker {
    GuestAssertionMarker::new(
        AssertionId::from_name("a-guest-sometimes"),
        "guest sometimes marker",
        GuestAssertionKind::Sometimes,
        true,
        true,
        vec![GuestAssertionDetail::new("case", "determinism")],
        "determinism.rs:1",
    )
}

fn event_log() -> Vec<SchedulerEventLogEntry> {
    let marker = ObservableEvent::guest_assertion_marker(icount(1), node("guest"), guest_marker());
    vec![
        crucible::test_support::condition_observation_entry_for_test(0, &marker),
        crucible::test_support::condition_boundary_entry_for_test(
            1,
            time(2),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    ]
}

fn prefix(entries: Vec<SchedulerEventLogEntry>) -> crucible::ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries)
        .expect("assertion determinism prefix should be checked")
}

#[test]
fn merged_host_and_guest_outcomes_are_bit_identical_online_offline_and_repeated() {
    let world = world();
    let properties = properties(&world);
    let event_log = event_log();
    let recorded_log =
        RecordedAssertionLog::from_segments(vec![event_log[..1].to_vec(), event_log[1..].to_vec()])
            .expect("recorded assertion determinism log should fold");

    let mut online_oracle = linted_host_oracle(DeterministicOracle);
    let mut online_evaluator = HostAssertionEvaluator::new(&properties)
        .with_world_white_box_policies(&world)
        .with_guest_assertion_catalog(vec![guest_marker()]);
    online_evaluator.observe_prefix(&prefix(event_log[..1].to_vec()), &mut online_oracle);
    let online_report =
        online_evaluator.finalize_prefix(&prefix(event_log.clone()), &mut online_oracle);

    let checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(&world)
        .with_guest_assertion_catalog(vec![guest_marker()]);
    let mut first_oracle = linted_host_oracle(DeterministicOracle);
    let first_offline = checker
        .check_run_with_oracle(&properties, &recorded_log, &mut first_oracle)
        .expect("first offline assertion determinism check should grade");
    let mut second_oracle = linted_host_oracle(DeterministicOracle);
    let second_offline = checker
        .check_run_with_oracle(&properties, &recorded_log, &mut second_oracle)
        .expect("second offline assertion determinism check should grade");

    assert_eq!(online_report, first_offline);
    assert_eq!(first_offline, second_offline);
    assert_eq!(first_offline.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        first_offline
            .outcomes()
            .iter()
            .map(|outcome| outcome.assertion.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a-guest-sometimes", "m-host-always", "z-host-sometimes"],
        "host and guest marker outcomes must merge by stable id"
    );
}

#[cfg(feature = "test-double")]
#[test]
fn assertion_evaluation_is_side_effect_free_for_backend_fingerprints() {
    let world = World::from_nodes(Vec::new()).expect("empty neutrality world should build");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![assertion(
            "sometimes-host",
            Property::Sometimes {
                predicate: Predicate::named("host-hit"),
            },
        )],
    )
    .expect("neutrality properties should validate");
    let mut backend = SimBackend::new();
    backend
        .deliver_input(BackendInput {
            node: node("guest"),
            payload: b"crucible".to_vec(),
        })
        .expect("test backend input should deliver");
    assert_eq!(
        backend.advance_to_horizon(ExecutionHorizon {
            icount: Icount { retired: 1024 },
        }),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
    let before = backend
        .fingerprint()
        .expect("fingerprint before assertion evaluation should read");

    let mut evaluator = HostAssertionEvaluator::new(&properties);
    let mut oracle = linted_host_oracle(DeterministicOracle);
    let report = evaluator.finalize_prefix(&prefix(event_log()), &mut oracle);

    let after = backend
        .fingerprint()
        .expect("fingerprint after assertion evaluation should read");
    assert_eq!(report.verdict(), &AssertionRunVerdict::Passed);
    assert_eq!(
        before, after,
        "assertion evaluation must not perturb backend fingerprint state"
    );
}

#[test]
fn host_assertion_harness_lint_rejects_banned_predicate_operations() {
    let source = r#"
        use std::collections::HashMap;
        fn predicate() -> bool {
            let _now = std::time::SystemTime::now();
            let _file = std::fs::read("/tmp/not-recorded");
            let _child = std::process::Command::new("date");
            let _rng = rand::thread_rng();
            let _entropy = getrandom::getrandom;
            let _os_rng = rand::rngs::OsRng;
            let _hasher = std::collections::hash_map::DefaultHasher::new();
            let _random_state = std::collections::hash_map::RandomState::new();
            let _seed = rand_chacha::ChaCha20Rng::from_entropy();
            let _map = HashMap::<String, String>::new();
            let _env = std::env::var("NOT_RECORDED");
            let _net = std::net::TcpStream::connect("127.0.0.1:1");
            let _stdin = std::io::stdin();
            let _state = std::sync::Mutex::new(0);
            let _cell = std::cell::RefCell::new(0);
            true
        }
        fn grouped_imports() {
            use std::{fs, process::Command};
            let _ = fs::read("/tmp/not-recorded");
            let _ = Command::new("date");
        }
    "#;

    let error = lint_host_assertion_harness_source(source)
        .expect_err("host assertion lint must reject nondeterministic predicate source");
    let patterns = error
        .violations()
        .iter()
        .map(|violation| violation.pattern.as_str())
        .collect::<Vec<_>>();

    for expected in [
        "HashMap",
        "SystemTime",
        "std::time",
        "getrandom",
        "OsRng",
        "DefaultHasher",
        "RandomState",
        "from_entropy",
        "std::env",
        "std::net",
        "TcpStream",
        "std::io",
        "stdin",
        "Mutex",
        "RefCell",
        "thread_rng",
        "rand::",
        "std::fs",
        "std::{fs",
        "fs::",
        "std::process",
        "process::Command",
        "Command::new",
    ] {
        assert!(
            patterns.contains(&expected),
            "host assertion lint should reject {expected}"
        );
    }
}

#[test]
fn host_assertion_harness_lint_accepts_observed_state_only_predicates() {
    let source = r#"
        fn predicate(state: ObservedState<'_>) -> bool {
            state.observable_events().iter().any(|event| event.at().ticks == state.at().ticks)
        }
    "#;

    lint_host_assertion_harness_source(source)
        .expect("observed-state-only predicate source should pass host assertion lint");
}

#[test]
fn assertion_evaluator_rejects_banned_nondeterminism_and_live_state_access() {
    let trigger = include_str!("../src/trigger.rs");
    let assertion_engine_block = trigger
        .split("pub struct OfflineAssertionChecker")
        .nth(1)
        .expect("offline assertion checker should exist")
        .split("fn push_observed_state_facts")
        .next()
        .expect("observed-state fact materialization should follow assertion engine");

    for forbidden in [
        "HashMap",
        "HashSet",
        "SystemTime",
        "Instant",
        "std::time",
        "thread_rng",
        "rand::",
        "getrandom",
        "OsRng",
        "DefaultHasher",
        "RandomState",
        "from_entropy",
        "std::env",
        "env::",
        "std::thread",
        "thread::",
        "thread_local!",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "std::io",
        "stdin",
        "stdout",
        "stderr",
        "Atomic",
        "Mutex",
        "RwLock",
        "OnceLock",
        "LazyLock",
        "RefCell",
        "borrow_mut",
        "std::fs",
        "std::process",
        "OpenOptions",
        "File::",
        "tokio::select",
        "select!",
        "unsafe",
    ] {
        assert!(
            !assertion_engine_block.contains(forbidden),
            "assertion evaluation must not use banned nondeterminism or live-state access: {forbidden}"
        );
    }
}
