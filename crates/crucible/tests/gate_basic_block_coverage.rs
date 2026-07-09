//! Implements `gate:basic-block-coverage` for TCG-exec coverage feedback.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BasicBlockCoverageConfig, BasicBlockCoverageError, BasicBlockCoverageMode,
    BasicBlockCoverageRegistrationPlan, BlackBoxObservationKind, BlackBoxObservationSource,
    Configuration, ContentHash, Decision, EventClass, ExecutionFingerprint, Icount, NodeId,
    ObservableEvent, RngDecision, RngStreamId, SchedulerEvaluationBoundaryKind,
    SchedulerEventLogEntry, SchedulerEventLogPayload, TcgExecBasicBlock, VirtualTime, World,
    basic_block_coverage_map_index, compare_event_log_determinism, reduce,
};

#[test]
fn gate_basic_block_coverage_is_registration_time_opt_in() {
    let off = BasicBlockCoverageConfig::new(BasicBlockCoverageMode::Off, 0);
    let off_plan = off
        .registration_plan()
        .unwrap_or_else(|error| panic!("off mode should not validate map settings: {error}"));

    assert_eq!(off_plan, BasicBlockCoverageRegistrationPlan::Disabled);
    assert!(!off_plan.requests_tcg_exec_coverage());
    assert!(off_plan.has_no_engine_hot_path_consumer());
    assert_eq!(
        off_plan.require_consumer(node("guest-a")),
        Err(BasicBlockCoverageError::CallbackWhileDisabled)
    );

    let on = BasicBlockCoverageConfig::on();
    let on_plan = on
        .registration_plan()
        .unwrap_or_else(|error| panic!("on mode should register coverage: {error}"));

    assert!(on_plan.requests_tcg_exec_coverage());
    assert!(!on_plan.has_no_engine_hot_path_consumer());
    assert_eq!(
        BasicBlockCoverageConfig::new(BasicBlockCoverageMode::On, 0).registration_plan(),
        Err(BasicBlockCoverageError::InvalidMapEntries { entries: 0 })
    );
}

#[test]
fn gate_basic_block_coverage_consumes_tcg_exec_blocks_without_guest_instrumentation() {
    let plan = BasicBlockCoverageConfig::new(BasicBlockCoverageMode::On, 1024)
        .registration_plan()
        .unwrap_or_else(|error| panic!("coverage should register: {error}"));
    let consumer = plan
        .require_consumer(node("unmodified-binary"))
        .unwrap_or_else(|error| panic!("enabled coverage should expose a consumer: {error}"));
    let block = TcgExecBasicBlock::new(icount(77), 0x4010, 0x20);
    let consumed = consumer
        .consume_tcg_exec_block(block)
        .unwrap_or_else(|error| panic!("valid TCG-exec block should be consumed: {error}"));

    assert_eq!(
        consumed.map_index(),
        basic_block_coverage_map_index(0x4010, 1024)
            .unwrap_or_else(|error| panic!("map index should fold: {error}"))
    );
    assert_eq!(
        consumed.event().payload().black_box_observation_kind(),
        Some(BlackBoxObservationKind::BasicBlockCoverage)
    );
    assert_eq!(
        consumed
            .event()
            .payload()
            .black_box_observation_contract()
            .map(|contract| contract.source()),
        Some(BlackBoxObservationSource::ExternalExecutionTrace)
    );
    let entry = observation_entry(0, consumed.event());

    assert_eq!(entry.event_payload().kind(), "coverage");
    assert_eq!(entry.event_payload().string("kind"), Some("basic_block"));
    assert_eq!(entry.event_payload().u64("guest_pc"), Some(0x4010));
    assert_eq!(entry.event_payload().u64("block_len"), Some(0x20));
    assert_eq!(entry.class(), EventClass::Observational);
    assert_eq!(
        consumer.consume_tcg_exec_block(TcgExecBasicBlock::new(icount(78), 0x4010, 0)),
        Err(BasicBlockCoverageError::InvalidBlockLength { block_len: 0 })
    );
}

#[test]
fn gate_basic_block_coverage_has_zero_fingerprint_effect() {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.basic-block-coverage.world",
        "zero-fingerprint-effect",
    ));
    let off_config = BasicBlockCoverageConfig::off();
    let on_config = BasicBlockCoverageConfig::on();
    let off_genesis = Configuration::genesis(world.scenario_def());
    let on_genesis = Configuration::genesis(world.scenario_def());
    let off_fingerprint = execution_fingerprint(&off_genesis);
    let on_fingerprint = execution_fingerprint(&on_genesis);
    let baseline = vec![rng_entry(0, 1, 7), boundary_entry(1, 3)];
    let coverage = on_config
        .registration_plan()
        .and_then(|plan| plan.require_consumer(node("guest-a")))
        .and_then(|consumer| {
            consumer
                .consume_tcg_exec_block(TcgExecBasicBlock::new(icount(2), 0x7000, 0x20))
                .map(|consumed| consumed.into_event())
        })
        .unwrap_or_else(|error| panic!("coverage event should be consumable: {error}"));
    let with_coverage = vec![
        rng_entry(0, 1, 7),
        observation_entry(1, &coverage),
        boundary_entry(2, 3),
    ];

    assert!(!off_config.affects_execution_fingerprint());
    assert!(!on_config.affects_execution_fingerprint());
    assert!(!on_config.requires_guest_instrumentation());
    assert_eq!(off_genesis.id(), on_genesis.id());
    assert_eq!(off_fingerprint, on_fingerprint);
    assert!(compare_event_log_determinism(&baseline, &with_coverage).passes());
}

fn execution_fingerprint(configuration: &Configuration) -> ExecutionFingerprint {
    let state = reduce(&configuration.def, &configuration.schedule)
        .unwrap_or_else(|error| panic!("configuration should reduce deterministically: {error}"));
    ExecutionFingerprint { hash: state.id }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn observation_entry(sequence: u64, event: &ObservableEvent) -> SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(sequence, event)
}

fn rng_entry(sequence: u64, ticks: u64, value: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("basic-block-coverage"),
            value,
        })),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}
