//! Authored atomic RAM mutations across physical placements.
//!
//! Each lane is a genuine accepted repository execution. Its checkpoint is
//! published and promoted through independent causal and locked native replay;
//! the fixture never supplies a mutation receipt or a replacement RAM observer.

use super::super::hot_fork_native::{fork_resources, native_repository};
use super::accepted_promotion::{extend_native_operations, promote_accepted_checkpoint_with_model};
use super::*;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct,
    decode_crucible_attempt_execution,
};
use crucible::model::*;
use crucible_campaign::CampaignExecutorStore;

pub(super) mod discovery;

const SEEDS: [u64; 3] = [7, 42, 991];
const FAULT_QUANTA: usize = 32;
const MUTATION_START: u64 = 60 * 1024 * 1024 + 4095;
const MUTATION_BYTES: u64 = 2;

#[derive(Debug, PartialEq, Eq)]
struct FaultBoundary {
    logical: Boundary,
    resolved: Option<ResolvedEffectTrace>,
    locked: Option<ResolvedEffectTrace>,
    emitted: Vec<ReferencedSignalEvent>,
}

struct FaultLane {
    boundaries: Vec<FaultBoundary>,
    ram_record: Vec<u8>,
    activity: HostRamActivity,
    bitflips: usize,
}

#[test]
#[ignore = "requires the isolated AOS paging VM and genuine accepted native promotion"]
fn production_managed_memory_faults_preserve_replay_state() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/vm/unprivileged_userfaultfd")
            .expect("disposable host kernel userfaultfd policy")
            .trim(),
        "1"
    );
    let mut bitflips = 0;
    let mut missing = 0;
    let mut write_protect = 0;
    let mut discards = 0;

    discovery::with_discovered_world(|world| {
        for (ordinal, seed) in SEEDS.into_iter().enumerate() {
            let source = fault_scenario(world, seed);
            let project = 35_000 + u32::try_from(ordinal).expect("bounded seed index") * 200;
            let resident = run_lane(&source, &format!("fault-resident-{seed}"), project, false);
            let cold = run_lane(&source, &format!("fault-cold-{seed}"), project + 100, true);

            assert_eq!(resident.boundaries, cold.boundaries, "replay seed {seed}");
            assert_eq!(resident.ram_record, cold.ram_record, "RAM root seed {seed}");
            assert!(cold.bitflips > 0, "actual atomic bitflip commits required");
            assert_eq!(resident.bitflips, cold.bitflips);
            assert!(cold.activity.physical_discards > 0);
            assert!(cold.activity.successful_missing_installs > 0);
            assert!(cold.activity.write_protect_transitions > 0);

            bitflips += cold.bitflips;
            missing += cold.activity.successful_missing_installs;
            write_protect += cold.activity.write_protect_transitions;
            discards += cold.activity.physical_discards;
        }
    });

    println!("managed_memory_faults_seed_count={}", SEEDS.len());
    println!("managed_memory_faults_committed_bitflips={bitflips}");
    println!("managed_memory_faults_missing_installs={missing}");
    println!("managed_memory_faults_wp_transitions={write_protect}");
    println!("managed_memory_faults_cold_discards={discards}");
    println!("managed_memory_faults_state_identity=true");
    println!("managed_memory_faults_ram_root_identity=true");
    println!("managed_memory_faults_fault_trace_identity=true");
    println!("managed_memory_faults_modeled_time_identity=true");
    println!("managed_memory_faults_actual_checkpoint_promotion=true");
    println!("managed_memory_faults_actual_target_manifest=true");
    println!("MANAGED_MEMORY_FAULTS_NATIVE_PASS");
}

fn fault_scenario(world: &World, seed: u64) -> ScenarioDefForm {
    ScenarioDefForm::from_components(
        world,
        &fault_plan(),
        &Properties::empty(),
        Seed::from_u64(seed),
    )
    .expect("unmodified guest with authenticated authored memory faults")
}

fn fault_plan() -> Plan {
    let flips = SignalId::parse("cross-page-bitflip").expect("event signal ID");
    let schema = SignalId::parse("memory-bitflip-event").expect("event schema");
    let program = SignalProgram::new(
        vec![SignalNode {
            id: flips.clone(),
            domain: SignalDomain::Event,
            output: SignalShape::new(
                SignalValueType::Event(schema.clone()),
                SignalUnit::Dimensionless,
                0,
            )
            .expect("typed impulse shape"),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: [100_000, 500_000, 1_000_000, 2_000_000]
                    .into_iter()
                    .enumerate()
                    .map(|(ordinal, ticks)| SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { ticks }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: schema.clone(),
                            payload: vec![u8::try_from(ordinal).expect("bounded event ordinal")],
                        },
                    })
                    .collect(),
            }),
        }],
        vec![flips.clone()],
        SignalResourceLimits::default(),
    )
    .expect("exact impulse program");
    let node = FaultObjectId::parse("memory").expect("exact realized node identity");
    let target = |start, length| {
        TargetSelector::Exact(
            ResolvedTargetSet::new(
                vec![ResolvedFaultTarget::MemoryRange {
                    node: node.clone(),
                    address_space: FaultObjectId::parse("gpa").expect("guest physical identity"),
                    guest_address: start,
                    vcpu: None,
                    length_bytes: length,
                }],
                false,
            )
            .expect("exact guest RAM range"),
        )
    };
    let observe = BindingObservabilityPolicy {
        samples: SampleObservation::ChangesAndEffects,
        record_inactive_opportunities: false,
        retain_mapped_values: true,
    };
    let mutation = FaultBinding::new(
        FaultObjectId::parse("cold-cross-page-bitflip").expect("binding ID"),
        vec![flips],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        target(MUTATION_START, MUTATION_BYTES),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
                address_space: MemoryAddressSpace::GuestPhysical,
                range: ByteRange::new(MUTATION_START, MUTATION_BYTES).expect("cross-page range"),
                mutation: MemoryMutationKind::BitFlip {
                    mask: HexBytes::parse("01", 1).expect("one-bit XOR mask"),
                },
                atomicity: MemoryMutationAtomicity::AllOrNothing,
            }),
        )
        .expect("atomic cross-page mutation"),
        None,
        BindingSearchPolicy::Fixed,
        observe,
        &program,
    )
    .expect("actual atomic mutation binding");
    Plan::empty()
        .with_fault_signals(
            FaultSignalPlan::new(
                vec![program],
                vec![mutation],
                FaultResourceLimits::default(),
            )
            .expect("bounded memory fault plan"),
        )
        .expect("canonical memory mutation plan")
}

fn run_lane(source: &ScenarioDefForm, lane: &str, project: u32, cold: bool) -> FaultLane {
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(source, root, storage),
        fork_resources,
        |prepared, config, repository| {
            let (_promoted, mut worker) = promote_accepted_checkpoint_with_model(
                prepared,
                config,
                repository,
                source,
                |_host, store| FaultModel {
                    store,
                    config: config.clone(),
                    prepared,
                    cold,
                    lane: None,
                },
            );
            worker
                .model_mut()
                .lane
                .take()
                .expect("completed native fault lane")
        },
    )
}

struct FaultModel<'a> {
    store: CampaignExecutorStore,
    config: PackagedQemuExecutorConfig,
    prepared: &'a PackagedPreparation,
    cold: bool,
    lane: Option<FaultLane>,
}

impl AttemptExecutionModel for FaultModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("authenticated accepted scenario");
        let source = input.scenario();
        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("actual ext4 quota and process containment");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            self.config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let mut lifecycle = factory
            .begin_fresh(&source.scenario_def(), source, context)
            .expect("actual production pager and RAM transaction callbacks");
        let registry = &self.prepared.host_operational_registry;
        let target = discover_target(registry, context);
        let initial = status(registry, target);
        let mut configuration = lifecycle
            .resume_state()
            .expect("initial scheduler")
            .into_parts()
            .0;
        let mut boundaries = Vec::with_capacity(FAULT_QUANTA);

        for _ in 0..FAULT_QUANTA {
            if self.cold {
                let before = status(registry, target).activity.expect("actual activity");
                registry
                    .apply_native_qualification_policy(target, 0)
                    .expect("paused-only target under the retained full execution peak");
                await_reclaim(registry, target, context, before.physical_discards);
            }
            context
                .charge_execution_quantum()
                .expect("original accepted execution quantum allowance");
            let outcome = QemuFreshAttemptLifecycleOwner::drive_quantum(
                &mut lifecycle,
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
            )
            .expect("genuine guest execution with atomic fault mutations");
            configuration = outcome.configuration;
            let faults = lifecycle
                .fault_evidence_snapshot()
                .expect("actual fault ledger");
            boundaries.push(FaultBoundary {
                logical: boundary(&mut lifecycle),
                resolved: faults.resolved_effect_trace,
                locked: faults.locked_effect_trace,
                emitted: faults.emitted_events,
            });
            let current = status(registry, target);
            assert_eq!(current.admitted_resources, initial.admitted_resources);
            assert_eq!(current.reservation_revision, initial.reservation_revision);
        }

        assert!(
            lifecycle
                .exact_checkpoint_ready()
                .expect("actual coherent capture boundary")
        );
        let faults = lifecycle
            .fault_evidence_snapshot()
            .expect("final fault trace");
        let trace = faults
            .resolved_effect_trace
            .expect("recorded actual effects");
        let effects = trace.work_items.iter().flat_map(|work| &work.records);
        let bitflips = effects
            .clone()
            .filter(|record| record.effect == EffectKind::MemoryMutation)
            .count();
        let capture = lifecycle
            .capture_attempt_checkpoint(context)
            .expect("real coherent paged RAM checkpoint");
        let capture = capture.into_closure();
        let ram_record = capture.ram_sources()[0].root().record().encode();
        let staged = context
            .prepare_and_stage_checkpoint(
                crate::CapturedAttemptCheckpoint::from_production_closure(capture),
            )
            .expect("same-ledger durable checkpoint handoff before teardown");
        let activity = status(registry, target)
            .activity
            .expect("real pager counters");
        lifecycle
            .shutdown()
            .expect("actual node reap and fault/source worker joins");
        self.lane = Some(FaultLane {
            boundaries,
            ram_record,
            activity,
            bitflips,
        });
        Ok(AttemptExecutionProduct::exact_checkpoint(staged))
    }
}

pub(super) fn discover_target(
    registry: &crate::HostOperationalRegistry,
    context: &AttemptExecutionContext,
) -> HostRamTarget {
    match registry
        .execute(
            OPERATOR,
            HostOperationalRequest::ListTargets {
                target: HostRamOwnerTarget {
                    daemon_epoch: context.host_daemon_epoch(),
                    owner_id: context.host_ram_owner_id().expect("accepted owner"),
                },
                after: None,
                limit: 2,
            },
        )
        .expect("actual arena discovery")
    {
        HostOperationalResponse::Targets { targets, next, .. } => {
            assert_eq!(targets.len(), 1);
            assert!(next.is_none());
            targets[0]
        }
        response => panic!("unexpected target discovery: {response:?}"),
    }
}

pub(super) fn await_reclaim(
    registry: &crate::HostOperationalRegistry,
    target: HostRamTarget,
    context: &AttemptExecutionContext,
    before: u64,
) {
    let operation = context
        .host_operation_supervisor()
        .expect("original attempt cap")
        .begin(HostOperationClass::Quiescence)
        .expect("finite paused-reclaim operation");
    loop {
        let current = status(registry, target);
        if current
            .activity
            .expect("actual successful discard counter")
            .physical_discards
            > before
        {
            operation
                .complete()
                .expect("real completed discard without deadline renewal");
            return;
        }
        std::thread::sleep(
            operation
                .wait_slice()
                .expect("original paused-reclaim deadline")
                .min(Duration::from_millis(10)),
        );
    }
}

#[test]
fn authored_memory_fault_bindings_are_atomic_cross_page_impulses() {
    let plan = fault_plan();
    let faults = plan.fault_signals();
    assert_eq!(faults.bindings().len(), 1);
    let mutation = faults
        .bindings()
        .iter()
        .find(|binding| binding.effect().kind() == EffectKind::MemoryMutation)
        .expect("atomic impulse");
    let EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
        range, atomicity, ..
    }) = mutation.effect().specification()
    else {
        panic!("exact memory mutation");
    };
    assert_eq!(range.start(), MUTATION_START);
    assert_eq!(range.length(), MUTATION_BYTES);
    assert_eq!(*atomicity, MemoryMutationAtomicity::AllOrNothing);
    assert_eq!(
        MUTATION_START / 4096 + 1,
        (MUTATION_START + MUTATION_BYTES - 1) / 4096
    );
    for seed in SEEDS {
        assert!(seed > 0);
    }
}
