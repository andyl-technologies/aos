//! Seeded byte-access service latency on an unchanged ordinary multiboot guest.
//!
//! The discovery machine finds the real stopped cut in the ELF delay loop.
//! Each lane replays that prefix, then selects either the guest's byte load or
//! its following result store. The STORE fixture verifies the authenticated
//! captured result vector under the fixed low-RAM launch profile. It does not
//! establish held PageIn, intermediate rollback, dirty tracking, or generalized
//! multi-byte, MMU and atomic continuation behavior.

use super::super::hot_fork_native::{fork_resources, native_repository};
use super::accepted_promotion::{extend_native_operations, promote_accepted_checkpoint_with_model};
use super::faults::{await_reclaim, discover_target};
use super::*;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct,
    decode_crucible_attempt_execution,
};
use crucible::model::*;
use crucible_campaign::CampaignExecutorStore;
use crucible_qemu::QemuMemoryServiceOccurrence;

const SEEDS: [u64; 3] = [7, 42, 991];
const SERVICE_QUANTA: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteAccess {
    Load,
    Store,
}

impl ByteAccess {
    fn phase(self) -> FaultPhase {
        match self {
            Self::Load => FaultPhase::Load,
            Self::Store => FaultPhase::Store,
        }
    }

    fn binding(self) -> &'static str {
        match self {
            Self::Load => "byte-load-latency",
            Self::Store => "byte-store-latency",
        }
    }

    fn target(self) -> u64 {
        asset_number(match self {
            Self::Load => "CRUCIBLE_BYTE_TARGET",
            Self::Store => "CRUCIBLE_BYTE_RESULT",
        })
    }
}

#[derive(Clone, Copy)]
struct ByteCut {
    pc: u64,
    raw: u64,
    ticks: u64,
    prefix_quanta: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ServiceBoundary {
    logical: Boundary,
    resolved: Option<ResolvedEffectTrace>,
    locked: Option<ResolvedEffectTrace>,
    occurrence: Option<QemuMemoryServiceOccurrence>,
}

struct ServiceLane {
    boundaries: Vec<ServiceBoundary>,
    ram_record: Vec<u8>,
    activity: HostRamActivity,
    latency: u64,
    stored_result: Option<u8>,
}

#[test]
#[ignore = "requires the isolated AOS paging VM and actual byte-service guest asset"]
fn production_byte_service_latency_is_placement_independent() {
    qualify_byte_service(ByteAccess::Load);
}

#[test]
#[ignore = "requires the isolated AOS paging VM and actual unchanged byte-service guest"]
fn production_byte_store_service_is_placement_independent() {
    qualify_byte_service(ByteAccess::Store);
}

fn qualify_byte_service(access: ByteAccess) {
    let mut latencies = std::collections::BTreeSet::new();
    let mut missing = 0;
    let mut discards = 0;
    discover_byte_world(|world, cut| {
        for (ordinal, seed) in SEEDS.into_iter().enumerate() {
            let source = ScenarioDefForm::from_components(
                world,
                &service_plan_for_access(access.target(), cut.ticks, access),
                &Properties::empty(),
                Seed::from_u64(seed),
            )
            .expect("authenticated byte-service scenario");
            let base = if access == ByteAccess::Load {
                36_000
            } else {
                37_000
            };
            let project = base + u32::try_from(ordinal).expect("bounded seed") * 200;
            let resident = run_service_lane(
                &source,
                &format!("byte-resident-{seed}"),
                project,
                false,
                cut,
                access,
            );
            let cold = run_service_lane(
                &source,
                &format!("byte-cold-{seed}"),
                project + 100,
                true,
                cut,
                access,
            );
            assert_eq!(
                resident.boundaries, cold.boundaries,
                "service ledger and modeled cuts seed {seed}"
            );
            assert_eq!(resident.ram_record, cold.ram_record);
            assert_eq!(resident.latency, cold.latency);
            assert_eq!(resident.stored_result, cold.stored_result);
            if access == ByteAccess::Store {
                assert_eq!(cold.stored_result, Some(0x5a));
            }
            assert!(cold.activity.successful_missing_installs > 0);
            assert!(cold.activity.physical_discards > 0);
            latencies.insert(cold.latency);
            missing += cold.activity.successful_missing_installs;
            discards += cold.activity.physical_discards;
        }
    });
    assert!(
        latencies.len() > 1,
        "native access ledger must exhibit genuinely seeded durations"
    );
    println!("byte_service_seed_count=3");
    println!("byte_service_state_identity=true");
    println!("byte_service_ram_root_identity=true");
    println!("byte_service_modeled_time_identity=true");
    println!("byte_service_actual_guest_entry=true");
    println!("byte_service_one_byte_access=true");
    println!("byte_service_native_latency_variation=true");
    println!("byte_service_native_service_ledger_identity=true");
    println!("byte_service_missing_installs={missing}");
    println!("byte_service_cold_discards={discards}");
    if access == ByteAccess::Store {
        println!(
            "byte_service_store_pc={}",
            asset_number("CRUCIBLE_BYTE_STORE_PC")
        );
        println!("byte_service_store_result=90");
        println!("byte_service_store_target={}", access.target());
        println!("BYTE_STORE_SERVICE_NATIVE_PASS");
    } else {
        println!("BYTE_SERVICE_NATIVE_PASS");
    }
}

fn asset_number(name: &str) -> u64 {
    std::env::var(name)
        .expect("source-built ELF metadata")
        .parse()
        .expect("checked ELF scalar")
}

fn byte_config(mut config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    config.lifecycle = Arc::new(
        crucible_api::vm_lifecycle::ProductionVmLifecycleConfig::new(
            environment_path("CRUCIBLE_PAGING_QEMU"),
            environment_path("CRUCIBLE_PAGING_PLUGIN"),
            environment_path("CRUCIBLE_BYTE_KERNEL"),
            environment_path("CRUCIBLE_PAGING_ROOT"),
            config.lifecycle.run_state_root(),
        )
        .with_root_image_format(crucible_qemu::QemuRootImageFormat::Raw)
        .with_run_ceiling_ticks(50_000_000_000)
        .with_rendezvous_interval_ticks(8_000_000)
        .with_quantum_budget(150_000)
        .with_completion_timeout(Duration::from_secs(10_500)),
    );
    config
}

fn discover_byte_world(run: impl FnOnce(&World, ByteCut)) {
    let source = paging_scenario();
    environment::with_native_repository_environment(
        "byte-discovery",
        35_900,
        |root, storage| super::super::hot_fork_native::native_repository(&source, root, storage),
        byte_config,
        |prepared, config, _repository| {
            run_capture(prepared, config, &source, |context| {
                extend_native_operations(context);
                let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                    .expect("actual ext4 quota");
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    config.lifecycle.clone(),
                    ComposedQemuAttemptResourceGuardFactory::new(host),
                );
                let mut lifecycle = factory
                    .begin_fresh(&source.scenario_def(), &source, context)
                    .expect("real admitted discovery machine");
                let node = source.world().vm_nodes().first().expect("one node");
                let manifest = lifecycle
                    .register_capability_manifest(&node.id)
                    .expect("setup-authenticated CPU manifest");
                let loan = lifecycle
                    .reserve_fault_manifest_metadata(
                        &node.id,
                        faults::discovery::retained_metadata_bound(manifest),
                    )
                    .expect("original node metadata custody");
                let capabilities = faults::discovery::world_capabilities(manifest, node);
                let start = asset_number("CRUCIBLE_BYTE_DELAY_START");
                let end = asset_number("CRUCIBLE_BYTE_DELAY_END");
                assert!(start >= asset_number("CRUCIBLE_BYTE_ENTRY") && end > start);
                let mut configuration = lifecycle
                    .resume_state()
                    .expect("actual scheduler")
                    .into_parts()
                    .0;
                let mut prefix_quanta = 0usize;
                let cut = loop {
                    let observed = lifecycle
                        .paused_cpu(&node.id, 0, None)
                        .expect("read-only genuine paused CPU");
                    if (start..end).contains(&observed.pc) {
                        break observed;
                    }
                    context
                        .charge_execution_quantum()
                        .expect("bounded discovery quantum allowance");
                    prefix_quanta = prefix_quanta
                        .checked_add(1)
                        .expect("bounded discovery quantum count");
                    configuration = QemuFreshAttemptLifecycleOwner::drive_quantum(
                        &mut lifecycle,
                        QuantumRequest {
                            configuration,
                            control: Vec::new(),
                        },
                    )
                    .expect("unchanged guest execution")
                    .configuration;
                };
                let repeated = lifecycle
                    .paused_cpu(&node.id, 0, Some(cut.generation))
                    .expect("unchanged retained pause generation");
                assert_eq!(cut, repeated);
                assert!(
                    lifecycle
                        .paused_cpu(&node.id, u32::MAX, Some(cut.generation))
                        .is_err()
                );
                assert!(
                    lifecycle
                        .paused_cpu(&node.id, 0, Some(cut.generation - 1))
                        .is_err()
                );
                assert_eq!(
                    cut,
                    lifecycle
                        .paused_cpu(&node.id, 0, Some(cut.generation))
                        .expect("refusals leave execution and scope unchanged")
                );
                let ticks = boundary(&mut lifecycle).frontier.ticks;
                let proof = ByteCut {
                    pc: cut.pc,
                    raw: cut.absolute_icount,
                    ticks,
                    prefix_quanta,
                };
                let world = source
                    .world()
                    .clone()
                    .with_fault_topology(WorldFaultTopology {
                        node_capabilities: vec![capabilities],
                        ..WorldFaultTopology::default()
                    })
                    .expect("authenticated actual CPU topology");
                println!("byte_service_ready_absolute_icount={}", cut.absolute_icount);
                println!("byte_service_ready_pc={}", cut.pc);
                run(&world, proof);
                drop(world);
                drop(loan);
                lifecycle
                    .shutdown()
                    .expect("discovery cleanup after all metadata borrowers");
                Ok(())
            })
            .expect("real discovery Service");
        },
    );
}

fn service_plan(target_address: u64, active_ticks: u64) -> Plan {
    service_plan_for_access(target_address, active_ticks, ByteAccess::Load)
}

fn service_plan_for_access(target_address: u64, active_ticks: u64, access: ByteAccess) -> Plan {
    let random = SignalId::parse("latency-key").expect("signal ID");
    let duration = SignalId::parse("latency-duration").expect("signal ID");
    let gate = SignalId::parse("actual-byte-ready").expect("signal ID");
    let gated = SignalId::parse("admitted-latency-key").expect("signal ID");
    let program = SignalProgram::new(
        vec![
            SignalNode {
                id: random.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::I64, SignalUnit::Dimensionless, 0)
                    .expect("integer shape"),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::UniformInteger {
                    minimum: 1,
                    maximum: 256,
                    key_domain: StochasticKeyDomain::Coordinate,
                    opportunity_filter: None,
                }),
            },
            SignalNode {
                id: gate.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::I64, SignalUnit::Dimensionless, 0)
                    .expect("exact admission gate"),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::Step {
                    points: vec![SignalPoint {
                        coordinate: SignalCoordinate::VirtualTime {
                            ticks: active_ticks,
                        },
                        sequence: 0,
                        value: SignalValue::I64(256),
                    }],
                    before: SignalBoundaryBehavior::Constant(SignalValue::I64(0)),
                }),
            },
            SignalNode {
                id: gated.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(SignalValueType::I64, SignalUnit::Dimensionless, 0)
                    .expect("gated random key"),
                inputs: vec![random, gate],
                kind: SignalNodeKind::Pure(PureSignalSpecification::Simple {
                    operator: PureSignalOperator::Min,
                    overflow: SignalOverflow::Error,
                }),
            },
            SignalNode {
                id: duration.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(
                    SignalValueType::DurationNanos,
                    SignalUnit::VirtualNanoseconds,
                    0,
                )
                .expect("duration shape"),
                inputs: vec![gated],
                kind: SignalNodeKind::Pure(PureSignalSpecification::LookupStep {
                    points: (1..=256)
                        .map(|n| (SignalValue::I64(n), SignalValue::DurationNanos(n as u64)))
                        .collect(),
                    before: SignalBoundaryBehavior::Inactive,
                    after: SignalBoundaryBehavior::Hold,
                }),
            },
        ],
        vec![duration.clone()],
        SignalResourceLimits::default(),
    )
    .expect("seeded exact duration program");
    let target = TargetSelector::Exact(
        ResolvedTargetSet::new(
            vec![ResolvedFaultTarget::MemoryRange {
                node: FaultObjectId::parse("memory").expect("actual node"),
                address_space: FaultObjectId::parse("gva").expect("GVA"),
                guest_address: target_address,
                vcpu: Some(0),
                length_bytes: 1,
            }],
            false,
        )
        .expect("one byte target"),
    );
    let binding = FaultBinding::new(
        FaultObjectId::parse(access.binding()).expect("binding"),
        vec![duration],
        BindingSampling::AtBoundary,
        BindingMapping::MapParameter {
            parameter: MappedEffectParameter::DurationNanos,
        },
        target,
        [access.phase()].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Node(NodeEffectSpecification::MemoryService {
                latency_picoseconds: 1,
                bandwidth_bytes_per_second: None,
                operations_per_second: None,
                sharing_scope: MemoryServiceScope::Range,
            }),
        )
        .expect("native byte service"),
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .expect("actual mapped duration");
    Plan::empty()
        .with_fault_signals(
            FaultSignalPlan::new(vec![program], vec![binding], FaultResourceLimits::default())
                .expect("one bounded active service rule"),
        )
        .expect("canonical byte-service plan")
}

fn run_service_lane(
    source: &ScenarioDefForm,
    lane: &str,
    project: u32,
    cold: bool,
    cut: ByteCut,
    access: ByteAccess,
) -> ServiceLane {
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(source, root, storage),
        |config| byte_config(fork_resources(config)),
        |prepared, config, repository| {
            let (_promoted, mut worker) = promote_accepted_checkpoint_with_model(
                prepared,
                config,
                repository,
                source,
                |_host, store| ServiceModel {
                    store,
                    config: config.clone(),
                    prepared,
                    cold,
                    cut,
                    access,
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

struct ServiceModel<'a> {
    store: CampaignExecutorStore,
    config: PackagedQemuExecutorConfig,
    prepared: &'a PackagedPreparation,
    cold: bool,
    cut: ByteCut,
    access: ByteAccess,
    lane: Option<ServiceLane>,
}

impl AttemptExecutionModel for ServiceModel<'_> {
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
        let world_node = source
            .world()
            .vm_nodes()
            .first()
            .expect("one byte-service CPU");
        let registry = &self.prepared.host_operational_registry;
        let target = discover_target(registry, context);
        let initial = status(registry, target);
        let mut configuration = lifecycle
            .resume_state()
            .expect("initial scheduler")
            .into_parts()
            .0;
        let mut boundaries = Vec::with_capacity(SERVICE_QUANTA);

        for ordinal in 0..self.cut.prefix_quanta + SERVICE_QUANTA {
            if ordinal == self.cut.prefix_quanta {
                let observed = lifecycle
                    .paused_cpu(&world_node.id, 0, None)
                    .expect("replayed genuine delay-loop cut");
                assert_eq!(observed.pc, self.cut.pc);
                assert_eq!(observed.absolute_icount, self.cut.raw);
                assert_eq!(boundary(&mut lifecycle).frontier.ticks, self.cut.ticks);
                let prefix = lifecycle.fault_evidence_snapshot().expect("prefix effects");
                assert!(prefix.memory_service_occurrence.is_none());
                assert!(
                    prefix
                        .resolved_effect_trace
                        .as_ref()
                        .is_none_or(|trace| trace
                            .work_items
                            .iter()
                            .flat_map(|work| &work.records)
                            .all(|record| record.effect != EffectKind::MemoryService)),
                    "no service rule is authored before the discovered execution cut"
                );
            }
            if self.cold && ordinal >= self.cut.prefix_quanta {
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
            if ordinal >= self.cut.prefix_quanta {
                let faults = lifecycle
                    .fault_evidence_snapshot()
                    .expect("actual fault ledger");
                boundaries.push(ServiceBoundary {
                    logical: boundary(&mut lifecycle),
                    resolved: faults.resolved_effect_trace,
                    locked: faults.locked_effect_trace,
                    occurrence: faults.memory_service_occurrence,
                });
            }
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
        let occurrence = boundaries
            .iter()
            .filter_map(|boundary| boundary.occurrence)
            .next_back()
            .expect("actual supported byte service occurrence");
        let actual_accesses: std::collections::BTreeSet<_> = boundaries
            .iter()
            .filter_map(|boundary| boundary.occurrence)
            .map(|observed| (observed.event_sequence, observed.evidence_hash))
            .collect();
        assert_eq!(
            actual_accesses.len(),
            1,
            "unchanged guest has one observed admitted target access identity"
        );
        assert_service_occurrence(&trace, &occurrence);
        let latency = occurrence.configured_latency_ticks;
        let capture = lifecycle
            .capture_attempt_checkpoint(context)
            .expect("real coherent paged RAM checkpoint");
        let capture = capture.into_closure();
        let backing = &capture.ram_sources()[0];
        let stored_result = if self.access == ByteAccess::Store {
            assert_eq!(world_node.arch, crucible::VmArchitecture::X86_64);
            assert_eq!(world_node.memory_mib, 64);
            assert_eq!(world_node.smp_vcpus, 1);
            assert_eq!(backing.node(), &world_node.id);
            Some(assert_captured_store_result(
                backing,
                context,
                self.access.target(),
            ))
        } else {
            None
        };
        let ram_record = backing.root().record().encode();
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
        self.lane = Some(ServiceLane {
            boundaries,
            ram_record,
            activity,
            latency,
            stored_result,
        });
        Ok(AttemptExecutionProduct::exact_checkpoint(staged))
    }
}

// This fixture's unchanged pc-q35 launch maps low guest physical RAM to offset
// zero of pc.ram, and the guest's first 2 MiB are identity mapped. This is a
// source-bound profile assertion, not a mapping inferred from portable topology.
fn assert_captured_store_result(
    backing: &crucible_api::vm_lifecycle::ProductionPagedRamSource,
    context: &AttemptExecutionContext,
    address: u64,
) -> u8 {
    use crucible_linux_resource::host_supervision::{HostOperationState, HostSupervisionError};
    use crucible_qemu::ram_source::{QemuRamBacking, QemuRamReadBoundaryError};

    assert!((0x100000..0x200000 - 16).contains(&address));
    let record = backing.root().record();
    assert_eq!(record.scope(), crucible_ram::Scope::Exact);
    let region = record
        .topology()
        .region("pc.ram")
        .expect("fixed realized low RAM owner");
    assert_eq!(region.class(), crucible_ram::RegionClass::MutableMain);
    assert_eq!(region.logical_length(), 64 << 20);
    let page_size = u64::from(crucible_ram::LOGICAL_PAGE_SIZE);
    let page = address / page_size;
    let offset = usize::try_from(address % page_size).expect("one page offset");
    assert!(offset + 16 <= page_size as usize);

    let supervisor = context
        .host_operation_supervisor()
        .expect("same original outer cap");
    let mut boundary = || {
        let cap = supervisor.outer_cap_status()?;
        if cap.state != HostOperationState::Running {
            return Err(QemuRamReadBoundaryError::Supervision(
                HostSupervisionError::Terminal { state: cap.state },
            ));
        }
        Ok(())
    };
    let mut result = None;
    backing
        .with_page_response("pc.ram", page, &mut boundary, &mut |response, boundary| {
            boundary().expect("original cap before result consumption");
            assert!(result.is_none(), "one authenticated page completion");
            assert_eq!(response.proof().region_id(), "pc.ram");
            assert_eq!(response.proof().page_index(), page);
            response
                .proof()
                .verify(response.bytes(), record, record.digest())
                .expect("actual bytes under retained captured root");
            assert_eq!(response.bytes()[offset], 0x5a);
            assert_eq!(&response.bytes()[offset + 1..offset + 16], &[0; 15]);
            result = Some(response.bytes()[offset]);
            boundary().expect("original cap after result consumption");
        })
        .expect("saved original pays and retains page/proof until callback returns");
    boundary().expect("original cap after captured result read");
    result.expect("one actual result completion")
}

fn assert_service_occurrence(trace: &ResolvedEffectTrace, observed: &QemuMemoryServiceOccurrence) {
    let action = trace
        .work_items
        .iter()
        .flat_map(|work| work.records.iter().map(move |record| (work, record)))
        .find_map(|(work, record)| {
            let mut action = record.locked_action();
            action.coordinate = work.coordinate;
            action.expected_precondition = None;
            (action.id().bytes == observed.action_hash).then_some(action)
        })
        .expect("native ledger binds the genuinely issued action");
    let ResolvedMappingOutput::Parameter {
        parameter: MappedEffectParameter::DurationNanos,
        value: SignalValue::DurationNanos(nanos),
    } = action.mapping_output.as_ref()
    else {
        panic!("real seeded duration");
    };
    assert_eq!(
        observed.configured_latency_ticks,
        nanos
            .checked_mul(crucible::model::SIM_TICKS_PER_NS)
            .expect("bounded picosecond conversion")
    );
    assert_eq!(
        observed.fixed_latency_ticks,
        observed.configured_latency_ticks
    );
    assert_eq!(observed.demand_ticks, 0);
    assert_eq!(observed.ready_before_ticks, 0);
    assert_eq!(observed.queue_delay_ticks, 0);
    assert_eq!(observed.bytes_per_second, 0);
    assert_eq!(observed.operations_per_second, 0);
    assert_eq!(observed.rate_flags, 0);
    assert_eq!(
        observed.completion_delay_ticks,
        observed.fixed_latency_ticks + observed.queue_delay_ticks
    );
    assert!(observed.ready_after_ticks > 0);
    assert!(observed.completion_delay_ticks > 0);
}

#[test]
fn byte_service_plan_declares_only_one_load_byte_and_seeded_duration() {
    let plan = service_plan(0x102000, 100_000);
    assert_eq!(plan.fault_signals().bindings().len(), 1);
    let binding = &plan.fault_signals().bindings()[0];
    assert_eq!(binding.effect().kind(), EffectKind::MemoryService);
    let scenario = paging_scenario();
    assert!(
        ScenarioDefForm::from_components(
            scenario.world(),
            &plan,
            &Properties::empty(),
            Seed::from_u64(7)
        )
        .is_err(),
        "real manifest declaration remains mandatory"
    );
}

#[test]
fn byte_service_duration_is_inactive_before_the_discovered_cut() {
    let plan = service_plan(0x102000, 100_000);
    let store = crucible::MemoryDagStore::new();
    let provider = DagSignalArtifactProvider::new(&store);
    let program = &plan.fault_signals().programs()[0];
    let mut evaluator = SignalEvaluator::new(
        program,
        &provider,
        SignalBoundarySnapshot::default(),
        FaultResourceLimits::default(),
    )
    .expect("real admitted evaluator");
    let mut request = SignalEvaluationRequest {
        output: SignalId::parse("latency-duration").expect("actual export"),
        coordinate: SignalCoordinate::VirtualTime { ticks: 99_999 },
        same_coordinate_sequence: 0,
        choice: SignalChoiceContext {
            scenario_seed: ContentHash::from_bytes(b"seed-7"),
            consumer: FaultObjectId::parse("byte-load-latency").expect("actual binding"),
            opportunity: None,
            transition_sequence: None,
        },
    };
    assert_eq!(
        evaluator.evaluate(&request).expect("unchanged boot prefix"),
        EvaluatedSignal::Inactive
    );
    request.coordinate = SignalCoordinate::VirtualTime { ticks: 100_000 };
    let EvaluatedSignal::Value(SignalValue::DurationNanos(duration)) = evaluator
        .evaluate(&request)
        .expect("genuine seeded duration at the cut")
    else {
        panic!("duration must become active at the actual cut");
    };
    assert!((1..=256).contains(&duration));
}

#[test]
fn byte_store_service_plan_selects_result_store_without_load_rule() {
    let plan = service_plan_for_access(0x102100, 100_000, ByteAccess::Store);
    let bindings = plan.fault_signals().bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].id(),
        &FaultObjectId::parse("byte-store-latency").expect("static Store binding")
    );
    assert_eq!(
        bindings[0].phases(),
        &[FaultPhase::Store].into_iter().collect()
    );
    let TargetSelector::Exact(targets) = bindings[0].selector() else {
        panic!("one exact STORE target");
    };
    assert_eq!(
        targets.targets(),
        &[ResolvedFaultTarget::MemoryRange {
            node: FaultObjectId::parse("memory").expect("static node"),
            address_space: FaultObjectId::parse("gva").expect("static address space"),
            guest_address: 0x102100,
            vcpu: Some(0),
            length_bytes: 1,
        }]
    );
}
