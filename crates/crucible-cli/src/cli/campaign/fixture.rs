//! Executable, verifier-backed campaign reference fixtures.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crucible::{
    Action, Aggregation, AssertionDef, AssertionId, BoundarySelector, CohortPolicy, EventGraph,
    LinkDef, LinkLossProbability, LogLevel, MarkerId, MeasurementDefinition,
    MeasurementDefinitions, MeasurementId, MetricDefinition, MetricId, MetricSource,
    MetricValueType, ModeledMeasurementTimeout, NodeId, NodeTemplate, Plan, Predicate, Properties,
    ReadyPoint, ScenarioDefForm, Schedule, Seed, SimDuration, UnitId, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::{
    CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, ChoicePolicy, ExactRational, ExplorerPolicy, FairnessPolicy,
    GuidanceWeight, Objective, ObjectiveGoal, ProgressiveWideningPolicy, PuctPolicy,
    RetentionPolicy, WeightedGenerator,
};
use crucible_daemon::{encode_crucible_configuration_artifact, encode_crucible_scenario_artifact};
use serde::Serialize;

const FIXTURE_REPORT_SCHEMA: &str = "crucible.cli.campaign-fixture.v1";
const WORKED_NETWORK_SEED: u64 = 802_750_664_550_812_378;

#[derive(Serialize)]
pub(super) struct WorkedNetworkFixtureReport {
    schema: &'static str,
    directory: PathBuf,
    manifest: PathBuf,
    lineage: PathBuf,
    policy: PathBuf,
    scenario: String,
    configuration: String,
    generators: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct CampaignImportManifest<'a> {
    schema: &'static str,
    version: u32,
    configuration: Vec<CampaignImportConfiguration<'a>>,
    generator: Vec<CampaignImportGenerator<'a>>,
}

#[derive(Serialize)]
struct CampaignImportConfiguration<'a> {
    scenario: &'a Path,
    schedule: &'a Path,
}

#[derive(Serialize)]
struct CampaignImportGenerator<'a> {
    specification: &'a Path,
}

struct WorkedNetworkFixture {
    scenario: ScenarioDefForm,
    schedule: Schedule,
    lineage: CampaignLineage,
    policy: CampaignPolicy,
    generators: Vec<(&'static str, CandidateGeneratorSpec)>,
}

pub(super) fn generate_worked_network_fixture(
    output: &Path,
) -> Result<WorkedNetworkFixtureReport, CliError> {
    let fixture = worked_network_fixture()?;
    let output = absolute_output_path(output)?;
    create_fixture_directory(&output)?;

    let scenario_path = output.join("scenario.bin");
    let schedule_path = output.join("schedule.bin");
    let lineage_path = output.join("lineage.bin");
    let policy_path = output.join("policy.bin");
    let manifest_path = output.join("import.toml");
    write_fixture_file(&scenario_path, &fixture.scenario.to_compact_binary())?;
    write_fixture_file(&schedule_path, &fixture.schedule.to_compact_binary())?;
    write_fixture_file(&lineage_path, &fixture.lineage.canonical_bytes())?;
    write_fixture_file(&policy_path, &fixture.policy.canonical_bytes())?;

    let mut generator_paths = Vec::with_capacity(fixture.generators.len());
    let mut generator_ids = BTreeMap::new();
    for (name, generator) in &fixture.generators {
        let path = output.join(format!("generator-{name}.bin"));
        write_fixture_file(&path, &generator.canonical_bytes())?;
        let id = generator
            .id()
            .map_err(|error| fixture_error(format!("address {name} generator: {error}")))?;
        generator_paths.push(path);
        generator_ids.insert((*name).to_owned(), id.to_string());
    }

    let manifest = CampaignImportManifest {
        schema: "crucible.campaign-import",
        version: 1,
        configuration: vec![CampaignImportConfiguration {
            scenario: &scenario_path,
            schedule: &schedule_path,
        }],
        generator: generator_paths
            .iter()
            .map(|path| CampaignImportGenerator {
                specification: path,
            })
            .collect(),
    };
    let manifest = toml::to_string(&manifest)
        .map_err(|error| fixture_error(format!("encode import manifest: {error}")))?;
    write_fixture_file(&manifest_path, manifest.as_bytes())?;

    let validation = validate_campaign_import_manifests(std::slice::from_ref(&manifest_path))?;
    if validation.configurations().len() != 1
        || validation.generators().len() != fixture.generators.len()
    {
        return Err(fixture_error(
            "generated import manifest did not validate its complete fixture closure",
        ));
    }

    let scenario_artifact = encode_crucible_scenario_artifact(&fixture.scenario)
        .map_err(|error| fixture_error(format!("encode scenario artifact: {error}")))?;
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &fixture.schedule)
            .map_err(|error| fixture_error(format!("encode configuration artifact: {error}")))?;
    Ok(WorkedNetworkFixtureReport {
        schema: FIXTURE_REPORT_SCHEMA,
        directory: output,
        manifest: manifest_path,
        lineage: lineage_path,
        policy: policy_path,
        scenario: scenario_artifact
            .id()
            .map_err(|error| fixture_error(format!("address scenario artifact: {error}")))?
            .to_string(),
        configuration: configuration_artifact
            .id()
            .map_err(|error| fixture_error(format!("address configuration artifact: {error}")))?
            .to_string(),
        generators: generator_ids,
    })
}

pub(super) fn render_worked_network_fixture(
    report: &WorkedNetworkFixtureReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| fixture_error(format!("encode fixture JSON: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| fixture_error(format!("encode fixture JSON: {error}"))),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<16} {}", "directory", report.directory.display()),
                format!("{:<16} {}", "manifest", report.manifest.display()),
                format!("{:<16} {}", "lineage", report.lineage.display()),
                format!("{:<16} {}", "policy", report.policy.display()),
                format!("{:<16} {}", "scenario", report.scenario),
                format!("{:<16} {}", "configuration", report.configuration),
            ];
            lines.extend(
                report
                    .generators
                    .iter()
                    .map(|(name, id)| format!("{:<16} {name} {id}", "generator")),
            );
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| Fixture field | Value |"),
                String::from("| --- | --- |"),
                format!("| directory | `{}` |", report.directory.display()),
                format!("| manifest | `{}` |", report.manifest.display()),
                format!("| lineage | `{}` |", report.lineage.display()),
                format!("| policy | `{}` |", report.policy.display()),
                format!("| scenario | `{}` |", report.scenario),
                format!("| configuration | `{}` |", report.configuration),
            ];
            lines.extend(
                report
                    .generators
                    .iter()
                    .map(|(name, id)| format!("| generator `{name}` | `{id}` |")),
            );
            Ok(lines.join("\n"))
        }
    }
}

fn worked_network_fixture() -> Result<WorkedNetworkFixture, CliError> {
    let world = worked_network_world()?;
    let properties = worked_network_properties(&world)?;
    let plan = worked_network_plan(&world, &properties)?;
    let measurements = worked_network_measurements(&world, &plan, &properties)?;
    let scenario = ScenarioDefForm::from_components_with_measurements(
        &world,
        &plan,
        &properties,
        &measurements,
        Seed::from_u64(WORKED_NETWORK_SEED),
    )
    .map_err(|error| fixture_error(format!("build worked-network scenario: {error}")))?;
    let schedule = Schedule::empty();
    let generators = worked_network_generators()?;
    let policy = worked_network_policy(&scenario, &generators)?;

    let scenario_artifact = encode_crucible_scenario_artifact(&scenario)
        .map_err(|error| fixture_error(format!("encode scenario artifact: {error}")))?;
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
            .map_err(|error| fixture_error(format!("encode configuration artifact: {error}")))?;
    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_artifact
            .id()
            .map_err(|error| fixture_error(format!("address scenario artifact: {error}")))?,
        configuration_artifact.configuration(),
        configuration_artifact
            .id()
            .map_err(|error| fixture_error(format!("address configuration artifact: {error}")))?,
        env!("CARGO_PKG_VERSION"),
        "reference-qemu-10.0.2",
        BTreeMap::from([
            (String::from("control"), 1),
            (String::from("shared-memory"), 1),
        ]),
        scenario_artifact.payload_schema(),
        crucible_daemon::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    )
    .map_err(|error| fixture_error(format!("build campaign lineage: {error}")))?;
    Ok(WorkedNetworkFixture {
        scenario,
        schedule,
        lineage,
        policy,
        generators,
    })
}

fn worked_network_world() -> Result<World, CliError> {
    let nodes = [
        ("router-a", "router"),
        ("router-b", "router"),
        ("router-c", "router"),
        ("traffic-west", "endpoint"),
        ("traffic-east", "endpoint"),
    ]
    .into_iter()
    .map(|(name, role)| WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: format!("console=ttyS0 quiet network.role={role} network.fixture=worked-recovery"),
        ready_point: ReadyPoint::AgentSignal,
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: 7,
        kernel: None,
        root_image: None,
        initrd: None,
    })
    .collect::<Vec<_>>();
    let links = [
        ("traffic-west", "router-a"),
        ("router-a", "router-b"),
        ("router-b", "router-c"),
        ("router-a", "router-c"),
        ("router-c", "traffic-east"),
    ]
    .into_iter()
    .map(|(left, right)| {
        LinkDef::with_transport(
            node(left),
            node(right),
            SimDuration { nanos: 1_000_000 },
            SimDuration { nanos: 100_000 },
            LinkLossProbability::ZERO,
            Some(10_000_000_000),
        )
        .map_err(|error| fixture_error(format!("build {left}-{right} link: {error}")))
    })
    .collect::<Result<Vec<_>, _>>()?;
    World::from_nodes_and_links(nodes, links)
        .map_err(|error| fixture_error(format!("build worked-network world: {error}")))
}

fn worked_network_properties(world: &World) -> Result<Properties, CliError> {
    Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef::guest_unreachable(
                AssertionId::from_name("persistent-forwarding-loop"),
                "no persistent forwarding loop may be observed",
            ),
            AssertionDef::guest_unreachable(
                AssertionId::from_name("forbidden-destination-delivery"),
                "traffic must not reach a forbidden destination",
            ),
            AssertionDef::guest_unreachable(
                AssertionId::from_name("control-plane-crash-or-deadlock"),
                "control-plane processes must not crash or deadlock",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("bounded-recovery-outcome"),
                "the product converges or declares a bounded terminal failure",
            ),
            AssertionDef::guest_sometimes(
                AssertionId::from_name("selection-acknowledged-once"),
                "every delivered selection is acknowledged exactly once",
            ),
        ],
    )
    .map_err(|error| fixture_error(format!("build worked-network properties: {error}")))
}

fn worked_network_plan(world: &World, properties: &Properties) -> Result<Plan, CliError> {
    let mut graph = EventGraph::builder();
    for boundary in [
        "network.converged",
        "fault.transport.ready",
        "fault.transport.signaled",
        "recovery.measured",
        "fault.followup.ready",
        "campaign.complete",
    ] {
        graph = graph
            .event(boundary)
            .when(Predicate::guest_marker(MarkerId::from_name(boundary)))
            .action(Action::log(
                LogLevel::Info,
                format!("worked-network boundary: {boundary}"),
            ));
    }
    let assertions = properties
        .assertions()
        .iter()
        .map(|assertion| assertion.id.clone())
        .collect::<Vec<_>>();
    let graph = graph
        .build_with_assertions_for_world(assertions.iter().cloned(), world)
        .map_err(|error| fixture_error(format!("build worked-network event graph: {error}")))?;
    Plan::from_event_graph_with_assertions_for_world(world, assertions, graph)
        .map_err(|error| fixture_error(format!("build worked-network plan: {error}")))
}

fn worked_network_measurements(
    world: &World,
    plan: &Plan,
    properties: &Properties,
) -> Result<MeasurementDefinitions, CliError> {
    let routers = [node("router-a"), node("router-b"), node("router-c")];
    let begin = BoundarySelector::GuestMarker {
        marker: MarkerId::from_name("fault.transport.signaled"),
        instance: None,
    };
    let end = BoundarySelector::GuestMarker {
        marker: MarkerId::from_name("recovery.measured"),
        instance: None,
    };
    let timeout = Some(ModeledMeasurementTimeout::VirtualTime {
        nanos: 30_000_000_000,
    });
    let definitions = vec![
        MeasurementDefinition {
            id: measurement_id("recovery_time_us")?,
            begin: begin.clone(),
            end: end.clone(),
            timeout: timeout.clone(),
            cohort: CohortPolicy::All(routers.to_vec()),
            metrics: vec![MetricDefinition {
                id: metric_id("elapsed_virtual_time")?,
                value_type: MetricValueType::UnsignedInteger,
                unit: unit_id("virtual_nanoseconds")?,
                source: MetricSource::VirtualTime,
                aggregation: Aggregation::EventDelta,
            }],
        },
        MeasurementDefinition {
            id: measurement_id("traffic_loss_packets")?,
            begin: begin.clone(),
            end: end.clone(),
            timeout: timeout.clone(),
            cohort: CohortPolicy::All(routers.to_vec()),
            metrics: vec![MetricDefinition {
                id: metric_id("modeled_drop_count")?,
                value_type: MetricValueType::UnsignedInteger,
                unit: unit_id("packets")?,
                source: MetricSource::NetworkModeledDropCount { link: None },
                aggregation: Aggregation::EventDelta,
            }],
        },
        MeasurementDefinition {
            id: measurement_id("control_plane_cpu_us")?,
            begin,
            end,
            timeout,
            cohort: CohortPolicy::All(routers.to_vec()),
            metrics: vec![MetricDefinition {
                id: metric_id("router_a_instruction_work")?,
                value_type: MetricValueType::UnsignedInteger,
                unit: unit_id("instructions")?,
                source: MetricSource::NodeIcount {
                    node: node("router-a"),
                },
                aggregation: Aggregation::EventDelta,
            }],
        },
    ];
    MeasurementDefinitions::new(world, plan, properties, definitions)
        .map_err(|error| fixture_error(format!("build worked-network measurements: {error}")))
}

fn worked_network_generators() -> Result<Vec<(&'static str, CandidateGeneratorSpec)>, CliError> {
    let all = generator("all", CandidateGeneratorAlgorithm::All)?;
    let boundary = generator("boundary", CandidateGeneratorAlgorithm::BoundaryInteger)?;
    let logarithmic = generator(
        "logarithmic",
        CandidateGeneratorAlgorithm::LogInteger { base: 2 },
    )?;
    let progressive = generator(
        "progressive",
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 8,
            feedback_interval: 16,
        },
    )?;
    let mixture = generator(
        "integer-mixture",
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![
                WeightedGenerator::new(generator_id("boundary", &boundary)?, 4).map_err(
                    |error| fixture_error(format!("weight boundary generator: {error}")),
                )?,
                WeightedGenerator::new(generator_id("logarithmic", &logarithmic)?, 2)
                    .map_err(|error| fixture_error(format!("weight log generator: {error}")))?,
                WeightedGenerator::new(generator_id("progressive", &progressive)?, 3).map_err(
                    |error| fixture_error(format!("weight progressive generator: {error}")),
                )?,
            ],
        },
    )?;
    Ok(vec![
        ("all", all),
        ("boundary", boundary),
        ("logarithmic", logarithmic),
        ("progressive", progressive),
        ("integer-mixture", mixture),
    ])
}

fn worked_network_policy(
    scenario: &ScenarioDefForm,
    generators: &[(&'static str, CandidateGeneratorSpec)],
) -> Result<CampaignPolicy, CliError> {
    let all = named_generator_id(generators, "all")?;
    let integer = named_generator_id(generators, "integer-mixture")?;
    let mut choices = BTreeMap::new();
    for selector in [
        "recovery.strategy",
        "recovery.fast_reroute",
        "fault.kind",
        "fault.affected_path",
    ] {
        choices.insert(
            selector.to_owned(),
            ChoicePolicy::new(selector, all, true)
                .map_err(|error| fixture_error(format!("build {selector} policy: {error}")))?,
        );
    }
    for selector in [
        "recovery.hold_down_us",
        "recovery.retry_limit",
        "fault.loss_bps",
        "fault.latency_us",
        "fault.duration_us",
    ] {
        choices.insert(
            selector.to_owned(),
            ChoicePolicy::new(selector, integer, true)
                .map_err(|error| fixture_error(format!("build {selector} policy: {error}")))?,
        );
    }
    let objectives = [
        "recovery_time_us",
        "traffic_loss_packets",
        "control_plane_cpu_us",
    ]
    .into_iter()
    .map(|measurement| {
        Objective::new(measurement, ObjectiveGoal::Minimize, 1_000_000)
            .map(|objective| (measurement.to_owned(), objective))
            .map_err(|error| fixture_error(format!("build {measurement} objective: {error}")))
    })
    .collect::<Result<BTreeMap<_, _>, _>>()?;
    let guidance = GuidanceWeight::new("coverage", 250_000)
        .map_err(|error| fixture_error(format!("build coverage guidance: {error}")))?;
    CampaignPolicy::new(
        encode_crucible_scenario_artifact(scenario)
            .map_err(|error| fixture_error(format!("encode policy scenario artifact: {error}")))?
            .scenario(),
        CampaignSeed::from_bytes(
            WORKED_NETWORK_SEED
                .to_le_bytes()
                .repeat(4)
                .try_into()
                .map_err(|_| {
                    fixture_error("worked-network campaign seed did not contain 32 bytes")
                })?,
        ),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_400_000, 250_000, 100_000),
            widening: Some(
                ProgressiveWideningPolicy::new(
                    ExactRational::new(2, 1)
                        .map_err(|error| fixture_error(format!("build widening k: {error}")))?,
                    ExactRational::new(1, 2)
                        .map_err(|error| fixture_error(format!("build widening alpha: {error}")))?,
                    4,
                    4_096,
                    1,
                )
                .map_err(|error| fixture_error(format!("build widening policy: {error}")))?,
            ),
        },
        choices,
        objectives,
        BTreeMap::from([(String::from("coverage"), guidance)]),
        BTreeSet::from([String::from("campaign.complete")]),
        FairnessPolicy::new(10, 32)
            .map_err(|error| fixture_error(format!("build fairness policy: {error}")))?,
        RetentionPolicy::new(true, 128, true, true),
        true,
    )
    .map_err(|error| fixture_error(format!("build campaign policy: {error}")))
}

fn generator(
    name: &'static str,
    algorithm: CandidateGeneratorAlgorithm,
) -> Result<CandidateGeneratorSpec, CliError> {
    CandidateGeneratorSpec::new(1, algorithm)
        .map_err(|error| fixture_error(format!("build {name} generator: {error}")))
}

fn generator_id(
    name: &'static str,
    generator: &CandidateGeneratorSpec,
) -> Result<crucible_campaign::CandidateGeneratorSpecId, CliError> {
    generator
        .id()
        .map_err(|error| fixture_error(format!("address {name} generator: {error}")))
}

fn named_generator_id(
    generators: &[(&'static str, CandidateGeneratorSpec)],
    name: &'static str,
) -> Result<crucible_campaign::CandidateGeneratorSpecId, CliError> {
    let generator = generators
        .iter()
        .find_map(|(candidate, generator)| (*candidate == name).then_some(generator))
        .ok_or_else(|| fixture_error(format!("fixture has no {name} generator")))?;
    generator_id(name, generator)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn measurement_id(name: &str) -> Result<MeasurementId, CliError> {
    MeasurementId::parse(name)
        .map_err(|error| fixture_error(format!("invalid measurement {name}: {error}")))
}

fn metric_id(name: &str) -> Result<MetricId, CliError> {
    MetricId::parse(name).map_err(|error| fixture_error(format!("invalid metric {name}: {error}")))
}

fn unit_id(name: &str) -> Result<UnitId, CliError> {
    UnitId::parse(name).map_err(|error| fixture_error(format!("invalid unit {name}: {error}")))
}

fn absolute_output_path(output: &Path) -> Result<PathBuf, CliError> {
    if output.is_absolute() {
        Ok(output.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(output))
            .map_err(|error| fixture_error(format!("resolve fixture output directory: {error}")))
    }
}

fn create_fixture_directory(output: &Path) -> Result<(), CliError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(output).map_err(|error| {
        fixture_error(format!(
            "create new fixture directory {}: {error}",
            output.display()
        ))
    })
}

fn write_fixture_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            fixture_error(format!("create fixture file {}: {error}", path.display()))
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| fixture_error(format!("write fixture file {}: {error}", path.display())))
}

fn fixture_error(reason: impl Into<String>) -> CliError {
    CliError::Artifact(reason.into())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture tests use exact panic localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use crucible_campaign::{
        CampaignAuthorizationError, CampaignClient, CampaignHash, CampaignName, CampaignPrincipal,
        CampaignPrincipalAuthorizer, CampaignRepository, CampaignServiceOperation,
        CreateCampaignRequest, RepositoryCampaignService,
    };
    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};
    use crucible_daemon::CrucibleCampaignArtifactStore;

    use super::*;

    struct PermitFixture;

    impl CampaignPrincipalAuthorizer for PermitFixture {
        fn authorize(
            &self,
            _principal: &CampaignPrincipal,
            _operation: CampaignServiceOperation,
            _campaign: &CampaignName,
            _request_digest: CampaignHash,
        ) -> Result<(), CampaignAuthorizationError> {
            Ok(())
        }
    }

    #[test]
    fn worked_network_fixture_validates_imports_and_creates_on_a_blank_repository() {
        let temporary = tempfile::tempdir().expect("fixture temporary directory");
        let output = temporary.path().join("worked-network");
        let report = generate_worked_network_fixture(&output).expect("worked-network fixture");
        let validation = validate_campaign_import_manifests(std::slice::from_ref(&report.manifest))
            .expect("strict generated manifest");
        assert_eq!(validation.configurations().len(), 1);
        assert_eq!(validation.generators().len(), 5);

        let scenario = ScenarioDefForm::from_compact_binary(
            &fs::read(output.join("scenario.bin")).expect("scenario bytes"),
        )
        .expect("canonical scenario");
        let schedule = Schedule::from_compact_binary(
            &fs::read(output.join("schedule.bin")).expect("schedule bytes"),
        )
        .expect("canonical schedule");
        assert_eq!(scenario.world().vm_nodes().len(), 5);
        assert_eq!(scenario.world().links().len(), 5);
        assert_eq!(scenario.measurements().definitions().len(), 3);
        assert_eq!(scenario.plan().event_graph().events().len(), 6);
        assert_eq!(scenario.properties().assertions().len(), 5);
        assert!(schedule.is_empty());

        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("worked-network-fixture", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        ));
        let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
        store
            .import_configuration(&scenario, &schedule)
            .expect("import fixture configuration");
        for name in [
            "all",
            "boundary",
            "logarithmic",
            "progressive",
            "integer-mixture",
        ] {
            let generator = CandidateGeneratorSpec::from_canonical_bytes(
                &fs::read(output.join(format!("generator-{name}.bin"))).expect("generator bytes"),
            )
            .expect("canonical generator");
            store
                .import_generator(&generator)
                .expect("import generator");
        }
        let lineage = CampaignLineage::from_canonical_bytes(
            &fs::read(&report.lineage).expect("lineage bytes"),
        )
        .expect("canonical lineage");
        assert_eq!(
            lineage.exact_closure_schema(),
            crucible_daemon::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
        );
        let policy =
            CampaignPolicy::from_canonical_bytes(&fs::read(&report.policy).expect("policy bytes"))
                .expect("canonical policy");
        let request = CreateCampaignRequest::new(
            CampaignPrincipal::new("fixture-operator").expect("principal"),
            CampaignName::new("worked-network").expect("campaign name"),
            lineage,
            policy,
        )
        .expect("creation request");
        let client = CampaignClient::new(RepositoryCampaignService::new(
            repository.as_ref(),
            PermitFixture,
        ));
        let created = client
            .create_campaign(&request)
            .expect("create imported fixture campaign");
        assert!(!created.replayed());
    }

    #[test]
    fn worked_network_fixture_never_overwrites_an_existing_output() {
        let temporary = tempfile::tempdir().expect("fixture temporary directory");
        let output = temporary.path().join("worked-network");
        fs::create_dir(&output).expect("existing output directory");
        assert!(generate_worked_network_fixture(&output).is_err());
        assert_eq!(fs::read_dir(&output).expect("empty output").count(), 0);
    }
}
