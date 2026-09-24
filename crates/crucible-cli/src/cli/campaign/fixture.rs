//! Executable, verifier-backed campaign reference fixtures.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crucible::{
    Action, Aggregation, AssertionDef, AssertionId, BoundarySelector, CohortPolicy,
    ContentAddressedBlobRef, ContentHash, EventGraph, FaultDirection, LinkDef, LinkLossProbability,
    LogLevel, MarkerId, MeasurementDefinition, MeasurementDefinitions, MeasurementId,
    MetricDefinition, MetricId, MetricSource, MetricValueType, ModeledMeasurementTimeout, NodeId,
    NodeTemplate, Plan, Predicate, Properties, ReadyPoint, ScenarioDefForm,
    ScenarioSelectableLimits, ScenarioSelectables, Schedule, Seed, SignalId, SimDuration, UnitId,
    VmArchitecture, WhiteBoxPolicy, World, WorldFaultDomain, WorldFaultTargetRef,
    WorldFaultTopology, WorldNetworkInterface, WorldNetworkPath, WorldNetworkPathHop,
    WorldNetworkSegment, WorldNetworkSegmentKind, WorldNetworkTechnology, WorldNode,
};
use crucible_campaign::{
    AlternativeId, BooleanDomain, CampaignHash, CampaignLineage, CampaignMode, CampaignPolicy,
    CampaignSeed, CandidateGeneratorAlgorithm, CandidateGeneratorSpec, ChoiceClassContext,
    ChoiceDomain, ChoiceGroup, ChoiceGroupApplication, ChoiceGroupDomain, ChoicePolicy,
    ChoiceSource, ChoiceTuple, ChoiceValue, DiscreteAlternative, DiscreteDomain, ExactRational,
    ExplorerPolicy, FairnessPolicy, GuidanceWeight, IntegerDomain, IntegerRepresentation,
    IntegerValue, Objective, ObjectiveGoal, ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
    SelectableDeclaration,
};
use crucible_core::NetworkFaultSelectable;
use crucible_daemon::{encode_crucible_configuration_artifact, encode_crucible_scenario_artifact};
use serde::Serialize;

#[path = "fixture/topology.rs"]
mod topology;

use topology::worked_network_world;

const FIXTURE_REPORT_SCHEMA: &str = "crucible.cli.campaign-fixture.v1";
const WORKED_NETWORK_SEED: u64 = 802_750_664_550_812_378;
// Fault domains disrupt the competing routes while leaving traffic endpoints reachable.
const WORKED_NETWORK_LINKS: [(&str, &str, Option<&str>); 5] = [
    ("router-a", "traffic-west", None),
    ("router-a", "router-b", Some("primary")),
    ("router-b", "router-c", Some("primary")),
    ("router-a", "router-c", Some("backup")),
    ("router-c", "traffic-east", None),
];

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

#[derive(Clone, Copy)]
struct WorkedNetworkBoot {
    kernel: ContentAddressedBlobRef,
    root_image: ContentAddressedBlobRef,
}

pub(super) fn generate_worked_network_fixture(
    output: &Path,
    kernel: Option<&Path>,
    root_image: Option<&Path>,
) -> Result<WorkedNetworkFixtureReport, CliError> {
    let boot = match (kernel, root_image) {
        (None, None) => None,
        (Some(kernel), Some(root_image)) => Some(WorkedNetworkBoot {
            kernel: reference_for_file("kernel", kernel)?,
            root_image: reference_for_file("root image", root_image)?,
        }),
        _ => {
            return Err(fixture_error(
                "kernel and root image must be supplied together",
            ));
        }
    };
    let fixture = worked_network_fixture(boot)?;
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

fn worked_network_fixture(
    boot: Option<WorkedNetworkBoot>,
) -> Result<WorkedNetworkFixture, CliError> {
    let world = worked_network_world(boot)?;
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
    .map_err(|error| fixture_error(format!("build worked-network scenario: {error}")))?
    .with_selectables(worked_network_selectables(&world)?)
    .map_err(|error| fixture_error(format!("attach worked-network choices: {error}")))?;
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
        "reference-qemu-11.1.1",
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

fn worked_network_selectables(world: &World) -> Result<ScenarioSelectables, CliError> {
    let strategies = [
        (0x11, "retain_and_probe"),
        (0x22, "withdraw_then_relearn"),
        (0x33, "restart_adjacency"),
        (0x44, "recompute_all"),
        (0xff, "unsafe_short_circuit"),
    ];
    let alternatives = strategies
        .into_iter()
        .map(|(byte, label)| {
            let id = AlternativeId::from_hash(CampaignHash::from_bytes([byte; 32]));
            DiscreteAlternative::new(id, label, None)
                .map(|alternative| (id, alternative))
                .map_err(|error| fixture_error(format!("build {label} alternative: {error}")))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let strategy = ChoiceDomain::Discrete(
        DiscreteDomain::new(1, alternatives)
            .map_err(|error| fixture_error(format!("build recovery.strategy domain: {error}")))?,
    );
    let scale = ExactRational::new(1, 1)
        .map_err(|error| fixture_error(format!("build recovery choice unit scale: {error}")))?;
    let unsigned_domain = |name: &str, maximum: u64, unit: &str| {
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(maximum),
            1,
            Some(unit.to_owned()),
            scale,
            Vec::new(),
        )
        .map(ChoiceDomain::Integer)
        .map_err(|error| fixture_error(format!("build {name} domain: {error}")))
    };
    let member_declarations = vec![
        guest_recovery_declaration(
            "recovery.strategy",
            strategy,
            ChoiceValue::Discrete(AlternativeId::from_hash(CampaignHash::from_bytes(
                [0x11; 32],
            ))),
        )?,
        guest_recovery_declaration(
            "recovery.hold_down_us",
            unsigned_domain("recovery.hold_down_us", 5_000_000, "us")?,
            ChoiceValue::Integer(IntegerValue::Unsigned(20_000)),
        )?,
        guest_recovery_declaration(
            "recovery.retry_limit",
            unsigned_domain("recovery.retry_limit", 12, "count")?,
            ChoiceValue::Integer(IntegerValue::Unsigned(3)),
        )?,
        guest_recovery_declaration(
            "recovery.fast_reroute",
            ChoiceDomain::Boolean(BooleanDomain::new(1).map_err(|error| {
                fixture_error(format!("build recovery.fast_reroute domain: {error}"))
            })?),
            ChoiceValue::Boolean(true),
        )?,
    ];

    let mut declarations = BTreeMap::new();
    let mut member_domains = BTreeMap::new();
    let mut default_values = BTreeMap::new();
    for declaration in member_declarations {
        let id = declaration
            .id()
            .map_err(|error| fixture_error(format!("address recovery member: {error}")))?;
        member_domains.insert(id, declaration.domain().clone());
        default_values.insert(id, declaration.default().clone());
        declarations.insert(id, declaration);
    }
    let group = ChoiceGroup::new(
        &declarations,
        ChoiceGroupDomain::Cartesian {
            members: member_domains,
            constraints: BTreeSet::new(),
        },
        ChoiceGroupApplication::new("envoy.recovery", 1)
            .map_err(|error| fixture_error(format!("build recovery adapter: {error}")))?,
    )
    .map_err(|error| fixture_error(format!("build recovery group: {error}")))?;
    let default = group
        .select(ChoiceTuple::new(default_values))
        .map(ChoiceValue::Group)
        .map_err(|error| fixture_error(format!("build default recovery tuple: {error}")))?;
    let response = guest_recovery_declaration(
        "recovery.response",
        ChoiceDomain::Group(Box::new(group)),
        default,
    )?;

    let network_fault = NetworkFaultSelectable::declaration()
        .map_err(|error| fixture_error(format!("build network fault group: {error}")))?;
    // Router A registers one guest group twice; the environment owns one
    // separate group opportunity at each verified network phase boundary.
    let limits = ScenarioSelectableLimits::new(1, 2, 2, 2)
        .map_err(|error| fixture_error(format!("bound worked-network choices: {error}")))?;
    ScenarioSelectables::new(world, limits, vec![response, network_fault])
        .map_err(|error| fixture_error(format!("build worked-network catalog: {error}")))
}

fn guest_recovery_declaration(
    name: &str,
    domain: ChoiceDomain,
    default: ChoiceValue,
) -> Result<SelectableDeclaration, CliError> {
    let class_context = ChoiceClassContext::new(BTreeSet::new())
        .map_err(|error| fixture_error(format!("build {name} class context: {error}")))?;
    SelectableDeclaration::new(
        name,
        ChoiceSource::Guest {
            node: String::from("router-a"),
            protocol_version: u32::from(crucible_api::SELECTABLE_PROTOCOL_VERSION),
        },
        domain,
        default,
        class_context,
        BTreeSet::new(),
        true,
    )
    .map_err(|error| fixture_error(format!("build {name} declaration: {error}")))
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
        "network.failover.observed",
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
    let group = CandidateGeneratorSpec::new(
        crucible_campaign::GROUP_PROGRESSIVE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::GroupProgressive {
            maximum_proposals: 4_096,
        },
    )
    .map_err(|error| fixture_error(format!("build group-progressive generator: {error}")))?;
    Ok(vec![("group-progressive", group)])
}

fn worked_network_policy(
    scenario: &ScenarioDefForm,
    generators: &[(&'static str, CandidateGeneratorSpec)],
) -> Result<CampaignPolicy, CliError> {
    let group = named_generator_id(generators, "group-progressive")?;
    let mut choices = BTreeMap::new();
    choices.insert(
        String::from("recovery.response"),
        ChoicePolicy::new("recovery.response", group, true)
            .map_err(|error| fixture_error(format!("build recovery group policy: {error}")))?,
    );
    choices.insert(
        String::from("fault.network"),
        ChoicePolicy::new("fault.network", group, true)
            .map_err(|error| fixture_error(format!("build network fault group policy: {error}")))?,
    );
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
        CampaignPolicy::identity(
            encode_crucible_scenario_artifact(scenario)
                .map_err(|error| {
                    fixture_error(format!("encode policy scenario artifact: {error}"))
                })?
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
                        ExactRational::new(1, 2).map_err(|error| {
                            fixture_error(format!("build widening alpha: {error}"))
                        })?,
                        4,
                        4_096,
                        1,
                    )
                    .map_err(|error| fixture_error(format!("build widening policy: {error}")))?,
                ),
            },
        ),
        CampaignPolicy::rules(
            choices,
            objectives,
            BTreeMap::from([(String::from("coverage"), guidance)]),
            BTreeSet::from([String::from("campaign.complete")]),
            FairnessPolicy::new(10, 32)
                .map_err(|error| fixture_error(format!("build fairness policy: {error}")))?,
            RetentionPolicy::new(true, 128, true, true),
            true,
        ),
    )
    .map_err(|error| fixture_error(format!("build campaign policy: {error}")))
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

fn reference_for_file(label: &str, path: &Path) -> Result<ContentAddressedBlobRef, CliError> {
    let file = File::open(path)
        .map_err(|error| fixture_error(format!("open {label} {}: {error}", path.display())))?;
    if !file
        .metadata()
        .map_err(|error| fixture_error(format!("inspect {label} {}: {error}", path.display())))?
        .is_file()
    {
        return Err(fixture_error(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    let hash = ContentHash::from_reader(file)
        .map_err(|error| fixture_error(format!("hash {label} {}: {error}", path.display())))?;
    Ok(ContentAddressedBlobRef::from_hash(hash))
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
#[path = "fixture/tests.rs"]
mod tests;
