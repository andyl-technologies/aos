//! Checks RFC-0010 T-WL-1 in-guest workload model invariants.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use crucible::{
    APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST, EngineError, GuestWorkloadBinary, GuestWorkloadSeed,
    Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioBuilder, ScenarioDefForm, Seed,
    WORKLOAD_ENGINE_ROLE, WORKLOAD_SCENARIO_PARAMETER, WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES,
    WORKLOAD_SEED_REQUIRES_WHITE_BOX, WORKLOAD_SEED_SCENARIO_PARAMETER, WhiteBoxPolicy,
    WorkloadEngineRole, World, WorldNode,
};

#[test]
fn workload_model_declares_supported_in_guest_binaries() {
    let supported = GuestWorkloadBinary::SUPPORTED
        .map(|workload| (workload.display_name(), workload.scenario_parameter_value()));

    assert_eq!(
        supported,
        [
            ("httpd", "httpd"),
            ("client loop", "httpget"),
            ("benchmark", "bench"),
        ]
    );
    assert_eq!(WORKLOAD_SCENARIO_PARAMETER, "crucible.workload");
    const { assert!(APPLICATION_TRAFFIC_ORIGINATES_IN_GUEST) };
    assert_eq!(
        WORKLOAD_ENGINE_ROLE,
        WorkloadEngineRole::ObservationAndSteeringOnly
    );
    assert!(!WORKLOAD_ENGINE_ROLE.originates_application_traffic());
    assert!(!WORKLOAD_ENGINE_ROLE.permits_host_side_traffic_injector());
}

#[test]
fn workload_selection_is_a_scenario_cmdline_parameter() {
    let selected = GuestWorkloadBinary::ClientLoop.selected_cmdline("console=ttyS0 quiet");
    assert_eq!(selected, "console=ttyS0 quiet crucible.workload=httpget");
    assert_eq!(
        GuestWorkloadBinary::from_cmdline(&selected),
        Some(GuestWorkloadBinary::ClientLoop)
    );

    let replaced =
        GuestWorkloadBinary::Benchmark.selected_cmdline("console=ttyS0 crucible.workload=httpget");
    assert_eq!(replaced, "console=ttyS0 crucible.workload=bench");
    assert_eq!(
        GuestWorkloadBinary::from_cmdline(&replaced),
        Some(GuestWorkloadBinary::Benchmark)
    );
}

#[test]
fn workload_selection_changes_scenario_identity() {
    let baseline = scenario_with_workload(None);
    let client_loop = scenario_with_workload(Some(GuestWorkloadBinary::ClientLoop));
    let benchmark = scenario_with_workload(Some(GuestWorkloadBinary::Benchmark));

    assert_ne!(baseline.id(), client_loop.id());
    assert_ne!(client_loop.id(), benchmark.id());
    assert_eq!(baseline.seed(), client_loop.seed());
    assert_eq!(client_loop.seed(), benchmark.seed());
}

#[test]
fn workload_seed_is_plain_content_addressed_cmdline_config() {
    let seed = GuestWorkloadSeed::from_u64(0x1234);
    let selected = seed.selected_cmdline("console=ttyS0 quiet");
    assert_eq!(WORKLOAD_SEED_SCENARIO_PARAMETER, "wseed");
    assert_eq!(
        selected,
        "console=ttyS0 quiet wseed=0x3412000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(GuestWorkloadSeed::from_cmdline(&selected), Some(seed));

    let replaced = GuestWorkloadSeed::from_u64(0x5678).selected_cmdline(&selected);
    assert_eq!(
        replaced,
        "console=ttyS0 quiet wseed=0x7856000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(
        GuestWorkloadSeed::from_cmdline(&replaced),
        Some(GuestWorkloadSeed::from_u64(0x5678))
    );
}

#[test]
fn workload_seed_changes_scenario_identity_without_changing_global_seed() {
    let without_seed = scenario_with_workload_and_seed(Some(GuestWorkloadBinary::ClientLoop), None);
    let seed_a = scenario_with_workload_and_seed(
        Some(GuestWorkloadBinary::ClientLoop),
        Some(GuestWorkloadSeed::from_u64(0x1234)),
    );
    let seed_b = scenario_with_workload_and_seed(
        Some(GuestWorkloadBinary::ClientLoop),
        Some(GuestWorkloadSeed::from_u64(0x5678)),
    );

    assert_ne!(without_seed.id(), seed_a.id());
    assert_ne!(seed_a.id(), seed_b.id());
    assert_eq!(without_seed.seed(), seed_a.seed());
    assert_eq!(seed_a.seed(), seed_b.seed());
}

#[test]
fn workload_seed_black_box_config_path_suffices_without_white_box() {
    const { assert!(WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES) };
    const { assert!(!WORKLOAD_SEED_REQUIRES_WHITE_BOX) };

    let cmdline = GuestWorkloadSeed::from_u64(0x1234)
        .selected_cmdline(&GuestWorkloadBinary::ClientLoop.selected_cmdline("console=ttyS0"));
    let world = World::from_nodes(vec![world_node_with_cmdline(cmdline)])
        .expect("black-box workload seed world should validate");
    let node = world
        .nodes()
        .first()
        .expect("workload seed world should contain one node");

    assert_eq!(node.white_box, WhiteBoxPolicy::Disabled);
    assert_eq!(
        node.guest_workload_seed(),
        Some(GuestWorkloadSeed::from_u64(0x1234))
    );
    ScenarioBuilder::new()
        .world(&world)
        .seed(Seed::from_u64(7))
        .build()
        .expect("black-box workload seed should not require white-box opt-in");
}

#[test]
fn workload_reserved_parameter_rejects_unknown_and_duplicate_values() {
    assert_unsupported_workload(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 crucible.workload=badwork"),
            )
            .seed(Seed::from_u64(7))
            .build(),
        "badwork",
    );

    assert_duplicate_workload(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 crucible.workload=httpget crucible.workload=bench"),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );
}

#[test]
fn workload_seed_rejects_malformed_and_duplicate_values() {
    assert_invalid_workload_seed(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 })
                    .cmdline("console=ttyS0 wseed=0x1234"),
            )
            .seed(Seed::from_u64(7))
            .build(),
        "0x1234",
    );

    assert_duplicate_workload_seed(
        ScenarioBuilder::new()
            .node(
                "client",
                NodeTemplate::fixed_icount(Icount { retired: 1 }).cmdline(
                    "console=ttyS0 wseed=0x3412000000000000000000000000000000000000000000000000000000000000 wseed=0x7856000000000000000000000000000000000000000000000000000000000000",
                ),
            )
            .seed(Seed::from_u64(7))
            .build(),
    );
}

#[test]
fn workload_seed_rejects_malformed_toml_and_binary_forms() {
    let form = valid_workload_seed_form("console=ttyS0");
    let toml = replace_once(
        form.to_canonical_toml()
            .expect("scenario TOML should render"),
        "0x3412000000000000000000000000000000000000000000000000000000000000",
        "0xA412000000000000000000000000000000000000000000000000000000000000",
    );
    assert_invalid_workload_seed(
        ScenarioDefForm::from_canonical_toml(&toml),
        "0xA412000000000000000000000000000000000000000000000000000000000000",
    );

    let bytes = replace_ascii_once(
        form.to_compact_binary(),
        "0x3412000000000000000000000000000000000000000000000000000000000000",
        "0xA412000000000000000000000000000000000000000000000000000000000000",
    );
    assert_invalid_workload_seed(
        ScenarioDefForm::from_compact_binary(&bytes),
        "0xA412000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn workload_reserved_parameter_rejects_malformed_toml_and_binary_forms() {
    let form = valid_workload_form("console=ttyS0");
    let toml = replace_once(
        form.to_canonical_toml()
            .expect("scenario TOML should render"),
        "httpget",
        "badwork",
    );
    assert_unsupported_workload(ScenarioDefForm::from_canonical_toml(&toml), "badwork");

    let bytes = replace_ascii_once(form.to_compact_binary(), "httpget", "badwork");
    assert_unsupported_workload(ScenarioDefForm::from_compact_binary(&bytes), "badwork");

    let duplicate_form = valid_workload_form("console=ttyS0 duplicate-workload-padx");
    let duplicate_toml = replace_once(
        duplicate_form
            .to_canonical_toml()
            .expect("scenario TOML should render"),
        "duplicate-workload-padx",
        "crucible.workload=bench",
    );
    assert_duplicate_workload(ScenarioDefForm::from_canonical_toml(&duplicate_toml));

    let duplicate_bytes = replace_ascii_once(
        duplicate_form.to_compact_binary(),
        "duplicate-workload-padx",
        "crucible.workload=bench",
    );
    assert_duplicate_workload(ScenarioDefForm::from_compact_binary(&duplicate_bytes));
}

#[test]
fn engine_source_has_no_application_traffic_origination_path() {
    let mut engine_sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut engine_sources,
    );
    assert!(!engine_sources.is_empty());

    let forbidden_needles = [
        "struct ApplicationTrafficInjector",
        "enum ApplicationTrafficInjector",
        "struct HostTrafficInjector",
        "enum HostTrafficInjector",
        "struct ApplicationLoadGenerator",
        "enum ApplicationLoadGenerator",
        "struct TrafficGenerator",
        "enum TrafficGenerator",
        "struct WorkloadGenerator",
        "enum WorkloadGenerator",
        "fn originate_application_traffic",
        "fn inject_application_traffic",
        "fn generate_application_traffic",
    ];

    for file in engine_sources {
        let source =
            fs::read_to_string(&file).expect("engine source file should be readable during tests");
        for needle in forbidden_needles {
            assert!(
                !source.contains(needle),
                "{} contains forbidden host-side workload origination API: {needle}",
                file.display()
            );
        }
    }
}

#[test]
fn backend_and_device_delivery_surfaces_are_documented_as_non_originators() {
    let backend = include_str!("../src/backend.rs");
    assert!(backend.contains("not a host-side workload generator"));
    assert!(backend.contains("MUST NOT be used to originate application traffic"));
    assert!(backend.contains("Application workload traffic must originate"));

    let device = include_str!("../src/device.rs");
    assert!(device.contains("already emitted by a modeled guest/device endpoint"));
    assert!(device.contains("not a host-side workload"));
    assert!(device.contains("generator and MUST NOT be used to originate application traffic"));
}

fn collect_rust_sources(root: &Path, sources: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("engine source directory should be readable") {
        let path = entry
            .expect("engine source directory entry should be readable")
            .path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    sources.sort();
}

fn valid_workload_form(base_cmdline: &str) -> ScenarioDefForm {
    let cmdline = GuestWorkloadBinary::ClientLoop.selected_cmdline(base_cmdline);
    let world = World::from_nodes(vec![world_node_with_cmdline(cmdline)])
        .expect("valid workload world should validate");
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
        10,
    )
    .expect("valid workload form should validate")
}

fn valid_workload_seed_form(base_cmdline: &str) -> ScenarioDefForm {
    let cmdline = GuestWorkloadSeed::from_u64(0x1234)
        .selected_cmdline(&GuestWorkloadBinary::ClientLoop.selected_cmdline(base_cmdline));
    let world = World::from_nodes(vec![world_node_with_cmdline(cmdline)])
        .expect("valid workload seed world should validate");
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
        10,
    )
    .expect("valid workload seed form should validate")
}

fn world_node_with_cmdline(cmdline: impl Into<String>) -> WorldNode {
    WorldNode {
        id: crucible::NodeId {
            name: String::from("client"),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: cmdline.into(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn assert_unsupported_workload<T: std::fmt::Debug>(result: Result<T, EngineError>, expected: &str) {
    match result {
        Err(EngineError::WorldNodeUnsupportedWorkload { value, .. }) => {
            assert_eq!(value, expected);
        }
        other => panic!("expected unsupported workload {expected}, got {other:?}"),
    }
}

fn assert_duplicate_workload<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkload { .. }) => {}
        other => panic!("expected duplicate workload rejection, got {other:?}"),
    }
}

fn assert_invalid_workload_seed<T: std::fmt::Debug>(
    result: Result<T, EngineError>,
    expected: &str,
) {
    match result {
        Err(EngineError::WorldNodeInvalidWorkloadSeed { value, .. }) => {
            assert_eq!(value, expected);
        }
        other => panic!("expected invalid workload seed {expected}, got {other:?}"),
    }
}

fn assert_duplicate_workload_seed<T: std::fmt::Debug>(result: Result<T, EngineError>) {
    match result {
        Err(EngineError::WorldNodeDuplicateWorkloadSeed { .. }) => {}
        other => panic!("expected duplicate workload seed rejection, got {other:?}"),
    }
}

fn replace_once(haystack: String, from: &str, to: &str) -> String {
    assert_eq!(from.len(), to.len());
    assert_eq!(haystack.matches(from).count(), 1);
    haystack.replace(from, to)
}

fn replace_ascii_once(mut haystack: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let from = from.as_bytes();
    let to = to.as_bytes();
    let matches = haystack
        .windows(from.len())
        .enumerate()
        .filter_map(|(index, window)| (window == from).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    let start = matches[0];
    haystack[start..start + to.len()].copy_from_slice(to);
    haystack
}

fn scenario_with_workload(workload: Option<GuestWorkloadBinary>) -> crucible::ScenarioDef {
    scenario_with_workload_and_seed(workload, None)
}

fn scenario_with_workload_and_seed(
    workload: Option<GuestWorkloadBinary>,
    workload_seed: Option<GuestWorkloadSeed>,
) -> crucible::ScenarioDef {
    let template = NodeTemplate::fixed_icount(Icount { retired: 1 }).cmdline("console=ttyS0");
    let template = match workload {
        Some(workload) => template.guest_workload(workload),
        None => template,
    };
    let template = match workload_seed {
        Some(seed) => template.guest_workload_seed(seed),
        None => template,
    };
    ScenarioBuilder::new()
        .node("client", template)
        .seed(Seed::from_u64(7))
        .build()
        .expect("workload scenario should validate")
}
