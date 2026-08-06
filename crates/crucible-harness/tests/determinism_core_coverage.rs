//! Checks the RFC-0010 determinism-core coverage floor.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CoverageStatus {
    Active,
    Planned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstrumentationMode {
    SeparateDeterministicBuild,
    SharedTestBuild,
}

#[derive(Clone, Copy, Debug)]
struct CoverageSurface {
    id: &'static str,
    source_path: &'static str,
    test_path: &'static str,
    status: CoverageStatus,
    instrumentation: InstrumentationMode,
    required_test_markers: &'static [&'static str],
    activation_markers: &'static [&'static str],
    activation_source_roots: &'static [&'static str],
}

type SourceOverrides = BTreeMap<&'static str, String>;

const COVERAGE_INSTRUMENTATION_PROFILE: &str = "crucible-determinism-core-coverage";
const COVERAGE_MEASUREMENT_MODE: InstrumentationMode =
    InstrumentationMode::SeparateDeterministicBuild;

const SCHEDULER_QUANTUM_MARKERS: &[&str] = &[
    "quantum_loop_trait_is_object_safe",
    "quantum_outcome_carries_step_decisions",
    "scheduler_errors_render_all_variants_deterministically",
];

const SCHEDULER_ORDERING_MARKERS: &[&str] = &[
    "scheduled_event_keys_define_total_order",
    "scheduled_event_keys_cover_producer_tie_break",
];

const ERROR_VARIANT_MARKERS: &[&str] = &[
    "schedule_prefix_bounds_are_checked",
    "engine_and_backend_errors_render_all_variants_deterministically",
];

const INSTANTIATE_MARKERS: &[&str] = &[
    "instantiate_loads_exact_snapshot_without_genesis",
    "instantiate_replays_from_nearest_cached_ancestor",
    "instantiate_loads_baked_genesis_for_genesis",
    "instantiate_replays_from_baked_genesis_for_uncached_descendant",
    "instantiate_requires_baked_genesis_when_no_cached_path",
    "temporal_graph_rejects_mismatched_or_thin_cached_snapshots",
    "temporal_graph_rejects_plain_cached_genesis_snapshot",
    "temporal_graph_rejects_mismatched_or_thin_baked_genesis",
];

const SIM_BACKEND_ERROR_MARKERS: &[&str] = &[
    "sim_backend_rejects_backward_advance_and_post_shutdown_mutation",
    "sim_backend_rejects_unknown_checkpoint_deterministically",
];

const DIGEST_MARKERS: &[&str] = &[
    "stable_hasher_is_repeatable",
    "stable_hasher_is_order_sensitive",
    "stable_hasher_covers_chunk_remainder_and_bool_inputs",
];

const REPLAY_ORACLE_MARKERS: &[&str] = &[
    "replay_oracle_accepts_matching_corpus",
    "replay_oracle_reports_first_mismatch",
];

const DECISION_RNG_MARKERS: &[&str] = &[
    "decision_recorder_records_rng_draws_and_effect_outcomes",
    "decision_recorder_keeps_per_entity_streams_stable",
    "decision_recorder_records_app_random_after_rng_draw",
    "decision_recorder_records_app_random_guest_request_id",
    "decision_recorder_rejects_invalid_app_random_widths",
    "decision_recorder_resumes_stream_positions_from_existing_schedule",
    "decision_recorder_derives_default_rr_preemption_without_recording_schedule",
    "decision_recorder_records_preemption_overrides_in_schedule",
    "decision_recorder_rejects_invalid_default_preemption_shape",
    "decision_recorder_derives_default_rr_preemption_without_overflow",
    "decision_recorder_serves_app_random_override_without_rerolling_stream",
    "decision_recorder_rejects_invalid_app_random_override_values",
    "assert_decision_rng_branch_coverage(",
    "assert_per_entity_rng_forking_coverage(",
];

const SPSC_RING_MARKERS: &[&str] = &[
    "assert_spsc_ring_exhaustive_ordering_model(",
    "assert_spsc_ring_exhaustive_trace_properties(",
];

const PROTOCOL_CODEC_MARKERS: &[&str] = &[
    "assert_protocol_codec_fuzz_corpus(",
    "assert_decode_encode_roundtrip(",
];

const REPRO_ARTIFACT_MARKERS: &[&str] = &[
    "assert_reproduction_artifact_roundtrip_coverage(",
    "assert_reproduction_artifact_error_variant_coverage(",
];

const PROTOCOL_CODEC_ACTIVATION_MARKERS: &[&str] = &[
    "pub fn encode",
    "pub fn decode",
    "ProtocolFrame",
    "FrameCodec",
];
const DETERMINISM_CORE_COVERAGE_FLOOR: &[CoverageSurface] = &[
    CoverageSurface {
        id: "scheduler-quantum-loop",
        source_path: "crates/crucible/src/scheduler.rs",
        test_path: "crates/crucible/src/scheduler",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: SCHEDULER_QUANTUM_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "scheduler-ordering-keys",
        source_path: "crates/crucible/src/scheduler.rs",
        test_path: "crates/crucible/src/scheduler",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: SCHEDULER_ORDERING_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "error-variant-floor",
        source_path: "crates/crucible/src/lib.rs",
        test_path: "crates/crucible/src/tests",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: ERROR_VARIANT_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "instantiate-recursion",
        source_path: "crates/crucible/src/model.rs",
        test_path: "crates/crucible/src/tests",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: INSTANTIATE_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "sim-backend-error-variants",
        source_path: "crates/crucible/src/sim_backend.rs",
        test_path: "crates/crucible/src/sim_backend.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: SIM_BACKEND_ERROR_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "content-addressed-digest",
        source_path: "crates/crucible-sim/src/lib.rs",
        test_path: "crates/crucible-sim/src/lib.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: DIGEST_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "replay-oracle-path",
        source_path: "crates/crucible-harness/src/replay_oracle.rs",
        test_path: "crates/crucible-harness/src/replay_oracle.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: REPLAY_ORACLE_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "decision-rng-and-forking",
        source_path: "crates/crucible/src/decision.rs",
        test_path: "crates/crucible/src/decision.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: DECISION_RNG_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "spsc-ring",
        source_path: "crates/crucible-shmem/src/lib.rs",
        test_path: "crates/crucible-shmem/tests/gate_layer1_injection.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: SPSC_RING_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "protocol-codec",
        source_path: "crates/crucible-protocol/src/lib.rs",
        test_path: "crates/crucible-protocol/tests/gate_abi_conformance.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: PROTOCOL_CODEC_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
    CoverageSurface {
        id: "reproduction-artifact-serializer",
        source_path: "crates/crucible/src/model.rs",
        test_path: "crates/crucible/tests/gate_replay_oracle.rs",
        status: CoverageStatus::Active,
        instrumentation: COVERAGE_MEASUREMENT_MODE,
        required_test_markers: REPRO_ARTIFACT_MARKERS,
        activation_markers: &[],
        activation_source_roots: &[],
    },
];

const PLANNED_DETERMINISM_CORE_COVERAGE: &[CoverageSurface] = &[];

#[test]
fn determinism_core_coverage_floor_names_required_surfaces() {
    let actual: BTreeSet<&str> = all_coverage_surfaces()
        .iter()
        .map(|surface| surface.id)
        .collect();

    assert_eq!(
        actual,
        BTreeSet::from([
            "scheduler-quantum-loop",
            "scheduler-ordering-keys",
            "error-variant-floor",
            "instantiate-recursion",
            "sim-backend-error-variants",
            "content-addressed-digest",
            "replay-oracle-path",
            "decision-rng-and-forking",
            "spsc-ring",
            "protocol-codec",
            "reproduction-artifact-serializer",
        ])
    );
}

#[test]
fn active_determinism_core_paths_have_branch_and_error_coverage_markers()
-> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut failures = coverage_floor_failures(&all_coverage_surfaces(), &root, &BTreeMap::new())?;
    failures.extend(coverage_floor_regression_failures());

    assert!(
        failures.is_empty(),
        "Crucible determinism-core coverage-floor lint failed:\n{}",
        failures.join("\n")
    );

    Ok(())
}

fn all_coverage_surfaces() -> Vec<CoverageSurface> {
    DETERMINISM_CORE_COVERAGE_FLOOR
        .iter()
        .chain(PLANNED_DETERMINISM_CORE_COVERAGE.iter())
        .copied()
        .collect()
}

fn coverage_floor_failures(
    surfaces: &[CoverageSurface],
    root: &Path,
    source_overrides: &SourceOverrides,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut failures = Vec::new();

    for surface in surfaces {
        if surface.instrumentation != InstrumentationMode::SeparateDeterministicBuild {
            failures.push(format!(
                "{} must be measured in the {COVERAGE_INSTRUMENTATION_PROFILE} separate deterministic instrumentation build",
                surface.id
            ));
        }

        let source = root.join(surface.source_path);
        if !source.is_file() && !source_overrides.contains_key(surface.source_path) {
            failures.push(format!(
                "{}: missing determinism-core source {}",
                surface.id, surface.source_path
            ));
            continue;
        }

        if surface.status == CoverageStatus::Planned {
            let source_content = activation_source_content(surface, root, source_overrides)?;
            if planned_surface_is_implemented(surface, &source_content) {
                failures.push(format!(
                    "{}: planned determinism-core surface is implemented but is not measured by {COVERAGE_INSTRUMENTATION_PROFILE}; promote it to Active and add separate coverage measurement wiring",
                    surface.id
                ));
            }
            continue;
        }

        let content = test_source_content(surface.test_path, root, source_overrides)?;
        let code = scrub_comments_and_strings(&content);

        for marker in surface.required_test_markers {
            if !code.contains(marker) {
                failures.push(format!(
                    "{}: active determinism-core coverage marker `{marker}` is missing from {}",
                    surface.id, surface.test_path
                ));
            }
        }
    }

    failures.extend(required_surface_regression_failures(surfaces));
    Ok(failures)
}

fn test_source_content(
    test_path: &str,
    root: &Path,
    source_overrides: &SourceOverrides,
) -> Result<String, Box<dyn Error>> {
    if let Some(content) = source_overrides.get(test_path) {
        return Ok(content.clone());
    }

    let path = root.join(test_path);
    if path.is_file() {
        return Ok(fs::read_to_string(path)?);
    }

    let mut files = Vec::new();
    collect_rust_files(&path, &mut files)?;
    let mut content = String::new();
    for file in files {
        content.push_str(&fs::read_to_string(file)?);
        content.push('\n');
    }
    Ok(content)
}

fn planned_surface_is_implemented(surface: &CoverageSurface, source_content: &str) -> bool {
    if surface.status == CoverageStatus::Active {
        return true;
    }

    let code = scrub_comments_and_strings(source_content);
    surface
        .activation_markers
        .iter()
        .any(|marker| code.contains(marker))
}

fn activation_source_content(
    surface: &CoverageSurface,
    root: &Path,
    source_overrides: &SourceOverrides,
) -> Result<String, Box<dyn Error>> {
    let scan_roots: Vec<&str> = if surface.activation_source_roots.is_empty() {
        vec![surface.source_path]
    } else {
        surface.activation_source_roots.to_vec()
    };
    let mut content = String::new();

    for scan_root in scan_roots {
        let mut matched_override = false;
        for (path, override_content) in source_overrides {
            let root_prefix = format!("{scan_root}/");
            if *path == scan_root || (*path).starts_with(&root_prefix) {
                matched_override = true;
                content.push_str(override_content);
                content.push('\n');
            }
        }

        if matched_override {
            continue;
        }

        let path = root.join(scan_root);
        if path.is_dir() {
            let mut files = Vec::new();
            collect_rust_files(&path, &mut files)?;
            for file in files {
                content.push_str(&fs::read_to_string(file)?);
                content.push('\n');
            }
        } else if path.is_file() {
            content.push_str(&fs::read_to_string(path)?);
            content.push('\n');
        }
    }

    Ok(content)
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    let mut entries = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();

    for path in entries {
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }

    Ok(())
}

fn required_surface_regression_failures(surfaces: &[CoverageSurface]) -> Vec<String> {
    let ids: BTreeSet<&str> = surfaces.iter().map(|surface| surface.id).collect();
    [
        "scheduler-quantum-loop",
        "scheduler-ordering-keys",
        "error-variant-floor",
        "instantiate-recursion",
        "sim-backend-error-variants",
        "decision-rng-and-forking",
        "content-addressed-digest",
        "spsc-ring",
        "protocol-codec",
        "replay-oracle-path",
        "reproduction-artifact-serializer",
    ]
    .into_iter()
    .filter(|required| !ids.contains(required))
    .map(|required| format!("missing determinism-core coverage surface `{required}`"))
    .collect()
}

fn coverage_floor_regression_failures() -> Vec<String> {
    let root = workspace_root();
    let broken = [
        CoverageSurface {
            id: "scheduler-quantum-loop",
            source_path: "crates/crucible/src/scheduler.rs",
            test_path: "synthetic.rs",
            status: CoverageStatus::Active,
            instrumentation: InstrumentationMode::SharedTestBuild,
            required_test_markers: SCHEDULER_QUANTUM_MARKERS,
            activation_markers: &[],
            activation_source_roots: &[],
        },
        CoverageSurface {
            id: "content-addressed-digest",
            source_path: "crates/crucible-sim/src/lib.rs",
            test_path: "synthetic.rs",
            status: CoverageStatus::Active,
            instrumentation: COVERAGE_MEASUREMENT_MODE,
            required_test_markers: DIGEST_MARKERS,
            activation_markers: &[],
            activation_source_roots: &[],
        },
        CoverageSurface {
            id: "protocol-codec",
            source_path: "synthetic-protocol/src/lib.rs",
            test_path: "synthetic-protocol-test.rs",
            status: CoverageStatus::Planned,
            instrumentation: COVERAGE_MEASUREMENT_MODE,
            required_test_markers: PROTOCOL_CODEC_MARKERS,
            activation_markers: PROTOCOL_CODEC_ACTIVATION_MARKERS,
            activation_source_roots: &["synthetic-protocol/src"],
        },
    ];
    let source_overrides = BTreeMap::from([
        (
            "synthetic.rs",
            String::from(
                "fn stable_hasher_is_repeatable() {}\n/* stable_hasher_is_order_sensitive */\n",
            ),
        ),
        (
            "synthetic-protocol/src/lib.rs",
            String::from("mod codec;\n"),
        ),
        (
            "synthetic-protocol/src/codec.rs",
            String::from("pub fn encode(value: &[u8]) -> Vec<u8> { value.to_vec() }"),
        ),
    ]);
    let findings =
        coverage_floor_failures(&broken, &root, &source_overrides).unwrap_or_else(|error| {
            vec![format!(
                "coverage-floor regression failed while scanning synthetic surfaces: {error}"
            )]
        });
    let mut failures = Vec::new();

    if !findings
        .iter()
        .any(|finding| finding.contains("separate deterministic instrumentation build"))
    {
        failures.push(
            "coverage-floor regression failed to reject shared instrumentation builds".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("stable_hasher_is_order_sensitive"))
    {
        failures.push(
            "coverage-floor regression failed to reject missing branch coverage marker".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("decision-rng-and-forking"))
    {
        failures.push(
            "coverage-floor regression failed to reject missing required surface".to_string(),
        );
    }
    if !findings
        .iter()
        .any(|finding| finding.contains("planned determinism-core surface is implemented"))
    {
        failures.push(
            "coverage-floor regression failed to reject unmeasured planned surface activation"
                .to_string(),
        );
    }

    failures
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest_dir.parent().and_then(Path::parent) {
        Some(root) => root.to_path_buf(),
        None => panic!("crucible-harness manifest is not inside the workspace"),
    }
}

fn scrub_comments_and_strings(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut index = 0;
    let mut state = ScannerState::Code;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            ScannerState::Code => {
                if ch == '/' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::LineComment;
                } else if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(1);
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::String;
                } else {
                    out.push(ch);
                    index += 1;
                }
            }
            ScannerState::LineComment => {
                if ch == '\n' {
                    out.push('\n');
                    state = ScannerState::Code;
                } else {
                    out.push(' ');
                }
                index += 1;
            }
            ScannerState::BlockComment(depth) => {
                if ch == '/' && next == Some('*') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    state = ScannerState::BlockComment(depth + 1);
                } else if ch == '*' && next == Some('/') {
                    out.push(' ');
                    out.push(' ');
                    index += 2;
                    if depth == 1 {
                        state = ScannerState::Code;
                    } else {
                        state = ScannerState::BlockComment(depth - 1);
                    }
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            ScannerState::String => {
                if ch == '\\' && next.is_some() {
                    out.push(' ');
                    out.push(if next == Some('\n') { '\n' } else { ' ' });
                    index += 2;
                } else if ch == '"' {
                    out.push(' ');
                    index += 1;
                    state = ScannerState::Code;
                } else {
                    out.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
        }
    }

    out
}

#[derive(Clone, Copy, Debug)]
enum ScannerState {
    Code,
    LineComment,
    BlockComment(usize),
    String,
}
