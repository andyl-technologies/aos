//! Runs the reduction-path static determinism lint.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crucible_harness::spec_index::crate_spec_index;
use toml::Value;

#[path = "support/harness_lint/allow.rs"]
mod allow;
#[path = "support/harness_lint/clippy.rs"]
mod clippy;
#[path = "support/harness_lint/common.rs"]
mod common;
#[path = "support/harness_lint/confinement.rs"]
mod confinement;
#[path = "support/harness_lint/error_logging.rs"]
mod error_logging;
#[path = "support/harness_lint/lex.rs"]
mod lex;
#[path = "support/harness_lint/reference_integrity.rs"]
mod reference_integrity;
#[path = "support/harness_lint/scan.rs"]
mod scan;

use allow::*;
use clippy::*;
use common::*;
use confinement::*;
use error_logging::*;
use lex::*;
use reference_integrity::*;
use scan::*;

#[test]
fn gate_evidence_references_are_integral() -> Result<(), Box<dyn Error>> {
    let findings = gate_reference_integrity_failures(&repo_root())?;

    assert!(
        findings.is_empty(),
        "gate:harness-lint reference-integrity findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn gate_evidence_rejects_checklist_state_needles() {
    let findings = checklist_state_needle_failures(
        Path::new("tests/crucible/synthetic.nix"),
        r#"
          failuresFor "docs/rfcs/0010-crucible/example.md" doc [
            {
              label = "circular completion evidence";
              needle = "- [x] **T-SYNTH-1**";
            }
            {
              label = "circular open evidence";
              needle = "- [ ] **T-SYNTH-2**";
            }
          ]
        "#,
    );

    assert_contains(&findings, "T-SYNTH-1");
    assert_contains(&findings, "T-SYNTH-2");
}

#[test]
fn retired_fault_surfaces_cannot_reenter_executable_or_user_documentation_paths()
-> Result<(), Box<dyn Error>> {
    let identifier_fragments: &[&[&str]] = &[
        &["Fault", "PlanEntry"],
        &["Fault", "Tag"],
        &["Active", "FaultTable"],
        &["Inject", "Fault"],
        &["Heal", "Fault"],
        &["Random", "Fault"],
        &["Membership", "Fault"],
        &["Network", "Fault"],
        &["Block", "Fault"],
        &["NineP", "Fault"],
        &["Node", "Fault"],
        &["Fault", "Id"],
        &["Fault", "State"],
        &["Fault", "Duration"],
        &["Fault", "RateBasisPoints"],
        &["Fault", "BandwidthBitsPerSecond"],
        &["Fault", "SlowdownFactorBasisPoints"],
        &["NineP", "Errno"],
        &["Fault", "Activation"],
        &["SessionCommand", "Inject"],
        &["SessionCommandKind", "Inject"],
        &["ControlOperationKind", "Inject"],
        &["SessionCommand", "Snapshot"],
        &["SessionCommandKind", "Snapshot"],
    ];
    let snake_fragments: &[&[&str]] = &[
        &["active", "faults"],
        &["active", "fault", "tags"],
        &["inject", "fault"],
        &["heal", "fault"],
        &["random", "fault"],
        &["no", "active", "faults"],
        &["fault", "entry"],
        &["fault", "plan"],
        &["fault", "active"],
        &["fault", "activation"],
    ];
    let retired = identifier_fragments
        .iter()
        .map(|parts| parts.concat())
        .chain(snake_fragments.iter().map(|parts| parts.join("_")))
        .collect::<BTreeSet<_>>();

    let workspace = workspace_root();
    let repo = repo_root();
    let mut files = Vec::new();
    for package in [
        "crucible",
        "crucible-api",
        "crucible-cli",
        "crucible-device",
        "crucible-harness",
        "crucible-protocol",
        "crucible-qemu",
        "crucible-session",
        "crucible-shmem",
    ] {
        for directory in ["src", "tests", "examples"] {
            collect_fault_surface_files(&workspace.join(package).join(directory), &mut files)?;
        }
    }
    collect_fault_surface_files(&repo.join("docs/users/crucible"), &mut files)?;
    collect_fault_surface_files(&repo.join("tests/crucible"), &mut files)?;
    files.sort();

    let mut findings = Vec::new();
    for file in files {
        if file.ends_with("fault-model-migration.md") {
            continue;
        }
        let content = fs::read_to_string(&file)?;
        for (line_index, line) in content.lines().enumerate() {
            for token in line
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            {
                if retired.contains(token) {
                    findings.push(format!(
                        "{}:{}: retired fault surface `{token}`",
                        file.display(),
                        line_index + 1
                    ));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "retired fault surfaces remain outside historical RFCs or the migration guide:\n{}",
        findings.join("\n")
    );
    Ok(())
}

#[test]
fn user_reference_names_every_executable_effect_kind() -> Result<(), Box<dyn Error>> {
    let reference = fs::read_to_string(repo_root().join("docs/users/crucible/reference.md"))?;
    let registry = fs::read_to_string(
        workspace_root().join("crucible/src/model/fault_signal/effect_registry.rs"),
    )?;
    let missing = registry
        .lines()
        .filter_map(|line| line.split_once("=> { key: \"").map(|(_, rest)| rest))
        .filter_map(|rest| rest.split_once('\"').map(|(key, _)| key))
        .filter(|kind| !reference.contains(&format!("`{kind}`")))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "Crucible user reference omits executable effect kinds: {}",
        missing.join(", ")
    );
    Ok(())
}

fn collect_fault_surface_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_fault_surface_files(&path, files)?;
            continue;
        }
        if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "toml" | "md" | "nix")
        ) {
            files.push(path);
        }
    }
    Ok(())
}

#[test]
fn session_terminal_outcomes_have_one_engine_owned_construction_path() -> Result<(), Box<dyn Error>>
{
    let source =
        fs::read_to_string(workspace_root().join("crucible-session/src/session/engine.rs"))?;
    let findings = terminal_outcome_construction_failures(&source);
    assert!(
        findings.is_empty(),
        "session terminal-outcome construction findings:\n{}",
        findings.join("\n")
    );

    let negative_control = terminal_outcome_construction_failures(
        "fn compensate_in_cli() { let _ = Outcome::Timeout; }",
    );
    assert_contains(&negative_control, "outside enter_stopped");
    Ok(())
}

#[test]
fn reduction_path_sources_have_no_banned_nondeterminism() -> Result<(), Box<dyn Error>> {
    let mut findings = Vec::new();
    for package in REDUCTION_PATH_PACKAGES {
        let src_dir = workspace_root().join(package).join("src");
        for source in rust_sources(&src_dir)? {
            let content = fs::read_to_string(&source)?;
            findings.extend(scan_content(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn host_boundary_nondeterminism_is_confined_from_state() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let repo = repo_root();
    let baseline = HarnessLintBaseline::load(&repo)?;
    let workspace_manifest: Value = fs::read_to_string(root.join("Cargo.toml"))?.parse()?;
    let workspace_dependencies = workspace_dependency_table(&workspace_manifest);
    let findings = baseline.filter_findings(
        "confinement",
        &repo,
        workspace_confinement_findings(&root, &workspace_dependencies)?,
    );

    assert!(
        findings.is_empty(),
        "host-boundary nondeterminism confinement findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn production_sources_follow_error_and_logging_conventions() -> Result<(), Box<dyn Error>> {
    let mut findings = Vec::new();
    let root = workspace_root();
    let repo = repo_root();
    let baseline = HarnessLintBaseline::load(&repo)?;

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        let manifest = fs::read_to_string(package_dir.join("Cargo.toml"))?;
        let is_library = spec.package != BINARY_BOUNDARY_PACKAGE;
        let mut has_typed_error =
            !is_library || manifest_declares_dependency(&manifest, "thiserror");

        findings.extend(manifest_error_dependency_failures(
            spec.package,
            &manifest,
            is_library,
        ));

        for source in rust_sources(&package_dir.join("src"))? {
            if is_test_only_source(&package_dir, &source) {
                continue;
            }
            let content = fs::read_to_string(&source)?;
            has_typed_error |= source_declares_typed_error(&content);
            findings.extend(error_logging_failures(
                &source,
                &content,
                is_binary_boundary_source(spec.package, &package_dir, &source),
            ));
        }

        if !has_typed_error {
            findings.push(missing_typed_error_finding(spec.package));
        }
    }

    let findings = baseline.filter_findings("error-logging", &repo, findings);

    assert!(
        findings.is_empty(),
        "gate:harness-lint error/logging findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn clippy_tier_is_checked_in_and_wired() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let repo = repo_root();
    let workspace_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let clippy_config = fs::read_to_string(root.join("clippy.toml"))?;
    let crucible_package = fs::read_to_string(repo.join("pkgs/tools/crucible/crucible.nix"))?;
    let mut package_manifests = Vec::new();

    for spec in crate_spec_index() {
        let manifest = fs::read_to_string(root.join(spec.package).join("Cargo.toml"))?;
        package_manifests.push((spec.package, manifest));
    }

    let findings = clippy_tier_failures(
        &workspace_manifest,
        &clippy_config,
        &package_manifests,
        &crucible_package,
    );

    assert!(
        findings.is_empty(),
        "gate:harness-lint clippy tier findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn custom_static_analysis_tier_runs_over_crucible_sources() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut findings = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        for source in rust_sources(&package_dir.join("src"))? {
            let content = fs::read_to_string(&source)?;
            findings.extend(custom_static_analysis_failures(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint custom static-analysis findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn allow_annotations_are_checked_for_all_crucible_targets() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut findings = Vec::new();

    for spec in crate_spec_index() {
        let package_dir = root.join(spec.package);
        for source in rust_sources(&package_dir)? {
            let content = fs::read_to_string(&source)?;
            findings.extend(allow_annotation_failures(&source, &content));
        }
    }

    assert!(
        findings.is_empty(),
        "gate:harness-lint allow-annotation findings:\n{}",
        findings.join("\n")
    );

    Ok(())
}

#[test]
fn harness_lint_rejects_banned_code_patterns() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                let _ = std::time::SystemTime::now();
                let _ = rand::thread_rng();
                let _ = std::collections::HashMap::<u8, u8>::new();
                let _ = std::collections::hash_map::DefaultHasher::new();
                tokio::select! { _ = async {} => {} }
            }
        "#,
    );

    assert_contains(&findings, "host wall-clock");
    assert_contains(&findings, "thread/global RNG");
    assert_contains(&findings, "unordered map/set");
    assert_contains(&findings, "default/random hasher");
    assert_contains(&findings, "nondeterministic select");
}

#[test]
fn harness_lint_rejects_host_boundary_state_leaks() -> Result<(), Box<dyn Error>> {
    let failures = confinement_regression_failures()?;
    assert!(
        failures.is_empty(),
        "harness-lint confinement regression failures:\n{}",
        failures.join("\n")
    );

    Ok(())
}

#[test]
fn harness_lint_rejects_spaced_paths_and_grouped_imports() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::hash_map::{DefaultHasher, RandomState};
            use std::collections::{HashMap, HashSet};
            use std::time::{Instant, SystemTime};

            fn bad() {
                let _ = HashMap :: <u8, u8> :: new();
                let _ = HashSet :: <u8> :: new();
                let _ = DefaultHasher :: new();
                let _ = RandomState :: new();
                let _ = SystemTime :: now();
                let _ = Instant :: now();
                rand :: thread_rng();
                rand :: rng();
                tokio::select ! { _ = async {} => {} }
            }
        "#,
    );

    assert_contains(&findings, "host wall-clock");
    assert_contains(&findings, "host monotonic time");
    assert_contains(&findings, "thread/global RNG");
    assert_contains(&findings, "unordered map/set");
    assert_contains(&findings, "default/random hasher");
    assert_contains(&findings, "nondeterministic select");
}

#[test]
fn harness_lint_ignores_comments_and_strings() {
    let findings = scan_content(
        Path::new("synthetic.rs"),
        r##"
            //! std::time::SystemTime::now()
            // rand::thread_rng()
            /*
              std::collections::HashMap::<u8, u8>::new()
            */
            /*
              /*
                rand::thread_rng()
              */
            */
            const TEXT: &str = "tokio::select!";
            const RAW: &str = r#"SystemTime::now and thread_rng()"#;
            const LIFE: &'static str = "lifetimes are not char literals";
        "##,
    );

    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn harness_lint_rejects_error_and_logging_drift() {
    let library_findings = error_logging_failures(
        Path::new("crucible-sim/src/lib.rs"),
        r#"
            pub fn bad() -> Result<(), Box<dyn Error>> {
                let value = maybe().unwrap();
                let other = maybe().expect /* comment */ ("value exists");
                println!("library diagnostic");
                eprintln!("library diagnostic");
                print!("library diagnostic");
                anyhow::bail!("erased error");
            }
        "#,
        false,
    );

    assert_contains(&library_findings, "panic shortcut");
    assert_contains(&library_findings, "direct stdout/stderr diagnostic");
    assert_contains(&library_findings, "erased error");

    let binary_findings = error_logging_failures(
        Path::new("crucible-cli/src/main.rs"),
        r#"
            fn main() -> anyhow::Result<()> {
                println!("cli output is allowed");
                Ok(())
            }
        "#,
        true,
    );

    assert!(binary_findings.is_empty(), "{binary_findings:?}");

    let cli_module_findings = error_logging_failures(
        Path::new("crucible-cli/src/command.rs"),
        r#"
            pub fn command() -> anyhow::Result<()> {
                println!("command module output crosses the binary boundary");
                Ok(())
            }
        "#,
        true,
    );

    assert!(cli_module_findings.is_empty(), "{cli_module_findings:?}");

    let cfg_all_test_findings = error_logging_failures(
        Path::new("crucible-shmem/src/lib.rs"),
        r#"
            #[cfg(all(test, target_os = "linux"))]
            mod tests {
                fn test_helper() -> Result<(), Box<dyn Error>> {
                    maybe().expect("test assertion");
                    Ok(())
                }
            }
        "#,
        false,
    );
    assert!(
        cfg_all_test_findings.is_empty(),
        "{cfg_all_test_findings:?}"
    );
}

#[test]
fn harness_lint_rejects_erased_error_dependencies_in_libraries() {
    let findings = manifest_error_dependency_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
            thiserror = { workspace = true }
            anyhow = { workspace = true }
        "#,
        true,
    );

    assert_contains(&findings, "erased error dependency");

    let cli_findings = manifest_error_dependency_failures(
        "crucible-cli",
        r#"
            [package]
            name = "crucible-cli"

            [dependencies]
            anyhow = { workspace = true }
        "#,
        false,
    );

    assert!(cli_findings.is_empty(), "{cli_findings:?}");
}

#[test]
fn harness_lint_rejects_missing_typed_error_signal_in_libraries() {
    let findings = typed_error_policy_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
        "#,
        &[],
        true,
    );

    assert_contains(&findings, "missing typed error");

    let thiserror_findings = typed_error_policy_failures(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"

            [dependencies]
            thiserror = { workspace = true }
        "#,
        &[],
        true,
    );

    assert!(thiserror_findings.is_empty(), "{thiserror_findings:?}");

    let hand_rolled_findings = typed_error_policy_failures(
        "crucible-harness",
        r#"
            [package]
            name = "crucible-harness"

            [dependencies]
        "#,
        &[r#"
            use std::error::Error;

            pub struct HarnessError;

            impl Error for HarnessError {}
        "#],
        true,
    );

    assert!(hand_rolled_findings.is_empty(), "{hand_rolled_findings:?}");

    let cli_findings = typed_error_policy_failures(
        "crucible-cli",
        r#"
            [package]
            name = "crucible-cli"

            [dependencies]
            anyhow = { workspace = true }
        "#,
        &[],
        false,
    );

    assert!(cli_findings.is_empty(), "{cli_findings:?}");
}

#[test]
fn harness_lint_rejects_clippy_tier_drift() {
    let package_manifests = [(
        "crucible-sim",
        r#"
            [package]
            name = "crucible-sim"
        "#
        .to_owned(),
    )];
    let findings = clippy_tier_failures(
        r#"
            [workspace.lints.clippy]
            all = "warn"
            disallowed_methods = "deny"
        "#,
        r#"
            disallowed-methods = []
            disallowed-types = []
        "#,
        &package_manifests,
        "",
    );

    assert_contains(&findings, "workspace clippy deny");
    assert_contains(&findings, "disallowed method");
    assert_contains(&findings, "disallowed type");
    assert_contains(&findings, "workspace lint inheritance");
    assert_contains(&findings, "clippy gate wiring");
}

#[test]
fn harness_lint_rejects_custom_static_analysis_drift() {
    let findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::HashMap;

            fn bad() {
                let map: HashMap<u8, u8> = HashMap::new();
                for item in map.iter() {
                    consume(item);
                }
                let _ = std::collections::hash_map::DefaultHasher::new();
                let _ = map.keys();
                let _ = map.values_mut();
                let _ = map.into_values();
                tokio::select! { _ = async {} => {} }
                unsafe {
                    core::ptr::read_volatile(core::ptr::null::<u8>());
                }
            }
        "#,
    );

    assert_contains(&findings, "unordered hash-container iteration");
    assert_contains(&findings, "default/random hasher");
    assert_contains(&findings, "unordered select");
    assert_contains(&findings, "bare unsafe block");

    let stale_safety_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                // SAFETY: stale comment is separated from the unsafe block.

                unsafe {}
                // SAFETY: this applies only to the next unsafe block.
                unsafe {}
                unsafe {}
            }
        "#,
    );

    assert!(
        stale_safety_findings.len() >= 2,
        "expected stale and missing SAFETY comments to be rejected, got {stale_safety_findings:?}"
    );

    let allowed_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::BTreeMap;

            fn allowed() {
                let map: BTreeMap<u8, u8> = BTreeMap::new();
                for item in map.iter() {
                    consume(item);
                }
                tokio::select! {
                    biased;
                    _ = async {} => {}
                }
                // SAFETY: synthetic volatile read is isolated to test the marker.
                unsafe {
                    core::ptr::read_volatile(core::ptr::null::<u8>());
                }
            }
        "#,
    );

    assert!(
        allowed_findings.is_empty(),
        "expected deterministic custom tier sample to pass, got {allowed_findings:?}"
    );
}

#[test]
fn harness_lint_rejects_distribution_metadata_in_identity_paths() {
    let findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            fn metadata_reaches_artifact(host_id: String, lease_owner: String, fleet_size: usize) {
                let owner_bytes = lease_owner.into_bytes();
                let fleet_bytes = fleet_size.to_string().into_bytes();
                let artifact = CampaignReplayArtifact::new(
                    host_id.into_bytes(),
                    [owner_bytes, fleet_bytes].concat(),
                    b"schedule".to_vec(),
                );
                let _key = ContentHash::from_bytes(artifact.replay_hash().to_hex().as_bytes());
            }

            fn metadata_reaches_decision(peer_count: usize, schedule: &mut Schedule) {
                let decision = Decision::Preemption(peer_count as u64);
                schedule.push(decision);
            }

            fn metadata_reaches_reduce(now_tick: u64, def: ScenarioDef, schedule: Schedule) {
                let _ = reduce(&def, &schedule);
                consume(now_tick);
            }

            fn claim_replay_artifact(owner: String, acquired_at_tick: u64) {
                let artifact = CampaignReplayArtifact::new(
                    owner.into_bytes(),
                    acquired_at_tick.to_string().into_bytes(),
                    b"schedule".to_vec(),
                );
                consume(artifact);
            }

            fn progress_reduce(peer_count: usize, def: ScenarioDef, schedule: Schedule) {
                let _ = reduce(&def, &schedule);
                emit_telemetry(peer_count);
            }
        "#,
    );

    assert_contains(
        &findings,
        "distribution metadata reaching reduce/Decision/content key/artifact path",
    );
    assert_contains(&findings, "host_id");
    assert_contains(&findings, "lease_owner");
    assert_contains(&findings, "fleet_size");
    assert_contains(&findings, "peer_count");
    assert_contains(&findings, "now_tick");
    assert_contains(&findings, "owner");
    assert_contains(&findings, "acquired_at_tick");
}

#[test]
fn harness_lint_allows_distribution_metadata_in_coordination_paths() {
    let findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            fn claim_next(host_id: String, now_tick: u64) {
                let expires_at_tick = now_tick + 5;
                write_claim_metadata(host_id, expires_at_tick);
            }

            fn progress_report(fleet_size: usize, peer_count: usize) {
                emit_telemetry(fleet_size, peer_count);
            }

            fn lease_record(owner: String, acquired_at_tick: u64, node: ContentHash) {
                let lease_id = ContentHash::from_bytes(
                    format!("{owner}:{acquired_at_tick}:{}", node.to_hex()).as_bytes(),
                );
                write_claim_metadata(owner, acquired_at_tick, lease_id);
            }
        "#,
    );

    assert!(
        findings.is_empty(),
        "coordination-only distribution metadata should be accepted: {findings:?}"
    );
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BaselineKey {
    category: String,
    path: String,
    reason: String,
    pattern: String,
    suffix: String,
}

#[derive(Default)]
struct HarnessLintBaseline {
    caps: BTreeMap<BaselineKey, usize>,
}

impl HarnessLintBaseline {
    fn load(repo: &Path) -> Result<Self, Box<dyn Error>> {
        let path = repo.join("tests/crucible/harness-lint-baseline.txt");
        let content = fs::read_to_string(path)?;
        let mut caps = BTreeMap::new();

        for (index, line) in content.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 6 {
                return Err(format!(
                    "invalid harness-lint baseline entry on line {}: {line}",
                    index + 1
                )
                .into());
            }

            let count = fields[5].parse::<usize>().map_err(|error| {
                format!(
                    "invalid harness-lint baseline count on line {}: {error}",
                    index + 1
                )
            })?;
            caps.insert(
                BaselineKey {
                    category: fields[0].to_string(),
                    path: fields[1].to_string(),
                    reason: fields[2].to_string(),
                    pattern: fields[3].to_string(),
                    suffix: fields[4].to_string(),
                },
                count,
            );
        }

        Ok(Self { caps })
    }

    fn filter_findings(&self, category: &str, repo: &Path, findings: Vec<String>) -> Vec<String> {
        let mut observed = BTreeMap::new();
        let mut unbaselined = Vec::new();

        for finding in findings {
            let Some(key) = BaselineKey::from_finding(category, repo, &finding) else {
                unbaselined.push(finding);
                continue;
            };
            let observed_count = observed.entry(key.clone()).or_insert(0usize);
            *observed_count += 1;

            if self
                .caps
                .get(&key)
                .is_some_and(|cap| *observed_count <= *cap)
            {
                continue;
            }

            unbaselined.push(finding);
        }

        for (key, cap) in self.caps.iter().filter(|(key, _)| key.category == category) {
            let actual = observed.get(key).copied().unwrap_or_default();
            if actual < *cap {
                unbaselined.push(format!(
                    "tests/crucible/harness-lint-baseline.txt: stale {category} baseline `{}` expected {cap} observed {actual}",
                    key.display()
                ));
            }
        }

        unbaselined
    }
}

impl BaselineKey {
    fn from_finding(category: &str, repo: &Path, finding: &str) -> Option<Self> {
        let (path_and_line, rest) = finding.split_once(": banned ")?;
        let (path, _) = path_and_line.rsplit_once(':')?;
        let (reason, rest) = rest.split_once(" pattern `")?;
        let (pattern, suffix) = rest.split_once('`')?;
        Some(Self {
            category: category.to_string(),
            path: repo_relative_path(repo, path),
            reason: reason.to_string(),
            pattern: pattern.to_string(),
            suffix: suffix.to_string(),
        })
    }

    fn display(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            self.category, self.path, self.reason, self.pattern, self.suffix
        )
    }
}

fn repo_relative_path(repo: &Path, path: &str) -> String {
    let prefix = format!("{}/", repo.display());
    path.strip_prefix(&prefix).unwrap_or(path).to_string()
}
