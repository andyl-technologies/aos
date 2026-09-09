//! Process-level tests for offline checked ability inspection.

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aos_ability_inspect::{
    GraphQuery, INSPECTION_QUERY_MAX_DEPTH, InspectionBundle, InspectionView, NodeKey,
    RenderFormat, render,
};
use aos_ability_model::{DeploymentObligation, LocalKey, ObligationKind, TransactionId};
use aos_ability_plan::test_support::verified_planning_transition_plan;
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_runtime::execution::{ExecutionEvent, ExecutionEventKind};
use aos_ability_runtime::journal::{FileJournal, JournalLimits};
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::test_support::{checked_effect_plan, plan_fixture};
use aos_contract::Sha256Digest;

#[test]
fn diagnostic_cli_reports_outcomes_or_exact_namespace_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let root = std::fs::metadata("/")?;
    let process_owner = std::fs::metadata(workspace.path())?.uid();
    let trusted_namespace = root.uid() == 0 || root.uid() == process_owner;

    for case in [
        DiagnosticCase::Export,
        DiagnosticCase::WrongPlanBundle,
        DiagnosticCase::TornTail,
    ] {
        let case_workspace = tempfile::tempdir_in(workspace.path())?;
        let fixture = write_diagnostic_generation(
            case_workspace.path(),
            matches!(case, DiagnosticCase::WrongPlanBundle),
        )?;
        let before = if matches!(case, DiagnosticCase::TornTail) {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&fixture.journal)?;
            file.write_all(b"incomplete-frame")?;
            drop(file);
            Some(std::fs::read(&fixture.journal)?)
        } else {
            None
        };
        let output = run_diagnostic(
            &case_workspace,
            &fixture,
            trusted_namespace && !matches!(case, DiagnosticCase::WrongPlanBundle),
        )?;

        if trusted_namespace {
            assert_trusted_diagnostic_outcome(case, &output)?;
        } else {
            assert!(!output.status.success(), "case: {case:?}");
            assert!(output.stdout.is_empty(), "case: {case:?}");
            assert!(
                stderr(&output)?.contains("ancestor without trusted rename protection"),
                "case: {case:?}; stderr: {}",
                stderr(&output)?
            );
        }
        if let Some(before) = before {
            assert_eq!(std::fs::read(&fixture.journal)?, before);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum DiagnosticCase {
    Export,
    WrongPlanBundle,
    TornTail,
}

fn run_diagnostic(
    workspace: &tempfile::TempDir,
    fixture: &DiagnosticGenerationFixture,
    json: bool,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
    if json {
        command.arg("--json");
    }
    Ok(command
        .args([
            "ability",
            "diagnostic",
            path_text(&fixture.generation)?,
            &fixture.transaction,
        ])
        .env("AOS_PROFILE_ROOT", &fixture.profile_root)
        .current_dir(workspace.path())
        .output()?)
}

fn assert_trusted_diagnostic_outcome(
    case: DiagnosticCase,
    output: &Output,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(case, DiagnosticCase::WrongPlanBundle) {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(stderr(output)?.contains("does not match the selected transaction plan bundle"));
        return Ok(());
    }

    assert!(
        output.status.success(),
        "case: {case:?}; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        stderr(output)?
    );
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(diagnostic["schema"], "aos.ability.diagnostic-bundle/v1");
    assert_eq!(diagnostic["audience"], "redacted");
    assert_eq!(diagnostic["inputs"]["disclosure"], "redacted");
    assert_eq!(
        diagnostic["timeline"]["events"][0]["kind"],
        "transaction-planned"
    );

    if matches!(case, DiagnosticCase::TornTail) {
        assert_eq!(
            diagnostic["timeline"]["provenance"]["status"],
            "caller-asserted-journal-prefix"
        );
        assert_eq!(
            diagnostic["timeline"]["provenance"]["incomplete_tail_bytes"],
            serde_json::Value::from(16)
        );
        assert!(diagnostic["limitations"].as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value == "incomplete-journal-tail-excluded")
        }));
        assert!(output.stderr.is_empty());
    } else {
        assert!(diagnostic["limitations"].as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value == "native-execution-qualification-not-included")
        }));
        assert!(diagnostic["limitations"].as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value == "pending-dependency-state-unavailable")
        }));
        assert!(output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn json_mode_emits_only_the_canonical_checked_view() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let plan = checked_effect_plan();
    let bundle_path = workspace.path().join("inspection.json");
    let bundle = write_bundle(&bundle_path, &plan)?;
    let checked = bundle.clone().check(None)?;
    let expected = render(&InspectionView::from_bundle(&checked)?, RenderFormat::Json)?;

    let output = run(
        workspace.path(),
        &["--json", "ability", "inspect", path_text(&bundle_path)?],
    )?;
    assert!(output.status.success(), "{}", stderr(&output)?);
    assert_eq!(String::from_utf8(output.stdout)?, format!("{expected}\n"));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn independent_digest_mismatch_fails_before_rendering() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let bundle_path = workspace.path().join("inspection.json");
    write_bundle(&bundle_path, &checked_effect_plan())?;
    let mismatch = Sha256Digest::of_bytes("unrelated trusted record").to_string();

    let output = run(
        workspace.path(),
        &[
            "ability",
            "inspect",
            path_text(&bundle_path)?,
            "--expected-digest",
            &mismatch,
        ],
    )?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr(&output)?.contains("differs from its external digest"));
    Ok(())
}

#[test]
fn unresolved_obligations_are_rendered_as_non_executable() -> Result<(), Box<dyn std::error::Error>>
{
    let workspace = tempfile::tempdir()?;
    let bundle_path = workspace.path().join("blocked.json");
    write_bundle(&bundle_path, &blocked_plan()?)?;

    let output = run(
        workspace.path(),
        &[
            "ability",
            "inspect",
            path_text(&bundle_path)?,
            "--format",
            "text",
        ],
    )?;
    assert!(output.status.success(), "{}", stderr(&output)?);
    let stdout = String::from_utf8(output.stdout.clone())?;
    assert!(stdout.contains("executable: false"));
    assert!(stdout.contains("\"kind\":\"obligation\""));
    assert!(!stdout.contains("admitted"));
    assert!(!stdout.contains("executed"));
    assert!(stderr(&output)?.contains("not asserted current"));
    Ok(())
}

#[test]
fn projection_flag_emits_the_named_portable_projection() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let bundle_path = workspace.path().join("inspection.json");
    write_bundle(&bundle_path, &checked_effect_plan())?;

    let output = run(
        workspace.path(),
        &[
            "--json",
            "ability",
            "inspect",
            path_text(&bundle_path)?,
            "--projection",
            "retention",
        ],
    )?;
    assert!(output.status.success(), "{}", stderr(&output)?);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        value["schema"],
        serde_json::Value::String("aos.ability.inspection-projection/v1".to_string())
    );
    assert_eq!(
        value["kind"],
        serde_json::Value::String("retention".to_string())
    );
    assert!(value["nodes"].as_array().is_some_and(|nodes| {
        nodes
            .iter()
            .any(|node| node["kind"] == serde_json::Value::String("artifact".to_string()))
    }));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn canonical_query_file_bounds_a_named_projection() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let bundle_path = workspace.path().join("inspection.json");
    let query_path = workspace.path().join("query.json");
    let plan = checked_effect_plan();
    let binding = plan.binding_plan().bindings()[0].id.clone();
    write_bundle(&bundle_path, &plan)?;
    let query = GraphQuery::new([NodeKey::Binding(binding)], 1, 2);
    std::fs::write(&query_path, query.canonical_bytes()?)?;

    let output = run(
        workspace.path(),
        &[
            "--json",
            "ability",
            "inspect",
            path_text(&bundle_path)?,
            "--projection",
            "retention",
            "--query",
            path_text(&query_path)?,
        ],
    )?;
    assert!(output.status.success(), "{}", stderr(&output)?);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        value["schema"],
        serde_json::Value::String("aos.ability.inspection-slice/v1".to_string())
    );
    assert_eq!(
        value["projection"],
        serde_json::Value::String("retention".to_string())
    );
    assert_eq!(value["max_depth"], serde_json::Value::from(1));
    assert_eq!(value["max_nodes"], serde_json::Value::from(2));
    assert!(
        value["nodes"]
            .as_array()
            .is_some_and(|nodes| nodes.len() == 2)
    );
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn query_flag_rejects_noncanonical_input() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let bundle_path = workspace.path().join("inspection.json");
    let query_path = workspace.path().join("query.json");
    let plan = checked_effect_plan();
    let binding = plan.binding_plan().bindings()[0].id.clone();
    write_bundle(&bundle_path, &plan)?;
    let mut query = b" \n".to_vec();
    query.extend_from_slice(&GraphQuery::new([NodeKey::Binding(binding)], 1, 2).canonical_bytes()?);
    std::fs::write(&query_path, query)?;

    let output = run(
        workspace.path(),
        &[
            "ability",
            "inspect",
            path_text(&bundle_path)?,
            "--query",
            path_text(&query_path)?,
        ],
    )?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr(&output)?.contains("not canonically encoded"));
    Ok(())
}

#[test]
fn query_limits_fail_before_the_bundle_graph_is_loaded() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = tempfile::tempdir()?;
    let missing_bundle = workspace.path().join("missing-inspection.json");
    let query_path = workspace.path().join("query.json");
    let plan = checked_effect_plan();
    let binding = plan.binding_plan().bindings()[0].id.clone();
    let query = GraphQuery::new([NodeKey::Binding(binding)], 1, 2);
    let mut value: serde_json::Value = serde_json::from_slice(&query.canonical_bytes()?)?;
    value["max_depth"] = serde_json::Value::from(INSPECTION_QUERY_MAX_DEPTH + 1);
    std::fs::write(&query_path, aos_contract::canonical::to_vec(&value)?)?;

    let output = run(
        workspace.path(),
        &[
            "ability",
            "inspect",
            path_text(&missing_bundle)?,
            "--query",
            path_text(&query_path)?,
        ],
    )?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = stderr(&output)?;
    assert!(error.contains(&format!(
        "depth {} exceeds its limit {}",
        INSPECTION_QUERY_MAX_DEPTH + 1,
        INSPECTION_QUERY_MAX_DEPTH
    )));
    assert!(!error.contains("opening inspection bundle"));
    Ok(())
}

struct DiagnosticGenerationFixture {
    profile_root: PathBuf,
    generation: PathBuf,
    journal: PathBuf,
    transaction: String,
}

fn write_diagnostic_generation(
    workspace: &Path,
    wrong_plan_bundle: bool,
) -> Result<DiagnosticGenerationFixture, Box<dyn std::error::Error>> {
    let profile_root = workspace.join("profiles");
    let generation = profile_root.join("system").join("gen-42");
    let transaction = "diagnostic-transaction";
    let transaction_directory = generation.join("ability-transactions").join(transaction);
    std::fs::create_dir_all(&transaction_directory)?;
    std::fs::set_permissions(
        generation.join("ability-transactions"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    std::fs::set_permissions(
        &transaction_directory,
        std::fs::Permissions::from_mode(0o700),
    )?;

    let (planning, transition) = verified_planning_transition_plan();
    let plan = transition.checked_effect();
    let bundle = ReloadablePlanBundle::from_verified(&planning, None, None, &transition)?;
    let bundle_digest = bundle.digest()?;
    let bundle_path = transaction_directory.join("plan-bundle.json");
    std::fs::write(&bundle_path, bundle.canonical_bytes()?)?;
    std::fs::set_permissions(&bundle_path, std::fs::Permissions::from_mode(0o600))?;

    let retained_roots = plan
        .required_runtime_artifacts()
        .iter()
        .map(|artifact| artifact.closure)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let total_recovery_millis = plan
        .operations()
        .iter()
        .try_fold(0_u64, |total, operation| {
            total.checked_add(operation.deadline.total_recovery_millis.get())
        })
        .ok_or("fixture recovery budget overflow")?;
    let transaction_id = TransactionId(LocalKey::new(transaction)?);
    let journal_path = transaction_directory.join("execution.journal");
    let mut journal =
        FileJournal::<ExecutionEvent>::open(&journal_path, JournalLimits::default())?.journal;
    journal.append(&ExecutionEvent::new(
        ExecutionEventKind::TransactionPlanned {
            transaction: transaction_id,
            plan: plan.id(),
            plan_bundle: if wrong_plan_bundle {
                Sha256Digest::of_bytes("another retained plan bundle")
            } else {
                bundle_digest
            },
            retained_roots,
            total_recovery_millis,
        },
    ))?;
    drop(journal);

    Ok(DiagnosticGenerationFixture {
        profile_root,
        generation,
        journal: journal_path,
        transaction: transaction.to_string(),
    })
}

fn write_bundle(
    path: &Path,
    plan: &CheckedEffectPlan,
) -> Result<InspectionBundle, Box<dyn std::error::Error>> {
    let bundle = InspectionBundle::from_checked(plan)?;
    std::fs::write(path, bundle.canonical_bytes()?)?;
    Ok(bundle)
}

fn blocked_plan() -> Result<CheckedEffectPlan, aos_ability_validate::ValidationErrors> {
    let mut fixture = plan_fixture();
    let obligation = DeploymentObligation {
        key: fixture.binding_plan.requests[0].id.key.clone(),
        kind: ObligationKind::Authorization,
        request: fixture.binding_plan.requests[0].id.clone(),
        resource: None,
        description: "operator approval is absent".to_string(),
    };
    fixture.binding_plan.bindings.clear();
    fixture.binding_plan.obligations = vec![obligation.clone()];
    fixture.effect_plan.operations.clear();
    fixture.effect_plan.edges.clear();
    fixture.effect_plan.provider_readiness.clear();
    fixture.effect_plan.controllers.clear();
    fixture.effect_plan.artifacts.clear();
    fixture.effect_plan.obligations = vec![obligation];
    fixture.refresh_commitments();
    fixture.validate()
}

fn run(workspace: &Path, arguments: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_aos"))
        .args(arguments)
        .current_dir(workspace)
        .env_clear()
        .env("HOME", workspace)
        .output()
}

fn path_text(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| "test path is not UTF-8".into())
}

fn stderr(output: &Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stderr.clone())
}
