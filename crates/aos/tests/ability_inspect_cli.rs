//! Process-level tests for offline checked ability inspection.

use std::path::Path;
use std::process::{Command, Output};

use aos_ability_inspect::{InspectionBundle, InspectionView, RenderFormat, render};
use aos_ability_model::{DeploymentObligation, ObligationKind};
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::test_support::{checked_effect_plan, plan_fixture};
use aos_contract::Sha256Digest;

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
