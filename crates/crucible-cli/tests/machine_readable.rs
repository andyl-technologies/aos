//! Process-level checks for machine-readable CLI stdout.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

#[test]
fn cli_exit_machine_readable_process_stdout_is_pure_json() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let scenario = temp.path().join("scenario.toml");
    fs::write(&scenario, fixture.scenario.to_canonical_toml()?)?;

    let jsonl_stdout = run_machine_readable("jsonl", &scenario, &temp.path().join("run-jsonl"))?;
    assert_machine_readable_jsonl(&jsonl_stdout, &["run_scenario"])?;

    let json_stdout = run_machine_readable("json", &scenario, &temp.path().join("run-json"))?;
    assert!(
        json_stdout.starts_with('['),
        "json stdout must start with a JSON array, got `{json_stdout}`",
    );
    assert!(
        !json_stdout.contains("crucible:"),
        "json stdout must not contain human text, got `{json_stdout}`",
    );
    assert!(
        json_stdout.trim_end().ends_with(']'),
        "json stdout must end with a JSON array, got `{json_stdout}`",
    );
    assert_machine_readable_json(&json_stdout, &["run_scenario"])?;

    Ok(())
}

#[test]
fn cli_save_machine_readable_jsonl_reports_handle_path() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let scenario = temp.path().join("scenario.toml");
    let artifact_dir = temp.path().join("artifacts");
    fs::write(&scenario, fixture.scenario.to_canonical_toml()?)?;

    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "2",
            "--artifact-dir",
        ])
        .arg(&artifact_dir)
        .arg("save")
        .arg(&scenario)
        .args(["--at", "quiescence", "--label", "jsonl"])
        .output()?;
    assert!(
        output.status.success(),
        "crucible save --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert_machine_readable_jsonl(&stdout, &["save_export"])?;
    assert!(stdout.contains("out="));
    assert!(stdout.contains(".crucible-savepoint"));

    let handles = fs::read_dir(&artifact_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str()?;
            (file_name.starts_with("savepoint-jsonl-")
                && file_name.ends_with(".crucible-savepoint"))
            .then_some(entry)
        })
        .collect::<Vec<_>>();
    assert_eq!(handles.len(), 1);
    assert!(
        handles[0]
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("savepoint-jsonl-")
                && name.ends_with(".crucible-savepoint"))
    );

    Ok(())
}

#[test]
fn cli_save_qemu_process_jsonl_reports_identity_and_handle() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("qemu-save-artifacts");
    let (qemu, plugin) = qemu_process_artifacts(temp.path())?;

    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "--backend", "qemu", "--qemu"])
        .arg(&qemu)
        .arg("--plugin")
        .arg(&plugin)
        .args(["--seed", "7", "--artifact-dir"])
        .arg(&artifact_dir)
        .arg("save")
        .arg("builtin:happy-path.scn")
        .args(["--at", "quiescence", "--label", "qemu-process"])
        .output()?;
    assert!(
        output.status.success(),
        "crucible save --backend qemu --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert_machine_readable_jsonl(
        &stdout,
        &[
            "backend_fidelity",
            "save_oracle_validation",
            "save_qemu_runner",
            "save_export",
        ],
    )?;
    let expected_qemu_build_id = content_address_bytes(b"process-qemu-build-v1");
    let expected_plugin_abi = qemu_process_plugin_abi();
    assert!(stdout.contains("summary\":\"Qemu\""));
    assert!(stdout.contains("materialization=create-savepoint-reply"));
    assert!(stdout.contains(&format!("qemu_build_id={expected_qemu_build_id}")));
    assert!(stdout.contains("qemu_patch_series=sha256-process-qemu-patch-series"));
    assert!(stdout.contains(&format!("plugin_abi={expected_plugin_abi}")));
    assert!(stdout.contains(&format!("shmem_abi={}", crucible::SHMEM_ABI_VERSION)));
    assert!(stdout.contains("status=fat==thin-passed"));
    assert!(stdout.contains(".crucible-savepoint"));

    let handles = fs::read_dir(&artifact_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_name = entry.file_name();
            let file_name = file_name.to_str()?;
            (file_name.starts_with("savepoint-qemu-process-")
                && file_name.ends_with(".crucible-savepoint"))
            .then_some(entry.path())
        })
        .collect::<Vec<_>>();
    assert_eq!(handles.len(), 1);
    let handle = fs::read_to_string(&handles[0])?;
    assert!(handle.contains("label\tqemu-process\n"));
    assert!(handle.contains("materialization\tcreate-savepoint\treply\n"));
    assert!(handle.contains("oracle\tfat==thin-passed\n"));
    assert!(handle.contains("terminal-condition\tquiescence\n"));

    Ok(())
}

#[test]
fn cli_resume_qemu_process_jsonl_reports_identity_and_oracle() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let save_artifact_dir = temp.path().join("resume-source-artifacts");
    let save_store = temp.path().join("resume-source-store");
    let resume_artifact_dir = temp.path().join("qemu-resume-artifacts");
    let resume_store = temp.path().join("qemu-resume-store");
    let (qemu, plugin) = qemu_process_artifacts(temp.path())?;

    let save_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "8",
            "--artifact-dir",
        ])
        .arg(&save_artifact_dir)
        .arg("--store")
        .arg(&save_store)
        .arg("save")
        .arg("builtin:happy-path.scn")
        .args(["--at", "quiescence", "--label", "resume-source"])
        .output()?;
    assert!(
        save_output.status.success(),
        "source savepoint for qemu resume should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&save_output.stdout),
        String::from_utf8_lossy(&save_output.stderr),
    );
    let source = single_savepoint_handle(&save_artifact_dir, "resume-source")?;

    let resume_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "--backend", "qemu", "--qemu"])
        .arg(&qemu)
        .arg("--plugin")
        .arg(&plugin)
        .arg("--artifact-dir")
        .arg(&resume_artifact_dir)
        .arg("--store")
        .arg(&resume_store)
        .arg("resume")
        .arg(&source)
        .args(["--until", "virtual-time", "--max-virtual-time", "2ticks"])
        .output()?;
    assert!(
        resume_output.status.success(),
        "crucible resume --backend qemu --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&resume_output.stdout),
        String::from_utf8_lossy(&resume_output.stderr),
    );
    let stdout = String::from_utf8(resume_output.stdout)?;
    assert_machine_readable_jsonl(
        &stdout,
        &[
            "backend_fidelity",
            "resume_checkpoint",
            "resume_oracle_validation",
            "resume_qemu_runner",
        ],
    )?;
    let expected_qemu_build_id = content_address_bytes(b"process-qemu-build-v1");
    let expected_plugin_abi = qemu_process_plugin_abi();
    assert!(stdout.contains("summary\":\"Qemu\""));
    assert!(stdout.contains("until=virtual-time"));
    assert!(stdout.contains("checkpoint=blake3:"));
    assert!(stdout.contains("configuration=blake3:"));
    assert!(stdout.contains("status=fat==thin-passed"));
    assert!(stdout.contains(
        "materialization=qemu-vm-realization operation=resume branch=ancestor-replay"
    ));
    assert!(stdout.contains(&format!("qemu_build_id={expected_qemu_build_id}")));
    assert!(stdout.contains("qemu_patch_series=sha256-process-qemu-patch-series"));
    assert!(stdout.contains(&format!("plugin_abi={expected_plugin_abi}")));
    assert!(stdout.contains(&format!("shmem_abi={}", crucible::SHMEM_ABI_VERSION)));
    assert!(stdout.contains("exit_code=0"));

    Ok(())
}

#[test]
fn cli_fork_qemu_process_jsonl_reports_identity_and_artifact() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let save_artifact_dir = temp.path().join("fork-source-artifacts");
    let fork_artifact_dir = temp.path().join("qemu-fork-artifacts");
    let (qemu, plugin) = qemu_process_artifacts(temp.path())?;

    let save_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "9",
            "--artifact-dir",
        ])
        .arg(&save_artifact_dir)
        .arg("save")
        .arg("builtin:happy-path.scn")
        .args(["--at", "quiescence", "--label", "fork-source"])
        .output()?;
    assert!(
        save_output.status.success(),
        "source savepoint for qemu fork should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&save_output.stdout),
        String::from_utf8_lossy(&save_output.stderr),
    );
    let source = single_savepoint_handle(&save_artifact_dir, "fork-source")?;

    let fork_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "--backend", "qemu", "--qemu"])
        .arg(&qemu)
        .arg("--plugin")
        .arg(&plugin)
        .arg("--artifact-dir")
        .arg(&fork_artifact_dir)
        .arg("fork")
        .arg(&source)
        .args([
            "--until",
            "virtual-time",
            "--max-virtual-time",
            "2ticks",
            "--label",
            "qemu-process-child",
        ])
        .output()?;
    assert!(
        fork_output.status.success(),
        "crucible fork --backend qemu --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&fork_output.stdout),
        String::from_utf8_lossy(&fork_output.stderr),
    );
    let stdout = String::from_utf8(fork_output.stdout)?;
    assert_machine_readable_jsonl(
        &stdout,
        &[
            "backend_fidelity",
            "fork_checkpoint",
            "fork_oracle_validation",
            "fork_reproduction_artifact",
            "fork_qemu_runner",
        ],
    )?;
    let expected_qemu_build_id = content_address_bytes(b"process-qemu-build-v1");
    let expected_plugin_abi = qemu_process_plugin_abi();
    assert!(stdout.contains("summary\":\"Qemu\""));
    assert!(stdout.contains("label=qemu-process-child"));
    assert!(stdout.contains("status=fat==thin-passed"));
    assert!(stdout.contains("materialization=child-session-savepoint"));
    assert!(stdout.contains(&format!("qemu_build_id={expected_qemu_build_id}")));
    assert!(stdout.contains("qemu_patch_series=sha256-process-qemu-patch-series"));
    assert!(stdout.contains(&format!("plugin_abi={expected_plugin_abi}")));
    assert!(stdout.contains("digest=crucible-hash:"));
    assert!(stdout.contains("model_artifact=blake3:"));
    assert!(stdout.contains("replay_state=blake3:"));
    assert!(stdout.contains("fork_seed=inherited"));
    assert!(stdout.contains("exit_code=0"));

    let fork_artifacts = fs::read_dir(&fork_artifact_dir)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let file_name = path.file_name()?.to_str()?;
            (file_name.starts_with("fork-qemu-process-child-") && file_name.ends_with(".crucible"))
                .then_some(path)
        })
        .collect::<Vec<_>>();
    assert_eq!(fork_artifacts.len(), 1);

    Ok(())
}

#[test]
fn cli_exit_machine_readable_search_fuzz_jsonl_reports_final_outcome() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let scenario = temp.path().join("scenario.toml");
    let family = temp.path().join("family.toml");
    let search_artifact_dir = temp.path().join("search-artifacts");
    let fuzz_artifact_dir = temp.path().join("fuzz-artifacts");
    fs::write(&scenario, fixture.scenario.to_canonical_toml()?)?;
    fs::write(&family, valid_fuzz_family_toml())?;

    let search_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "3",
            "--artifact-dir",
        ])
        .arg(&search_artifact_dir)
        .arg("search")
        .arg(&scenario)
        .args(["--max-states", "1"])
        .output()?;
    assert!(
        search_output.status.success(),
        "crucible search --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&search_output.stdout),
        String::from_utf8_lossy(&search_output.stderr),
    );
    let search_stdout = String::from_utf8(search_output.stdout)?;
    assert_machine_readable_jsonl(&search_stdout, &["search_strategy_run"])?;

    let fuzz_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "4",
            "--artifact-dir",
        ])
        .arg(&fuzz_artifact_dir)
        .arg("fuzz")
        .arg(&family)
        .args(["--runs", "1"])
        .output()?;
    assert!(
        fuzz_output.status.success(),
        "crucible fuzz --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&fuzz_output.stdout),
        String::from_utf8_lossy(&fuzz_output.stderr),
    );
    let fuzz_stdout = String::from_utf8(fuzz_output.stdout)?;
    assert_machine_readable_jsonl(&fuzz_stdout, &["coverage_guided_fuzz_run"])?;

    Ok(())
}

#[test]
fn cli_exit_machine_readable_search_retained_evidence_failure_jsonl_reports_final_outcome()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let scenario = temp.path().join("retained-search-scenario.toml");
    let retained_evidence = temp.path().join("retained-evidence.toml");
    let artifact_dir = temp.path().join("retained-search-artifacts");
    fs::write(
        &scenario,
        search_retained_evidence_scenario()?.to_canonical_toml()?,
    )?;
    fs::write(&retained_evidence, valid_search_retained_evidence_toml())?;

    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "5",
            "--artifact-dir",
        ])
        .arg(&artifact_dir)
        .arg("search")
        .arg(&scenario)
        .args(["--max-states", "1", "--retained-evidence"])
        .arg(&retained_evidence)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "crucible retained-evidence search --format jsonl should exit 1; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert_machine_readable_jsonl_with_exit(&stdout, &["search_strategy_run"], 1)?;
    assert!(stdout.contains("scenario-assertions+retained-evidence"));
    assert!(stdout.contains("retained_evidence_digest=crucible-hash:"));

    Ok(())
}

#[test]
fn cli_exit_machine_readable_replay_check_jsonl_reports_final_outcome() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let scenario = temp.path().join("scenario.toml");
    let artifact_dir = temp.path().join("replay-artifacts");
    let check_path = temp.path().join("original.jsonl");
    let mismatch_check_path = temp.path().join("mismatch.jsonl");
    fs::write(&scenario, fixture.scenario.to_canonical_toml()?)?;

    let failure_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            "jsonl",
            "--backend",
            "double",
            "--seed",
            "6",
            "--artifact-dir",
        ])
        .arg(&artifact_dir)
        .arg("run")
        .arg(&scenario)
        .arg("--emit-mock-failure-artifact")
        .output()?;
    assert_eq!(
        failure_output.status.code(),
        Some(1),
        "mock failure run should exit 1; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&failure_output.stdout),
        String::from_utf8_lossy(&failure_output.stderr),
    );
    let failure_stdout = String::from_utf8(failure_output.stdout)?;
    assert_machine_readable_jsonl_with_exit(&failure_stdout, &["run_scenario"], 1)?;

    let artifact_path = single_reproduction_artifact(&artifact_dir)?;
    fs::write(
        &check_path,
        canonical_jsonl_from_reproduction_artifact(&artifact_path)?,
    )?;

    let replay_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "--backend", "double", "--artifact-dir"])
        .arg(&artifact_dir)
        .arg("replay")
        .arg(&artifact_path)
        .arg("--check")
        .arg(&check_path)
        .output()?;
    assert!(
        replay_output.status.success(),
        "crucible replay --check --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&replay_output.stdout),
        String::from_utf8_lossy(&replay_output.stderr),
    );
    let replay_stdout = String::from_utf8(replay_output.stdout)?;
    assert_machine_readable_jsonl(&replay_stdout, &["replay_artifact", "replay_check"])?;
    assert!(replay_stdout.contains("subcommand=replay"));
    assert!(replay_stdout.contains("status=passed"));
    assert!(replay_stdout.contains("artifact=crucible-hash:"));
    assert!(!replay_stdout.contains("crucible: replay artifact"));

    let mut mismatch_check = fs::read(&check_path)?;
    let first_byte = mismatch_check
        .first_mut()
        .ok_or_else(|| invalid_data("replay check fixture must not be empty"))?;
    *first_byte = first_byte.wrapping_add(1);
    fs::write(&mismatch_check_path, mismatch_check)?;

    let mismatch_output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "--backend", "double", "--artifact-dir"])
        .arg(&artifact_dir)
        .arg("replay")
        .arg(&artifact_path)
        .arg("--check")
        .arg(&mismatch_check_path)
        .output()?;
    assert_eq!(
        mismatch_output.status.code(),
        Some(1),
        "crucible replay --check mismatch --format jsonl should exit 1; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&mismatch_output.stdout),
        String::from_utf8_lossy(&mismatch_output.stderr),
    );
    let mismatch_stdout = String::from_utf8(mismatch_output.stdout)?;
    assert_machine_readable_jsonl_with_exit(
        &mismatch_stdout,
        &["replay_artifact", "replay_check"],
        1,
    )?;
    assert!(mismatch_stdout.contains("subcommand=replay"));
    assert!(mismatch_stdout.contains("status=failed"));
    assert!(mismatch_stdout.contains("status=mismatch"));
    assert!(mismatch_stdout.contains("first_diff_byte=0"));
    assert!(!mismatch_stdout.contains("crucible: replay artifact"));

    Ok(())
}

#[test]
fn cli_exit_machine_readable_replay_to_savepoint_jsonl_reports_final_outcome()
-> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let artifact_dir = temp.path().join("replay-to-artifacts");
    let fixture = replay_to_savepoint_process_fixture(temp.path())?;

    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "--backend", "double", "--artifact-dir"])
        .arg(&artifact_dir)
        .arg("replay")
        .arg(&fixture.artifact)
        .arg("--to")
        .arg(&fixture.savepoint)
        .output()?;
    assert!(
        output.status.success(),
        "crucible replay --to --format jsonl should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert_machine_readable_jsonl(&stdout, &["replay_artifact", "replay_to_savepoint"])?;
    assert!(stdout.contains("subcommand=replay"));
    assert!(stdout.contains("status=target-validated"));
    assert!(stdout.contains("schedule_prefix=typed"));
    assert!(stdout.contains("materialization=model-temporal-graph"));
    assert!(stdout.contains("unified_operation=replay"));
    assert!(stdout.contains("single_vm_fingerprint=blake3:"));
    assert!(stdout.contains("exit_code=0"));
    assert!(!stdout.contains("crucible: replay --to"));

    Ok(())
}

fn run_machine_readable(
    format: &str,
    scenario: &Path,
    artifact_dir: &Path,
) -> Result<String, Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            format,
            "--backend",
            "double",
            "--seed",
            "1",
            "--artifact-dir",
        ])
        .arg(artifact_dir)
        .arg("run")
        .arg(scenario)
        .output()?;
    assert!(
        output.status.success(),
        "crucible run --format {format} should exit 0; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn assert_machine_readable_jsonl(
    stdout: &str,
    expected_kinds: &[&str],
) -> Result<(), Box<dyn Error>> {
    assert_machine_readable_jsonl_with_exit(stdout, expected_kinds, 0)
}

fn assert_machine_readable_jsonl_with_exit(
    stdout: &str,
    expected_kinds: &[&str],
    expected_exit_code: i32,
) -> Result<(), Box<dyn Error>> {
    let lines = stdout.lines().collect::<Vec<_>>();
    assert!(!lines.is_empty(), "jsonl stdout must not be empty");
    let mut entries = Vec::new();
    for line in lines {
        assert!(
            !line.starts_with("crucible:"),
            "jsonl stdout must not contain human text, got `{line}`",
        );
        let value = serde_json::from_str::<Value>(line).map_err(|error| {
            invalid_data(format!(
                "jsonl stdout line must parse as a JSON object: {error}; line=`{line}`"
            ))
        })?;
        assert!(
            value.as_object().is_some(),
            "jsonl stdout must contain only JSON object lines, got `{line}`",
        );
        entries.push(value);
    }
    assert_machine_readable_entries(&entries, expected_kinds, "jsonl stdout", expected_exit_code)?;
    Ok(())
}

fn assert_machine_readable_json(
    stdout: &str,
    expected_kinds: &[&str],
) -> Result<(), Box<dyn Error>> {
    let value = serde_json::from_str::<Value>(stdout)
        .map_err(|error| invalid_data(format!("json stdout must parse as JSON: {error}")))?;
    let entries = value
        .as_array()
        .ok_or_else(|| invalid_data("json stdout must be a JSON array"))?;
    assert_machine_readable_entries(entries, expected_kinds, "json stdout", 0)
}

fn assert_machine_readable_entries(
    entries: &[Value],
    expected_kinds: &[&str],
    context: &str,
    expected_exit_code: i32,
) -> Result<(), Box<dyn Error>> {
    assert!(!entries.is_empty(), "{context} must not be empty");
    let mut kinds = Vec::new();
    for entry in entries {
        let kind = entry
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_data(format!("{context} entry must contain a string kind")))?;
        kinds.push(kind.to_owned());
    }
    for expected_kind in expected_kinds {
        assert!(
            kinds.iter().any(|kind| kind == expected_kind),
            "{context} kinds {kinds:?} must contain `{expected_kind}`",
        );
    }
    let final_entry = entries
        .last()
        .ok_or_else(|| invalid_data(format!("{context} must include a final outcome line")))?;
    assert_eq!(
        final_entry.get("kind").and_then(Value::as_str),
        Some("final_outcome"),
        "final_outcome should be the last machine-readable record in {context}",
    );
    let final_summary = final_entry
        .get("summary")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data(format!("{context} final outcome must include a summary")))?;
    let expected = format!("exit_code={expected_exit_code}");
    assert!(
        final_summary.contains(&expected),
        "{context} final outcome summary must include {expected}, got `{final_summary}`",
    );
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn valid_fuzz_family_toml() -> &'static str {
    r#"schema = "crucible.scenario-family.v1"
topology_shapes = ["ring"]

[seed_space]
kind = "generated"
meta_seed = "0x55"
count = 2

[fault_density]
min_millionths = 0
max_millionths = 1

[topology_size]
min = 1
max = 2

[node_template]
fixed_icount = 17
cmdline = "cli-fuzz-family"
"#
}

fn search_retained_evidence_scenario() -> Result<crucible::ScenarioDefForm, Box<dyn Error>> {
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: crucible::NodeId {
            name: String::from("cli-search-retained-node"),
        },
        arch: crucible::NodeTemplate::DEFAULT_ARCH,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("crucible-cli-search-retained"),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 100 },
        },
        white_box: crucible::WhiteBoxPolicy::Enabled,
        smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: crucible::AssertionId::from_name("cli-search-retained-evidence"),
            message: String::from("CLI search retained evidence marker must not appear"),
            property: crucible::Property::Always {
                predicate: crucible::Predicate::not(crucible::Predicate::guest_marker(
                    crucible::MarkerId::from_name("forbidden-search-marker"),
                )),
            },
        }],
    )?;
    Ok(crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &properties,
        crucible::Seed::from_u64(0x5252),
    )?)
}

fn valid_search_retained_evidence_toml() -> &'static str {
    r#"schema = "crucible.search-retained-evidence.v1"

[[evidence]]
configuration = "root"
kind = "guest-marker"
node = "cli-search-retained-node"
marker = "forbidden-search-marker"
retired_icount = 7
"#
}

fn qemu_process_artifacts(dir: &Path) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let qemu = dir.join("qemu-system-x86_64");
    let plugin = dir.join("crucible-qemu-plugin.so");
    fs::write(&qemu, b"patched-qemu")?;
    fs::write(&plugin, b"plugin")?;
    let shmem_abi_version = crucible::SHMEM_ABI_VERSION;
    let plugin_abi = qemu_process_plugin_abi();
    fs::write(
        dir.join("qemu-build-identity.env"),
        format!(
            "qemu_plugins_enabled=true\nqemu_crucible_patches_applied=true\nqemu_sim_capability=qemu-crucible\nqemu_patch_series_hash=sha256-process-qemu-patch-series\nqemu_shmem_abi_version={shmem_abi_version}\nqemu_shmem_abi={plugin_abi}\nqemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\nqemu_shmem_header_hash=sha256-process-shmem-header\nqemu_build_id=process-qemu-build-v1\n"
        ),
    )?;
    fs::write(
        dir.join("crucible-qemu-plugin-build-info"),
        format!(
            "package=crucible-qemu-plugin\nqemu_package=qemu-crucible\nqemu_build_id=process-qemu-build-v1\nshmem_abi_version={shmem_abi_version}\nshmem_abi={plugin_abi}\nshmem_generated_header=include/aos/crucible/crucible_shmem_abi.h\nshmem_generated_header_hash=sha256-process-shmem-header\nplugin_abi={plugin_abi}\n"
        ),
    )?;
    Ok((qemu, plugin))
}

fn qemu_process_plugin_abi() -> String {
    format!("crucible-shmem-abi-v{}", crucible::SHMEM_ABI_VERSION)
}

fn single_savepoint_handle(dir: &Path, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let prefix = format!("savepoint-{label}-");
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid_data(format!("non-UTF-8 entry in `{}`", dir.display())))?;
        if file_name.starts_with(&prefix) && file_name.ends_with(".crucible-savepoint") {
            paths.push(path);
        }
    }
    paths.sort();
    match paths.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(invalid_data(format!(
            "expected one savepoint handle with prefix `{prefix}` in `{}`, found {}",
            dir.display(),
            paths.len()
        ))
        .into()),
    }
}

#[derive(Debug)]
struct ArtifactDecision {
    sequence: u64,
    virtual_time_ticks: u64,
    node: String,
    kind: String,
    payload_digest: String,
}

#[derive(Debug)]
struct ReplayToSavepointProcessFixture {
    artifact: PathBuf,
    savepoint: PathBuf,
}

#[derive(Debug)]
struct ReplayToSavepointDecisionFixture {
    sequence: u64,
    virtual_time_ticks: u64,
    node: String,
    kind: String,
    payload: String,
    payload_digest: String,
}

fn replay_to_savepoint_process_fixture(
    dir: &Path,
) -> Result<ReplayToSavepointProcessFixture, Box<dyn Error>> {
    let fixture = crucible::happy_path_scenario()?;
    let form = fixture.scenario;
    let scenario = form.scenario_def();
    let schedule = replay_to_savepoint_schedule();
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_process_fixture(&configuration)?;
    let artifact = dir.join("process-replay-to.crucible");
    let savepoint = dir.join("process-replay-to.crucible-savepoint");
    fs::write(
        &artifact,
        replay_to_savepoint_artifact_text(&scenario, &schedule)?.into_bytes(),
    )?;
    fs::write(
        &savepoint,
        savepoint_handle_text(&form, &schedule, &checkpoint)?,
    )?;
    Ok(ReplayToSavepointProcessFixture {
        artifact,
        savepoint,
    })
}

fn replay_to_savepoint_schedule() -> crucible::Schedule {
    crucible::Schedule::from_decisions([crucible::Decision::DeliveryOrder(
        crucible::DeliveryOrderDecision {
            at: crucible::VirtualTime { ticks: 1 },
            order: Vec::new(),
        },
    )])
}

fn checkpoint_for_process_fixture(
    configuration: &crucible::Configuration,
) -> Result<crucible::Checkpoint, Box<dyn Error>> {
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let prefix = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))?;
        Some(crucible::Configuration {
            def: configuration.def.clone(),
            schedule: prefix,
        })
    };
    Ok(crucible::Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        crucible::VirtualTime {
            ticks: configuration.schedule.len() as u64,
        },
        BTreeMap::new(),
        crucible::CheckpointKind::Fat,
        BTreeMap::new(),
    )?)
}

fn replay_to_savepoint_artifact_text(
    scenario: &crucible::ScenarioDef,
    schedule: &crucible::Schedule,
) -> Result<String, Box<dyn Error>> {
    let scenario_bytes = scenario_identity_bytes(scenario);
    let scenario_digest = content_address_bytes(&scenario_bytes);
    let store_uri = format!("cas:{scenario_digest}");
    let decisions = replay_to_savepoint_decision_fixtures(schedule);
    let mut text = String::new();
    artifact_line(&mut text, &["schema", "crucible.reproduction-artifact.v2"]);
    artifact_line(&mut text, &["seed", "111"]);
    artifact_line(
        &mut text,
        &[
            "identity",
            env!("CARGO_PKG_VERSION"),
            "crucible-harness-e2e-v1",
            "crucible.reproduction-artifact.v2",
            &content_address_bytes(b"mock-backend-source-v1"),
            &content_address_bytes(b"mock-qemu-patch-series-v1"),
            &crucible::SHMEM_ABI_VERSION.to_string(),
            &crucible_protocol::CONTROL_PROTOCOL_VERSION.to_string(),
            &format!(
                "{}.{}.{}",
                crucible_api::RPC_PROTOCOL_MAJOR,
                crucible_api::RPC_PROTOCOL_MINOR,
                crucible_api::RPC_PROTOCOL_PATCH
            ),
            crucible_api::RPC_PROTOCOL_BUILD,
            "simdouble-mock-plugin-abi",
        ],
    );
    artifact_line(
        &mut text,
        &[
            "scenario",
            "scenario_def",
            "process-replay-to.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.scenario+text",
            &scenario_bytes.len().to_string(),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "component",
            "scenario_def",
            "process-replay-to.scn",
            &scenario_digest,
            &store_uri,
            "application/vnd.crucible.scenario+text",
            &scenario_bytes.len().to_string(),
        ],
    );
    for decision in &decisions {
        artifact_line(
            &mut text,
            &[
                "component",
                "other",
                &format!("decision-{}-payload", decision.sequence),
                &decision.payload_digest,
                &format!("cas:{}", decision.payload_digest),
                "application/vnd.crucible.recorded-decision-payload+text",
                &decision.payload.len().to_string(),
            ],
        );
    }
    artifact_line(
        &mut text,
        &["payload", &scenario_digest, &hex_bytes(&scenario_bytes)],
    );
    for decision in &decisions {
        artifact_line(
            &mut text,
            &[
                "payload",
                &decision.payload_digest,
                &hex_bytes(decision.payload.as_bytes()),
            ],
        );
    }
    artifact_line(
        &mut text,
        &[
            "schedule",
            &replay_to_savepoint_schedule_digest(&decisions),
            &decisions.len().to_string(),
        ],
    );
    for decision in &decisions {
        artifact_line(
            &mut text,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    artifact_line(
        &mut text,
        &[
            "fingerprint",
            "0",
            &content_address_bytes(b"process-replay-to"),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "sampling",
            "every-fingerprint-sample",
            "final",
            "1",
            "execution-fingerprint-stream",
        ],
    );
    Ok(text)
}

fn replay_to_savepoint_decision_fixtures(
    schedule: &crucible::Schedule,
) -> Vec<ReplayToSavepointDecisionFixture> {
    schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(index, decision)| {
            let payload = format!("{decision:?}");
            let kind = match decision {
                crucible::Decision::DeliveryOrder(_) => "delivery-order",
                crucible::Decision::FaultFires(_) => "fault-fires",
                crucible::Decision::RngDraw(_) => "rng-draw",
                crucible::Decision::Override(_) => "override",
                crucible::Decision::Preemption(_) => "preemption",
                crucible::Decision::AppRandom(_) => "app-random",
                crucible::Decision::ControlFault(_) => "control-fault",
            };
            ReplayToSavepointDecisionFixture {
                sequence: index as u64,
                virtual_time_ticks: index as u64 + 1,
                node: String::from("search"),
                kind: kind.to_owned(),
                payload_digest: content_address_bytes(payload.as_bytes()),
                payload,
            }
        })
        .collect()
}

fn replay_to_savepoint_schedule_digest(decisions: &[ReplayToSavepointDecisionFixture]) -> String {
    let mut material = String::new();
    for decision in decisions {
        artifact_line(
            &mut material,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

fn savepoint_handle_text(
    form: &crucible::ScenarioDefForm,
    schedule: &crucible::Schedule,
    checkpoint: &crucible::Checkpoint,
) -> Result<String, Box<dyn Error>> {
    let scenario = form.scenario_def();
    let scenario_payload = form.to_compact_binary();
    let schedule_payload = schedule.to_compact_binary();
    let mut text = String::new();
    artifact_line(&mut text, &["schema", "crucible.savepoint-handle.v2"]);
    artifact_line(&mut text, &["label", "process-replay-to"]);
    artifact_line(
        &mut text,
        &[
            "checkpoint",
            &crucible::ContentAddressedBlobRef::from_hash(checkpoint.id).to_uri(),
        ],
    );
    artifact_line(
        &mut text,
        &["scenario", &scenario.id().to_hex(), "process-replay-to.scn"],
    );
    artifact_line(
        &mut text,
        &[
            "scenario-payload",
            &content_address_bytes(&scenario_payload),
            &hex_bytes(&scenario_payload),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "schedule-payload",
            &content_address_bytes(&schedule_payload),
            &hex_bytes(&schedule_payload),
        ],
    );
    artifact_line(
        &mut text,
        &["frontier", &checkpoint.virtual_time.ticks.to_string()],
    );
    artifact_line(&mut text, &["at", "quiescence"]);
    artifact_line(&mut text, &["terminal-condition", "quiescence"]);
    artifact_line(&mut text, &["materialization", "create-savepoint", "reply"]);
    artifact_line(&mut text, &["oracle", "fat==thin-passed"]);
    artifact_line(
        &mut text,
        &[
            "canonical-log",
            &content_address_bytes(b"process-replay-to-canonical-log"),
        ],
    );
    Ok(text)
}

fn scenario_identity_bytes(scenario: &crucible::ScenarioDef) -> Vec<u8> {
    format!(
        "scenario_id={}\nseed={}\napp_random_draw_cap={}\n",
        scenario.id().to_hex(),
        scenario.seed().to_hex(),
        scenario.app_random_draw_cap()
    )
    .into_bytes()
}

fn content_address_bytes(bytes: &[u8]) -> String {
    format!("crucible-hash:{}", hex_bytes(&stable_digest(bytes)))
}

fn stable_digest(material: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ lane;
        for byte in b"crucible.reproduction.hash.v1"
            .iter()
            .copied()
            .chain([0xff])
            .chain(material.iter().copied())
        {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        output[lane as usize * 8..lane as usize * 8 + 8].copy_from_slice(&state.to_be_bytes());
    }
    output
}

fn artifact_line(text: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            text.push('\t');
        }
        text.push_str(&escape_artifact_field(field));
    }
    text.push('\n');
}

fn escape_artifact_field(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        match byte {
            b'%' => escaped.push_str("%25"),
            b'\t' => escaped.push_str("%09"),
            b'\n' => escaped.push_str("%0A"),
            b'\r' => escaped.push_str("%0D"),
            _ => escaped.push(char::from(byte)),
        }
    }
    escaped
}

fn single_reproduction_artifact(artifact_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let mut paths = fs::read_dir(artifact_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let file_name = path.file_name()?.to_str()?;
            (file_name.starts_with("repro-failed-") && file_name.ends_with(".crucible"))
                .then_some(path)
        })
        .collect::<Vec<_>>();
    paths.sort();
    match paths.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(invalid_data(format!(
            "expected one failed reproduction artifact in `{}`, found {}",
            artifact_dir.display(),
            paths.len()
        ))
        .into()),
    }
}

fn canonical_jsonl_from_reproduction_artifact(path: &Path) -> Result<String, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let mut payloads = BTreeMap::new();
    let mut decisions = Vec::new();
    for line in text.lines() {
        let fields = parse_artifact_fields(line)?;
        let Some(tag) = fields.first().map(String::as_str) else {
            continue;
        };
        match tag {
            "payload" if fields.len() == 3 => {
                payloads.insert(fields[1].clone(), hex_to_bytes(&fields[2])?);
            }
            "decision" if fields.len() == 6 => {
                decisions.push(ArtifactDecision {
                    sequence: fields[1].parse()?,
                    virtual_time_ticks: fields[2].parse()?,
                    node: fields[3].clone(),
                    kind: fields[4].clone(),
                    payload_digest: fields[5].clone(),
                });
            }
            _ => {}
        }
    }
    if decisions.is_empty() {
        return Err(invalid_data(format!(
            "artifact `{}` did not encode any replay decisions",
            path.display()
        ))
        .into());
    }

    let mut jsonl = String::new();
    for decision in decisions {
        let payload = payloads.get(&decision.payload_digest).ok_or_else(|| {
            invalid_data(format!(
                "artifact `{}` is missing payload `{}`",
                path.display(),
                decision.payload_digest
            ))
        })?;
        let summary = std::str::from_utf8(payload)?;
        jsonl.push_str(&format!(
            "{{\"seq\":{},\"virtual_time\":{},\"node\":{},\"kind\":{},\"summary\":{}}}\n",
            decision.sequence,
            decision.virtual_time_ticks,
            serde_json::to_string(&decision.node)?,
            serde_json::to_string(&decision.kind)?,
            serde_json::to_string(summary)?
        ));
    }
    Ok(jsonl)
}

fn parse_artifact_fields(line: &str) -> Result<Vec<String>, Box<dyn Error>> {
    line.split('\t').map(unescape_artifact_field).collect()
}

fn unescape_artifact_field(value: &str) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            output.push(ch);
            continue;
        }
        let high = chars
            .next()
            .ok_or_else(|| invalid_data(format!("truncated artifact escape in `{value}`")))?;
        let low = chars
            .next()
            .ok_or_else(|| invalid_data(format!("truncated artifact escape in `{value}`")))?;
        match (high, low) {
            ('2', '5') => output.push('%'),
            ('0', '9') => output.push('\t'),
            ('0', 'A') => output.push('\n'),
            ('0', 'D') => output.push('\r'),
            _ => {
                return Err(invalid_data(format!(
                    "unknown artifact escape %{high}{low} in `{value}`"
                ))
                .into());
            }
        }
    }
    Ok(output)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if hex.len() % 2 != 0 {
        return Err(invalid_data("hex payload has odd length").into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0]).ok_or_else(|| invalid_data("malformed hex payload"))?;
        let low = hex_nibble(chunk[1]).ok_or_else(|| invalid_data("malformed hex payload"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
