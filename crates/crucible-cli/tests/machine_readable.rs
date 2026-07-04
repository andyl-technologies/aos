//! Process-level checks for machine-readable CLI stdout.

use std::error::Error;
use std::fs;
use std::io;
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

fn run_machine_readable(
    format: &str,
    scenario: &std::path::Path,
    artifact_dir: &std::path::Path,
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
