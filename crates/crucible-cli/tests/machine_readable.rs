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

#[derive(Debug)]
struct ArtifactDecision {
    sequence: u64,
    virtual_time_ticks: u64,
    node: String,
    kind: String,
    payload_digest: String,
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
