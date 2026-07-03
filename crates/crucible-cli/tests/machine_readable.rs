//! Process-level checks for machine-readable CLI stdout.

use std::error::Error;
use std::fs;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn cli_exit_machine_readable_process_stdout_is_pure_json() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixture = crucible::happy_path_scenario()?;
    let scenario = temp.path().join("scenario.toml");
    fs::write(&scenario, fixture.scenario.to_canonical_toml()?)?;

    let jsonl_stdout = run_machine_readable("jsonl", &scenario)?;
    let jsonl_lines = jsonl_stdout.lines().collect::<Vec<_>>();
    assert!(!jsonl_lines.is_empty(), "jsonl stdout must not be empty");
    for line in &jsonl_lines {
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "jsonl stdout must contain only JSON object lines, got `{line}`",
        );
        assert!(
            !line.starts_with("crucible:"),
            "jsonl stdout must not contain human text, got `{line}`",
        );
    }
    let final_line = jsonl_lines
        .last()
        .ok_or("jsonl stdout should include a final outcome line")?;
    assert!(final_line.contains("\"kind\":\"final_outcome\""));
    assert!(final_line.contains("exit_code=0"));

    let json_stdout = run_machine_readable("json", &scenario)?;
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
    assert!(json_stdout.contains("\"kind\":\"final_outcome\""));
    assert!(json_stdout.contains("exit_code=0"));

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
    for line in stdout.lines() {
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "jsonl stdout must contain only JSON object lines, got `{line}`",
        );
    }
    assert!(stdout.contains("\"kind\":\"save_export\""));
    assert!(stdout.contains("out="));
    assert!(stdout.contains(".crucible-savepoint"));

    let handles = fs::read_dir(&artifact_dir)?.collect::<Result<Vec<_>, _>>()?;
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

fn run_machine_readable(
    format: &str,
    scenario: &std::path::Path,
) -> Result<String, Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args([
            "--format",
            format,
            "--backend",
            "double",
            "--seed",
            "1",
            "run",
        ])
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
