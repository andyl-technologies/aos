//! Checks native scalar directives with the retained systemd unit parser.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;

use super::{Definition, definition_for};

fn write_definition(directory: &Path, definition: &Definition) -> PathBuf {
    let path = directory.join(&definition.unit);
    fs::write(&path, &definition.text).unwrap();
    path
}

fn verify(directory: &Path, units: &[PathBuf]) -> Output {
    let analyzer = std::env::var_os("AOS_SYSTEMD_ANALYZE")
        .expect("systemd-parser-tests requires the retained AOS systemd-analyze");
    let vendor = std::env::var_os("AOS_SYSTEMD_UNIT_PATH")
        .expect("systemd-parser-tests requires the retained vendor unit directory");
    let search_path = std::env::join_paths([directory, Path::new(&vendor)]).unwrap();
    Command::new(analyzer)
        .args(["verify", "--man=no", "--generators=no"])
        .args(units)
        .env("SYSTEMD_UNIT_PATH", search_path)
        .env("LC_ALL", "C")
        .output()
        .unwrap()
}

#[test]
fn generated_resources_pass_actual_systemd_parser() {
    let directory = tempfile::tempdir().unwrap();
    let shell = std::env::var_os("AOS_SYSTEMD_PARSER_SHELL")
        .expect("systemd-parser-tests requires the retained AOS Bash");
    let service = directory.path().join("native-parser-target.service");
    fs::write(
        &service,
        format!(
            "[Unit]\nDescription=Parser target\n[Service]\nType=oneshot\nExecStart={} -c 'exit 0'\n",
            Path::new(&shell).display()
        ),
    )
    .unwrap();

    let revision = "a".repeat(64);
    let cases = [
        (
            "home",
            "mount",
            json!({
                "name": "root home", "source": "/dev/mapper/root-home", "destination": "/root",
                "filesystem": "ext4", "options": ["nodev", "nosuid"], "optional": true
            }),
        ),
        (
            "escaped",
            "mount",
            json!({
                "name": "literal percent % and backslash \\ character",
                "source": "/srv/data % path\\source", "destination": "/run/native % path\\mount",
                "options": ["bind"], "optional": true, "timeout_millis": 5000
            }),
        ),
        (
            "swap",
            "swap",
            json!({
                "name": "encrypted swap", "source": "/dev/mapper/cryptswap", "priority": 20
            }),
        ),
        (
            "calendar",
            "scheduledActivation",
            json!({
                "name": "calendar", "target": "native-parser-target.service",
                "schedule": {"kind": "calendar", "expression": "Sun *-*-* 02:00:00"},
                "persistent": true, "accuracy_millis": 1000, "randomized_delay_millis": 45000
            }),
        ),
        (
            "interval",
            "scheduledActivation",
            json!({
                "name": "interval", "target": "native-parser-target.service",
                "schedule": {"kind": "interval", "initial_delay_millis": 1000, "interval_millis": 5000}
            }),
        ),
    ];
    let mut units = vec![service];
    for (id, ability, input) in cases {
        let definition = definition_for(id, &revision, ability, &input).unwrap();
        units.push(write_definition(directory.path(), &definition));
    }

    let output = verify(directory.path(), &units);
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "systemd rejected generated units: {diagnostics}"
    );
    for rejected in ["Failed to parse", "ignoring:", "Refusing."] {
        assert!(
            !diagnostics.contains(rejected),
            "systemd discarded a generated directive: {diagnostics}"
        );
    }
}

#[test]
fn old_quoted_scalars_are_rejected_by_actual_parser() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("root.mount");
    fs::write(
        &path,
        "[Unit]\nDescription=Old quoted scalar\n[Mount]\nWhat=\"/dev/mapper/root-home\"\nWhere=\"/root\"\nType=\"ext4\"\n",
    )
    .unwrap();

    let timer = directory.path().join("old-quoted.timer");
    fs::write(
        &timer,
        "[Timer]\nUnit=\"native-parser-target.service\"\nOnCalendar=\"daily\"\n",
    )
    .unwrap();

    // Mount units may infer Where from their filename after discarding the
    // invalid scalar. The timer must fail, and the mount diagnostic must still
    // prove its authored directive was rejected rather than interpreted.
    let output = verify(directory.path(), &[path, timer]);
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "old quoted timer scalars were accepted"
    );
    assert!(
        diagnostics.contains("Where= path is not absolute"),
        "unexpected parser rejection: {diagnostics}"
    );
    assert!(
        diagnostics.contains("Timer unit lacks value setting"),
        "quoted calendar was not rejected: {diagnostics}"
    );
}
