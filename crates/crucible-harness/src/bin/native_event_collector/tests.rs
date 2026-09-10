//! Collector fixture and fail-closed regressions.

use super::*;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::symlink;
use std::sync::mpsc;
use std::time::Duration;

const SCENARIO: &str = "0c02b73f03b4705aec03a2989bfeb13dc7be67730f7c79994dd44a2b6265da69";

#[test]
fn collector_decodes_inventory_lifecycle_and_prerequisites() {
    let fixture = fixture_root();
    let scenario_source = fixture.path().join("scenario.toml");
    fs::write(
        &scenario_source,
        r#"
[[plan.event]]
id = "pass-on-ready"
[plan.event.trigger]
kind = "assertion_state"
name = "guest-ready"
state = "satisfied"
[plan.event.action]
kind = "pass"

[[properties.assertion]]
id = "guest-ready"
[properties.assertion.property]
kind = "sometimes"
[properties.assertion.property.predicate]
kind = "guest_marker"
marker = "guest-ready"
"#,
    )
    .expect("write scenario source");
    let root = fixture.path().join(SCENARIO);
    let report = collect(
        Args::parse(
            [
                "--root",
                root.to_str().expect("root UTF-8"),
                "--scenario-source",
                scenario_source.to_str().expect("source UTF-8"),
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("parse collector arguments"),
    )
    .expect("collect fixture");

    assert_eq!(report.objects.count, 1);
    assert_eq!(report.events.entries, 1);
    assert_eq!(report.events.kind_counts.get("guest_marker"), Some(&1));
    assert_eq!(report.events.sequence_minimum, Some(7));
    assert_eq!(report.lifecycle.phase, "committed");
    assert_eq!(report.lifecycle.current_generations["guest"].generation, 2);
    assert_eq!(
        report.prerequisites.pass_events[0].assertion_state_requirements[0]
            .canonical_material_matches,
        0
    );
    assert_eq!(
        report.prerequisites.guest_marker_assertions[0].canonical_material_matches,
        1
    );
}

#[test]
fn collector_rejects_corrupt_objects_and_truncated_segments() {
    let fixture = fixture_root();
    let root = fixture.path().join(SCENARIO);
    let object = only_object(&root);
    fs::write(&object, b"changed").expect("replace object");
    let error = collect(args_for_root(&root)).expect_err("corruption must fail");
    assert!(error.contains("hashes to"));

    let bytes = event_segment(7, "guest_marker", &guest_marker_material("guest-ready"));
    let truncated = &bytes[..bytes.len() - 1];
    replace_object(&root, truncated);
    let error = collect(args_for_root(&root)).expect_err("truncation must fail");
    assert!(error.contains("truncated entry material"));
}

#[test]
fn collector_enforces_object_and_byte_bounds() {
    let fixture = fixture_root();
    let root = fixture.path().join(SCENARIO);
    let mut args = args_for_root(&root);
    args.bounds.objects = 1;
    args.bounds.object_bytes = 4;
    let error = collect(args).expect_err("object byte bound must fail");
    assert!(error.contains("above bound 4"));
}

#[test]
fn decoder_rejects_binary_header_that_disagrees_with_authenticated_material() {
    let mut bytes = event_segment(7, "guest_marker", &guest_marker_material("guest-ready"));
    bytes[60..68].copy_from_slice(&8_u64.to_le_bytes());

    let error = segment::decode(&bytes, 1).expect_err("header mismatch must fail");

    assert!(error.contains("differs from material 7"));
}

#[test]
fn bounded_reader_rejects_symlinks_and_fifos_without_blocking() {
    let fixture = tempfile::tempdir().expect("create input fixture");
    let regular = fixture.path().join("regular");
    let link = fixture.path().join("link");
    fs::write(&regular, b"data").expect("write regular file");
    symlink(&regular, &link).expect("create symlink");
    let error = read_bounded_file(&link, 4, "test input").expect_err("symlink must fail");
    assert!(error.contains("Too many levels of symbolic links"));

    let fifo = fixture.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .expect("create FIFO");
    let (sender, receiver) = mpsc::channel();
    let fifo_for_reader = fifo.clone();
    let reader = std::thread::spawn(move || {
        sender
            .send(read_bounded_file(&fifo_for_reader, 4, "test input"))
            .expect("return FIFO result");
    });
    let result = match receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(error) => {
            let _unblock = fs::OpenOptions::new().read(true).write(true).open(&fifo);
            reader.join().expect("join unblocked FIFO reader");
            panic!("FIFO read did not return within one second: {error}");
        }
    };
    reader.join().expect("join FIFO reader");
    let error = result.expect_err("FIFO must fail");
    assert!(error.contains("not a regular file"));
}

fn fixture_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("create fixture root");
    let scenario = root.path().join(SCENARIO);
    fs::create_dir_all(scenario.join("checkpoint-objects")).expect("create object directory");
    fs::create_dir_all(scenario.join("checkpoint-closures")).expect("create closure directory");
    let bytes = event_segment(7, "guest_marker", &guest_marker_material("guest-ready"));
    replace_object(&scenario, &bytes);
    fs::write(
        scenario.join("run-state.json"),
        format!(
            r#"{{
  "version": 2,
  "runtime_event_records": 1,
  "runtime_event_log_bytes": 0,
  "manifest": {{
    "scenario": "{SCENARIO}",
    "processes": {{"guest": {{"process_id": 22, "start_time_ticks": 30}}}}
  }},
  "journal": {{
    "transaction": 1,
    "phase": "committed",
    "nodes": [],
    "completed_exits": [{{
      "transaction": 1,
      "node": "guest",
      "generation": 1,
      "transition": "Crash",
      "expected_exit_code": 70,
      "observed_exit_code": 70
    }}]
  }}
}}"#
        ),
    )
    .expect("write run state");
    root
}

fn args_for_root(root: &Path) -> Args {
    Args::parse(
        ["--root", root.to_str().expect("root UTF-8")]
            .into_iter()
            .map(OsString::from),
    )
    .expect("parse root arguments")
}

fn only_object(root: &Path) -> PathBuf {
    let shard = fs::read_dir(root.join("checkpoint-objects"))
        .expect("read object directory")
        .next()
        .expect("one shard")
        .expect("read shard");
    fs::read_dir(shard.path())
        .expect("read shard")
        .next()
        .expect("one object")
        .expect("read object")
        .path()
}

fn replace_object(root: &Path, bytes: &[u8]) {
    let objects = root.join("checkpoint-objects");
    if objects.exists() {
        fs::remove_dir_all(&objects).expect("remove old object directory");
    }
    let identity = blake3::hash(bytes).to_hex().to_string();
    let shard = objects.join(&identity[..2]);
    fs::create_dir_all(&shard).expect("create object shard");
    fs::write(shard.join(identity), bytes).expect("write object");
}

fn event_segment(sequence: u64, kind: &str, material: &str) -> Vec<u8> {
    let material = format!(
        "sequence={sequence}\nat_virtual_time_ticks=100\nat_icount_retired=99\nevent_payload.kind={kind}\n{material}"
    );
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CRUCIBLE-ELOGSEG");
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&[0_u8; 32]);
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&100_u64.to_le_bytes());
    bytes.extend_from_slice(&99_u64.to_le_bytes());
    bytes.push(0);
    write_string(&mut bytes, "entry.source=host");
    bytes.push(2);
    bytes.push(0);
    write_string(&mut bytes, kind);
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&segment::entry_content_hash(material.as_bytes()));
    write_string(&mut bytes, &material);
    bytes
}

fn guest_marker_material(marker: &str) -> String {
    format!(
        "event_payload.attribute.marker_kind.value.value=event\nevent_payload.attribute.marker.value.value={marker}"
    )
}

fn write_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
