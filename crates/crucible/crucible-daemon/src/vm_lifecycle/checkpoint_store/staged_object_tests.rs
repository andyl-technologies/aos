//! Staged closure object tests: streamed snapshot bytes, boundary refusal,
//! fail-closed publication, and cleanup.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use super::*;
use crucible_engine::{Icount, VirtualTime};

fn node() -> NodeId {
    NodeId {
        name: String::from("staged-object-node"),
    }
}

fn snapshot_fixture() -> ExactSnapshotHandle {
    let definition = crucible_engine::ScenarioDef::from_canonical_material(
        "crucible.test.api.staged-object",
        "staged object",
    );
    let configuration = Configuration::genesis(definition);
    let checkpoint = crucible_engine::Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime { ticks: 0 },
        BTreeMap::from([(node(), Icount { retired: 0 })]),
        crucible_engine::CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("build staged-object checkpoint");
    ExactSnapshotHandle::diskless(checkpoint).expect("build staged-object snapshot")
}

fn staged_file_count(directory: &Path) -> usize {
    fs::read_dir(directory)
        .expect("list staging directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".staged-"))
        .count()
}

#[test]
fn a_staged_snapshot_holds_the_canonical_envelope_and_its_identity() {
    let directory = tempfile::tempdir().expect("create staging directory");
    let snapshot = snapshot_fixture();
    let expected = snapshot
        .to_canonical_bytes()
        .expect("encode canonical snapshot");

    let staged =
        stage_snapshot_with_boundary(directory.path(), &node(), &snapshot, u64::MAX, &mut || {
            Ok(())
        })
        .expect("stage snapshot");

    assert_eq!(fs::read(staged.path()).expect("read staged file"), expected);
    assert_eq!(staged.identity(), ContentHash::from_bytes(&expected));
    assert_eq!(staged.length(), expected.len() as u64);

    drop(staged);
    assert_eq!(staged_file_count(directory.path()), 0);
}

#[test]
fn a_boundary_refusal_stops_staging_and_removes_the_file() {
    let directory = tempfile::tempdir().expect("create staging directory");
    let snapshot = snapshot_fixture();
    let mut calls = 0_u32;

    let error =
        stage_snapshot_with_boundary(directory.path(), &node(), &snapshot, u64::MAX, &mut || {
            calls += 1;
            if calls == 2 {
                return Err(store_error("canceled while staging"));
            }
            Ok(())
        })
        .expect_err("a refused boundary must stop staging");

    assert!(
        error.to_string().contains("canceled while staging"),
        "{error}"
    );
    assert_eq!(staged_file_count(directory.path()), 0);
}

#[test]
fn an_over_limit_snapshot_reports_its_node() {
    let directory = tempfile::tempdir().expect("create staging directory");

    let error = stage_snapshot_with_boundary(
        directory.path(),
        &node(),
        &snapshot_fixture(),
        64,
        &mut || Ok(()),
    )
    .expect_err("a 64-byte ceiling must reject the envelope");

    assert!(error.to_string().contains("staged-object-node"), "{error}");
    assert_eq!(staged_file_count(directory.path()), 0);
}

#[test]
fn publication_links_the_staged_file_and_reuses_an_existing_object() {
    let directory = tempfile::tempdir().expect("create object directory");
    let bytes = b"staged closure object".repeat(1024);

    let staged =
        stage_bytes_with_boundary(directory.path(), &bytes, &mut || Ok(())).expect("stage bytes");
    persist_staged_object_with_boundary(directory.path(), &staged, &mut || Ok(()))
        .expect("publish staged object");
    persist_staged_object_with_boundary(directory.path(), &staged, &mut || Ok(()))
        .expect("an existing object is reused");
    drop(staged);

    let stored = LocalDagStore::new(directory.path())
        .get(&ContentHash::from_bytes(&bytes))
        .expect("read published object");
    assert_eq!(stored, bytes);
    assert_eq!(staged_file_count(directory.path()), 0);
}

#[test]
fn publication_refuses_a_staged_file_changed_after_staging() {
    let directory = tempfile::tempdir().expect("create object directory");
    let bytes = b"original staged bytes".to_vec();
    let staged =
        stage_bytes_with_boundary(directory.path(), &bytes, &mut || Ok(())).expect("stage bytes");
    fs::write(staged.path(), b"tampered staged bytes").expect("tamper with staged file");

    persist_staged_object_with_boundary(directory.path(), &staged, &mut || Ok(()))
        .expect_err("a changed staged file must fail closed");

    assert!(!object_path(directory.path(), staged.identity()).exists());
}
