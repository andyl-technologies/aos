//! Checks actual retained descriptor/path revision and same-process boundaries.

// crucible-lint: allow panic-shortcut -- These source revision controls use assertions as the oracle.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::canonical;

fn installed(path: &Path, bytes: &[u8]) -> CurrentFiles {
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let originals = (0..10)
        .map(|_| original(path, &reference).unwrap())
        .collect();
    CurrentFiles {
        originals,
        process: std::process::id(),
    }
}

#[test]
fn same_extent_mutation_revokes_the_original_measured_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    std::fs::write(&path, b"source-one").unwrap();
    let original = installed(&path, b"source-one");
    assert!(original.current().is_ok());

    std::fs::write(&path, b"source-two").unwrap();

    assert!(original.current().is_err());
}

#[test]
fn replacing_path_or_process_never_adopts_a_new_original() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    std::fs::write(&path, b"same-body").unwrap();
    let mut original = installed(&path, b"same-body");
    original.process = original.process.wrapping_add(1);
    assert!(original.current().is_err());
    original.process = std::process::id();
    let replacement = directory.path().join("replacement");
    std::fs::write(&replacement, b"same-body").unwrap();

    std::fs::rename(replacement, &path).unwrap();

    assert!(original.current().is_err());
}

#[test]
fn graph_callback_replacement_revokes_source_before_dispatch() {
    use std::cell::Cell;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let replacement = directory.path().join("replacement");
    std::fs::write(&path, b"same-body").unwrap();
    std::fs::write(&replacement, b"same-body").unwrap();
    let original = installed(&path, b"same-body");
    assert!(original.current().is_ok());
    let graph_live = Cell::new(true);
    let native_live = Cell::new(true);
    let graph_reads = Cell::new(0);
    let source_reads = Cell::new(0);
    let dispatches = Cell::new(0);

    let result = super::super::policy::read_source_after_graph(
        || {
            // The independent predicate succeeds and keeps its own scope live,
            // but replaces a source path after the earlier issuance check.
            std::fs::rename(&replacement, &path).unwrap();
            graph_reads.set(graph_reads.get() + 1);
            assert!(graph_live.get());
            Ok(())
        },
        || {
            source_reads.set(source_reads.get() + 1);
            original.current()
        },
    );
    if result.is_ok() {
        dispatches.set(dispatches.get() + 1);
    }

    assert!(result.is_err());
    assert!(graph_live.get());
    assert!(native_live.get());
    assert_eq!(graph_reads.get(), 1);
    assert_eq!(source_reads.get(), 1);
    assert_eq!(dispatches.get(), 0);
}

#[test]
fn failed_graph_read_never_reaches_source_or_dispatch() {
    let source_reads = std::cell::Cell::new(0);
    let result = super::super::policy::read_source_after_graph(
        || Err(refused()),
        || {
            source_reads.set(source_reads.get() + 1);
            Ok(())
        },
    );

    assert!(result.is_err());
    assert_eq!(source_reads.get(), 0);
}
