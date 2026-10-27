//! Checks actual retained descriptor/path revision and same-process boundaries.

// crucible-lint: allow panic-shortcut -- These source revision controls use assertions as the oracle.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_format::canonical;
use std::fs::File;

fn installed(path: &Path, bytes: &[u8]) -> CurrentFiles {
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let originals = (0..10)
        .map(|_| original(path, &reference, None).unwrap())
        .collect();
    CurrentFiles {
        originals,
        process: std::process::id(),
        revoked: Cell::new(false),
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
    let foreign_process = installed(&path, b"same-body");
    let original = installed(&path, b"same-body");
    let mut foreign_process = foreign_process;
    foreign_process.process = foreign_process.process.wrapping_add(1);
    assert!(foreign_process.current().is_err());
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

#[test]
fn original_peer_bytes_require_full_credit_and_exact_installed_content() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-peer-model");
    let bytes = b"bounded-original-peer-model";
    std::fs::write(&path, bytes).unwrap();
    let original = installed(&path, bytes);
    let expected = canonical::content_ref(bytes, "text/plain").unwrap();
    let foreign = canonical::content_ref(b"different-original-peer---", "text/plain").unwrap();

    assert!(original.peer_content(&expected, bytes.len() - 1).is_err());
    assert!(original.peer_content(&foreign, bytes.len()).is_err());
    assert_eq!(
        original.peer_content(&expected, bytes.len()).unwrap(),
        bytes
    );
    assert!(original.current().is_ok());
}

#[test]
fn source_revision_replacement_never_returns_new_peer_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-peer-model");
    let bytes = b"bounded-original-peer-model";
    std::fs::write(&path, bytes).unwrap();
    let original = installed(&path, bytes);
    let expected = canonical::content_ref(bytes, "text/plain").unwrap();
    let replacement = directory.path().join("replacement");
    std::fs::write(&replacement, bytes).unwrap();

    std::fs::rename(replacement, &path).unwrap();

    assert!(original.peer_content(&expected, bytes.len()).is_err());
}

#[test]
fn observed_same_inode_byte_drift_remains_revoked_after_restoration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    let original = installed(&path, bytes);
    let inode = std::fs::metadata(&path).unwrap().ino();
    assert!(original.current().is_ok());

    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .write_all_at(b"source-two", 0)
        .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert!(original.current().is_err());
    std::fs::write(&path, bytes).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(original.current().is_err());
}

#[test]
fn complete_positional_validation_preserves_the_retained_descriptor_cursor() {
    use std::io::{Seek, SeekFrom};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    let original = installed(&path, bytes);
    let mut cursor = original.originals[0].file.file();
    cursor.seek(SeekFrom::Start(4)).unwrap();

    assert!(original.current().is_ok());

    assert_eq!(cursor.stream_position().unwrap(), 4);
}

fn leased(path: &Path, bytes: &[u8]) -> CurrentFiles {
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let originals = (0..10)
        .map(|_| original(path, &reference, Some(&owner)).unwrap())
        .collect();
    let files = CurrentFiles {
        originals,
        process: std::process::id(),
        revoked: Cell::new(false),
    };
    assert!(
        files
            .originals
            .iter()
            .all(|original| original.file.lease().is_some())
    );
    files
}

#[test]
fn kernel_pending_break_revokes_before_write_and_survives_restoration() {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    let files = leased(&path, bytes);
    assert!(files.current().is_ok());

    let writer = File::options()
        .write(true)
        .custom_flags(i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap())
        .open(&path);

    assert_eq!(
        writer.unwrap_err().raw_os_error(),
        Some(rustix::io::Errno::AGAIN.raw_os_error())
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(files.current().is_err());
    // Keep the actual original tokens throughout the kernel's unchanged
    // forced-break timeout. No public unlock, replacement or reacquire is used.
    // The independent writer eventually proceeds, but observed refusal sticks.
    std::fs::write(&path, b"source-two").unwrap();
    std::fs::write(&path, bytes).unwrap();

    assert!(files.current().is_err());
}

#[test]
fn leased_source_namespace_replacement_still_revokes_currentness() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let replacement = directory.path().join("replacement");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    std::fs::write(&replacement, bytes).unwrap();
    let files = leased(&path, bytes);
    assert!(files.current().is_ok());

    std::fs::rename(&replacement, &path).unwrap();

    assert!(files.current().is_err());
}

#[test]
fn conflicting_writer_keeps_complete_byte_validation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    let writer = File::options().write(true).open(&path).unwrap();
    let owner = Arc::new(LinuxReadLeaseOwner::new().unwrap());
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let originals = (0..10)
        .map(|_| original(&path, &reference, Some(&owner)).unwrap())
        .collect();
    let files = CurrentFiles {
        originals,
        process: std::process::id(),
        revoked: Cell::new(false),
    };
    assert!(
        files
            .originals
            .iter()
            .all(|original| original.file.lease().is_none())
    );
    assert!(files.current().is_ok());

    writer.write_all_at(b"source-two", 0).unwrap();

    assert!(files.current().is_err());
    writer.write_all_at(bytes, 0).unwrap();
    assert!(files.current().is_err());
}

#[test]
fn copied_callback_answer_refuses_a_break_during_the_callback_interval() {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("public-source");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    let files = leased(&path, bytes);
    files.current().unwrap();
    let answer = bytes.to_vec();

    // Simulate an actual conflicting writer between callback entry and exit.
    // Complete unchanged bytes cannot hide this pending kernel lease break.
    let writer = File::options()
        .write(true)
        .custom_flags(i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap())
        .open(&path);
    assert_eq!(
        writer.unwrap_err().raw_os_error(),
        Some(rustix::io::Errno::AGAIN.raw_os_error())
    );

    let result = current_answer(answer, || files.current());

    assert!(result.is_err());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(files.current().is_err());
}

#[test]
fn complete_profile_uses_terminal_full_bytes_with_same_descriptor_and_sticky_drift() {
    use std::io::{Seek, SeekFrom};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("complete-original");
    let bytes = b"source-one";
    std::fs::write(&path, bytes).unwrap();
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let files = complete_byte_originals(&[(path.as_path(), &reference); 10]).unwrap();
    assert!(
        files
            .originals
            .iter()
            .all(|original| original.file.lease().is_none())
    );
    let mut descriptor = files.originals[0].file.file();
    descriptor.seek(SeekFrom::Start(4)).unwrap();

    files.current().unwrap();
    assert_eq!(descriptor.stream_position().unwrap(), 4);
    let writer = File::options().write(true).open(&path).unwrap();
    writer.write_all_at(b"source-two", 0).unwrap();
    assert!(files.current().is_err());
    writer.write_all_at(bytes, 0).unwrap();

    assert!(files.current().is_err());
    assert!(
        files
            .originals
            .iter()
            .all(|original| original.file.lease().is_none())
    );
}

#[test]
fn complete_profile_equal_replacement_never_adopts_the_replacement_descriptor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("complete-original");
    let replacement = directory.path().join("replacement");
    let bytes = b"original";
    std::fs::write(&path, bytes).unwrap();
    std::fs::write(&replacement, bytes).unwrap();
    let reference = canonical::content_ref(bytes, "text/plain").unwrap();
    let files = complete_byte_originals(&[(path.as_path(), &reference); 10]).unwrap();
    let original_inode = files.originals[0].file.file().metadata().unwrap().ino();

    std::fs::rename(&replacement, &path).unwrap();

    assert!(files.current().is_err());
    assert_eq!(
        files.originals[0].file.file().metadata().unwrap().ino(),
        original_inode
    );
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), original_inode);
}

#[test]
fn complete_descriptor_observer_counts_actual_spare_banks_and_distinct_same_path_opens() {
    use crate::node_qualification::packet_collection::complete::retained::Counter;
    use std::mem::{align_of, size_of};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("actual-original-body");
    std::fs::write(&path, b"same-body").unwrap();
    let mut files = installed(&path, b"same-body");
    let mut before = Counter::new(1024 * 1024);
    files.charge_retained_storage(&mut before).unwrap();

    let old_slots = files.originals.capacity();
    let old_path = files.originals[0].path.capacity();
    let old_media = files.originals[0].content.media_type.capacity();
    files.originals.reserve_exact(64);
    files.originals[0].path.reserve(4096);
    files.originals[0].content.media_type.reserve(8192);
    let added = (files.originals.capacity() - old_slots) * size_of::<Original>()
        + files.originals[0].path.capacity()
        - old_path
        + files.originals[0].content.media_type.capacity()
        - old_media;
    let mut after = Counter::new(1024 * 1024);
    files.charge_retained_storage(&mut after).unwrap();
    assert_eq!(after.bytes(), before.bytes() + added);

    // Ten independent opens share a pathname, never their Arc<File> backing.
    let header = size_of::<File>()
        + 2 * size_of::<usize>()
        + 2 * (align_of::<File>().max(align_of::<usize>()) - 1);
    let nested = files
        .originals
        .iter()
        .map(|original| {
            original.path.capacity()
                + original.content.hash.algorithm.capacity()
                + original.content.hash.domain.capacity()
                + original.content.hash.digest.capacity()
                + original.content.media_type.capacity()
        })
        .sum::<usize>();
    assert_eq!(
        after.bytes(),
        files.originals.capacity() * size_of::<Original>() + nested + 10 * header
    );
    let mut insufficient = Counter::new(after.bytes() - 1);
    assert!(files.charge_retained_storage(&mut insufficient).is_err());
}
