//! Real backing-file identities, incomplete captures, and bounded refusal reports.

use super::*;

fn process_fixture(directory: &Path, inode: u64) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory.join("fd"))?;
    fs::create_dir_all(directory.join("fdinfo"))?;
    let mut fields = vec!["0"; 20];
    fields[0] = "R";
    fields[1] = "17";
    fields[19] = "12345";
    fs::write(
        directory.join("stat"),
        format!("31 (qemu fixture) {}", fields.join(" ")),
    )?;
    fs::write(
        directory.join("maps"),
        format!("1000-2000 rw-s 00000000 00:01 {inode} /memfd:crucible-qemu-shmem (deleted)\n"),
    )?;
    Ok(())
}

fn overlay_fixture(directory: &Path) -> Result<fs::File, Box<dyn Error>> {
    use std::os::fd::AsFd;

    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(directory.join("crucible-root-overlay.qcow2"))?;
    symlink(
        directory.join("crucible-root-overlay.qcow2"),
        directory.join("fd/42"),
    )?;
    let flags = rustix::fs::fcntl_getfl(file.as_fd())?;
    fs::write(
        directory.join("fdinfo/42"),
        format!("flags:\t{:o}\n", flags.bits()),
    )?;
    Ok(file)
}

#[test]
fn resource_reader_retains_real_writable_overlay_identity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 71)?;
    let overlay = overlay_fixture(directory.path())?;
    let metadata = overlay.metadata()?;
    let mut incomplete = None;
    let mut partial = None;

    let resources = qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?
        .ok_or("complete process fixture was unavailable")?;

    assert_eq!(resources.pid, 31);
    assert_eq!(resources.parent, 17);
    assert_eq!(resources.start_time_ticks, Some(12345));
    assert_eq!(resources.rings, BTreeSet::from([("00:01".into(), 71)]));
    assert_eq!(
        resources.overlays,
        BTreeSet::from([(metadata.dev(), metadata.ino())])
    );
    assert!(incomplete.is_none());
    Ok(())
}

#[test]
fn any_incomplete_descriptor_refuses_the_original_resource_snapshot() -> Result<(), Box<dyn Error>>
{
    for expected in [
        "fd-link-unreadable",
        "overlay-fdinfo-unreadable",
        "overlay-metadata-unreadable",
    ] {
        let directory = tempfile::tempdir()?;
        process_fixture(directory.path(), 73)?;
        let overlay = overlay_fixture(directory.path())?;
        match expected {
            "fd-link-unreadable" => {
                fs::write(directory.path().join("fd/99"), "not a descriptor link")?
            }
            "overlay-fdinfo-unreadable" => fs::remove_file(directory.path().join("fdinfo/42"))?,
            "overlay-metadata-unreadable" => {
                fs::remove_file(directory.path().join("crucible-root-overlay.qcow2"))?
            }
            _ => unreachable!(),
        }
        let mut incomplete = None;
        let mut partial = None;

        assert!(qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?.is_none());
        assert!(
            incomplete
                .as_deref()
                .is_some_and(|reason| reason.starts_with(expected))
        );
        assert!(
            incomplete
                .as_deref()
                .is_some_and(|reason| reason.contains("fd="))
        );
        let progress = partial
            .as_ref()
            .ok_or("incomplete FD lost prior process evidence")?;
        assert_eq!(progress.pid, 31);
        assert_eq!(progress.parent, 17);
        assert_eq!(progress.start_time_ticks, Some(12345));
        assert_eq!(progress.rings, BTreeSet::from([("00:01".into(), 73)]));
        let mut diagnostic = ForkDiagnostics::default();
        diagnostic.begin_sample();
        diagnostic.record(31, Some(progress), incomplete.as_deref());
        assert_eq!(diagnostic.incomplete, 1);
        assert!(diagnostic.rows.contains("parent=17"));
        assert!(diagnostic.rows.contains("resource_complete=false"));
        assert!(diagnostic.rows.contains(expected));
        drop(overlay);
    }
    Ok(())
}

#[test]
fn malformed_overlay_flags_keep_original_error_and_report_exact_step() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 75)?;
    let _overlay = overlay_fixture(directory.path())?;
    fs::write(directory.path().join("fdinfo/42"), "flags:\tnot-octal\n")?;
    let mut incomplete = None;
    let mut partial = None;

    let error = qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)
        .err()
        .ok_or("malformed flags did not refuse")?;

    assert_eq!(
        error.to_string(),
        "root-overlay descriptor omits its access flags"
    );
    assert_eq!(
        incomplete.as_deref(),
        Some("overlay-access-flags-malformed fd=\"42\"")
    );
    assert!(
        partial
            .as_ref()
            .is_some_and(|progress| progress.parent == 17 && !progress.rings.is_empty())
    );
    Ok(())
}

#[test]
fn actual_read_only_overlay_descriptor_never_becomes_writable_evidence()
-> Result<(), Box<dyn Error>> {
    use std::os::fd::AsFd;

    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 77)?;
    let _writable = overlay_fixture(directory.path())?;
    let read_only = fs::File::open(directory.path().join("crucible-root-overlay.qcow2"))?;
    let flags = rustix::fs::fcntl_getfl(read_only.as_fd())?;
    fs::write(
        directory.path().join("fdinfo/42"),
        format!("flags:\t{:o}\n", flags.bits()),
    )?;
    let mut incomplete = None;
    let mut partial = None;

    let observed = qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?
        .ok_or("complete read-only snapshot unavailable")?;

    assert!(observed.overlays.is_empty());
    let metadata = read_only.metadata()?;
    assert_eq!(
        observed.read_only_overlays,
        BTreeSet::from([(metadata.dev(), metadata.ino())])
    );
    assert!(incomplete.is_none());
    assert_eq!(
        pair_refusal(&source_resources(), &observed),
        Some("child-writable-overlay-set-empty")
    );
    Ok(())
}

#[test]
fn missing_maps_retains_parent_and_malformed_parent_keeps_original_parse_error()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 79)?;
    fs::remove_file(directory.path().join("maps"))?;
    let mut incomplete = None;
    let mut partial = None;

    assert!(qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?.is_none());
    assert_eq!(incomplete.as_deref(), Some("maps-unreadable"));
    assert!(
        partial
            .as_ref()
            .is_some_and(|progress| progress.parent == 17 && progress.rings.is_empty())
    );

    fs::write(
        directory.path().join("stat"),
        "31 (qemu fixture) R invalid-parent",
    )?;
    let error = qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)
        .err()
        .ok_or("invalid parent was accepted")?;
    assert_eq!(
        error.to_string(),
        "invalid-parent"
            .parse::<u32>()
            .err()
            .ok_or("invalid test parent parsed")?
            .to_string()
    );
    assert_eq!(incomplete.as_deref(), Some("process-parent-malformed"));
    assert!(partial.is_none());
    Ok(())
}

fn resources(pid: u32, inode: u64) -> QemuResources {
    QemuResources {
        pid,
        parent: 17,
        start_time_ticks: Some(9),
        rings: BTreeSet::from([("00:01".into(), inode)]),
        overlays: BTreeSet::from([(2, inode)]),
        read_only_overlays: BTreeSet::new(),
    }
}

fn source_resources() -> QemuResources {
    let mut source = resources(17, 81);
    source.parent = 7;
    source.read_only_overlays = std::mem::take(&mut source.overlays);
    source
}

#[test]
fn frozen_source_pair_requires_positive_read_only_basis_and_private_child() {
    let source = source_resources();
    let mut child = resources(31, 83);
    // The immutable ancestor may be shared, but never through a writable FD.
    child
        .read_only_overlays
        .clone_from(&source.read_only_overlays);
    assert!(pair_refusal(&source, &child).is_none());
    for expected in [
        "source-child-process-parent-mismatch",
        "source-child-process-start-time-unavailable",
        "source-ring-set-empty",
        "child-ring-set-empty",
        "source-read-only-overlay-set-empty",
        "child-writable-overlay-set-empty",
        "source-child-ring-sets-overlap",
        "source-read-only-basis-has-writable-alias",
        "child-writable-overlay-aliases-source-read-only-basis",
        "child-writable-overlay-has-read-only-alias",
        "source-child-writable-overlay-sets-overlap",
    ] {
        let mut source = source_resources();
        let mut child = resources(31, 83);
        match expected {
            "source-child-process-parent-mismatch" => child.parent = 99,
            "source-child-process-start-time-unavailable" => child.start_time_ticks = None,
            "source-ring-set-empty" => source.rings.clear(),
            "child-ring-set-empty" => child.rings.clear(),
            "source-read-only-overlay-set-empty" => source.read_only_overlays.clear(),
            "child-writable-overlay-set-empty" => child.overlays.clear(),
            "source-child-ring-sets-overlap" => child.rings.extend(source.rings.iter().cloned()),
            "source-read-only-basis-has-writable-alias" => source
                .overlays
                .extend(source.read_only_overlays.iter().copied()),
            "child-writable-overlay-aliases-source-read-only-basis" => child
                .overlays
                .extend(source.read_only_overlays.iter().copied()),
            "child-writable-overlay-has-read-only-alias" => {
                child.read_only_overlays.clone_from(&child.overlays)
            }
            "source-child-writable-overlay-sets-overlap" => {
                source.overlays.clone_from(&child.overlays)
            }
            _ => unreachable!(),
        }
        assert_eq!(pair_refusal(&source, &child), Some(expected));
    }
}

#[test]
fn resource_reader_authenticates_real_read_only_source_and_private_writable_child()
-> Result<(), Box<dyn Error>> {
    use std::os::fd::AsFd;

    let source_directory = tempfile::tempdir()?;
    let child_directory = tempfile::tempdir()?;
    process_fixture(source_directory.path(), 81)?;
    process_fixture(child_directory.path(), 83)?;
    let source_stat = fs::read_to_string(source_directory.path().join("stat"))?;
    fs::write(
        source_directory.path().join("stat"),
        source_stat
            .replacen("31 (", "17 (", 1)
            .replacen("R 17", "R 7", 1),
    )?;
    let _source_writer = overlay_fixture(source_directory.path())?;
    let source_file = fs::File::open(source_directory.path().join("crucible-root-overlay.qcow2"))?;
    let flags = rustix::fs::fcntl_getfl(source_file.as_fd())?;
    fs::write(
        source_directory.path().join("fdinfo/42"),
        format!("flags:\t{:o}\n", flags.bits()),
    )?;
    let child_file = overlay_fixture(child_directory.path())?;
    let mut incomplete = None;
    let mut partial = None;

    let source = qemu_resources_at(17, source_directory.path(), &mut incomplete, &mut partial)?
        .ok_or("read-only source observation unavailable")?;
    let child = qemu_resources_at(31, child_directory.path(), &mut incomplete, &mut partial)?
        .ok_or("writable child observation unavailable")?;

    assert!(source.overlays.is_empty());
    assert_eq!(
        source.read_only_overlays,
        BTreeSet::from([(source_file.metadata()?.dev(), source_file.metadata()?.ino())])
    );
    assert_eq!(
        child.overlays,
        BTreeSet::from([(child_file.metadata()?.dev(), child_file.metadata()?.ino())])
    );
    assert!(pair_refusal(&source, &child).is_none());
    Ok(())
}

#[test]
fn resource_identity_revalidation_refuses_pid_reuse_parent_change_and_exit()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 85)?;
    let _overlay = overlay_fixture(directory.path())?;
    let mut incomplete = None;
    let mut partial = None;
    let resources = qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?
        .ok_or("original live identity unavailable")?;
    let original = fs::read_to_string(directory.path().join("stat"))?;
    for changed in [
        original.replacen("31 (", "32 (", 1),
        original.replacen("R 17", "R 99", 1),
        original.replace("12345", "12346"),
        original.replacen(") R ", ") Z ", 1),
        original.replace("12345", "invalid"),
    ] {
        fs::write(directory.path().join("stat"), changed)?;
        assert!(!revalidate_process_identity(directory.path(), &resources));
    }
    fs::remove_file(directory.path().join("stat"))?;
    assert!(!revalidate_process_identity(directory.path(), &resources));
    Ok(())
}

#[test]
fn resource_reader_refuses_wrong_pid_missing_start_and_exited_process() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 89)?;
    let _overlay = overlay_fixture(directory.path())?;
    let original = fs::read_to_string(directory.path().join("stat"))?;
    for changed in [
        original.replacen("31 (", "32 (", 1),
        original.replace("12345", "invalid"),
        original.replacen(") R ", ") Z ", 1),
    ] {
        fs::write(directory.path().join("stat"), changed)?;
        let mut incomplete = None;
        let mut partial = None;
        assert!(qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?.is_none());
        assert_eq!(
            incomplete.as_deref(),
            Some("process-identity-unavailable-or-stale")
        );
    }
    Ok(())
}

#[test]
fn non_file_or_path_only_overlay_cannot_supply_read_only_basis() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    process_fixture(directory.path(), 87)?;
    let _overlay = overlay_fixture(directory.path())?;
    let mut incomplete = None;
    let mut partial = None;
    fs::write(
        directory.path().join("fdinfo/42"),
        format!("flags:\t{:o}\n", rustix::fs::OFlags::PATH.bits()),
    )?;
    assert!(qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial).is_err());
    fs::write(directory.path().join("fdinfo/42"), "flags:\t0\n")?;
    fs::remove_file(directory.path().join("crucible-root-overlay.qcow2"))?;
    fs::create_dir(directory.path().join("crucible-root-overlay.qcow2"))?;
    assert!(qemu_resources_at(31, directory.path(), &mut incomplete, &mut partial)?.is_none());
    assert!(
        incomplete
            .as_deref()
            .is_some_and(|value| value.starts_with("overlay-file-identity-invalid"))
    );
    Ok(())
}

#[test]
fn snapshot_and_global_report_bounds_survive_late_replacement() {
    let mut diagnostics = ForkDiagnostics::default();
    diagnostics.begin_sample();
    for pid in 1..1000 {
        let mut resource = resources(pid, u64::from(pid));
        resource.rings = (0..100)
            .map(|inode| ("device".repeat(100), inode))
            .collect();
        resource.overlays = (0..100).map(|inode| (u64::MAX, inode)).collect();
        resource.read_only_overlays.clone_from(&resource.overlays);
        diagnostics.record(pid, Some(&resource), Some(&"incomplete".repeat(100)));
    }
    assert!(diagnostics.rows.len() <= MAX_SNAPSHOT_BYTES);
    assert!(diagnostics.retained <= MAX_PROCESSES);
    assert_eq!(diagnostics.observed, 999);
    assert_eq!(diagnostics.incomplete, 999);
    assert!(diagnostics.rows.contains("omitted_rings=92"));
    assert!(diagnostics.rows.contains("omitted_read_only_overlays=92"));

    diagnostics.begin_sample();
    diagnostics.record(4505, Some(&resources(4505, 4437)), None);
    diagnostics.refusal("no-source-child-parent-pair", 1);
    let mut sink = Vec::new();
    diagnostics.report("guest-discovery", &mut sink);
    let first = sink.len();
    let text = String::from_utf8(sink.clone()).expect("ASCII diagnostic");
    assert!(text.contains("pid=4505"));
    assert!(!text.contains("pid=999"));
    assert!(text.contains("stage=\"guest-discovery\""));
    assert!(first <= MAX_SNAPSHOT_BYTES + 512);
    diagnostics.begin_sample();
    diagnostics.report("second-report", &mut sink);
    assert_eq!(sink.len(), first);
}

#[test]
fn broken_report_sink_preserves_original_failure_and_spends_only_one_report() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut audit = ProcessAudit::default();
    audit
        .fork_diagnostics
        .record(31, Some(&resources(31, 83)), None);
    assert!(audit.fork_diagnostics.rows.is_empty());
    assert_eq!(audit.fork_diagnostics.observed, 0);
    audit.fork_diagnostics.report("closed-sink", &mut Broken);
    assert!(audit.fork_diagnostics.reported);
    let error = audit
        .require_private_fork("guest-discovery")
        .expect_err("original refusal");
    assert_eq!(
        error.to_string(),
        "one-guest HotFork did not expose an actual source/child pair with distinct live ring and writable root-overlay backing files"
    );
    audit.private_fork = true;
    assert!(audit.require_private_fork("authenticated-pair").is_ok());
}
