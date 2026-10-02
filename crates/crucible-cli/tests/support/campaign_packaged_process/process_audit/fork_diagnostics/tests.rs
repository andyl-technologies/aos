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
    assert!(incomplete.is_none());
    assert_eq!(
        pair_refusal(&resources(17, 81), &observed),
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
    }
}

#[test]
fn unchanged_pair_predicate_requires_nonempty_and_fully_disjoint_sets() {
    let source = resources(17, 81);
    let child = resources(31, 83);
    assert!(pair_refusal(&source, &child).is_none());
    for expected in [
        "source-ring-set-empty",
        "child-ring-set-empty",
        "source-writable-overlay-set-empty",
        "child-writable-overlay-set-empty",
        "source-child-ring-sets-overlap",
        "source-child-writable-overlay-sets-overlap",
    ] {
        let mut source = resources(17, 81);
        let mut child = resources(31, 83);
        match expected {
            "source-ring-set-empty" => source.rings.clear(),
            "child-ring-set-empty" => child.rings.clear(),
            "source-writable-overlay-set-empty" => source.overlays.clear(),
            "child-writable-overlay-set-empty" => child.overlays.clear(),
            "source-child-ring-sets-overlap" => child.rings.extend(source.rings.iter().cloned()),
            "source-child-writable-overlay-sets-overlap" => {
                child.overlays.extend(source.overlays.iter().copied())
            }
            _ => unreachable!(),
        }
        assert_eq!(pair_refusal(&source, &child), Some(expected));
    }
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
        diagnostics.record(pid, Some(&resource), Some(&"incomplete".repeat(100)));
    }
    assert!(diagnostics.rows.len() <= MAX_SNAPSHOT_BYTES);
    assert!(diagnostics.retained <= MAX_PROCESSES);
    assert_eq!(diagnostics.observed, 999);
    assert_eq!(diagnostics.incomplete, 999);
    assert!(diagnostics.rows.contains("omitted_rings=92"));

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
