//! Real file identity and bounded-read controls for the normal family witness.
//!
//! Ordinary temporary directories exercise refusal and identity helpers; they
//! never stand in for an authenticated cgroup or issue a healthy family.

use super::*;

#[test]
fn exact_guardian_membership_rejects_ancestor_sibling_and_extra_records() {
    let root = "/system.slice/crucible-campaign.service";
    assert!(super::super::matches_service_membership(
        "0::/system.slice/crucible-campaign.service/guardian\n",
        root,
        true
    ));
    for wrong in [
        "0::/system.slice/crucible-campaign.service\n",
        "0::/system.slice/crucible-campaign.service/workload\n",
        "0::/system.slice/crucible-campaign.service-extra/guardian\n",
        "0::/system.slice/crucible-campaign.service/guardian",
        "0::/system.slice/crucible-campaign.service/guardian\n1::/other\n",
    ] {
        assert!(!super::super::matches_service_membership(wrong, root, true));
    }
    assert!(super::super::matches_service_membership(
        "0::/system.slice/crucible-campaign.service\n",
        root,
        false
    ));
    assert!(!super::super::matches_service_membership(
        "0::/system.slice/crucible-campaign.service/guardian\n",
        root,
        false
    ));
}

#[test]
fn retained_directory_identity_detects_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("workload");
    std::fs::create_dir(&path).unwrap();
    let retained = File::open(&path).unwrap();
    require_identity(retained.as_fd(), File::open(&path).unwrap().as_fd()).unwrap();

    std::fs::rename(&path, root.path().join("old-workload")).unwrap();
    std::fs::create_dir(&path).unwrap();

    assert!(require_identity(retained.as_fd(), File::open(&path).unwrap().as_fd()).is_err());
}

#[test]
fn ordinary_directory_and_symlink_cannot_issue_a_family() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("guardian")).unwrap();
    std::os::unix::fs::symlink("guardian", root.path().join("workload")).unwrap();
    let root = File::open(root.path()).unwrap();

    assert!(open_directory(root.as_fd(), "guardian").is_err());
    assert!(open_directory(root.as_fd(), "workload").is_err());
}

#[test]
fn real_control_reads_require_exact_value_and_complete_eof() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("memory.swap.max"), b"0\n").unwrap();
    let directory = File::open(root.path()).unwrap();
    require_value(directory.as_fd(), "memory.swap.max", b"0\n").unwrap();
    assert!(require_value(directory.as_fd(), "memory.swap.max", b"1\n").is_err());

    std::fs::write(root.path().join("memory.swap.max"), [b'0'; 129]).unwrap();

    assert!(require_value(directory.as_fd(), "memory.swap.max", b"0\n").is_err());
}

#[test]
fn control_symlink_does_not_replace_the_selected_kernel_file() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("other"), b"0\n").unwrap();
    std::os::unix::fs::symlink("other", root.path().join("memory.swap.max")).unwrap();
    let directory = File::open(root.path()).unwrap();

    assert!(require_value(directory.as_fd(), "memory.swap.max", b"0\n").is_err());
}

#[test]
fn empty_direct_membership_does_not_hide_a_live_descendant() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("cgroup.procs"), b"").unwrap();
    std::fs::write(
        root.path().join("cgroup.events"),
        b"populated 1\nfrozen 0\n",
    )
    .unwrap();
    let directory = File::open(root.path()).unwrap();
    require_value(directory.as_fd(), "cgroup.procs", b"").unwrap();

    assert!(
        require_value(
            directory.as_fd(),
            "cgroup.events",
            b"populated 0\nfrozen 0\n"
        )
        .is_err()
    );
    std::fs::write(
        root.path().join("cgroup.events"),
        b"populated 0\nfrozen 1\n",
    )
    .unwrap();
    assert!(
        require_value(
            directory.as_fd(),
            "cgroup.events",
            b"populated 0\nfrozen 0\n"
        )
        .is_err()
    );
    std::fs::write(
        root.path().join("cgroup.events"),
        b"populated 0\nfrozen 0\n",
    )
    .unwrap();
    require_value(
        directory.as_fd(),
        "cgroup.events",
        b"populated 0\nfrozen 0\n",
    )
    .unwrap();
}

#[test]
fn aggregate_cpu_and_task_requests_reject_zero_and_overflow() {
    for (cpu, tasks) in [(0, 1), (1, 0), (u64::MAX, 1)] {
        assert!(NativeFamilyLimits::new(cpu, tasks).is_err());
    }
    let limits = NativeFamilyLimits::new(1, 69).unwrap();
    assert_eq!(limits.cpu_quota_micros, 100_000);
    assert_eq!(limits.tasks, 69);
}

#[test]
fn actual_parent_controls_refuse_increased_task_or_cpu_assignments() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let requested = NativeFamilyLimits::new(1, 69).unwrap();
    std::fs::write(root.path().join("pids.max"), b"69\n").unwrap();
    std::fs::write(root.path().join("cpu.max"), b"100000 100000\n").unwrap();
    require_monotonic_native_limits(directory.as_fd(), &requested).unwrap();

    std::fs::write(root.path().join("pids.max"), b"68\n").unwrap();
    assert!(require_monotonic_native_limits(directory.as_fd(), &requested).is_err());
    std::fs::write(root.path().join("pids.max"), b"69\n").unwrap();
    std::fs::write(root.path().join("cpu.max"), b"99999 100000\n").unwrap();
    assert!(require_monotonic_native_limits(directory.as_fd(), &requested).is_err());
}

#[test]
fn cpu_rate_comparison_handles_different_periods_and_unlimited_initial_parent() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let requested = NativeFamilyLimits::new(1, 69).unwrap();
    std::fs::write(root.path().join("pids.max"), b"max\n").unwrap();
    std::fs::write(root.path().join("cpu.max"), b"max 100000\n").unwrap();
    require_monotonic_native_limits(directory.as_fd(), &requested).unwrap();
    std::fs::write(root.path().join("cpu.max"), b"200000 200000\n").unwrap();
    require_monotonic_native_limits(directory.as_fd(), &requested).unwrap();

    std::fs::write(root.path().join("cpu.max"), b"199999 200000\n").unwrap();
    assert!(require_monotonic_native_limits(directory.as_fd(), &requested).is_err());
}

#[test]
fn aggregate_readback_detects_changed_either_control_and_requires_canonical_period() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let limits = NativeFamilyLimits::new(1, 69).unwrap();
    std::fs::write(root.path().join("pids.max"), b"69\n").unwrap();
    std::fs::write(root.path().join("cpu.max"), b"100000 100000\n").unwrap();
    require_native_limits(directory.as_fd(), &limits).unwrap();

    std::fs::write(root.path().join("pids.max"), b"70\n").unwrap();
    assert!(require_native_limits(directory.as_fd(), &limits).is_err());
    std::fs::write(root.path().join("pids.max"), b"69\n").unwrap();
    std::fs::write(root.path().join("cpu.max"), b"200000 200000\n").unwrap();
    assert!(require_native_limits(directory.as_fd(), &limits).is_err());
}

#[test]
fn malformed_cpu_controls_cannot_claim_finite_aggregate_assignment() {
    for value in [
        b"".as_slice(),
        b"0 100000\n",
        b"1 0\n",
        b"1\n",
        b"max 100000 extra\n",
    ] {
        assert!(cpu_limit_fields(value).is_err());
    }
}

#[test]
fn parent_limit_write_refuses_symlink_without_touching_target() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("other"), b"original\n").unwrap();
    std::os::unix::fs::symlink("other", root.path().join("pids.max")).unwrap();
    let directory = File::open(root.path()).unwrap();

    assert!(write_control(directory.as_fd(), "pids.max", b"69\n").is_err());
    assert_eq!(
        std::fs::read(root.path().join("other")).unwrap(),
        b"original\n"
    );
}
