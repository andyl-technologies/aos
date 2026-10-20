//! VM-only checks for installed reader confinement and Controller denials.
//!
//! The reader probe inherits the real template's restrictions in ExecStartPre.
//! It sends nothing on the inherited protocol socket and mints no readback,
//! receipt, signing, journal-cut, or SourceRoot authority.

use super::*;
use aos_sandbox_linux::mount::{FileSystemContext, MountAttributes};
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use std::collections::BTreeMap;
use std::process::Command;

fn process_status() -> BTreeMap<String, String> {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
        .collect()
}

fn require_permission_denied(error: std::io::Error) {
    assert!(
        matches!(error.kind(), std::io::ErrorKind::PermissionDenied)
            || error.raw_os_error() == Some(rustix::io::Errno::ROFS.raw_os_error()),
        "operation failed for a reason other than the permission boundary: {error}",
    );
}

#[test]
#[ignore = "requires the installed reader unit's inherited confinement"]
fn installed_confinement() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let status = process_status();
    for field in ["CapEff", "CapBnd", "CapPrm", "CapAmb"] {
        assert_eq!(u64::from_str_radix(&status[field], 16).unwrap(), 1 << 21);
    }
    assert_eq!(status["NoNewPrivs"], "1");
    assert_eq!(status["Seccomp"], "2");
    require_private_mount_namespace().unwrap();
    assert!(!Path::new("/dev/zfs").exists());

    let error = SeqpacketSocket::pair_with_record_subjects().unwrap_err();
    let aos_sandbox_linux::seqpacket::SeqpacketError::Kernel(aos_sandbox_linux::Error::Syscall {
        source,
        ..
    }) = error
    else {
        panic!("socketpair was not denied by the installed filter: {error}");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::PERM.raw_os_error())
    );

    // Fresh detached mounting is permitted; attaching it is not. An owned
    // disposable destination makes even an unexpected success VM-local.
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("target")).unwrap();
    let parent = BeneathRoot::from_owned(
        rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap(),
    )
    .unwrap();
    let target = parent
        .resolve(Path::new("target"), ResolveOptions::directory())
        .unwrap();
    let before = MountId::from_fd(target.as_fd()).unwrap();
    let mount = FileSystemContext::open("tmpfs")
        .unwrap()
        .create()
        .unwrap()
        .mount()
        .unwrap();
    mount
        .set_attributes(
            true,
            MountAttributes::secure_read_only().with_no_exec(true),
            None,
        )
        .unwrap();
    let error = mount.attach(&target).unwrap_err();
    let aos_sandbox_linux::Error::Syscall { source, .. } = error else {
        panic!("move_mount was not denied by the installed filter: {error}");
    };
    assert_eq!(
        source.raw_os_error(),
        Some(rustix::io::Errno::PERM.raw_os_error())
    );
    assert_eq!(MountId::from_fd(target.as_fd()).unwrap(), before);
}

#[test]
#[ignore = "requires the fleet's cap-empty non-root Controller fixture"]
fn controller_denials() {
    let expected_uid: u32 = std::env::var("AOS_HELD_READER_CONTROLLER_UID")
        .unwrap()
        .parse()
        .unwrap();
    let expected_gid: u32 = std::env::var("AOS_HELD_READER_CONTROLLER_GID")
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(expected_uid, 0);
    assert_eq!(rustix::process::geteuid().as_raw(), expected_uid);
    assert_eq!(rustix::process::getegid().as_raw(), expected_gid);
    let status = process_status();
    for field in ["CapEff", "CapBnd", "CapPrm", "CapAmb"] {
        assert_eq!(u64::from_str_radix(&status[field], 16).unwrap(), 0);
    }
    assert_eq!(status["NoNewPrivs"], "1");

    for path in [
        "/run/systemd/system/aos-sandbox-held-snapshot-reader@.service.d/unauthorized.conf",
        "/etc/systemd/system/aos-held-reader-unauthorized.service",
    ] {
        let error = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap_err();
        require_permission_denied(error);
    }
    let error = fs::OpenOptions::new()
        .write(true)
        .open("/sys/fs/cgroup/aos.slice/aos-control.slice/aos-storaged.service/cgroup.procs")
        .unwrap_err();
    require_permission_denied(error);

    let error = SeqpacketSocket::connect(Path::new(SOCKET_PATH)).unwrap_err();
    let aos_sandbox_linux::seqpacket::SeqpacketError::Kernel(aos_sandbox_linux::Error::Syscall {
        source,
        ..
    }) = error
    else {
        panic!("Controller was not rejected at the reader socket boundary: {error}");
    };
    require_permission_denied(source);

    let systemctl = std::env::var_os("AOS_HELD_READER_SYSTEMCTL").unwrap();
    for arguments in [
        vec!["daemon-reload"],
        vec![
            "set-property",
            "--runtime",
            "aos-held-reader-mutation-decoy.service",
            "TasksMax=99",
        ],
        vec!["start", "aos-held-reader-mutation-decoy.service"],
    ] {
        let output = Command::new(&systemctl)
            .arg("--no-ask-password")
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "Controller obtained privileged unit management"
        );
        let error = String::from_utf8(output.stderr)
            .unwrap()
            .to_ascii_lowercase();
        assert!(
            [
                "access denied",
                "permission denied",
                "authentication is required",
                "authentication required"
            ]
            .iter()
            .any(|denial| error.contains(denial)),
            "unit management failed without proving an authorization denial: {error}",
        );
    }
}
