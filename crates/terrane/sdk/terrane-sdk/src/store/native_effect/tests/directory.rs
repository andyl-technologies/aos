//! Exercises actual private-directory repair, exclusion, and projection transitions.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn absent_directory(request: &mut NativeFsEffect, held: &HeldLock, path: &std::path::Path) {
    request.preimages.push(ExactRead {
        path: path.to_owned(),
        expected: None,
        identity: None,
        metadata: None,
        policy: FencePolicy::ProtectedRecord {
            owner: held.file.metadata().unwrap().uid(),
        },
        owner: held.file.metadata().unwrap().uid(),
        parents: parents(path),
    });
}

fn run_child(test: &str, mask: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env("TERRANE_NATIVE_DIRECTORY_MASK", mask)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn restrictive_umask_repairs_the_actual_new_directory_or_refuses_handoff() {
    const CHILD: &str = "TERRANE_NATIVE_DIRECTORY_MASK";
    let Some(mask) = std::env::var_os(CHILD) else {
        let name = concat!(
            module_path!(),
            "::restrictive_umask_repairs_the_actual_new_directory_or_refuses_handoff"
        );
        let (_, test) = name.split_once("::").unwrap();
        for mask in ["0300", "0777"] {
            run_child(test, mask);
        }
        return;
    };
    let mask = u32::from_str_radix(mask.to_str().unwrap(), 8).unwrap();
    let (root, held) = fixture();
    let path = root.join("protected-control");
    let mut request = effect(&held, Plan::CreateDirectoryNew { path: path.clone() });
    absent_directory(&mut request, &held, &path);

    // Only this dedicated child changes process-global umask. Fixture creation
    // precedes it, so a denied final directory open cannot invalidate setup.
    let previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(mask));
    let result = request.execute_inline();
    rustix::process::umask(previous);

    let created = std::fs::symlink_metadata(&path).unwrap();
    assert!(created.is_dir());
    assert!(!created.file_type().is_symlink());
    assert_eq!(created.uid(), held.file.metadata().unwrap().uid());
    match result {
        Ok(()) => {
            assert_eq!(created.mode() & 0o7777, 0o700);
            let opened = open_native(&path, true).unwrap();
            assert_eq!(opened.metadata().unwrap().ino(), created.ino());
            println!(
                "umask{mask:04o}: actual owner{} descriptor repair succeeded, mode0700",
                created.uid()
            );
        }
        Err(NativeEffectFailure::Io(error)) if mask == 0o777 => {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(created.mode() & 0o7777, 0);
            println!(
                "umask{mask:04o}: actual owner{} open refused Unsupported, mode0000",
                created.uid()
            );
            // Cleanup is fixture-only and follows the observed refusal, not
            // a production fallback which repairs an unbound raw path.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        unexpected => panic!("unexpected actual directory result: {unexpected:?}"),
    }
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn restored_created_name_rejects_the_opened_directory_decoy() {
    let (root, held) = fixture();
    let path = root.join("protected-control");
    let saved = root.join("actual-created");
    let decoy = root.join("decoy");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&decoy)
        .unwrap();
    let foreign = decoy.join("foreign-record");
    std::fs::write(&foreign, b"unchanged foreign bytes").unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o500)).unwrap();
    let foreign_stamp = std::fs::symlink_metadata(&decoy).unwrap();
    let mut request = effect(&held, Plan::CreateDirectoryNew { path: path.clone() });
    absent_directory(&mut request, &held, &path);
    let (before, before_received) = std::sync::mpsc::channel();
    let (open, open_released) = std::sync::mpsc::channel();
    let (after, after_received) = std::sync::mpsc::channel();
    let (check, check_released) = std::sync::mpsc::channel();
    request.gates.push(TestGate {
        phase: TestGatePhase::BeforeOpen,
        arrived: before,
        release: open_released,
    });
    request.gates.push(TestGate {
        phase: TestGatePhase::AfterOpen,
        arrived: after,
        release: check_released,
    });
    let task = tokio::spawn(request.execute_tokio());
    tokio::task::spawn_blocking(move || {
        before_received.recv_timeout(std::time::Duration::from_secs(5))
    })
    .await
    .unwrap()
    .unwrap();
    let actual_created = std::fs::symlink_metadata(&path).unwrap();
    std::fs::rename(&path, &saved).unwrap();
    std::fs::rename(&decoy, &path).unwrap();
    open.send(()).unwrap();
    tokio::task::spawn_blocking(move || {
        after_received.recv_timeout(std::time::Duration::from_secs(5))
    })
    .await
    .unwrap()
    .unwrap();
    std::fs::rename(&path, &decoy).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    check.send(()).unwrap();
    assert!(task.await.unwrap().is_err());

    let unchanged = std::fs::symlink_metadata(&decoy).unwrap();
    assert_eq!(unchanged.ino(), foreign_stamp.ino());
    assert_eq!(unchanged.uid(), actual_created.uid());
    assert_eq!(unchanged.mode(), foreign_stamp.mode());
    assert_eq!(std::fs::read(foreign).unwrap(), b"unchanged foreign bytes");
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().ino(),
        actual_created.ino()
    );
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn changed_other_projection_after_creation_refuses_mode_repair() {
    let Some(mask) = std::env::var_os("TERRANE_NATIVE_DIRECTORY_MASK") else {
        let name = concat!(
            module_path!(),
            "::changed_other_projection_after_creation_refuses_mode_repair"
        );
        let (_, test) = name.split_once("::").unwrap();
        run_child(test, "0300");
        return;
    };
    let mask = u32::from_str_radix(mask.to_str().unwrap(), 8).unwrap();
    for change in ["control", "clock", "other-absence"] {
        let (root, held) = fixture();
        let path = root.join("protected-control");
        let control = root.join("used-registration");
        let other_absent = root.join("other-absent-target");
        std::fs::write(&control, b"checked complete control").unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o600)).unwrap();
        let stamp = std::fs::symlink_metadata(&control).unwrap();
        let mut request = effect(&held, Plan::CreateDirectoryNew { path: path.clone() });
        absent_directory(&mut request, &held, &path);
        absent_directory(&mut request, &held, &other_absent);
        request.preimages.push(ExactRead {
            path: control.clone(),
            expected: Some(b"checked complete control".to_vec()),
            identity: Some((stamp.dev(), stamp.ino())),
            metadata: Some(MetadataStamp::checked(&stamp).unwrap()),
            policy: FencePolicy::ProtectedRecord { owner: stamp.uid() },
            owner: stamp.uid(),
            parents: parents(&control),
        });
        let clock = Arc::new(AtomicUsize::new(0));
        request.final_check = Some(crate::selected_bridge::effect_test_checks::deadline_check(
            crate::store::NativeEffectClock::from_native_clock(TestClock(Arc::clone(&clock))),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(9),
        ));
        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        request.gates.push(TestGate {
            phase: TestGatePhase::AfterDirectoryCreate,
            arrived,
            release: released,
        });
        let previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(mask));
        let task = tokio::spawn(request.execute_tokio());
        tokio::task::spawn_blocking(move || {
            received.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .unwrap();
        let created = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(created.mode() & 0o7777, 0o400);
        match change {
            "control" => std::fs::write(&control, b"different complete control").unwrap(),
            "clock" => clock.store(10, Ordering::SeqCst),
            "other-absence" => std::fs::write(&other_absent, b"new unrelated value").unwrap(),
            unexpected => panic!("unknown fixture change: {unexpected}"),
        }
        release.send(()).unwrap();
        let result = task.await.unwrap();
        rustix::process::umask(previous);

        assert!(result.is_err());
        let unchanged = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(unchanged.ino(), created.ino());
        assert_eq!(unchanged.mode() & 0o7777, 0o400);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(held);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn failed_parent_sync_never_acknowledges_directory_repair() {
    let (root, held) = fixture();
    let path = root.join("protected-control");
    let mut request = effect(&held, Plan::CreateDirectoryNew { path: path.clone() });
    absent_directory(&mut request, &held, &path);
    let result = request
        .inject_test_faults(vec![EffectFault::BeforeDirectorySync])
        .execute_inline();

    assert!(
        matches!(result, Err(NativeEffectFailure::Io(error)) if error.kind() == io::ErrorKind::Other)
    );
    let created = std::fs::symlink_metadata(&path).unwrap();
    assert!(created.is_dir());
    assert_eq!(created.mode() & 0o7777, 0o700);
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn replacement_after_creation_preserves_the_same_owner_decoy() {
    let (root, held) = fixture();
    let path = root.join("protected-control");
    let saved = root.join("actual-created");
    let decoy = root.join("decoy");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&decoy)
        .unwrap();
    let foreign = decoy.join("foreign-record");
    std::fs::write(&foreign, b"unchanged foreign bytes").unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o500)).unwrap();
    let foreign_stamp = std::fs::symlink_metadata(&decoy).unwrap();
    let mut request = effect(&held, Plan::CreateDirectoryNew { path: path.clone() });
    absent_directory(&mut request, &held, &path);
    let (arrived, received) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    request.gates.push(TestGate {
        phase: TestGatePhase::AfterDirectoryCreate,
        arrived,
        release: released,
    });
    let task = tokio::spawn(request.execute_tokio());
    tokio::task::spawn_blocking(move || received.recv_timeout(std::time::Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    let actual_created = std::fs::symlink_metadata(&path).unwrap();
    std::fs::rename(&path, &saved).unwrap();
    std::fs::rename(&decoy, &path).unwrap();
    release.send(()).unwrap();
    assert!(task.await.unwrap().is_err());

    let current = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(
        (current.dev(), current.ino()),
        (foreign_stamp.dev(), foreign_stamp.ino())
    );
    assert_eq!(current.mode(), foreign_stamp.mode());
    assert_eq!(current.uid(), foreign_stamp.uid());
    assert_eq!(
        std::fs::read(path.join("foreign-record")).unwrap(),
        b"unchanged foreign bytes"
    );
    assert_eq!(
        std::fs::symlink_metadata(&saved).unwrap().ino(),
        actual_created.ino()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}
