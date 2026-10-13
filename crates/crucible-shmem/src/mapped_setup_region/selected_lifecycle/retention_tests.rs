//! Actual initializing-slot forks before original source effects.

// crucible-lint: allow panic-shortcut -- Lifecycle test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::mapped_setup_region::selected_lifecycle::{
    OwnedSetupMapping, registry, tests::original_aliases,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn initializing_original_retention_slot_fork_runs_in_isolation() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact",
            "mapped_setup_region::selected_lifecycle::retention::tests::initializing_original_retention_slot_fork_fixture",
            "--test-threads=1"])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "holds the actual ticket OnceLock initializer while owning a child replacement"]
fn initializing_original_retention_slot_fork_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    let (_source_file, first, alias) = original_aliases()?;
    let (file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    drop(destination);
    drop(destination_alias);
    first.exclude_from_hot_fork_child()?;
    let address = first.mapping_start();
    let parent_pid = std::process::id();
    let mut owner = OwnedSetupMapping::new(first);
    let slot = owner.retention_slot();
    let before = owner.mapping().hot_fork_ring_io_snapshot()?;
    reserve_quarantine()?;
    let worker_slot = Arc::clone(&slot);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        // Production set traverses this same OnceLock initializing state.
        // Hold a real initializer so fork deterministically copies it.
        worker_slot.ticket.get_or_init(|| {
            entered_tx
                .send(())
                .expect("report actual initializer entry");
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("finish parent initializer");
            RetentionTicket {
                process: parent_pid,
                transferred: AtomicBool::new(false),
            }
        });
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;
    assert!(slot.ticket.get().is_none());
    assert_eq!(quarantine().lock().unwrap().reserved, 1);
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: the fixture owns the child and its unique mapping. The other
    // thread borrows only a cloned private slot, never the mapped owner.
    let child = unsafe { libc::fork() };
    if child < 0 {
        release_tx.send(())?;
        worker
            .join()
            .map_err(|_| "parent initializer worker panicked")?;
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent_socket);
        let result = (|| -> TestResult {
            owner
                .ordinary_mapping_mut()?
                .install_hot_fork_child_mapping(file.as_fd(), expected)?;
            assert_eq!(
                owner.mapping().mapping_owner_key().process,
                std::process::id()
            );
            assert_ne!(slot.process, std::process::id());
            assert!(!slot.armed());
            assert_eq!(
                owner.prepare_whole_intent_retention(),
                Err(WholeMappingCustodyError::Unregistered)
            );
            assert_eq!(
                owner.begin_whole_intent(),
                Err(WholeMappingCustodyError::Selected)
            );
            assert_eq!(
                owner.select_whole_bounded(7, 1),
                Err(WholeMappingCustodyError::Selected)
            );
            assert_eq!(owner.mapping().hot_fork_ring_io_snapshot()?, before);
            assert_eq!(quarantine().lock().unwrap().reserved, 0);
            assert!(quarantine().lock().unwrap().owners.is_empty());

            drop(owner);
            assert!(!registry().lock().unwrap().mappings.contains_key(&address));
            child_socket.write_all(&[1])?;
            Ok(())
        })();
        // SAFETY: copied parent guards and vanished initializer threads must
        // not run destructors or attempt to complete inherited lock state.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    release_tx.send(())?;
    worker
        .join()
        .map_err(|_| "parent initializer worker panicked")?;
    let mut response = [0];
    let completion = parent_socket.read_exact(&mut response);
    if completion.is_err() {
        // SAFETY: this fixture owns the exact child and reaps after timeout.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: status is writable and child is the exact owned process.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    completion?;
    assert_eq!(response, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(slot.armed());
    owner.prepare_whole_intent_retention()?;
    assert_eq!(quarantine().lock().unwrap().reserved, 1);
    assert_eq!(owner.mapping().hot_fork_ring_io_snapshot()?, before);
    assert_eq!(alias.hot_fork_ring_io_snapshot()?, before);

    drop(owner);
    drop(slot);
    assert_eq!(quarantine().lock().unwrap().reserved, 0);
    assert!(quarantine().lock().unwrap().owners.is_empty());
    Ok(())
}
