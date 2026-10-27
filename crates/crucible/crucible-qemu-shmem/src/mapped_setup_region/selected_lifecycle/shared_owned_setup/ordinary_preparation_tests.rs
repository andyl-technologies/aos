//! Exercises same-map construction before intent and its sticky refusal edges.

// crucible-lint: allow panic-shortcut -- Test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::tests::original_aliases;
use super::*;
use crate::FrameEntry;
use std::sync::mpsc;
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn prepared_ticket_keeps_unique_same_map_and_ordinary_ring_gates() -> TestResult {
    let (_file, first, mut alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    let allocation = std::ptr::from_ref::<MappedSetupRegion>(&*owner.mapping()?) as usize;
    let frame = FrameEntry::new(7, 0, 23, b"original preparation")?;
    let domain = owner
        .generation()?
        .domain
        .as_ref()
        .map_err(|error| *error)?;

    let constructed = owner.with_ordinary_preparation(|mapping| {
        // The backing loan is not held across construction. Each actual
        // mutation below acquires its own ordinary protocol gate.
        assert!(domain.selection.try_lock().is_ok());
        assert_eq!(
            std::ptr::from_ref::<MappedSetupRegion>(mapping.mapping) as usize,
            allocation
        );
        let pair = mapping.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        pair.first.header.enqueue(pair.first.entries, &frame)?;
        Ok::<_, Box<dyn std::error::Error>>(mapping.mapping_start())
    })??;
    assert_eq!(constructed, owner.mapping()?.mapping_start());
    let pair = alias.node_directed_ring_pair_mut(
        0,
        0,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    assert_eq!(
        pair.first.header.dequeue(pair.first.entries)?.unwrap().seq,
        23
    );
    Ok(())
}

#[test]
fn busy_owner_and_callback_failure_preserve_fenced_same_mapping() -> TestResult {
    let (_file, first, mut alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    let read = owner.mapping()?;
    let address = read.mapping_start();
    let invoked = std::cell::Cell::new(false);
    assert_eq!(
        owner.with_ordinary_preparation(|_| {
            invoked.set(true);
            Ok::<_, ()>(())
        }),
        Err(WholeMappingCustodyError::Busy)
    );
    assert!(!invoked.get());
    assert_eq!(read.mapping_start(), address);
    drop(read);
    assert!(
        alias
            .node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )
            .is_err()
    );
    assert_eq!(
        owner.with_ordinary_preparation(|_| Ok::<_, ()>(())),
        Err(WholeMappingCustodyError::Selected)
    );

    let (_other_file, first, mut alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    assert_eq!(
        owner.with_ordinary_preparation(|_| Err::<(), _>("construction failed"))?,
        Err("construction failed")
    );
    assert!(
        alias
            .node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn concurrent_intent_prevents_preparation_result_publication() -> TestResult {
    let (_file, first, mut alias) = original_aliases()?;
    let owner = Arc::new(SharedOwnedSetupMapping::new(first));
    owner.prepare_whole_intent_retention()?;
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = mpsc::sync_channel(1);
    let worker_owner = Arc::clone(&owner);
    let worker = std::thread::spawn(move || {
        worker_owner.with_ordinary_preparation(|_| {
            entered_tx.send(()).unwrap();
            finish_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok::<_, ()>("unpublished construction")
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;
    owner.begin_whole_intent()?;
    finish_tx.send(())?;
    assert_eq!(
        worker.join().map_err(|_| "preparation worker panicked")?,
        Err(WholeMappingCustodyError::Selected)
    );
    assert!(
        alias
            .node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )
            .is_err()
    );
    assert!(
        owner
            .with_ordinary_preparation(|_| Ok::<_, ()>(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn foreign_pid_refuses_before_parent_held_owner() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "mapped_setup_region::selected_lifecycle::shared_owned_setup::ordinary_preparation_tests::foreign_pid_fixture", "--test-threads=1"])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "isolated kernel fork lifetime with original parent ownership lock held"]
fn foreign_pid_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let (_file, first, _alias) = original_aliases()?;
    let owner = Arc::new(SharedOwnedSetupMapping::new(first));
    owner.prepare_whole_intent_retention()?;
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker_owner = Arc::clone(&owner);
    let worker = std::thread::spawn(move || {
        let _guard = worker_owner.mapping().unwrap();
        locked_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(2))?;
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: this isolated harness owns and reaps the kernel child. The child
    // calls only the raw-PID refusal, writes a preallocated verdict and exits;
    // it never touches inherited ownership locks, TLS or Rust destructors.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let refused = matches!(
            owner.with_ordinary_preparation(|_| Ok::<_, ()>(())),
            Err(WholeMappingCustodyError::Unregistered)
        );
        let delivered = child_socket.write_all(&[u8::from(refused)]).is_ok();
        // SAFETY: avoids all copied parent actor and guard destructors.
        unsafe { libc::_exit(if refused && delivered { 70 } else { 71 }) };
    }
    release_tx.send(())?;
    worker
        .join()
        .map_err(|_| "parent ownership worker panicked")?;
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut verdict = [0];
    let received = parent_socket.read_exact(&mut verdict);
    if received.is_err() {
        // SAFETY: this exact PID belongs to this fixture; timeout is contained.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: writable status and exact owned child PID, reaped once.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    received?;
    assert_eq!(verdict, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 70);
    assert!(
        owner
            .with_ordinary_preparation(|_| Ok::<_, ()>(()))?
            .is_ok()
    );
    Ok(())
}

#[test]
fn fork_inside_construction_cannot_publish_or_drop_copied_results() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "mapped_setup_region::selected_lifecycle::shared_owned_setup::ordinary_preparation_tests::in_callback_fork_fixture", "--test-threads=1"])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "isolated in-callback fork with copied owner guard and generic destructor"]
fn in_callback_fork_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicI32, AtomicUsize};

    struct ResultDrop<'a>(&'a AtomicUsize);
    impl Drop for ResultDrop<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let (_file, first, _alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    let parent = std::process::id();
    let child_id = AtomicI32::new(-1);
    let result_drops = AtomicUsize::new(0);
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    let result = owner.with_ordinary_preparation(|_| {
        // SAFETY: this isolated fixture owns the fork. The copied child takes
        // only the helper's raw post-callback refusal and literal exit path.
        let child = unsafe { libc::fork() };
        child_id.store(child, Ordering::SeqCst);
        Ok::<_, ()>(ResultDrop(&result_drops))
    });
    if std::process::id() != parent {
        let refused = matches!(result, Err(WholeMappingCustodyError::Unregistered));
        let untouched = result_drops.load(Ordering::SeqCst) == 0;
        let sent = child_socket
            .write_all(&[u8::from(refused && untouched)])
            .is_ok();
        // SAFETY: no copied wrapper, guard, callback-result or socket destructor.
        unsafe { libc::_exit(if refused && untouched && sent { 70 } else { 71 }) };
    }

    let child = child_id.load(Ordering::SeqCst);
    drop(result?);
    assert_eq!(result_drops.load(Ordering::SeqCst), 1);
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut verdict = [0];
    let received = parent_socket.read_exact(&mut verdict);
    if received.is_err() {
        // SAFETY: this fixture owns the exact child PID and contains timeout.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: reaps this owned child once with writable status storage.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    received?;
    assert_eq!(verdict, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 70);
    assert!(
        owner
            .with_ordinary_preparation(|_| Ok::<_, ()>(()))?
            .is_ok()
    );
    Ok(())
}

#[test]
fn mutable_preparation_loan_blocks_child_replacement() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "mapped_setup_region::selected_lifecycle::shared_owned_setup::ordinary_preparation_tests::mutable_loan_replacement_fixture", "--test-threads=1"])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "isolated original mutable loan with actual DONTFORK replacement attempt"]
fn mutable_loan_replacement_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, AtomicI32};

    let (_source_file, first, source_alias) = original_aliases()?;
    let (destination_file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    first.exclude_from_hot_fork_child()?;
    destination.hold_hot_fork_ring_io()?;
    drop(source_alias);
    drop(destination);
    drop(destination_alias);
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    let parent = std::process::id();
    let child_id = AtomicI32::new(-1);
    let blocked = AtomicBool::new(false);
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    let result = owner.with_ordinary_preparation(|mapping| {
        let wrapper = std::ptr::from_ref(&owner) as usize;
        assert!(READ_OWNERS.with(|owners| owners.borrow().contains(&wrapper)));
        let original_address = mapping.mapping_start();
        // SAFETY: this isolated fixture owns the fork. The child invokes only
        // the loan-roster rejection before any old header or replacement effect,
        // then takes raw post-callback refusal and the literal exit path.
        let child = unsafe { libc::fork() };
        child_id.store(child, Ordering::SeqCst);
        if child == 0 {
            blocked.store(
                matches!(
                    owner.install_hot_fork_child_mapping(destination_file.as_fd(), expected),
                    Err(HotForkChildMappingInstallError::WholeCustody {
                        source: WholeMappingCustodyError::Busy
                    })
                ),
                Ordering::SeqCst,
            );
        }
        // Keeps the mutable heap-owner loan live without reading DONTFORK pages.
        std::hint::black_box(mapping.mapping_start() == original_address);
        Ok::<_, ()>(())
    });
    if std::process::id() != parent {
        let refused = matches!(result, Err(WholeMappingCustodyError::Unregistered));
        let guarded = blocked.load(Ordering::SeqCst);
        let sent = child_socket
            .write_all(&[u8::from(refused && guarded)])
            .is_ok();
        // SAFETY: does not destroy copied actor, borrowed view, guard or TLS marker.
        unsafe { libc::_exit(if refused && guarded && sent { 70 } else { 71 }) };
    }
    assert!(result?.is_ok());
    let child = child_id.load(Ordering::SeqCst);
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut verdict = [0];
    let received = parent_socket.read_exact(&mut verdict);
    if received.is_err() {
        // SAFETY: contains this exact owned child PID before reaping.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: writable status and once-only reap of the exact fixture child.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    received?;
    assert_eq!(verdict, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 70);
    assert_eq!(
        owner.mapping()?.backing_identity(),
        owner.generation()?.registration.owner.identity
    );
    let wrapper = std::ptr::from_ref(&owner) as usize;
    assert!(!READ_OWNERS.with(|owners| owners.borrow().contains(&wrapper)));
    assert!(
        owner
            .with_ordinary_preparation(|_| Ok::<_, ()>(()))?
            .is_ok()
    );
    Ok(())
}
