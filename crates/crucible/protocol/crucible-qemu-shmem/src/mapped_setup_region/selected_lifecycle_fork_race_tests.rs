//! Actual fork generations and ordinary teardown while another thread owns a loan.

// crucible-lint: allow panic-shortcut -- Lifecycle test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn fork_child_rebinds_while_parent_registry_and_domain_loans_are_inherited_locked() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "mapped_setup_region::selected_lifecycle::tests::fork_races::inherited_lock_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "invoked alone to isolate the actual fork and parent mutex owners"]
fn inherited_lock_fixture() -> TestResult {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let (_source_file, mut original, source_alias) = original_aliases()?;
    let (destination_file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    original.exclude_from_hot_fork_child()?;
    destination.hold_hot_fork_ring_io()?;
    drop(source_alias);
    drop(destination);
    drop(destination_alias);
    let domain = domain_at(original.mapping_start())?.ok_or("original domain absent")?;
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _domain_loan = domain
            .selection
            .lock()
            .expect("ordinary parent domain loan");
        let _registry_loan = registry().lock().expect("ordinary parent registry loan");
        locked_tx
            .send(())
            .expect("report both actual inherited mutex owners");
        release_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("release actual parent loans");
    });
    locked_rx.recv_timeout(Duration::from_secs(2))?;
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: this isolated fixture deliberately forks while another thread
    // owns both mutexes. Child install must use a fresh PID generation and
    // immutable registration, never either inherited locked mutex.
    let child = unsafe { libc::fork() };
    if child < 0 {
        release_tx.send(())?;
        worker.join().map_err(|_| "parent loan worker panicked")?;
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent_socket);
        let result = (|| -> TestResult {
            original.install_hot_fork_child_mapping(destination_file.as_fd(), expected)?;
            assert_eq!(original.mapping_process_id as u32, std::process::id());
            let records = locked_registry()?;
            assert_eq!(
                records
                    .mappings
                    .get(&original.mapping_start())
                    .ok_or("child record absent")?
                    .process,
                std::process::id()
            );
            drop(records);
            let retained = original.retain_whole_mapping(7);
            retained.selection_status()?;
            child_socket.write_all(&[1])?;
            Ok(())
        })();
        // SAFETY: child exits without destructors for copied parent actors.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    release_tx.send(())?;
    worker.join().map_err(|_| "parent loan worker panicked")?;
    let mut reply = [0];
    let completion = parent_socket.read_exact(&mut reply);
    if completion.is_err() {
        // SAFETY: this fixture owns this exact fork PID. On bounded socket
        // failure it reaps the real stalled child, rather than fabricating a
        // successful result or leaving an inherited-lock actor behind.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: status is writable and child is this fixture's exact PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    completion?;
    assert_eq!(reply, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    Ok(())
}

type BeforeUnmapHook = Box<dyn FnOnce(usize)>;

thread_local! {
    static BEFORE_UNMAP_WAIT: std::cell::RefCell<Option<BeforeUnmapHook>> =
        std::cell::RefCell::new(None);
}

pub(super) fn before_unmap_domain_lock(address: usize) {
    let hook = BEFORE_UNMAP_WAIT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(address);
    }
}

fn source_vma_present(address: usize, inode: u64) -> TestResultBool {
    for line in std::fs::read_to_string("/proc/self/maps")?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Some((start, end)) = fields[0].split_once('-') else {
            continue;
        };
        let start = usize::from_str_radix(start, 16)?;
        let end = usize::from_str_radix(end, 16)?;
        let candidate_inode = fields[4].parse::<u64>()?;
        if start <= address && address < end && candidate_inode == inode {
            return Ok(true);
        }
    }
    Ok(false)
}

type TestResultBool = Result<bool, Box<dyn std::error::Error>>;

#[test]
fn ordinary_alias_drop_waits_then_removes_actual_vma_and_registration() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    let address = first.mapping_start();
    let identity = first.backing_identity();
    let domain = domain_at(address)?.ok_or("ordinary domain absent")?;
    let loan = ordinary(&domain)?;
    let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        BEFORE_UNMAP_WAIT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |candidate| {
                assert_eq!(candidate, address);
                waiting_tx
                    .send(())
                    .expect("report real teardown reached domain wait");
            }));
        });
        drop(first);
        finished_tx
            .send(())
            .expect("report actual mapped owner Drop completed");
    });
    waiting_rx.recv_timeout(Duration::from_secs(2))?;
    assert!(locked_registry()?.mappings.contains_key(&address));
    assert!(source_vma_present(address, identity.inode())?);

    drop(loan);
    finished_rx.recv_timeout(Duration::from_secs(2))?;
    worker
        .join()
        .map_err(|_| "ordinary teardown worker panicked")?;

    assert!(!locked_registry()?.mappings.contains_key(&address));
    assert!(!source_vma_present(address, identity.inode())?);
    assert!(domain_at(alias.mapping_start())?.is_some());
    Ok(())
}
#[test]
fn foreign_pid_end_and_retirement_refuse_before_absent_mapping_reads() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "mapped_setup_region::selected_lifecycle::tests::fork_races::foreign_pid_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "invoked alone to isolate absent DONTFORK mappings and copied permits"]
fn foreign_pid_fixture() -> TestResult {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let (_file, first, alias) = original_aliases()?;
    first.exclude_from_hot_fork_child()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    retained.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 0,
            consumer_attempts: 0,
        },
    )?;
    let domain = Arc::clone(retained.domain.as_ref().ok_or("original domain absent")?);
    let cell = Arc::clone(
        retained
            .cell
            .as_ref()
            .ok_or("original endpoint cell absent")?,
    );
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _domain = domain
            .selection
            .lock()
            .expect("hold original selected domain mutex");
        let _cell = cell
            .selection
            .lock()
            .expect("hold original endpoint cell mutex");
        let _registry = registry()
            .lock()
            .expect("hold original selected registry mutex");
        locked_tx.send(()).expect("report actual held mutexes");
        release_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("release parent locks");
    });
    locked_rx.recv_timeout(Duration::from_secs(2))?;
    let (mut parent, mut child_socket) = UnixStream::pair()?;
    parent.set_read_timeout(Some(Duration::from_secs(2)))?;
    // SAFETY: the isolated child deliberately inherits absent source memory,
    // a parent-PID permit, and locked mutexes. End must refuse before any read.
    let child = unsafe { libc::fork() };
    if child < 0 {
        release_tx.send(())?;
        worker.join().map_err(|_| "selected lock worker panicked")?;
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent);
        let refused = matches!(
            retained.end_paired_scope(7, 1, 123),
            Err(WholeMappingCustodyError::Unregistered)
        );
        let reported = child_socket.write_all(&[u8::from(refused)]).is_ok();
        // SAFETY: child exits without running inherited parent destructors.
        unsafe { libc::_exit(if refused && reported { 0 } else { 1 }) };
    }
    drop(child_socket);
    release_tx.send(())?;
    worker.join().map_err(|_| "selected lock worker panicked")?;
    let mut reply = [0];
    let completion = parent.read_exact(&mut reply);
    if completion.is_err() {
        // SAFETY: this fixture owns and must reap this exact stalled child.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: status is writable and child is the actual owned fork PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    completion?;
    assert_eq!(reply, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    let completion = retained.end_paired_scope(7, 1, 123)?;

    // SAFETY: parent has closed its actual loan; the second child still has
    // no DONTFORK source VMA and cannot retire its parent's original token.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        let refused = matches!(
            retained.retire_paired_scope(7, 1, 123, completion),
            Err(WholeMappingCustodyError::Unregistered)
        );
        // SAFETY: child runs no copied owner destructor.
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }
    // SAFETY: status is writable and child is this second exact fork PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}
