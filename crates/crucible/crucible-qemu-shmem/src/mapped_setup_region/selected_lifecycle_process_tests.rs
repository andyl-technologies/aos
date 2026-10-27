//! Real kernel mapping replacement and socket custody across process boundaries.

use super::*;

#[test]
fn actual_fork_replacement_registers_current_process_and_selected_alias_domain() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "mapped_setup_region::selected_lifecycle::tests::process::fork_replacement_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "invoked in its own process to isolate fork from concurrent registry users"]
fn fork_replacement_fixture() -> TestResult {
    let (_source_file, mut original, source_alias) = original_aliases()?;
    let (destination_file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    let length = original.region_len();
    let address = original.mapping_start();
    original.exclude_from_hot_fork_child()?;
    drop(source_alias);
    drop(destination);
    drop(destination_alias);

    // SAFETY: this fixture runs alone in a dedicated test process. No other
    // registry operation or domain loan is active at this process boundary.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        let result = (|| -> TestResult {
            // The DONTFORK source VMA is absent. These refusals must happen
            // before any typed header read or inheritance syscall.
            assert!(matches!(
                original.node_directed_ring_pair_mut(
                    0,
                    0,
                    crate::SLOT_NET_ROUTER as u32,
                    crate::SLOT_NET_ROUTER as u32,
                    0
                ),
                Err(crate::MappedSetupRegionAccessError::WholeCustody {
                    source: WholeMappingCustodyError::Unregistered,
                })
            ));
            assert!(matches!(
                original.hold_hot_fork_ring_io(),
                Err(crate::MappedSetupRegionAccessError::WholeCustody {
                    source: WholeMappingCustodyError::Unregistered,
                })
            ));
            original.install_hot_fork_child_mapping(destination_file.as_fd(), expected)?;
            assert_eq!(original.mapping_start(), address);
            assert_eq!(original.mapping_process_id as u32, std::process::id());
            {
                let records = locked_registry()?;
                let record = records.mappings.get(&address).ok_or("child owner absent")?;
                assert_eq!(record.process, std::process::id());
                assert_eq!(record.identity, expected);
            }
            let alias = mmap_setup_region(destination_file.as_fd(), length)?;
            original.hold_hot_fork_ring_io()?;
            let retained = original.retain_whole_mapping(7);
            retained.selection_status()?;
            assert!(alias.release_hot_fork_ring_io().is_err());
            assert!(matches!(
                mmap_setup_region(destination_file.as_fd(), length),
                Err(SetupRegionMapError::WholeCustody { .. })
            ));
            assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
            Ok(())
        })();
        // SAFETY: exit skips inherited destructors; the parent owns its VMAs.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    let mut status = 0;
    // SAFETY: status is writable and child is the fixture's actual fork PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);

    original.hold_hot_fork_ring_io()?;
    let mut retained = original.retain_whole_mapping(7);
    retained.selection_status()?;

    // SAFETY: the original and destination registry loans have ended. This
    // second fork is isolated by the same dedicated-process fixture.
    let selected_child = unsafe { libc::fork() };
    if selected_child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if selected_child == 0 {
        let refused = Arc::get_mut(&mut retained.mapping).is_some_and(|mapping| {
            matches!(
                mapping.install_hot_fork_child_mapping(destination_file.as_fd(), expected),
                Err(crate::HotForkChildMappingInstallError::WholeCustody {
                    source: WholeMappingCustodyError::Selected,
                })
            )
        });
        // SAFETY: no inherited owner destructor may act on the absent VMA.
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }

    assert_eq!(
        unsafe {
            // SAFETY: selected_child is the successful fork PID owned by this
            // parent; status is a live writable c_int for the waitpid result.
            libc::waitpid(selected_child, &mut status, 0)
        },
        selected_child
    );
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(
        retained
            .mapping()
            .ok_or("selected owner absent")?
            .hot_fork_ring_io_snapshot()?
            .quiescent()
    );
    Ok(())
}

#[test]
fn actual_socket_paired_processes_service_same_held_ring_without_release() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "mapped_setup_region::selected_lifecycle::tests::process::socket_paired_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "invoked alone to isolate the actual shared-ring fork and socket peers"]
fn socket_paired_fixture() -> TestResult {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let (file, first, alias) = original_aliases()?;
    let length = first.region_len();
    first.hold_hot_fork_ring_io()?;
    let (mut host_socket, mut child_socket) = UnixStream::pair()?;
    for socket in [&host_socket, &child_socket] {
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    }

    // SAFETY: this process-isolated fixture has no active domain or registry
    // loan. The child registers its own mapping before touching ring bytes.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(host_socket);
        let result = (|| -> TestResult {
            let mapping = mmap_setup_region(file.as_fd(), length)?;
            let mut original = mapping.retain_whole_mapping(7);
            original.selection_status()?;
            child_socket.write_all(&[0])?;
            let mut command = [0];
            child_socket.read_exact(&mut command)?;
            assert_eq!(command, [1]);
            let (received, completion) = original.with_paired_selected_scope(
                7,
                1,
                123,
                SelectedRingAdmissionBudget {
                    producer_attempts: 0,
                    consumer_attempts: 1,
                },
                |mapping| {
                    let pair = mapping.node_directed_ring_pair_mut(
                        0,
                        0,
                        crate::SLOT_NET_ROUTER as u32,
                        crate::SLOT_NET_ROUTER as u32,
                        0,
                    )?;
                    let frame = pair
                        .first
                        .header
                        .dequeue(pair.first.entries)?
                        .ok_or("original interprocess frame absent")?;
                    assert!(pair.first.header.producer_barrier_snapshot().quiescent());
                    assert!(pair.first.header.consumer_barrier_snapshot().quiescent());
                    Ok::<_, Box<dyn std::error::Error>>(frame)
                },
            )??;
            assert_eq!(completion.consumer_attempts(), 1);
            assert_eq!(completion.producer_attempts(), 0);
            assert_eq!(received.seq, 42);
            child_socket.write_all(&received.data[..usize::from(received.len)])?;
            assert!(original.selection_status().is_err());
            // Actual socket and ring balance grants no native stopped or
            // complete-journal authority; no local retirement is attempted.
            drop(completion);
            Ok(())
        })();
        // SAFETY: the child skips every inherited owner destructor.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    let mut original = first.retain_whole_mapping(7);
    original.selection_status()?;
    let mut ready = [255];
    host_socket.read_exact(&mut ready)?;
    assert_eq!(ready, [0]);
    let frame = crate::FrameEntry::new(11, 0, 42, b"original-cross-process")?;
    let (received, completion) = original.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 0,
        },
        |mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            pair.first.header.enqueue(pair.first.entries, &frame)?;
            host_socket.write_all(&[1])?;
            let mut received = [0; 22];
            host_socket.read_exact(&mut received)?;
            assert_eq!(pair.first.header.live_len(pair.first.entries)?, 0);
            Ok::<_, Box<dyn std::error::Error>>(received)
        },
    )??;
    assert_eq!(&received, b"original-cross-process");
    assert_eq!(completion.producer_attempts(), 1);
    assert_eq!(completion.consumer_attempts(), 0);
    drop(completion);

    let mut status = 0;
    // SAFETY: status is writable and child is this fixture's actual PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(original.selection_status().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}
