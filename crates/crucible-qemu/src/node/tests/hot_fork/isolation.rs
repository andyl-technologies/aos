//! Physical resource-isolation regression for retained hot-fork children.

use super::*;

#[test]
#[cfg(target_os = "linux")]
fn gate_hot_fork_isolation_keeps_two_resource_generations_physically_private()
-> Result<(), Box<dyn Error>> {
    use std::os::fd::AsFd as _;

    const PRIVATE_RING_CLASSES: [&str; 7] = [
        "fault-command",
        "fault-event",
        "network",
        "block",
        "9p",
        "coverage",
        "doorbell",
    ];

    let (source_identity, host_barrier, image) = held_hot_fork_ring_image()?;
    let plugin_barrier =
        crate::QmpHotForkPluginBarrierState::one_quiescent(15, host_barrier.ring_count());
    let first_log = shared_log();
    let second_log = shared_log();
    let mut first_source = scripted_hot_fork_capture_node(
        Arc::clone(&first_log),
        source_identity,
        source_identity,
        host_barrier,
        image.clone(),
        [plugin_barrier; 8],
        DescriptorScript::Success,
    )?;
    let mut second_source = scripted_hot_fork_capture_node(
        Arc::clone(&second_log),
        source_identity,
        source_identity,
        host_barrier,
        image.clone(),
        [plugin_barrier; 8],
        DescriptorScript::Success,
    )?;
    first_source.prepare_hot_fork_child_resources(image.canonical_len()?)?;
    second_source.prepare_hot_fork_child_resources(image.canonical_len()?)?;
    let first_directory = tempfile::tempdir()?;
    let second_directory = tempfile::tempdir()?;
    let first_vmstate = std::fs::File::create(first_directory.path().join("vmstate.qcow2"))?;
    let second_vmstate = std::fs::File::create(second_directory.path().join("vmstate.qcow2"))?;
    let vmstate_root = crate::QmpHotForkChildFileRoot::node_name("vmstate")?;
    let first_destinations = [crate::QemuHotForkChildFileDestination::new(
        &vmstate_root,
        first_vmstate.as_fd(),
    )];
    let second_destinations = [crate::QemuHotForkChildFileDestination::new(
        &vmstate_root,
        second_vmstate.as_fd(),
    )];
    let mut first_owner = ScriptedHotForkTargetOwner {
        contract: unvalidated_hot_fork_process_contract()?,
        retained: Vec::new(),
    };
    let mut second_owner = ScriptedHotForkTargetOwner {
        contract: unvalidated_hot_fork_process_contract()?,
        retained: Vec::new(),
    };

    let first_launch = first_source.fork_prepared_hot_fork_template_with_files_into(
        &mut first_owner,
        |owner| Ok(&owner.contract),
        &first_destinations,
        1 << 20,
    )?;
    let second_launch = second_source.fork_prepared_hot_fork_template_with_files_into(
        &mut second_owner,
        |owner| Ok(&owner.contract),
        &second_destinations,
        1 << 20,
    )?;

    // A hot-fork ring image is an authenticated image of every queue-backed
    // ring class. Both live children use the same logical generation while
    // owning different physical setup-region backings.
    assert!(host_barrier.ring_count() >= PRIVATE_RING_CLASSES.len() as u64);
    assert_eq!(
        first_launch.host_continuation().private_ring_generation(),
        second_launch.host_continuation().private_ring_generation()
    );
    assert_ne!(
        first_launch.host_continuation().ring_identity(),
        second_launch.host_continuation().ring_identity()
    );
    assert_ne!(
        first_launch.host_continuation().plugin_endpoint_identity(),
        second_launch.host_continuation().plugin_endpoint_identity()
    );
    assert_ne!(
        first_launch.child_qmp().socket_cookie(),
        second_launch.child_qmp().socket_cookie()
    );
    assert_ne!(
        first_launch.diagnostics().socket_cookie(),
        second_launch.diagnostics().socket_cookie()
    );
    assert_ne!(
        first_launch.host_continuation().host_io_binding(),
        second_launch.host_continuation().host_io_binding()
    );

    let first_file = first_launch
        .child_files()
        .first()
        .ok_or("first launch omitted its writable destination")?;
    let second_file = second_launch
        .child_files()
        .first()
        .ok_or("second launch omitted its writable destination")?;
    assert_eq!(first_file.root(), second_file.root());
    assert_ne!(
        (first_file.device(), first_file.inode()),
        (second_file.device(), second_file.inode())
    );

    let (_first_parent, _first_process, first_qmp, mut first_diagnostics, mut first_continuation) =
        first_launch.into_parts();
    let (_second_parent, _second_process, second_qmp, mut second_diagnostics, second_continuation) =
        second_launch.into_parts();
    let second_log_before = recorded(&second_log);
    let first_log_before = recorded(&first_log).len();

    assert_eq!(
        first_continuation.shmem_hot_path_mut().current_icount()?,
        Icount { retired: 11 }
    );
    assert_eq!(recorded(&first_log).len(), first_log_before + 1);
    assert_eq!(recorded(&second_log), second_log_before);
    assert!(first_continuation.console_observation_available());
    assert!(second_continuation.console_observation_available());
    first_continuation.attach_console_observation(&mut first_source, node_id("first-child"))?;
    assert!(!first_continuation.console_observation_available());
    assert!(second_continuation.console_observation_available());

    let first_drain = first_diagnostics.drain_available()?;
    assert_eq!(first_drain.bytes_read(), 26);
    assert!(second_diagnostics.retained().is_empty());
    let second_drain = second_diagnostics.drain_available()?;
    assert_eq!(second_drain.bytes_read(), 26);

    // The live endpoint owners remain distinct until both sources complete
    // their ordered release paths.
    drop((
        first_qmp,
        second_qmp,
        first_continuation,
        second_continuation,
    ));
    first_source.release_hot_fork_plugin_endpoints()?;
    first_source.release_hot_fork_child_console()?;
    first_source.release_hot_fork_child_qmp()?;
    let _first_capture =
        first_source.release_hot_fork_child_diagnostics_with_consumer(&mut first_diagnostics)?;
    drop(first_source.release_hot_fork_private_ring_mapping()?);
    second_source.release_hot_fork_plugin_endpoints()?;
    second_source.release_hot_fork_child_console()?;
    second_source.release_hot_fork_child_qmp()?;
    let _second_capture =
        second_source.release_hot_fork_child_diagnostics_with_consumer(&mut second_diagnostics)?;
    drop(second_source.release_hot_fork_private_ring_mapping()?);
    first_source.shutdown_child()?;
    second_source.shutdown_child()?;
    Ok(())
}
