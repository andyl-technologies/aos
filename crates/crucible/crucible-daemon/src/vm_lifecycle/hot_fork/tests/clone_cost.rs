//! Measures the private memory that cloning a host-world continuation adds.

use super::*;

/// Clones one captured continuation into many siblings and bounds the
/// private memory the clones add to this process.
pub(super) fn measure_host_continuation_clone_cost() {
    const SIBLINGS: usize = 64;
    const OBJECT_BYTES: usize = 16 * 1024 * 1024;
    const MAX_PRIVATE_GROWTH_KIB: u64 = 64 * 1024;

    let (source, mut captured) = active_multi_node_continuation();
    let first_artifact_bytes = vec![3; OBJECT_BYTES];
    let first_artifact = ContentHash::from_bytes(&first_artifact_bytes);
    Arc::make_mut(&mut captured.signal_artifact_objects)
        .insert(first_artifact, first_artifact_bytes);
    let signal_bytes = vec![5; OBJECT_BYTES];
    let signal = ContentHash::from_bytes(&signal_bytes);
    Arc::make_mut(&mut captured.signal_artifact_objects).insert(signal, signal_bytes);

    let baseline_kib = host_private_dirty_kib();
    let (siblings, clone_elapsed_micros) = time_host_clone(|| {
        (0..SIBLINGS)
            .map(|_| {
                captured
                    .try_clone_for_branch()
                    .unwrap_or_else(|error| panic!("clone host sibling: {error}"))
            })
            .collect::<Vec<_>>()
    });
    let private_growth_kib = host_private_dirty_kib().saturating_sub(baseline_kib);

    for sibling in &siblings {
        sibling
            .validate_complete_internal_state()
            .unwrap_or_else(|error| panic!("active sibling should remain complete: {error}"));
        sibling
            .validate_world_io(source.world())
            .unwrap_or_else(|error| panic!("active sibling host I/O should validate: {error}"));
        assert!(Arc::ptr_eq(&captured.scheduler, &sibling.scheduler));
        assert!(Arc::ptr_eq(
            &captured.signal_artifact_objects,
            &sibling.signal_artifact_objects
        ));
        assert_eq!(
            sibling.signal_artifact_objects[&first_artifact].len(),
            OBJECT_BYTES
        );
        assert_eq!(sibling.signal_artifact_objects[&signal].len(), OBJECT_BYTES);
        assert_eq!(sibling.active_host_io, captured.active_host_io);
        assert!(sibling.failed_host_io.is_empty());
    }
    assert_eq!(Arc::strong_count(&captured.scheduler), SIBLINGS + 1);
    assert_eq!(
        Arc::strong_count(&captured.signal_artifact_objects),
        SIBLINGS + 1
    );
    assert!(
        private_growth_kib <= MAX_PRIVATE_GROWTH_KIB,
        "{SIBLINGS} host clones consumed {private_growth_kib} KiB private memory"
    );

    let mut siblings = siblings;
    let changed_node = captured.nodes[0].node.clone();
    let original_host_io = captured.active_host_io[&changed_node].clone();
    let replacement_host_io =
        QemuHostIoCheckpoint::without_devices(ContentHash::from_bytes(b"child-only-host-io"));
    siblings[0]
        .active_host_io
        .insert(changed_node.clone(), replacement_host_io.clone());
    siblings[0].node_generations.insert(changed_node.clone(), 2);
    siblings[0].nodes[0].generation = 2;

    assert_eq!(
        siblings[0].active_host_io[&changed_node],
        replacement_host_io
    );
    assert_eq!(siblings[0].node_generations[&changed_node], 2);
    assert_eq!(captured.active_host_io[&changed_node], original_host_io);
    assert_eq!(siblings[1].active_host_io[&changed_node], original_host_io);
    assert_eq!(captured.node_generations[&changed_node], 1);
    assert_eq!(siblings[1].node_generations[&changed_node], 1);
    siblings[0]
        .validate_complete_internal_state()
        .unwrap_or_else(|error| panic!("mutated active sibling should remain complete: {error}"));

    println!("host_continuation_siblings={SIBLINGS}");
    println!("host_active_nodes={}", captured.nodes.len());
    println!("host_immutable_object_bytes={}", 2 * OBJECT_BYTES);
    println!("host_shared_backing_copies=1");
    println!("host_clone_private_growth_kib={private_growth_kib}");
    println!("host_clone_private_growth_limit_kib={MAX_PRIVATE_GROWTH_KIB}");
    println!("host_clone_elapsed_micros={clone_elapsed_micros}");
}

fn host_private_dirty_kib() -> u64 {
    let rollup = std::fs::read_to_string("/proc/self/smaps_rollup")
        .unwrap_or_else(|error| panic!("read host memory rollup: {error}"));
    rollup
        .lines()
        .find_map(|line| line.strip_prefix("Private_Dirty:"))
        .and_then(|value| value.trim().strip_suffix(" kB"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("host memory rollup lacks Private_Dirty in KiB"))
}

// Host time is operational gate evidence and never enters deterministic state.
// crucible-lint: allow clippy-disallowed-method -- this helper only times test cloning.
#[allow(clippy::disallowed_methods)]
fn time_host_clone<T>(clone: impl FnOnce() -> T) -> (T, u128) {
    let started = std::time::Instant::now();
    let result = clone();
    (result, started.elapsed().as_micros())
}
