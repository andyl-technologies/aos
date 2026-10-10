//! Managed same-parent sibling cohorts with seventeen complete world charges.
//!
//! One accepted Execution and sixteen independently admitted Services cover
//! the original source and sixteen live children. A real directory retention
//! catalog and production fallback authenticator keep the exact source pinned.

use super::concurrent::world_config;
use super::*;
use crate::{
    AuthenticatedHotCheckpointDemotionSink, AuthenticatedQemuHotForkSourceBasis,
    DirectoryHotCheckpointFallbackRetentionStore, HotCheckpointHotnessSignals, HotCheckpointLimits,
    HotCheckpointResourceProfile, ManagedQemuHotForkSourceWorldPool,
    ProductionBakedGenesisReplayCatalogFactory, ProductionQemuHotForkSourceFactory,
    QemuHotCheckpointFallbackAuthenticator, QemuHotForkSourceWorldDemoter,
    SharedManagedQemuHotForkSourceWorldPool,
};
use std::collections::BTreeSet;

pub(super) fn run(
    model: &ResumeModel<'_>,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
) -> RunEvidence {
    let source = input.scenario();
    assert_eq!(source.world().vm_nodes().len(), 1);
    assert_eq!(
        source
            .world()
            .vm_nodes()
            .iter()
            .next()
            .expect("one actual selected VM")
            .memory_mib,
        512
    );
    let available_before = available_resources(model.prepared);
    let services = RetainedTemplateServiceFactory::new(model.prepared, &model.config);
    let mut selected = context.take_selected_checkpoint();
    let service = Arc::new(
        services
            .start_for_resume(source, model.checkpoint, context, &mut selected)
            .expect("genuine selected exact source authority"),
    );
    assert!(selected.is_none());
    extend_native_operations(service.context());
    let source_config = world_config(&model.config, "sibling-source", 51_000);
    let basis = AuthenticatedQemuHotForkSourceBasis::authenticate(
        &model.store,
        input.lineage().id().expect("actual immutable lineage"),
        &crucible_campaign::ExecutorCompatibilityProfile::from_lineage(input.lineage()),
    )
    .expect("actual repository genesis basis");
    let build = basis.profile().qemu_build().to_owned();
    let mut source_factory = ProductionQemuHotForkSourceFactory::new(
        basis.clone(),
        fresh_factory(&source_config, "world"),
        &build,
    )
    .expect("actual launch profile matches the authenticated lineage");
    let authenticated = source_factory
        .capture_exact(&model.prepared.checkpoints, input, service.context())
        .expect("actual exact restore and retained barriers")
        .expect("selected source has the same requested configuration")
        .with_cleanup_observer(service.clone());
    let source_pids = cgroup_processes(source_config.host.cgroup_root());
    assert_eq!(source_pids.len(), 1);
    let source_memory = process_memory_evidence(&source_pids);
    let source_storage = allocated_tree_bytes(source_config.host.run_root());
    let source_preservation = inode_allocated_bytes(&unlinked_disk_files(
        &[source_pids[0], std::process::id()],
        &[source_config.host.run_root()],
    ));
    assert!(
        source_preservation > 0,
        "actual anonymous disk reservation exists"
    );
    let backing_peak = model
        .config
        .retained_template_resources()
        .expect("actual source backing entitlement")
        .backing_peak_bytes;
    assert!(
        source_storage
            .checked_add(source_preservation)
            .expect("bounded source storage")
            <= backing_peak
    );
    let child_disk_limit = source_storage / 2 + (16 << 20);
    let source_threads = count_process_entries(&source_pids, "task");
    let source_fds = count_process_entries(&source_pids, "fd");
    let replay_host = LinuxQemuAttemptHostResourceFactory::open(source_config.host.clone())
        .expect("actual replay guard namespace");
    let catalog = ProductionBakedGenesisReplayCatalogFactory::new(
        [model.baked.clone()],
        ComposedQemuAttemptResourceGuardFactory::new(replay_host),
    )
    .expect("same actual native basis used by accepted promotion")
    .with_replay_services(services.clone());
    let authenticator = QemuHotCheckpointFallbackAuthenticator::new(
        model.store.clone(),
        Arc::clone(&model.prepared.checkpoints),
        catalog,
    );
    let retention = DirectoryHotCheckpointFallbackRetentionStore::open(
        model
            .config
            .lifecycle
            .run_state_root()
            .join("sibling-retention"),
    )
    .expect("actual durable fallback custody");
    let profile = HotCheckpointResourceProfile::new(32 << 30, 16 << 30, 17, 17, 65_536, 128)
        .expect("explicit retained source and sixteen child ceiling");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        HotCheckpointLimits::new(1, profile, 64, 1_000_000_000).expect("bounded actual pool"),
        AuthenticatedHotCheckpointDemotionSink::new(authenticator, QemuHotForkSourceWorldDemoter),
        retention,
    )
    .expect("production authenticated source retention");
    pool.admit_authenticated_exact_source(authenticated, HotCheckpointHotnessSignals::new())
        .unwrap_or_else(|error| panic!("genuine managed source admission: {error}"));
    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut result = RunEvidence::default();
    let mut expected_ram = None;
    let peak = model
        .config
        .retained_template_resources()
        .expect("full world vector");
    for count in [1_usize, 2, 4, 8, 16] {
        let mut owners = Vec::with_capacity(count - 1);
        for _ in 1..count {
            let owner = services
                .start_comparison_child_for_test(source, context)
                .expect("fresh Service independently charged to the active accepted Execution");
            extend_native_operations(owner.context());
            owners.push(owner);
        }
        let distinct_owners = owners
            .iter()
            .map(|owner| owner.context().host_ram_owner_id())
            .chain([
                context.host_ram_owner_id(),
                service.context().host_ram_owner_id(),
            ])
            .collect::<BTreeSet<_>>();
        assert_eq!(distinct_owners.len(), count + 1);
        assert_template_charge(model.prepared, available_before, peak, count as u64);
        let sample_start = result.ready_samples.len();
        let mut children = Vec::with_capacity(count);
        let mut lane_paths = Vec::with_capacity(count);
        for index in 0..count {
            let lane = format!("siblings-{count}-{index}");
            let child_config = world_config(
                &model.config,
                &lane,
                52_000 + u32::try_from(count * 100 + index * 4).expect("bounded project identity"),
            );
            let child_context = if index == 0 {
                context
            } else {
                owners[index - 1].context()
            };
            let host = LinuxQemuAttemptHostResourceFactory::open(child_config.host.clone())
                .expect("fresh actual child cgroup and disk quota");
            let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
                shared
                    .provider()
                    .expect("independent checked-out source session"),
                ComposedQemuAttemptResourceGuardFactory::new(host),
                child_config.lifecycle.run_state_root().to_path_buf(),
                QemuShutdownPolicy {
                    control_quit_wait: Duration::from_secs(30),
                    qmp_quit_wait: Duration::from_secs(30),
                    sigterm_wait: Duration::from_secs(30),
                    sigkill_wait: Duration::from_secs(30),
                    reap_wait: Duration::from_secs(30),
                },
                QemuAsyncDriverPolicy::new(
                    Duration::from_secs(300),
                    Duration::from_secs(300),
                    Duration::from_secs(300),
                    Duration::from_secs(300),
                ),
            );
            let started = operational_monotonic_nanoseconds();
            let mut child = match factory
                .try_start(input, child_context)
                .expect("genuine fresh staged native sibling")
            {
                QemuHotForkWorldLifecycleStart::Started(child) => child,
                QemuHotForkWorldLifecycleStart::Declined => {
                    panic!("authenticated shared source declined")
                }
            };
            result
                .ready_samples
                .push(operational_monotonic_nanoseconds().saturating_sub(started));
            let pending = drain_exact_pending(&mut child);
            let boundary = capture_boundary_evidence(
                &mut child,
                source,
                model.captured.boundary.configuration.clone(),
                pending,
                topology(source),
            );
            assert_eq!(boundary, model.captured.boundary);
            let roots = child
                .capture_attempt_checkpoint(child_context)
                .expect("real child RAM roots")
                .into_closure()
                .ram_sources()
                .iter()
                .map(|source| (source.node().name.clone(), source.root().record().encode()))
                .collect::<BTreeMap<_, _>>();
            match &expected_ram {
                Some(expected) => assert_eq!(&roots, expected),
                None => expected_ram = Some(roots),
            }
            lane_paths.push((
                child_config.host.cgroup_root().to_path_buf(),
                child_config.host.run_root().to_path_buf(),
            ));
            children.push((factory, child));
        }
        let mut all_pids = BTreeSet::new();
        let mut private_rss = 0;
        let mut allocated = 0;
        let mut preservation = 0;
        for (cgroup, storage) in &lane_paths {
            let pids = cgroup_processes(cgroup);
            assert_eq!(pids.len(), 1);
            assert!(all_pids.insert(pids[0]));
            assert!(!source_pids.contains(&pids[0]));
            let footprint = process_memory_evidence(&pids);
            assert!(footprint.private_rss_kib <= 512 * 256 + 32 * 1024);
            private_rss += footprint.private_rss_kib;
            let bytes = allocated_tree_bytes(storage);
            assert!(bytes <= child_disk_limit);
            allocated += bytes;
            let private_disk = inode_allocated_bytes(&unlinked_disk_files(
                &[pids[0], std::process::id()],
                &[storage.as_path()],
            ));
            assert!(
                private_disk > 0,
                "each child owns real preservation extents"
            );
            assert!(
                bytes
                    .checked_add(private_disk)
                    .expect("bounded child storage")
                    <= backing_peak
            );
            preservation += private_disk;
        }
        let processes = source_pids
            .iter()
            .copied()
            .chain(all_pids.iter().copied())
            .chain([std::process::id()])
            .collect::<Vec<_>>();
        let run_roots = std::iter::once(source_config.host.run_root())
            .chain(lane_paths.iter().map(|(_, root)| root.as_path()))
            .collect::<Vec<_>>();
        let cohort_preservation =
            inode_allocated_bytes(&unlinked_disk_files(&processes, &run_roots));
        assert_eq!(cohort_preservation, source_preservation + preservation);
        let live_source = process_memory_evidence(&source_pids);
        assert!(
            live_source
                .private_dirty_kib
                .saturating_sub(source_memory.private_dirty_kib)
                <= 16 * 1024
        );
        assert!(
            live_source
                .private_rss_kib
                .saturating_sub(source_memory.private_rss_kib)
                <= 16 * 1024
        );
        crate::qemu_hot_fork_world_factory::assert_native_sibling_resources_private(&lane_paths)
            .expect("actual memfd/eventfd/socket/tempfile/overlay identity is private");
        assert!(
            shared.orderly_shutdown().is_err(),
            "live native leases forbid source retirement"
        );
        println!(
            "simultaneous_{count}_child_ready_samples_ns={}",
            result.ready_samples[sample_start..]
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("simultaneous_{count}_live_processes={count}");
        println!("simultaneous_{count}_child_private_rss_kib={private_rss}");
        println!(
            "simultaneous_{count}_world_private_rss_kib={}",
            private_rss + live_source.private_rss_kib
        );
        println!("simultaneous_{count}_child_allocated_bytes={allocated}");
        println!("simultaneous_{count}_child_anonymous_disk_bytes={preservation}");
        println!("simultaneous_{count}_cohort_anonymous_disk_bytes={cohort_preservation}");
        println!("simultaneous_{count}_backing_ceiling_bytes={backing_peak}");
        for (mut factory, mut child) in children {
            child
                .shutdown()
                .expect("actual sibling process and services reaped");
            let mut reconciled = false;
            for _ in 0..64 {
                if child
                    .reconcile_execution_disposition(crate::AttemptExecutionDisposition::Canceled)
                    .expect("same checked-out source reconciliation")
                    == AttemptExecutionReconciliationStep::Complete
                {
                    reconciled = true;
                    break;
                }
            }
            assert!(reconciled);
            assert!(factory.recover(child).is_ok());
            result.completed_children += 1;
        }
        for (cgroup, _) in &lane_paths {
            assert!(cgroup_processes(cgroup).is_empty());
        }
        for owner in owners {
            owner
                .release_after_world_cleanup()
                .expect("actual child watcher joined and full vector discharged");
        }
        assert_eq!(
            cgroup_processes(source_config.host.cgroup_root()),
            source_pids
        );
        assert_eq!(count_process_entries(&source_pids, "task"), source_threads);
        assert_eq!(count_process_entries(&source_pids, "fd"), source_fds);
        assert_template_charge(model.prepared, available_before, peak, 1);
    }
    assert_eq!(
        shared
            .orderly_shutdown()
            .expect("authenticate fallback and physically retire source after last lease")
            .len(),
        1
    );
    service
        .release_after_world_cleanup()
        .expect("source watcher joined after source reap");
    model
        .store
        .load_configuration_artifact(basis.source_artifact())
        .expect("actual immutable thin fallback remains available");
    assert!(cgroup_processes(source_config.host.cgroup_root()).is_empty());
    assert_eq!(available_resources(model.prepared), available_before);
    println!("simultaneous_sibling_counts=1,2,4,8,16");
    println!("simultaneous_child_boundary_equivalence=1,2,4,8,16");
    println!("simultaneous_source_boundary=authenticated-promoted-exact");
    println!("simultaneous_storage_metrics=linked-artifacts,unique-anonymous-disk-inodes");
    println!("simultaneous_source_private_growth_limit_kib=16384");
    println!(
        "simultaneous_child_resource_isolation=cgroup,storage,run-state,project-id,ring,socket,overlay"
    );
    println!("simultaneous_source_retirement=after-last-lease-release");
    println!("thin_fallback_after_source_retirement=authenticated");
    result
}
