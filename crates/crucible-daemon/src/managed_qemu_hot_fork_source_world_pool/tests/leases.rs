//! Shared lease accounting, abandonment, shutdown, and restart regressions.

use super::*;

#[test]
fn shared_source_leases_allow_bounded_siblings_and_delay_reuse_until_the_last_release() {
    let _original_fixture_scope =
        crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let source_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source node");
    let (_nodes, mut source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
            .expect("prepared source world");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x3a),
        source.continuation().unwrap().configuration().def.id(),
        source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let usage = source
        .measure_retained_resources()
        .expect("measure retained source");
    let source_resources = HotCheckpointResourceProfile::new(
        usage.template_bytes(),
        usage.expected_private_dirty_bytes(),
        usage.process_count(),
        usage.virtual_cpu_count(),
        usage.descriptor_count(),
        usage.overlay_count(),
    )
    .expect("source resource profile");
    let parent_and_two_child_resources = HotCheckpointResourceProfile::new(
        source_resources.template_bytes() * 3,
        source_resources.expected_private_dirty_bytes() * 3,
        source_resources.process_count() * 3,
        source_resources.virtual_cpu_count() * 3,
        source_resources.descriptor_count() * 3,
        source_resources.overlay_count() * 3,
    )
    .expect("parent-and-two-child resource ceiling");
    // Keep all checkouts in one rate window so rejected starts cannot be hidden
    // by a clock-window rollover during this accounting regression.
    let limits = HotCheckpointLimits::new(1, parent_and_two_child_resources, 3, u64::MAX)
        .expect("two-child lease limits");
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention)
        .expect("managed source pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x49),
    )
    .expect("admit shared source");

    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut first_provider = shared.provider().expect("first provider");
    let mut second_provider = shared.provider().expect("second provider");
    let mut excess_provider = shared.provider().expect("excess provider");
    let first = first_provider
        .checkout(&key)
        .expect("first lease checkout")
        .expect("first lease");
    let second = second_provider
        .checkout(&key)
        .expect("second lease checkout")
        .expect("second lease");

    assert!(Arc::ptr_eq(&first.source, &second.source));
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    {
        let pool = shared
            .pool
            .lock()
            .expect("pool-authenticated sibling refusal");
        assert!(
            pool.authenticate_parent_park_lease(first_provider.provider, &first)
                .is_err()
        );
        assert!(
            pool.authenticate_parent_park_lease(second_provider.provider, &second)
                .is_err()
        );
        assert!(
            pool.worlds
                .values()
                .all(|world| world.parent_park.is_none())
        );
    }

    let (lease_usage, next_lease) = {
        let pool = shared.pool.lock().expect("shared pool before rejection");
        (pool.source_lease_usage(), pool.next_lease)
    };
    for _ in 0..3 {
        let error = match excess_provider.checkout(&key) {
            Err(SharedQemuHotForkSourceWorldProviderError::Checkout(error)) => error,
            _ => panic!("excess child must fail capacity admission"),
        };
        assert!(matches!(
            &error,
            ManagedQemuHotForkSourceWorldCheckoutError::LeaseCapacity {
                pressure, current, projected, limits: rejected_limits,
            } if pressure.template_bytes()
                && pressure.expected_private_dirty_bytes()
                && pressure.process_count()
                && pressure.virtual_cpu_count()
                && pressure.descriptor_count()
                && pressure.overlay_count()
                && current.template_bytes() == source_resources.template_bytes() * 3
                && projected.template_bytes() == source_resources.template_bytes() * 4
                && **rejected_limits == limits
        ));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("current=HotCheckpointUsage"));
        assert!(diagnostic.contains("projected=HotCheckpointUsage"));
        assert!(diagnostic.contains("limits=HotCheckpointLimits"));

        let pool = shared.pool.lock().expect("shared pool after rejection");
        assert_eq!(pool.source_lease_usage(), lease_usage);
        assert_eq!(pool.next_lease, next_lease);
        assert_eq!(pool.leased_out.len(), 2);
    }
    assert!(shared.orderly_shutdown().is_err());

    first_provider.restore(first);
    {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        {
            let pool = shared.pool.lock().expect("single exact lease admission");
            assert!(
                pool.authenticate_parent_park_lease(second_provider.provider, &second)
                    .is_ok()
            );
            assert!(
                pool.authenticate_parent_park_lease(first_provider.provider, &second)
                    .is_err()
            );
            assert!(
                pool.worlds
                    .values()
                    .all(|world| world.parent_park.is_none())
            );
        }

        let pool = shared.pool.lock().expect("shared pool after first release");
        let lease_usage = pool.source_lease_usage();
        assert_eq!(
            lease_usage.template_bytes(),
            source_resources.template_bytes()
        );
        assert!(pool.source_lease_available(&key));
        assert!(!pool.source_available(&key));
    }
    assert!(shared.orderly_shutdown().is_err());

    // Rejected checkouts must leave the third fork-start permit available.
    let replacement = excess_provider
        .checkout(&key)
        .expect("capacity rejection did not consume fork rate")
        .expect("replacement child lease");
    {
        let pool = shared.pool.lock().expect("shared pool after replacement");
        let record = pool
            .leased_out
            .get(&excess_provider.provider)
            .expect("replacement reservation");
        assert_eq!(record._permit.ordinal(), 3);
    }
    excess_provider.restore(replacement);

    second_provider.restore(second);
    {
        let pool = shared.pool.lock().expect("shared pool after final release");
        assert_eq!(pool.source_lease_usage(), HotCheckpointUsage::default());
        assert!(pool.source_available(&key));
    }

    let demotions = shared
        .orderly_shutdown()
        .expect("retire source after final lease release");
    assert_eq!(demotions.len(), 1);
}

#[test]
fn source_admission_accounts_for_live_child_lease_reservations() {
    let _original_fixture_scope =
        crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let first_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_first_nodes, mut first_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first_node])
            .expect("first prepared source");
    let (_second_nodes, mut second_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![second_node])
            .expect("second prepared source");
    let first_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x3c),
        first_source
            .continuation()
            .unwrap()
            .configuration()
            .def
            .id(),
        first_source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let second_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x3d),
        second_source
            .continuation()
            .unwrap()
            .configuration()
            .def
            .id(),
        second_source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let first_usage = first_source
        .measure_retained_resources()
        .expect("measure first source");
    let second_usage = second_source
        .measure_retained_resources()
        .expect("measure second source");
    // Private_Dirty is a live, page-granular procfs sample. Equivalent
    // scripted processes can differ by one allocator-residency page, so the
    // admission ceiling must add each authenticated sample independently.
    assert_eq!(first_usage.template_bytes(), second_usage.template_bytes());
    assert_eq!(first_usage.process_count(), second_usage.process_count());
    assert_eq!(
        first_usage.virtual_cpu_count(),
        second_usage.virtual_cpu_count()
    );
    assert_eq!(
        first_usage.descriptor_count(),
        second_usage.descriptor_count()
    );
    assert_eq!(first_usage.overlay_count(), second_usage.overlay_count());
    assert!(
        first_usage.expected_private_dirty_bytes() >= first_usage.template_bytes()
            && second_usage.expected_private_dirty_bytes() >= second_usage.template_bytes()
    );
    // Keep the moving procfs sample out of this exact pressure predicate. The
    // stable dimensions below still prove that the checked-out child's full
    // resource reservation participates in candidate admission.
    let two_source_resources = HotCheckpointResourceProfile::new(
        first_usage.template_bytes() + second_usage.template_bytes(),
        u64::MAX,
        first_usage.process_count() + second_usage.process_count(),
        first_usage.virtual_cpu_count() + second_usage.virtual_cpu_count(),
        first_usage.descriptor_count() + second_usage.descriptor_count(),
        first_usage.overlay_count() + second_usage.overlay_count(),
    )
    .expect("two-source aggregate ceiling");
    let limits = HotCheckpointLimits::new(2, two_source_resources, 2, 1_000_000_000)
        .expect("source-and-child limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("managed source pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(first_key.clone(), first_source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x4b),
    )
    .expect("admit first source");

    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut provider = shared.provider().expect("source provider");
    let lease = provider
        .checkout(&first_key)
        .expect("lease checkout")
        .expect("source lease");
    let failure = shared
        .pool
        .lock()
        .expect("shared pool")
        .admit_authenticated_source(
            AuthenticatedCanonicalQemuHotForkSource::new_for_test(second_key, second_source),
            HotCheckpointHotnessSignals::new(),
            exact_fallback(0x4c),
        )
        .expect_err("live lease must consume candidate capacity");
    let ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) = failure else {
        panic!("second source binding unexpectedly failed");
    };
    let (candidate, cleanup_slot, error) = failure.into_parts();
    assert!(cleanup_slot.is_none());
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldAdmissionError::LeaseCapacity { pressure }
            if pressure.template_bytes()
                && !pressure.expected_private_dirty_bytes()
                && pressure.process_count()
                && pressure.virtual_cpu_count()
                && pressure.descriptor_count()
                && pressure.overlay_count()
    ));
    let candidate = match candidate.into_source() {
        Ok(candidate) => candidate,
        Err(candidate) => {
            let _retained_for_process_lifetime = Box::leak(candidate);
            panic!("rejected candidate did not retain exclusive source ownership");
        }
    };
    candidate.retire().expect("retire rejected candidate");

    provider.restore(lease);
    shared
        .orderly_shutdown()
        .expect("retire first source after lease release");
}

#[test]
fn abandoned_shared_lease_closes_admission_without_revoking_a_healthy_sibling() {
    let _original_fixture_scope =
        crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let source_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("source node");
    let (_nodes, mut source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
            .expect("prepared source world");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x3b),
        source.continuation().unwrap().configuration().def.id(),
        source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let usage = source
        .measure_retained_resources()
        .expect("measure retained source");
    let parent_and_two_child_resources = HotCheckpointResourceProfile::new(
        usage.template_bytes() * 3,
        usage.expected_private_dirty_bytes() * 3,
        usage.process_count() * 3,
        usage.virtual_cpu_count() * 3,
        usage.descriptor_count() * 3,
        usage.overlay_count() * 3,
    )
    .expect("parent-and-two-child resource ceiling");
    let limits = HotCheckpointLimits::new(1, parent_and_two_child_resources, 3, 1_000_000_000)
        .expect("two-child lease limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("managed source pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x4a),
    )
    .expect("admit shared source");

    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut ambiguous_provider = shared.provider().expect("ambiguous provider");
    let mut healthy_provider = shared.provider().expect("healthy provider");
    let mut later_provider = shared.provider().expect("later provider");
    let ambiguous = ambiguous_provider
        .checkout(&key)
        .expect("ambiguous lease checkout")
        .expect("ambiguous lease");
    let healthy = healthy_provider
        .checkout(&key)
        .expect("healthy lease checkout")
        .expect("healthy lease");

    ambiguous_provider.abandon();
    drop(ambiguous);
    assert!(
        later_provider
            .checkout(&key)
            .expect("closed admission is a clean miss")
            .is_none()
    );
    assert!(
        healthy
            .source
            .lock()
            .expect("healthy sibling retains source access")
            .fork_continuation()
            .is_ok()
    );

    healthy_provider.restore(healthy);
    let pool = shared.pool.lock().expect("invalidated shared pool");
    assert!(!pool.source_lease_available(&key));
    assert_eq!(
        pool.source_lease_usage().template_bytes(),
        usage.template_bytes()
    );
    drop(pool);
    assert!(shared.orderly_shutdown().is_err());
}

#[test]
fn shared_worker_providers_release_before_orderly_shutdown_and_restart_inventory() {
    let _original_fixture_scope =
        crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let first_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_first_nodes, mut first_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first_node])
            .expect("first prepared source world");
    let (_second_nodes, mut second_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![second_node])
            .expect("second prepared source world");
    let first_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x36),
        first_source
            .continuation()
            .unwrap()
            .configuration()
            .def
            .id(),
        first_source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let second_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x37),
        second_source
            .continuation()
            .unwrap()
            .configuration()
            .def
            .id(),
        second_source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let first_usage = first_source
        .measure_retained_resources()
        .expect("measure first source");
    let second_usage = second_source
        .measure_retained_resources()
        .expect("measure second source");
    let retained_and_leased_resources = HotCheckpointResourceProfile::new(
        (first_usage.template_bytes() + second_usage.template_bytes()) * 2,
        (first_usage.expected_private_dirty_bytes() + second_usage.expected_private_dirty_bytes())
            * 2,
        (first_usage.process_count() + second_usage.process_count()) * 2,
        (first_usage.virtual_cpu_count() + second_usage.virtual_cpu_count()) * 2,
        (first_usage.descriptor_count() + second_usage.descriptor_count()) * 2,
        (first_usage.overlay_count() + second_usage.overlay_count()) * 2,
    )
    .expect("two-source and two-lease resource ceiling");
    let limits = HotCheckpointLimits::new(2, retained_and_leased_resources, 2, 1_000_000_000)
        .expect("shared managed limits");
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("shared managed pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(first_key.clone(), first_source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x47),
    )
    .expect("admit first shared source");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(second_key.clone(), second_source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x48),
    )
    .expect("admit second shared source");

    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut first_provider = shared.provider().expect("first worker provider");
    let mut second_provider = shared.provider().expect("second worker provider");
    let first_checked_out = first_provider
        .checkout(&first_key)
        .expect("first worker checkout")
        .expect("first source available");
    let second_checked_out = second_provider
        .checkout(&second_key)
        .expect("second worker checkout")
        .expect("second source available");
    assert!(matches!(
        first_provider.checkout(&second_key),
        Err(SharedQemuHotForkSourceWorldProviderError::Checkout(
            ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending
        ))
    ));
    let shutdown = shared
        .orderly_shutdown()
        .expect_err("checked-out sources block orderly shutdown");
    let SharedManagedQemuHotForkSourceWorldShutdownError::Sources(shutdown) = shutdown else {
        panic!("shared shutdown lock remained healthy");
    };
    let failed_keys = shutdown
        .failures()
        .iter()
        .map(|(key, _source)| *key)
        .collect::<Vec<_>>();
    assert_eq!(
        failed_keys,
        vec![first_key.template_key(), second_key.template_key()]
    );

    first_provider.restore(first_checked_out);
    second_provider.restore(second_checked_out);
    drop(first_provider);
    drop(second_provider);

    let demotions = shared.orderly_shutdown().expect("retire shared sources");
    assert_eq!(demotions.len(), 2);
    assert!(
        demotions
            .iter()
            .all(|demotion| demotion.reason() == HotCheckpointDemotionReason::DaemonShutdown)
    );
    drop(shared);

    let mut reopened =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention)
            .expect("reopen cold fallback inventory");
    assert_eq!(reopened.cold_fallbacks().count(), 2);

    let restarted_node = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)
        .expect("restarted source");
    let (_nodes, restarted_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![restarted_node])
            .expect("restarted prepared source world");
    reopened
        .admit_authenticated_source(
            AuthenticatedCanonicalQemuHotForkSource::new_for_test(
                first_key.clone(),
                restarted_source,
            ),
            HotCheckpointHotnessSignals::new(),
            exact_fallback(0x47),
        )
        .expect("promote matching cold fallback to active after restart");

    assert_eq!(reopened.records.len(), 2);
    assert_eq!(reopened.cold_fallbacks().count(), 1);
    reopened
        .orderly_shutdown()
        .expect("retire restarted source");
    assert_eq!(reopened.cold_fallbacks().count(), 2);
}

#[test]
fn exclusive_source_refuses_live_and_weak_borrowers_before_the_world_lock() {
    let _original_fixture_scope =
        crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let node = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)
        .expect("actual scripted source fixture");
    let (_, source) = prepared_multi_node_hot_fork_source_world_for_test(vec![node])
        .expect("complete fixture lifecycle");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x63),
        source.continuation().unwrap().configuration().def.id(),
        source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let template = manager_source_key(&key);
    let identity = QemuHotForkSourceWorldCheckoutIdentity::capture(&source).unwrap();
    let lease = QemuHotForkSourceWorldLease::exclusive(template, source, identity);
    let concurrent = lease.source_owner();
    let held_world = concurrent.lock().expect("existing child's world borrow");

    // The fixed handover must refuse before trying to lock or restore this
    // world. A phase facade alone would not exclude this actual child alias.
    let lease = match lease.into_exclusive_source() {
        Err(retained) => *retained,
        Ok(_) => panic!("shared source cannot enter an exclusive parent phase"),
    };
    assert!(Arc::ptr_eq(&lease.source, &concurrent));
    drop(held_world);
    drop(concurrent);

    let potential_child = Arc::downgrade(&lease.source);
    let lease = match lease.into_exclusive_source() {
        Err(retained) => *retained,
        Ok(_) => panic!("a surviving weak source borrower can reopen the world"),
    };
    assert!(potential_child.upgrade().is_some());
    drop(potential_child);

    let source = lease
        .into_exclusive_source()
        .expect("sole complete world owner");
    source
        .retire()
        .expect("retire the actual fixture lifecycle");
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
#[test]
fn managed_parent_park_refusal_keeps_exact_pool_record_and_reservation() {
    let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let source_node = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)
        .expect("scripted source with no genuine park issuer");
    // The park gate supports one declared parent process. The general fixture
    // keeps three World boundaries even when only one has a running source.
    let base = crucible::crash_restart_scenario()
        .expect("fixture scenario")
        .scenario;
    let node = base.world().vm_nodes().first().expect("fixture VM").clone();
    let world = crucible::World::from_nodes_and_links(vec![node], Vec::new())
        .expect("one declared parent World");
    let plan = crucible::Plan::empty();
    let properties = crucible::Properties::from_assertions_for_world(&world, Vec::new())
        .expect("host custody control has no guest assertions");
    let scenario = crucible::ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        crucible::Seed::from_u64(7),
        10,
    )
    .expect("same fixture seed and application draw ceiling");
    let (_, mut source) =
        crucible_api::vm_lifecycle::prepared_multi_node_hot_fork_source_world_for_scenario_for_test(
            &scenario,
            vec![source_node],
        )
        .expect("prepared single-parent source");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x71),
        source.continuation().unwrap().configuration().def.id(),
        source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let usage = source
        .measure_retained_resources()
        .expect("source resources");
    let limits = HotCheckpointLimits::new(
        1,
        HotCheckpointResourceProfile::new(
            usage.template_bytes() * 3,
            usage.expected_private_dirty_bytes() * 3,
            usage.process_count() * 3,
            usage.virtual_cpu_count() * 3,
            usage.descriptor_count() * 3,
            usage.overlay_count() * 3,
        )
        .expect("existing three-world geometry"),
        3,
        u64::MAX,
    )
    .expect("limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x72),
    )
    .expect("source admission");
    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut provider = shared.provider().expect("real pool provider");
    let mut sibling = shared.provider().expect("distinct provider");
    let lease = provider
        .checkout(&key)
        .expect("checkout")
        .expect("actual lease");
    assert!(lease.identity.single_node().is_some());
    let lease_id = lease.managed_lease;
    let (caller, decoder, resident, metadata) =
        crate::private_original_capture::park_caller::controlled_park_caller_for_test();
    let before = shared.pool.lock().expect("before").source_lease_usage();

    let refusal = provider
        .park_parent_before_fork(&lease, &caller)
        .expect_err("scripted launcher cannot fabricate a native owner");

    assert!(
        matches!(&refusal, parent_park::ManagedParentParkError::Retained(_)),
        "{refusal:?}"
    );
    assert!(std::error::Error::source(&refusal).is_some());
    assert!(sibling.checkout(&key).expect("gate refusal").is_none());
    provider.restore(lease);
    provider.abandon();
    {
        let pool = shared.pool.lock().expect("retained exact record");
        let record = pool
            .leased_out
            .get(&provider.provider)
            .expect("record survives facade restore/abandon");
        assert_eq!(Some(record.lease), lease_id);
        assert_eq!(pool.source_lease_usage(), before);
        let gate = pool
            .worlds
            .get(&record.template)
            .expect("world")
            .parent_park
            .as_ref()
            .expect("gate retained");
        assert!(gate.first_cause_retained());
        assert!(record.source.upgrade().is_some());
    }
    assert!(shared.orderly_shutdown().is_err());
    assert!(decoder.try_close().is_err());
    assert!(resident.reserve_resources(1, 64, 1 << 20).is_err());
    assert!(metadata.reserve_resources(1, 64, 1 << 20).is_err());
    // No release or physical retirement is fabricated for this negative. The
    // occupied pool keeps its real host loan for containment at process exit.
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
#[test]
fn declared_multi_node_parent_park_refuses_before_pool_publication() {
    let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let source_node = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)
        .expect("scripted source with no genuine park issuer");
    let (_, mut source) = prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
        .expect("prepared source");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x71),
        source.continuation().unwrap().configuration().def.id(),
        source.continuation().unwrap().configuration().id(),
        compatibility_profile(),
    );
    let usage = source
        .measure_retained_resources()
        .expect("source resources");
    let limits = HotCheckpointLimits::new(
        1,
        HotCheckpointResourceProfile::new(
            usage.template_bytes() * 3,
            usage.expected_private_dirty_bytes() * 3,
            usage.process_count() * 3,
            usage.virtual_cpu_count() * 3,
            usage.descriptor_count() * 3,
            usage.overlay_count() * 3,
        )
        .expect("existing three-world geometry"),
        3,
        u64::MAX,
    )
    .expect("limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x72),
    )
    .expect("source admission");
    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut provider = shared.provider().expect("real pool provider");
    let lease = provider
        .checkout(&key)
        .expect("checkout")
        .expect("actual lease");
    let lease_id = lease.managed_lease;
    assert_eq!(
        lease
            .source
            .lock()
            .expect("source")
            .continuation()
            .unwrap()
            .nodes()
            .len(),
        3
    );
    assert!(lease.identity.single_node().is_none());
    let (caller, decoder, resident, metadata) =
        crate::private_original_capture::park_caller::controlled_park_caller_for_test();
    let before = shared.pool.lock().expect("before").source_lease_usage();

    let refusal = provider
        .park_parent_before_fork(&lease, &caller)
        .expect_err("three declared parents refuse before phase publication");

    assert!(
        matches!(
            &refusal,
            parent_park::ManagedParentParkError::Early(
                crucible_api::ProductionVmParentParkDrainRefusal::Unavailable(
                    "managed park requires one declared parent process"
                )
            )
        ),
        "{refusal:?}"
    );
    let pool = shared.pool.lock().expect("unmodified pool");
    let record = pool.leased_out.get(&provider.provider).expect("same lease");
    assert_eq!(Some(record.lease), lease_id);
    assert_eq!(pool.source_lease_usage(), before);
    assert!(
        pool.worlds
            .get(&record.template)
            .expect("world")
            .parent_park
            .is_none()
    );
    assert!(record.source.upgrade().is_some());
    drop(pool);

    // No phase or new caller alias was born on this unsupported topology.
    drop(caller);
    assert!(decoder.try_close().is_ok());
    assert!(resident.reserve_resources(1, 64, 1 << 20).is_ok());
    assert!(metadata.reserve_resources(1, 64, 1 << 20).is_ok());
}
