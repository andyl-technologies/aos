//! Packaged executor lifecycle ownership and recovery regressions.

use super::*;

#[test]
fn packaged_executor_completion_is_sticky_across_owner_panic() {
    let state = Arc::new((Mutex::new(false), Condvar::new()));
    let completion = PackagedQemuExecutorCompletion {
        state: Arc::clone(&state),
    };
    let owner = thread::spawn(move || {
        let _completion = PackagedQemuExecutorCompletionGuard(state);
        panic!("injected packaged executor owner panic");
    });

    assert!(owner.join().is_err());
    completion.wait();
}

#[test]
fn competing_packaged_startup_preserves_live_native_catalogs() {
    let directory = tempfile::tempdir().expect("packaged competing-start directory");
    let mut config = config(&directory, 1);
    config.lifecycle = ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        "kernel",
        "root",
        directory.path().join("run-state"),
    );
    let run_state_root = config.lifecycle.run_state_root();
    let workers = run_state_root.join("campaign-workers");
    let promotions = run_state_root.join("campaign-checkpoint-promotions");
    std::fs::create_dir_all(&workers).expect("live worker catalog");
    std::fs::write(workers.join("sentinel"), b"worker").expect("live worker sentinel");
    std::fs::create_dir_all(&promotions).expect("live promotion catalog");
    std::fs::write(promotions.join("sentinel"), b"promotion").expect("live promotion sentinel");
    let _live_ledger =
        DirectoryAssignmentLedger::open(&config.ledger_root).expect("live assignment ledger");

    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let result = compose_packaged_qemu_executor(
        PackagedQemuExecutorStorage::new(
            repository,
            Arc::new(DirectoryBlobBackend::new(
                "packaged-competing-start-checkpoints",
                directory.path().join("shared-store"),
            )),
        ),
        profile(),
        scenario_artifact(),
        config,
        UnusedHostFactory,
    );
    let Err(PackagedQemuExecutorError::Ledger(_)) = result else {
        panic!("competing packaged startup must fail at ledger ownership");
    };

    assert_eq!(
        std::fs::read(workers.join("sentinel")).expect("retained worker sentinel"),
        b"worker"
    );
    assert_eq!(
        std::fs::read(promotions.join("sentinel")).expect("retained promotion sentinel"),
        b"promotion"
    );
}

#[test]
fn packaged_native_catalog_recovery_is_crash_safe_and_idempotent() {
    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let workers = directory.path().join("campaign-workers");
    let promotions = directory.path().join("campaign-checkpoint-promotions");
    std::fs::create_dir_all(workers.join("worker-0/scenario")).expect("active worker catalog");
    std::fs::write(workers.join("worker-0/scenario/native"), b"worker")
        .expect("worker catalog sentinel");
    std::fs::create_dir_all(promotions.join("worker-0/scenario"))
        .expect("active promotion catalog");
    std::fs::write(promotions.join("worker-0/scenario/native"), b"promotion")
        .expect("promotion catalog sentinel");

    reconcile_packaged_native_catalogs(directory.path()).expect("retire active catalogs");
    for namespace in PACKAGED_NATIVE_NAMESPACES {
        assert!(!directory.path().join(namespace).exists());
        assert!(
            !directory
                .path()
                .join(format!(".retired-{namespace}"))
                .exists()
        );
    }

    reconcile_packaged_native_catalogs(directory.path()).expect("idempotent catalog recovery");
}

#[test]
fn packaged_native_catalog_recovery_finishes_a_renamed_generation() {
    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let retired_workers = directory.path().join(".retired-campaign-workers");
    let promotions = directory.path().join("campaign-checkpoint-promotions");
    std::fs::create_dir_all(retired_workers.join("worker-0/scenario"))
        .expect("retired worker catalog");
    std::fs::create_dir_all(promotions.join("worker-0/scenario"))
        .expect("active promotion catalog");

    reconcile_packaged_native_catalogs(directory.path()).expect("finish catalog recovery");
    assert!(!retired_workers.exists());
    assert!(!promotions.exists());
}

#[test]
fn packaged_native_catalog_recovery_rejects_conflicting_generations() {
    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let active = directory.path().join("campaign-workers");
    let retired = directory.path().join(".retired-campaign-workers");
    std::fs::create_dir(&active).expect("active worker catalog");
    std::fs::create_dir(&retired).expect("retired worker catalog");

    assert!(matches!(
        reconcile_packaged_native_catalogs(directory.path()),
        Err(PackagedNativeCatalogRecoveryError::ConflictingGeneration {
            namespace: "campaign-workers"
        })
    ));
    assert!(active.exists());
    assert!(retired.exists());
}

#[cfg(unix)]
#[test]
fn packaged_native_catalog_recovery_rejects_namespace_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("packaged native catalog root");
    let target = directory.path().join("unrelated");
    std::fs::create_dir(&target).expect("unrelated directory");
    let workers = directory.path().join("campaign-workers");
    symlink(&target, &workers).expect("worker namespace symlink");

    assert!(matches!(
        reconcile_packaged_native_catalogs(directory.path()),
        Err(PackagedNativeCatalogRecoveryError::InvalidPath { path }) if path == workers
    ));
    assert!(target.exists());
}

#[test]
fn operational_phase_uses_exact_actor_ownership_and_durable_phase() {
    let epoch = DaemonEpoch::from_bytes([0x91; 16]).expect("daemon epoch");
    let execution = ExecutionId::from_bytes([0x92; 16]).expect("execution");
    let basis = CampaignHash::derive("packaged-status-test", b"basis");
    let running = AttemptRuntimeState::Running {
        execution_basis: basis,
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
    };
    let activity = |worker_in_flight, cancellation_requested, completion_pending| {
        BTreeMap::from([(
            execution,
            LocalExecutionActivity {
                execution,
                worker_in_flight,
                cancellation_requested,
                completion_pending,
                cancellation_pending: false,
            },
        )])
    };

    assert_eq!(
        operational_phase(
            running,
            epoch,
            &activity(false, false, false),
            &BTreeMap::new(),
        ),
        Ok(Some(OperationalPhase::Preparing))
    );
    let preparing = BTreeMap::from([(execution, PackagedWorldLifecyclePhase::Preparing)]);
    assert_eq!(
        operational_phase(running, epoch, &activity(true, false, false), &preparing),
        Ok(Some(OperationalPhase::Preparing))
    );
    let active = BTreeMap::from([(execution, PackagedWorldLifecyclePhase::Running)]);
    assert_eq!(
        operational_phase(running, epoch, &activity(true, false, false), &active),
        Ok(Some(OperationalPhase::Running))
    );
    assert_eq!(
        operational_phase(running, epoch, &activity(true, true, false), &active),
        Ok(Some(OperationalPhase::Canceling))
    );
    assert_eq!(
        operational_phase(
            running,
            epoch,
            &activity(false, false, true),
            &BTreeMap::new(),
        ),
        Ok(Some(OperationalPhase::Publishing))
    );
    assert_eq!(
        operational_phase(
            running,
            DaemonEpoch::from_bytes([0x93; 16]).expect("stale epoch"),
            &activity(true, false, false),
            &active,
        ),
        Ok(None)
    );
    assert_eq!(
        operational_phase(
            running,
            epoch,
            &activity(true, false, false),
            &BTreeMap::new()
        ),
        Err(())
    );

    let checkpoint = ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        b"packaged-status-checkpoint",
    ))
    .expect("checkpoint");
    let paused = AttemptRuntimeState::Paused {
        execution_basis: basis,
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch: epoch,
        execution,
        checkpoint,
        promotion_basis: None,
    };
    assert_eq!(
        operational_phase(paused, epoch, &BTreeMap::new(), &BTreeMap::new()),
        Ok(Some(OperationalPhase::Paused))
    );
}

#[test]
fn actor_status_snapshots_reject_intervening_ownership_changes() {
    let epoch = DaemonEpoch::from_bytes([0x94; 16]).expect("daemon epoch");
    let stable = LocalExecutorOperationalSnapshot {
        revision: 7,
        daemon_epoch: epoch,
        activities: Vec::new(),
    };
    assert!(successive_actor_snapshots(&stable, &stable));

    let changed = LocalExecutorOperationalSnapshot {
        revision: 8,
        ..stable.clone()
    };
    assert!(!successive_actor_snapshots(&stable, &changed));
}
