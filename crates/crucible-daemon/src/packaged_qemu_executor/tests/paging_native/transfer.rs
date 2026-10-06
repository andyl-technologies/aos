//! Authenticated archive exchange and a fresh cold receiver on the same kernel.
//!
//! Both repositories have distinct quota-backed object namespaces and actual
//! executor ledgers. The receiver consumes only its authenticated archive pin,
//! never a copied source execution row. This is instance-transfer evidence; it
//! makes no claim about transport between physical hosts.

use super::super::hot_fork_native::{fork_resources, native_repository};
use super::*;
use crate::campaign_transfer::{
    CampaignArchiveTransferEndpoint, DirectoryCampaignTransferJournal,
    ExactPinCampaignArchiveCheckpointResolver, transfer_campaign_archive_durably_with_boundary,
};
use crate::imported_checkpoint::{
    AuthenticatedImportedCheckpoint, ImportedCheckpointAdmission, ReceiverCheckpointPolicy,
};
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::{
    DirectoryExactPinMaterializationStore, ExactPinMaterializationSelection,
    SharedQemuAttemptHostResourceFactory,
};
use crucible_api::host_operational::HostResourceVector;
use crucible_campaign::{
    CampaignArchivePlan, CampaignArchivePolicy, CampaignCommandId, CampaignHash, CampaignName,
    PinChange, PinRequest, PinRetention,
};
use crucible_cas::content_store::{ContentId, DurabilityRequirement};
use crucible_cas::ram::RamStoreError;
use std::path::{Path, PathBuf};

struct ReceiverEvidence {
    boundary: Boundary,
    ram_record: Vec<u8>,
    missing_installs: u64,
    first_quantum_ns: u64,
}

struct TransferRoute<'a> {
    sender: &'a CampaignRepository,
    receiver: &'a CampaignRepository,
    plan: &'a CampaignArchivePlan,
    source_path: &'a Path,
    receiver_path: &'a Path,
    checkpoints: &'a ExactCheckpointStore,
    selections: &'a mut DirectoryExactPinMaterializationStore,
}

struct RestoreLane<'a> {
    prepared: &'a PackagedPreparation,
    config: &'a PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    selections: &'a mut DirectoryExactPinMaterializationStore,
    archive: &'a str,
    campaign: &'a str,
    configuration: crucible_campaign::ConfigurationId,
    source: &'a ScenarioDefForm,
    cold: bool,
}

#[test]
#[ignore = "requires the isolated kernel VM, actual quotas, native accepted promotion and cold receiver"]
fn production_authenticated_archive_transfer_restores_a_fresh_cold_receiver() {
    let source = paging_scenario();
    let source_path = std::cell::RefCell::new(PathBuf::new());
    environment::with_native_repository_storage(
        "transfer-source",
        35_000,
        environment::NativeCatalogBudget::default(),
        |root, storage| {
            *source_path.borrow_mut() = root.join("objects");
            native_repository(&source, root, storage)
        },
        |repository, _root, _admitted_checkpoint_backend| repository.blob_backend(),
        transfer_resources,
        |source_prepared, source_config, sender| {
            let source_path = source_path.borrow();
            let source_available = available(source_prepared);
            let promotion = accepted_promotion::promote_accepted_checkpoint(
                source_prepared,
                source_config,
                Arc::clone(&sender),
                &source,
            );
            assert_eq!(available(source_prepared), source_available);
            let configuration =
                crucible_campaign::ConfigurationId::from_hash(CampaignHash::from_bytes(
                    source_prepared
                        .checkpoints
                        .load_attempt_checkpoint(promotion.checkpoint)
                        .expect("actual promoted source root")
                        .configuration()
                        .bytes,
                ));
            let selections_root = source_path
                .parent()
                .expect("repository parent")
                .join("source-pins");
            let mut source_pins = DirectoryExactPinMaterializationStore::open(&selections_root)
                .expect("durable source exact pin journal under actual quota");
            let plan = with_transfer(
                source_prepared,
                source_config,
                &source,
                |context, boundary| {
                    let campaign = CampaignName::new("packaged").expect("source campaign");
                    let head = sender
                        .head(campaign.as_str())
                        .expect("source published head");
                    let pinned = sender
                        .apply_pin(
                            campaign.as_str(),
                            &PinRequest {
                                command: CampaignCommandId::from_hash(CampaignHash::derive(
                                    "crucible.native.transfer.pin.v1",
                                    b"source",
                                )),
                                expected_snapshot: head.snapshot_id(),
                                change: PinChange::new(
                                    configuration,
                                    Some(PinRetention::Exact),
                                    "native transfer",
                                )
                                .expect("exact retention intent"),
                            },
                        )
                        .expect("durable semantic exact pin");
                    source_pins
                        .select(
                            ExactPinMaterializationSelection::prepare(
                                &sender,
                                &source_prepared.checkpoints,
                                &campaign,
                                configuration,
                                promotion.checkpoint,
                            )
                            .expect("actual promoted source exact selection"),
                        )
                        .expect("durable selection");
                    let mut resolver = ExactPinCampaignArchiveCheckpointResolver::new(
                        &sender,
                        &source_prepared.checkpoints,
                        campaign,
                        &mut source_pins,
                    )
                    .expect("actual source checkpoint resolver");
                    let plan = sender
                        .plan_campaign_archive_with_boundary(
                            pinned.new_snapshot,
                            CampaignArchivePolicy::Executable,
                            BTreeSet::new(),
                            Some(&mut resolver),
                            boundary,
                        )
                        .expect("authenticated root-last executable archive inventory");
                    assert!(!context.cancellation().is_canceled());
                    sender
                        .publish_campaign_archive_with_boundary(
                            "source-oracle",
                            None,
                            &plan,
                            boundary,
                        )
                        .expect("complete source archive publication");
                    plan
                },
            );
            let oracle = restore(RestoreLane {
                prepared: source_prepared,
                config: source_config,
                repository: Arc::clone(&sender),
                selections: &mut source_pins,
                archive: "source-oracle",
                campaign: "packaged",
                configuration,
                source: &source,
                cold: false,
            });
            assert_eq!(available(source_prepared), source_available);

            let receiver_path = std::cell::RefCell::new(PathBuf::new());
            environment::with_native_repository_storage(
                "transfer-receiver",
                35_100,
                environment::NativeCatalogBudget::default(),
                |root, storage| {
                    *receiver_path.borrow_mut() = root.join("objects");
                    native_repository(&source, root, storage)
                },
                |repository, _root, _admitted_checkpoint_backend| repository.blob_backend(),
                transfer_resources,
                |receiver_prepared, receiver_config, receiver| {
                    let receiver_path = receiver_path.borrow();
                    assert!(!Arc::ptr_eq(
                        &sender.blob_backend(),
                        &receiver.blob_backend()
                    ));
                    let receiver_available = available(receiver_prepared);
                    let receiver_root = receiver_path.parent().expect("receiver repository root");
                    let mut receiver_pins = DirectoryExactPinMaterializationStore::open(
                        receiver_root.join("receiver-pins"),
                    )
                    .expect("durable receiver selection under its actual quota");
                    with_transfer(
                        source_prepared,
                        source_config,
                        &source,
                        |_context, boundary| {
                            transfer_and_refuse_incomplete(
                                TransferRoute {
                                    sender: &sender,
                                    receiver: &receiver,
                                    plan: &plan,
                                    source_path: &source_path,
                                    receiver_path: &receiver_path,
                                    checkpoints: &receiver_prepared.checkpoints,
                                    selections: &mut receiver_pins,
                                },
                                boundary,
                            );
                        },
                    );
                    assert_eq!(available(receiver_prepared), receiver_available);
                    assert_receiver_refusals(
                        receiver_prepared,
                        receiver_config,
                        Arc::clone(&receiver),
                        &mut receiver_pins,
                        configuration,
                        &source,
                    );
                    let cold = restore(RestoreLane {
                        prepared: receiver_prepared,
                        config: receiver_config,
                        repository: receiver,
                        selections: &mut receiver_pins,
                        archive: "received",
                        campaign: "imported",
                        configuration,
                        source: &source,
                        cold: true,
                    });
                    assert_eq!(oracle.boundary, cold.boundary);
                    assert_eq!(oracle.ram_record, cold.ram_record);
                    assert!(cold.missing_installs > 0);
                    assert_eq!(available(receiver_prepared), receiver_available);
                    println!("managed_transfer_distinct_backend_authority=true");
                    println!("managed_transfer_complete_archive_before_launch=true");
                    println!("managed_transfer_corrupt_missing_refused_unpublished=true");
                    println!("managed_transfer_first_quantum_identity=true");
                    println!("managed_transfer_ram_root_identity=true");
                    println!(
                        "managed_transfer_missing_installs={}",
                        cold.missing_installs
                    );
                    println!(
                        "managed_transfer_first_quantum_ns={}",
                        cold.first_quantum_ns
                    );
                    println!("managed_transfer_all_eight_resources_after_cleanup=true");
                    println!("MANAGED_AUTHENTICATED_TRANSFER_NATIVE_PASS");
                },
            );
            assert_eq!(available(source_prepared), source_available);
        },
    );
}

fn transfer_resources(config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    let mut config = fork_resources(config);
    // The authentication Service retains decoded metadata until the fresh
    // Replay Service takes it. Both coexist with authored assignment headroom.
    config.capacity = ExecutorCapacity::new(1, 8, 2 << 30, 4 << 30, 150_000)
        .expect("independent authentication and replay capacity in each eight-CPU instance");
    let catalog = config
        .ram_catalog()
        .expect("same real installed catalog quota");
    let mut resources = catalog.resources();
    // Offer/root authentication can retain two decoded roots while a receiver
    // publication and its exact pin keep a third. SQL has its separate subset.
    resources.metadata_bytes = 128 * 1024 * 1024;
    resources.resident_peak_bytes = 192 * 1024 * 1024;
    let transfer_catalog = crate::PackagedRamCatalogConfig::new(
        catalog.root(),
        catalog.project_id(),
        catalog.maximum_inodes(),
        resources,
        catalog.maximum_sqlite_heap_bytes(),
    )
    .expect("authored concurrent receiver metadata and physical resident allowance");
    config
        .with_ram_catalog(transfer_catalog)
        .expect("transfer catalog remains within complete authored aggregate")
}

fn with_transfer<T>(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    source: &ScenarioDefForm,
    run: impl FnOnce(&AttemptExecutionContext, &mut dyn FnMut() -> Result<(), RamStoreError>) -> T,
) -> T {
    run_capture(prepared, config, source, |context| {
        accepted_promotion::extend_native_operations(context);
        let operation = context
            .host_operation_supervisor()
            .expect("actual original Service cap")
            .begin(HostOperationClass::Transfer)
            .expect("original finite transfer class");
        let value = run(context, &mut || {
            operation
                .wait_slice()
                .map(|_| ())
                .map_err(|_| RamStoreError::Canceled)
        });
        operation
            .complete()
            .expect("transfer completion before original expiry");
        Ok(value)
    })
    .expect("genuine full-vector transfer preparation owner and watcher cleanup")
}

fn transfer_and_refuse_incomplete(
    route: TransferRoute<'_>,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) {
    let TransferRoute {
        sender,
        receiver,
        plan,
        source_path,
        receiver_path,
        checkpoints,
        selections,
    } = route;
    let mut source_journal = DirectoryCampaignTransferJournal::open(
        source_path
            .parent()
            .expect("source root")
            .join("source-transfer"),
    )
    .expect("durable source transfer custody");
    let mut receiver_journal = DirectoryCampaignTransferJournal::open(
        receiver_path
            .parent()
            .expect("receiver root")
            .join("receiver-transfer"),
    )
    .expect("durable receiver transfer custody");
    let durability =
        DurabilityRequirement::new(1, false).expect("actual durable directory backend");
    let mut attempt = |writable: bool| {
        let mut source = CampaignArchiveTransferEndpoint::new(
            sender,
            &mut source_journal,
            "native-source",
            true,
        );
        let mut destination = CampaignArchiveTransferEndpoint::new_with_operational_checkpoints(
            receiver,
            &mut receiver_journal,
            "native-receiver",
            writable,
            checkpoints,
            selections,
        );
        transfer_campaign_archive_durably_with_boundary(
            &mut source,
            &mut destination,
            plan,
            "received",
            Some("imported"),
            durability,
            boundary,
        )
    };
    assert!(attempt(false).is_err());
    assert!(receiver.inspect_campaign_archive_ref("received").is_err());

    // Exercise actual file authentication, not a synthetic receiver success
    // flag. Failed publication retains the real journal root for retry.
    let object = plan
        .selected()
        .iter()
        .find(|entry| entry.id().kind() == crucible_cas::content_store::ObjectKind::ExactManifest)
        .expect("archive selected promoted checkpoint")
        .id();
    let source_file = object_path(source_path, object);
    let hidden = source_file.with_extension("temporarily-missing");
    std::fs::rename(&source_file, &hidden).expect("withhold actual source root");
    assert!(attempt(true).is_err());
    assert!(receiver.inspect_campaign_archive_ref("received").is_err());
    std::fs::rename(&hidden, &source_file).expect("restore source custody for retry");

    receiver
        .blob_backend()
        .put_if_absent(
            object,
            &sender
                .blob_backend()
                .read(object, None)
                .expect("authenticated actual source frame"),
        )
        .expect("seed real receiver root for corruption test");
    let receiver_file = object_path(receiver_path, object);
    std::fs::write(&receiver_file, b"corrupt object frame")
        .expect("corrupt physical receiver root");
    assert!(attempt(true).is_err());
    assert!(receiver.inspect_campaign_archive_ref("received").is_err());
    std::fs::remove_file(&receiver_file)
        .expect("discard untrusted physical frame under retained owner");
    attempt(true).expect("complete authenticated root-last transfer and publication");
    receiver
        .inspect_campaign_archive_ref("received")
        .expect("complete receiver archive");
}

fn object_path(root: &Path, object: ContentId) -> PathBuf {
    let encoded = object.encode();
    let digest = encoded
        .rsplit_once('.')
        .expect("canonical content digest")
        .1;
    root.join("objects").join(&digest[..2]).join(encoded)
}

fn receiver_policy(
    repository: &CampaignRepository,
    config: &PackagedQemuExecutorConfig,
) -> ReceiverCheckpointPolicy {
    let head = repository
        .head("packaged")
        .expect("receiver-selected published campaign");
    // The receiver's locally authored campaign supplies trust. The imported
    // campaign cannot select its own expected compatibility or policy identity.
    ReceiverCheckpointPolicy {
        lineage: head.snapshot().lineage(),
        policy: head.snapshot().active_policy(),
        resources: config
            .assignment_limits()
            .expect("authored semantic limits"),
        resource_ceiling: config
            .assignment_limits()
            .expect("authored receiver maximum"),
    }
}

// crucible-lint: allow clippy-disallowed-method -- native flight measures wall-clock latency as external evidence, never as a modeled coordinate.
#[allow(clippy::disallowed_methods)]
fn restore(lane: RestoreLane<'_>) -> ReceiverEvidence {
    let RestoreLane {
        prepared,
        config,
        repository,
        selections,
        archive,
        campaign,
        configuration,
        source,
        cold,
    } = lane;
    let before = available(prepared);
    let campaign = CampaignName::new(campaign).expect("receiver campaign spelling");
    let host = SharedQemuAttemptHostResourceFactory::new(
        LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
            .expect("actual host allocator"),
    );
    let state = crate::packaged_qemu_executor::guarded::PackagedGuardedState {
        actor: prepared.actor.campaign_port(),
        config: config.clone(),
        checkpoints: Arc::clone(&prepared.checkpoints),
        host: Some(host),
    };
    let owner = crate::qemu_campaign_lifecycle::GuardedCampaignOwner::from_packaged(
        &state,
        Arc::clone(&repository),
        crucible_campaign::PlannerAuthorityKey::from_bytes([0x31; 32])
            .expect("receiver-local planner authority"),
    )
    .expect("operator owner shares the actual prepared actor and backend");
    let (mut replay, started) = with_transfer(prepared, config, source, |context, boundary| {
        let imported = AuthenticatedImportedCheckpoint::prepare(
            ImportedCheckpointAdmission {
                repository: Arc::clone(&repository),
                checkpoints: &prepared.checkpoints,
                selections,
                archive,
                campaign: &campaign,
                configuration,
                policy: receiver_policy(&repository, config),
                context,
            },
            boundary,
        )
        .expect("complete published receiver archive issues one launch claim");
        let started = std::time::Instant::now();
        let replay = owner
            .begin_imported_checkpoint(imported, ExecutionCancellation::default())
            .expect("production entry consumes import while authentication remains charged");
        (replay, started)
    });
    assert!(
        replay
            .context()
            .expect("fresh Service")
            .runtime_basis()
            .is_none()
    );
    let context = replay.context().expect("actual receiver context").clone();
    accepted_promotion::extend_native_operations(&context);
    let registry = &prepared.host_operational_registry;
    let target = super::lazy_restore::discover_target(registry, &context);
    if cold {
        registry
            .apply_native_qualification_policy(target, 0)
            .expect("actual cold implementation policy");
    } else {
        drop(super::lazy_restore::capture(
            replay.lifecycle_mut().expect("resident oracle"),
            &context,
        ));
    }
    let before_quantum = status(registry, target);
    let lifecycle = replay
        .lifecycle_mut()
        .expect("actual native receiver lifecycle");
    let configuration = lifecycle
        .resume_state()
        .expect("actual restored scheduler cut")
        .into_parts()
        .0;
    QemuFreshAttemptLifecycleOwner::drive_quantum(
        lifecycle,
        QuantumRequest {
            configuration,
            control: Vec::new(),
        },
    )
    .expect("first receiver quantum with authenticated real missing faults");
    let first_quantum_ns =
        u64::try_from(started.elapsed().as_nanos()).expect("bounded wall-clock observation");
    let after = status(registry, target);
    let missing_installs = after
        .activity
        .expect("native receiver counters")
        .successful_missing_installs
        .checked_sub(
            before_quantum
                .activity
                .expect("initial native counters")
                .successful_missing_installs,
        )
        .expect("same original receiver operation namespace");
    assert_eq!(before_quantum.admitted_resources, after.admitted_resources);
    assert_eq!(
        before_quantum.reservation_revision,
        after.reservation_revision
    );
    let observed = boundary(lifecycle);
    let closure = super::lazy_restore::capture(lifecycle, &context);
    let ram_record = closure.ram_sources()[0].root().record().encode();
    drop(closure);
    replay
        .finish()
        .expect("actual receiver reap, source joins and last-close before actor discharge");
    assert_eq!(available(prepared), before);
    ReceiverEvidence {
        boundary: observed,
        ram_record,
        missing_installs,
        first_quantum_ns,
    }
}

fn assert_receiver_refusals(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    selections: &mut DirectoryExactPinMaterializationStore,
    configuration: crucible_campaign::ConfigurationId,
    source: &ScenarioDefForm,
) {
    with_transfer(prepared, config, source, |context, boundary| {
        let campaign = CampaignName::new("imported").expect("receiver campaign");
        let mut prepare = |configuration, archive: &str, policy, checkpoints| {
            AuthenticatedImportedCheckpoint::prepare(
                ImportedCheckpointAdmission {
                    repository: Arc::clone(&repository),
                    checkpoints,
                    selections,
                    archive,
                    campaign: &campaign,
                    configuration,
                    policy,
                    context,
                },
                boundary,
            )
        };
        assert!(
            prepare(
                configuration,
                "unpublished",
                receiver_policy(&repository, config),
                prepared.checkpoints.as_ref()
            )
            .is_err()
        );
        let other_configuration =
            crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
                "crucible.native.transfer.wrong-configuration.v1",
                b"receiver",
            ));
        assert!(
            prepare(
                other_configuration,
                "received",
                receiver_policy(&repository, config),
                prepared.checkpoints.as_ref()
            )
            .is_err()
        );
        let mut policy = receiver_policy(&repository, config);
        policy.policy = crucible_campaign::CampaignPolicyId::parse(&format!(
            "crucible.campaign.policy@{}",
            ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::Policy,
                5,
                b"wrong receiver policy"
            )
            .encode(),
        ))
        .expect("typed mismatching policy identity");
        assert!(
            prepare(
                configuration,
                "received",
                policy,
                prepared.checkpoints.as_ref()
            )
            .is_err()
        );
        let foreign_backend = Arc::new(DirectoryBlobBackend::new(
            repository.blob_backend().name(),
            config
                .lifecycle
                .run_state_root()
                .join("foreign-import-checkpoints"),
        ));
        let foreign = ExactCheckpointStore::new(
            foreign_backend,
            config.maximum_checkpoint_bytes,
            repository.ram_retention_authority(),
        )
        .expect("unopened foreign backend cannot substitute its name for authority");
        assert!(matches!(
            prepare(
                configuration,
                "received",
                receiver_policy(&repository, config),
                &foreign
            ),
            Err(crate::imported_checkpoint::ImportedCheckpointError::Store(
                crate::ExactCheckpointStoreError::InvalidRoot {
                    reason: "replay-oracle promotion source belongs to another backend",
                },
            )),
        ));

        let checkpoint = repository
            .inspect_campaign_archive_ref_with_boundary("received", boundary)
            .expect("immutable authenticated import selection")
            .manifest()
            .checkpoint_selections()
            .iter()
            .find(|selected| selected.configuration() == configuration)
            .expect("actual selected receiver configuration")
            .checkpoint();
        selections
            .clear(&campaign, configuration)
            .expect("remove actual durable receiver selection");
        assert!(
            AuthenticatedImportedCheckpoint::prepare(
                ImportedCheckpointAdmission {
                    repository: Arc::clone(&repository),
                    checkpoints: &prepared.checkpoints,
                    selections,
                    archive: "received",
                    campaign: &campaign,
                    configuration,
                    policy: receiver_policy(&repository, config),
                    context,
                },
                boundary
            )
            .is_err()
        );
        selections
            .select(
                ExactPinMaterializationSelection::prepare(
                    &repository,
                    &prepared.checkpoints,
                    &campaign,
                    configuration,
                    checkpoint,
                )
                .expect("restore only the complete authenticated pin proof"),
            )
            .expect("restore durable selection for the valid subsequent launch");
        assert!(
            AuthenticatedImportedCheckpoint::prepare(
                ImportedCheckpointAdmission {
                    repository: Arc::clone(&repository),
                    checkpoints: &prepared.checkpoints,
                    selections,
                    archive: "received",
                    campaign: &campaign,
                    configuration,
                    policy: receiver_policy(&repository, config),
                    context,
                },
                &mut || Err(RamStoreError::Canceled)
            )
            .is_err()
        );
    });
}

fn available(prepared: &PackagedPreparation) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("actual available complete eight-dimensional capacity")
}
