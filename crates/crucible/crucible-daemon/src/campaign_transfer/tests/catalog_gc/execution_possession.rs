//! Real durable-copy ownership bindings without minting receiving readiness.

use super::*;

#[test]
fn executable_possession_retains_exact_namespace_and_durability_owners() {
    let temporary = tempfile::tempdir().expect("component physical namespace");
    let source_owner = OriginalNamespace::new(&temporary.path().join("source"));
    let destination_owner = OriginalNamespace::new(&temporary.path().join("destination"));
    {
        let source = source_owner.open(&temporary.path().join("source-refs"));
        let destination = destination_owner.open(&temporary.path().join("destination-refs"));
        let _scope = source.original.enter();
        let _fixture = source
            .original
            .reserve_scratch_bytes(65_536)
            .expect("same original fixture paths");
        let plan =
            plan_in_repository_with_policy(&source.repository, CampaignArchivePolicy::Executable);
        let mut source_journal =
            DirectoryCampaignTransferJournal::open(temporary.path().join("source-journal"))
                .expect("source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(temporary.path().join("destination-journal"))
                .expect("destination journal");
        let possession = transfer_campaign_archive_for_execution_with_boundary(
            &mut CampaignArchiveTransferEndpoint::new(
                &source.repository,
                &mut source_journal,
                "source",
                true,
            ),
            &mut CampaignArchiveTransferEndpoint::new(
                &destination.repository,
                &mut destination_journal,
                "destination",
                true,
            ),
            &plan,
            "executable",
            None,
            DurabilityRequirement::new(1, false).expect("durable copy"),
            &mut || Ok(()),
        )
        .expect("actual copied objects and durable publication");
        let namespace = CampaignHash::derive(
            "crucible.executor.receiver-storage-namespace.v1",
            b"destination",
        );
        let source_backend = source.repository.blob_backend();
        let destination_backend = destination.repository.blob_backend();
        assert!(possession.verify_binding(
            &source_backend,
            &destination_backend,
            plan.manifest_id(),
            namespace,
            1
        ));
        assert!(!possession.verify_binding(
            &destination_backend,
            &source_backend,
            plan.manifest_id(),
            namespace,
            1
        ));
        assert!(!possession.verify_binding(
            &source_backend,
            &destination_backend,
            plan.manifest_id(),
            CampaignHash::from_bytes([13; 32]),
            1
        ));
        assert!(!possession.verify_binding(
            &source_backend,
            &destination_backend,
            plan.manifest_id(),
            namespace,
            2
        ));
        assert!(possession.recorded_transfer().copied_objects > 0);
        assert!(
            possession
                .recorded_transfer()
                .minimum_observed_durable_placements
                >= 1
        );
        assert_eq!(
            destination
                .repository
                .inspect_campaign_archive_ref("executable")
                .expect("real archive")
                .manifest_id(),
            plan.manifest_id()
        );

        // Replacing the public name cannot retire either independent reader.
        let second_reader = destination
            .repository
            .retain_campaign_archive_ref_with_boundary(
                "executable",
                plan.manifest_id(),
                &mut || Ok(()),
            )
            .expect("independent second archive reader");
        let mut reader_claims = 0;
        destination
            .refs_admin
            .acquire_ref_inventory_fence()
            .expect("inventory while readers remain alive")
            .visit_refs(&mut |record| {
                if record.name().as_str().starts_with("archive-readers/") {
                    let lock_name = blake3::hash(record.name().as_str().as_bytes()).to_hex();
                    let lock_path = temporary
                        .path()
                        .join("destination-refs/locks")
                        .join(lock_name.as_str());
                    assert!(
                        !lock_path.exists(),
                        "reader claims leave no per-name lock artifact"
                    );
                    reader_claims += 1;
                }
                Ok(())
            })
            .expect("reader claims require no persistent per-name locks");
        assert_eq!(reader_claims, 2);
        let public_name = crucible_store::content_store::RefName::new("archives/executable")
            .expect("published archive name");
        destination
            .refs
            .compare_remove(&public_name, plan.manifest_id().content_id())
            .expect("retire public name while readers remain");
        let garbage = BlobHandle::from_bytes(b"unrelated execution-possession garbage".to_vec());
        let garbage_id = ContentId::for_bytes(
            ObjectKind::DiskExtent,
            1,
            b"unrelated execution-possession garbage",
        );
        destination
            .graph
            .put_if_absent(garbage_id, &garbage)
            .expect("unrelated collectable object");

        // An exclusive inventory must be available while possession is alive.
        // A nonblocking OS probe makes a lifetime-lock regression fail promptly.
        let lock_descriptor = destination
            .graph
            .metadata_resources()
            .expect("same original descriptor authority")
            .reserve_resources(1, 0)
            .expect("descriptor before publication-lock probe");
        let lock_file = File::open(
            temporary
                .path()
                .join("destination-refs/.ref-admin/publication-lock"),
        )
        .expect("real namespace publication lock");
        flock(&lock_file, FlockOperation::NonBlockingLockExclusive)
            .expect("possession does not exclude unrelated GC");
        drop(lock_file);
        drop(lock_descriptor);
        let marks = destination
            .admin
            .gc_mark_backend("primary", "execution-possession")
            .expect("same original GC mark backend");
        let mut check = || Ok(());
        let operation = CampaignGcOperationContext::new(marks, &destination.original, &mut check)
            .expect("same original GC operation");
        let maintenance = CampaignGcMaintenance::new(&destination.admin, &operation);
        let mut ledger = MemoryAssignmentLedger::default();
        let prepared = plan_single_host_campaign_gc_with_transfers(
            &destination.repository,
            destination.refs_admin.as_ref(),
            &mut ledger,
            None,
            &destination_journal,
            None,
            maintenance,
        )
        .expect("GC plans with possession alive");
        assert!(
            prepared
                .candidates()
                .iter()
                .any(|entry| entry.id() == garbage_id)
        );
        assert!(prepared.candidates().iter().all(|entry| {
            entry.id() != plan.manifest_id().content_id()
                && plan
                    .selected()
                    .iter()
                    .all(|selected| selected.id() != entry.id())
        }));
        let (mut gc_journal, _) = DirectoryCampaignGcJournal::create(
            temporary.path().join("possession-gc-journal"),
            &prepared,
            &operation,
        )
        .expect("durable GC plan");
        let report = apply_single_host_campaign_gc_with_transfers(
            &mut gc_journal,
            &destination.repository,
            destination.refs_admin.as_ref(),
            &mut ledger,
            None,
            &destination_journal,
            None,
            maintenance,
        )
        .expect("GC collects unrelated objects while readers remain");
        assert_eq!(report.status(), crate::CampaignGcApplyStatus::Applied);
        assert!(
            !destination
                .graph
                .contains(garbage_id)
                .expect("garbage membership")
        );

        drop(possession);
        destination
            .repository
            .inspect_campaign_archive(plan.manifest_id())
            .expect("second reader still retains the complete archive");
        drop(second_reader);
        let mut remaining_refs = 0;
        destination
            .refs_admin
            .acquire_ref_inventory_fence()
            .expect("exclusive inventory after final reader retirement")
            .visit_refs(&mut |_| {
                remaining_refs += 1;
                Ok(())
            })
            .expect("remaining reader inventory");
        assert_eq!(remaining_refs, 0);
    }
    source_owner.assert_idle();
    destination_owner.assert_idle();
}

#[test]
fn archive_reader_claim_refuses_missing_ref_and_retires_after_late_cancellation() {
    let temporary = tempfile::tempdir().expect("reader claim namespace");
    let owner = OriginalNamespace::new(&temporary.path().join("objects"));
    {
        let namespace = owner.open(&temporary.path().join("refs"));
        let _scope = namespace.original.enter();
        let _fixture = namespace
            .original
            .reserve_scratch_bytes(65_536)
            .expect("finite archive fixture metadata");
        let plan = plan_in_repository_with_policy(
            &namespace.repository,
            CampaignArchivePolicy::Executable,
        );
        namespace
            .repository
            .publish_campaign_archive("executable", None, &plan)
            .expect("publish actual archive");

        let mut published_refs = Vec::new();
        namespace
            .refs_admin
            .acquire_ref_inventory_fence()
            .expect("inventory before reader publication")
            .visit_refs(&mut |record| {
                published_refs.push((record.name().as_str().to_owned(), record.target()));
                Ok(())
            })
            .expect("original campaign and archive refs");
        assert_eq!(published_refs.len(), 2);

        assert!(matches!(
            namespace
                .repository
                .retain_campaign_archive_ref_with_boundary(
                    "missing",
                    plan.manifest_id(),
                    &mut || Ok(()),
                ),
            Err(CampaignRepositoryError::RefConflict { current: None })
        ));
        let mut checks = 0;
        let canceled = namespace
            .repository
            .retain_campaign_archive_ref_with_boundary(
                "executable",
                plan.manifest_id(),
                &mut || {
                    checks += 1;
                    if checks == 3 {
                        Err(RamStoreError::Canceled)
                    } else {
                        Ok(())
                    }
                },
            );
        assert!(matches!(
            canceled,
            Err(CampaignRepositoryError::Ram(RamStoreError::Canceled))
        ));
        assert_eq!(checks, 3, "refusal follows the reader claim CAS");

        let mut remaining_refs = Vec::new();
        namespace
            .refs_admin
            .acquire_ref_inventory_fence()
            .expect("reader publication fence closed")
            .visit_refs(&mut |record| {
                remaining_refs.push((record.name().as_str().to_owned(), record.target()));
                Ok(())
            })
            .expect("no refused reader claim survives");
        assert_eq!(remaining_refs, published_refs);
    }
    owner.assert_idle();
}

#[test]
fn metadata_archive_cannot_obtain_execution_possession_or_publish_a_journal() {
    let temporary = tempfile::tempdir().expect("component namespace");
    let source = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("source", 64 * 1024 * 1024)),
        Arc::new(MemoryRefBackend::new()),
        crucible_campaign::CampaignRamAdmission::Unavailable,
    );
    let destination = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("destination", 64 * 1024 * 1024)),
        Arc::new(MemoryRefBackend::new()),
        crucible_campaign::CampaignRamAdmission::Unavailable,
    );
    let plan = plan_in_repository(&source);
    let mut source_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("source-journal"))
            .expect("source journal");
    let mut destination_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("destination-journal"))
            .expect("destination journal");
    let result = transfer_campaign_archive_for_execution_with_boundary(
        &mut CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, "source", true),
        &mut CampaignArchiveTransferEndpoint::new(
            &destination,
            &mut destination_journal,
            "destination",
            true,
        ),
        &plan,
        "metadata",
        None,
        DurabilityRequirement::new(1, false).expect("durability"),
        &mut || Ok(()),
    );
    assert!(matches!(
        result,
        Err(CampaignArchiveTransferError::Repository(
            CampaignRepositoryError::Store(StoreError::Unsupported {
                capability: "archive-execution-possession-executable-policy"
            })
        ))
    ));
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "source",
        "destination",
        "metadata",
        None,
        DurabilityRequirement::new(1, false).expect("durability"),
    )
    .expect("operation declaration");
    assert!(
        !source_journal
            .contains(operation)
            .expect("source remains untouched")
    );
    assert!(
        !destination_journal
            .contains(operation)
            .expect("destination remains untouched")
    );
}
