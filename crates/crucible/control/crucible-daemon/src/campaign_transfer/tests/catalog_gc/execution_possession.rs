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
        drop(possession);
    }
    source_owner.assert_idle();
    destination_owner.assert_idle();
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
