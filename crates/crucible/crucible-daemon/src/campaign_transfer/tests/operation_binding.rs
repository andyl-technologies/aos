//! Source authority is part of a durable metadata archive operation's identity.
//!
//! Independent directory repositories publish and transfer genuine metadata
//! archives. These controls grant neither RAM nor machine execution admission.

use super::*;

fn repository(root: &Path) -> CampaignRepository {
    CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "archive-binding",
            root.join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(root.join("refs"))),
        crucible_campaign::CampaignRamAdmission::Unavailable,
    )
}

#[test]
fn metadata_archive_operations_bind_the_selected_source_authority() {
    let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let temporary = tempfile::tempdir().expect("archive operation binding fixture");
    let first_source = repository(&temporary.path().join("source-a"));
    let second_source = repository(&temporary.path().join("source-b"));
    let destination = repository(&temporary.path().join("destination"));
    let first_plan = plan_in_repository(&first_source);
    let second_plan = plan_in_repository(&second_source);
    assert_eq!(first_plan.manifest_id(), second_plan.manifest_id());
    let mut first_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("journal-a"))
            .expect("first source journal");
    let mut second_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("journal-b"))
            .expect("second source journal");
    let mut destination_journal =
        DirectoryCampaignTransferJournal::open(temporary.path().join("destination-journal"))
            .expect("destination journal");
    let durability = DurabilityRequirement::new(1, false).expect("archive durability");
    let mut transfer = |source: &CampaignRepository,
                        journal: &mut DirectoryCampaignTransferJournal,
                        identity: &str| {
        let mut source_endpoint =
            CampaignArchiveTransferEndpoint::new(source, journal, identity, true);
        let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
            &destination,
            &mut destination_journal,
            "destination",
            true,
        );
        transfer_campaign_archive_durably(
            &mut source_endpoint,
            &mut destination_endpoint,
            &first_plan,
            "metadata",
            None,
            durability,
        )
        .expect("transfer the actual metadata archive")
    };

    let first = transfer(&first_source, &mut first_journal, "source-a");
    let repeated_transfer = transfer(&first_source, &mut first_journal, "source-a");
    let second = transfer(&second_source, &mut second_journal, "source-b");

    assert_eq!(first.manifest(), second.manifest());
    assert_eq!(first.requirement(), second.requirement());
    assert!(first.transfer().copied_objects > 0);
    assert_eq!(repeated_transfer.transfer().copied_objects, 0);
    assert_eq!(second.transfer().copied_objects, 0);
    assert_eq!(first.operation(), repeated_transfer.operation());
    assert_ne!(first.operation(), second.operation());
    assert_eq!(
        destination
            .inspect_campaign_archive_ref("metadata")
            .expect("authenticate actual destination publication")
            .manifest_id(),
        first_plan.manifest_id(),
    );
}

#[test]
fn invalid_source_authority_refuses_before_journaling_or_publication() {
    let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let oversized = "s".repeat(1025);
    for identity in ["", oversized.as_str()] {
        let temporary = tempfile::tempdir().expect("invalid source authority fixture");
        let source = repository(&temporary.path().join("source"));
        let destination_root = temporary.path().join("destination");
        let destination = repository(&destination_root);
        let plan = plan_in_repository(&source);
        let source_journal_root = temporary.path().join("source-journal");
        let destination_journal_root = temporary.path().join("destination-journal");
        let mut source_journal =
            DirectoryCampaignTransferJournal::open(&source_journal_root).expect("source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(&destination_journal_root)
                .expect("destination journal");
        assert!(!destination_root.join("objects").exists());
        let mut source_endpoint =
            CampaignArchiveTransferEndpoint::new(&source, &mut source_journal, identity, true);
        let mut destination_endpoint = CampaignArchiveTransferEndpoint::new(
            &destination,
            &mut destination_journal,
            "destination",
            true,
        );

        let error = transfer_campaign_archive_durably(
            &mut source_endpoint,
            &mut destination_endpoint,
            &plan,
            "metadata",
            None,
            DurabilityRequirement::new(1, false).expect("archive durability"),
        )
        .expect_err("invalid source authority must refuse before transfer effects");

        assert!(matches!(
            error,
            CampaignArchiveTransferError::Journal(CampaignTransferJournalError::InvalidOperation)
        ));
        assert!(!destination_root.join("objects").exists());
        assert!(matches!(
            destination.inspect_campaign_archive_ref("metadata"),
            Err(CampaignRepositoryError::NotFound)
        ));
        for root in [&source_journal_root, &destination_journal_root] {
            assert_eq!(
                fs::read_dir(root.join(RECORDS_DIRECTORY))
                    .expect("actual journal records")
                    .count(),
                0
            );
        }
    }
}

#[test]
fn source_bound_journals_refuse_and_preserve_previous_edition_records() {
    let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let plan = archive_plan();
    let durability = DurabilityRequirement::new(1, false).expect("archive durability");
    let operation = CampaignTransferOperationId::for_archive(
        plan.manifest_id(),
        "source",
        "destination",
        "metadata",
        None,
        durability,
    )
    .expect("source-bound operation");
    let current = TransferRecord::new(
        operation,
        TransferJournalRole::Source,
        plan.manifest_id(),
        plan.transfer_objects(),
        plan.ram_roots().to_vec(),
    )
    .expect("current source record")
    .canonical_bytes()
    .expect("current record bytes");

    assert_eq!(&current[..32], b"CRUCIBLE-CAMPAIGN-TRANSFER-V3!!!");
    assert_eq!(&current[32..36], &3_u32.to_be_bytes());
    let decoded = TransferRecord::from_canonical_bytes(&current, operation)
        .expect("current record acceptance");
    assert_eq!(decoded.operation, operation);
    assert_eq!(decoded.role, TransferJournalRole::Source);

    // Reconstruct the previous journal format without the complete-RAM-root
    // inventory. Only the current edition can establish transitive ownership.
    let previous_operation = operation;
    let mut previous = TransferRecord::new(
        previous_operation,
        TransferJournalRole::Source,
        plan.manifest_id(),
        plan.transfer_objects(),
        Vec::new(),
    )
    .expect("previous record payload")
    .canonical_bytes()
    .expect("record payload bytes");
    let checksum_offset = previous.len() - 32;
    previous.drain(checksum_offset - 4..checksum_offset);
    previous[..32].copy_from_slice(b"CRUCIBLE-CAMPAIGN-TRANSFER-V2!!!");
    previous[32..36].copy_from_slice(&2_u32.to_be_bytes());
    let payload_length = previous.len() - 32;
    let checksum = blake3::hash(&previous[..payload_length]);
    previous[payload_length..].copy_from_slice(checksum.as_bytes());
    assert!(matches!(
        TransferRecord::from_canonical_bytes(&previous, previous_operation),
        Err(CampaignTransferJournalError::Corrupt)
    ));

    let temporary = tempfile::tempdir().expect("previous journal fixture");
    let root = temporary.path().join("journal");
    let journal = DirectoryCampaignTransferJournal::open(&root).expect("empty journal namespace");
    let record = journal.record_path(previous_operation);
    fs::write(&record, &previous).expect("retain the previous ownership record");
    drop(journal);

    assert!(matches!(
        DirectoryCampaignTransferJournal::open(&root),
        Err(CampaignTransferJournalError::Corrupt)
    ));
    assert_eq!(
        fs::read(&record).expect("old ownership is not deleted"),
        previous
    );
}
