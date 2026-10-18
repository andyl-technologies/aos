//! Actual durable journal, retention and terminal-uncertainty controls.
//!
//! These fixed records are component fixtures, not live readiness grants.
//! No native World, source resource authority or receiving capability is minted.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn record() -> Result<ReceivingTransferRecord, Box<dyn std::error::Error>> {
    let key = AttemptExecutionKey::new(
        CampaignLineageId::parse(&format!(
            "crucible.campaign.lineage@campaign-fact.1.{}",
            encode_hex(&[1; 32])
        ))?,
        AttemptId::parse(&format!(
            "crucible.campaign.attempt@campaign-fact.9.{}",
            encode_hex(&[2; 32])
        ))?,
    );
    let transfer = SourceTransferState::prepared(SourceTransferIntent {
        operation: CampaignHash::from_bytes([3; 32]),
        destination: DaemonEpoch::from_bytes([4; 16])?,
        namespace: CampaignHash::from_bytes([5; 32]),
        offer_generation: 1,
        durable_placements: 1,
    })
    .ok_or("component transfer intent")?;
    let source = AttemptRuntimeState::Paused {
        execution_basis: CampaignHash::from_bytes([6; 32]),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: DaemonEpoch::from_bytes([7; 16])?,
        execution: ExecutionId::from_bytes([8; 16])?,
        checkpoint: ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@exact-manifest.6.{}",
            encode_hex(&[9; 32])
        ))?,
        promotion_basis: None,
        source_transfer: Some(transfer),
    };
    Ok(ReceivingTransferRecord {
        source_key: key,
        source,
        archive: crucible_campaign::CampaignArchiveManifestId::parse(&format!(
            "crucible.campaign.archive-manifest@projection.2.{}",
            encode_hex(&[10; 32])
        ))?,
        publication: CampaignHash::from_bytes([11; 32]),
        phase: ReceivingTransferPhase::Ready,
    })
}

#[test]
fn terminal_receiving_commit_survives_reopen_and_never_becomes_an_attempt() -> TestResult {
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let committed = ready.committed().ok_or("committed component record")?;
    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(None, ready)?,
        ReceivingTransferCas::Advanced
    ));
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(Some(ready), committed)?,
        ReceivingTransferCas::Advanced
    ));
    drop(ledger);

    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    assert_eq!(ledger.load_receiving_transfer(ready)?, Some(committed));
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(Some(committed), ready)?,
        ReceivingTransferCas::Conflict
    ));
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(
            Some(committed),
            ready.aborted().ok_or("abort record")?
        )?,
        ReceivingTransferCas::Conflict
    ));
    let mut attempts = 0;
    ledger.visit_attempt_states(&mut |_, _| attempts += 1)?;
    assert_eq!(attempts, 0);
    Ok(())
}

#[test]
fn receiving_root_is_fenced_for_gc_without_recovering_execution() -> TestResult {
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    let before = ledger.retention_state.digest();
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(None, ready)?,
        ReceivingTransferCas::Advanced
    ));
    assert_ne!(ledger.retention_state.digest(), before);
    let mut roots = Vec::new();
    let mut fence = ledger.acquire_retention_fence()?;
    let summary = fence.visit_roots(&mut |root| {
        roots.push(root);
        Ok(())
    })?;
    assert_eq!(summary.attempt_records(), 0);
    assert_eq!(summary.checkpoint_roots(), 1);
    assert_eq!(
        roots,
        vec![AssignmentRetentionRoot::ExactCheckpoint(
            ready.source.checkpoint().ok_or("source checkpoint")?
        )]
    );
    Ok(())
}

#[test]
fn canceled_receiving_original_prevents_publication_and_postcut_keeps_observation() -> TestResult {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use std::time::Duration;
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let ledger = DirectoryAssignmentLedger::open(root.path())?;
    let mut executor = crate::LocalExecutorSupervisor::new(
        ledger,
        crate::executor_supervisor::AllowAllAttemptAdmission,
        DaemonEpoch::from_bytes([4; 16])?,
        crate::ExecutorCapacity::new(1, 2, 4096, 8192, 64)?,
    );
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )?;
    let operation = supervisor.begin(HostOperationClass::Transfer)?;
    supervisor.cancel()?;
    assert!(matches!(
        executor.write_receiving_transfer(None, ready, &mut || operation.wait_slice().map(|_| ())),
        Err(crate::executor_supervisor::ReceivingTransitionFailure::Original(_))
    ));
    assert_eq!(executor.ledger().load_receiving_transfer(ready)?, None);

    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )?;
    let operation = supervisor.begin(HostOperationClass::Transfer)?;
    let mut seen = 0;
    let result = executor.write_receiving_transfer(None, ready, &mut || {
        seen += 1;
        if seen == 3 {
            supervisor.cancel()?;
        }
        operation.wait_slice().map(|_| ())
    });
    assert_eq!(seen, 3);
    assert!(matches!(
        result,
        Err(crate::executor_supervisor::ReceivingTransitionFailure::Original(_))
    ));
    assert_eq!(
        executor.ledger().load_receiving_transfer(ready)?,
        Some(ready)
    );
    // No production constructor consumes this observed row as live Ready.
    Ok(())
}

#[test]
fn journal_rejects_resigned_invalid_phase_trailing_bytes_and_foreign_path() -> TestResult {
    let ready = record()?;
    let encoded = ready.encode();
    assert_eq!(ReceivingTransferRecord::decode(&encoded)?, ready);
    let mut payload = open_sealed(&encoded, DOMAIN)?.to_vec();
    let last = payload.last_mut().ok_or("phase byte")?;
    *last = 3;
    assert!(matches!(
        ReceivingTransferRecord::decode(&seal(payload, DOMAIN)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "receiving-phase"
        })
    ));
    let mut payload = open_sealed(&encoded, DOMAIN)?.to_vec();
    payload.push(0);
    assert!(matches!(
        ReceivingTransferRecord::decode(&seal(payload, DOMAIN)),
        Err(AssignmentLedgerError::Corrupt {
            reason: "record-trailing-bytes"
        })
    ));

    let root = tempfile::tempdir()?;
    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(None, ready)?,
        ReceivingTransferCas::Advanced
    ));
    let path = ledger.receiving_path(ready)?;
    let foreign = path.parent().ok_or("shard")?.join(encode_hex(&[12; 32]));
    std::fs::rename(path, foreign)?;
    drop(ledger);
    assert!(DirectoryAssignmentLedger::open(root.path()).is_err());
    Ok(())
}

#[test]
fn moved_valid_record_in_a_foreign_shard_refuses_retention_and_reopen() -> TestResult {
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(None, ready)?,
        ReceivingTransferCas::Advanced
    ));

    let canonical = ledger.receiving_path(ready)?;
    let leaf = canonical.file_name().ok_or("record leaf")?;
    let canonical_shard = canonical.parent().ok_or("canonical shard")?;
    let wrong_shard_name = if canonical_shard.file_name() == Some(std::ffi::OsStr::new("00")) {
        "01"
    } else {
        "00"
    };
    let foreign_shard = root.path().join("receiving").join(wrong_shard_name);
    std::fs::create_dir(&foreign_shard)?;
    let foreign = foreign_shard.join(leaf);
    let retained = std::fs::read(&canonical)?;
    std::fs::rename(&canonical, &foreign)?;
    assert_eq!(std::fs::read(&foreign)?, retained);
    assert_eq!(ledger.load_receiving_transfer(ready)?, None);

    let mut visited = 0;
    let result = {
        let mut fence = ledger.acquire_retention_fence()?;
        fence.visit_roots(&mut |_| {
            visited += 1;
            Ok(())
        })
    };
    assert!(matches!(
        result,
        Err(AssignmentRetentionInventoryError::Backend(
            AssignmentLedgerError::Corrupt {
                reason: "receiving-path-identity"
            }
        ))
    ));
    assert_eq!(visited, 0);
    assert_eq!(std::fs::read(&foreign)?, retained);
    drop(ledger);

    assert!(matches!(
        DirectoryAssignmentLedger::open(root.path()),
        Err(AssignmentLedgerError::Corrupt {
            reason: "receiving-path-identity"
        })
    ));
    assert_eq!(std::fs::read(foreign)?, retained);
    Ok(())
}

#[test]
fn receiving_abort_is_terminal_and_replacement_of_the_bound_writer_refuses() -> TestResult {
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let aborted = ready.aborted().ok_or("abort record")?;
    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(None, ready)?,
        ReceivingTransferCas::Advanced
    ));
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(Some(ready), aborted)?,
        ReceivingTransferCas::Advanced
    ));
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(
            Some(aborted),
            ready.committed().ok_or("commit record")?
        )?,
        ReceivingTransferCas::Conflict
    ));
    let path = ledger.receiving_path(ready)?;
    let retained = std::fs::read(&path)?;
    std::fs::rename(
        root.path().join("writer.lock"),
        root.path().join("old-writer.lock"),
    )?;
    std::fs::write(root.path().join("writer.lock"), [])?;
    assert!(
        ledger
            .compare_exchange_receiving_transfer(Some(aborted), aborted)
            .is_err()
    );
    assert_eq!(std::fs::read(path)?, retained);
    Ok(())
}

#[test]
fn committed_after_error_preserves_initiating_cause_and_never_accepts_readiness() -> TestResult {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use std::time::Duration;
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let ledger = DirectoryAssignmentLedger::open(root.path())?;
    let mut executor = crate::LocalExecutorSupervisor::new(
        ledger,
        crate::executor_supervisor::AllowAllAttemptAdmission,
        DaemonEpoch::from_bytes([4; 16])?,
        crate::ExecutorCapacity::new(1, 2, 4096, 8192, 64)?,
    );
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )?;
    let operation = supervisor.begin(HostOperationClass::Transfer)?;
    FAIL_AFTER_RECEIVING_PUBLICATION.set(true);
    let result =
        executor.write_receiving_transfer(None, ready, &mut || operation.wait_slice().map(|_| ()));
    assert!(matches!(
        result,
        Err(
            crate::executor_supervisor::ReceivingTransitionFailure::Persistence {
                source: AssignmentLedgerError::Io {
                    operation: "injected-receiving-post-publication",
                    ..
                },
                observed: true,
                reconciliation: None,
                original: None,
            }
        )
    ));
    assert_eq!(
        executor.ledger().load_receiving_transfer(ready)?,
        Some(ready)
    );
    // A second preparation must refuse the observed row instead of recovering
    // the missing live capability from its durable bytes.
    assert!(matches!(
        executor.write_receiving_transfer(None, ready, &mut || operation.wait_slice().map(|_| ())),
        Err(crate::executor_supervisor::ReceivingTransitionFailure::Conflict)
    ));
    Ok(())
}

#[test]
fn initiating_durable_write_error_survives_later_original_cancellation() -> TestResult {
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use std::time::Duration;
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let mut executor = crate::LocalExecutorSupervisor::new(
        DirectoryAssignmentLedger::open(root.path())?,
        crate::executor_supervisor::AllowAllAttemptAdmission,
        DaemonEpoch::from_bytes([4; 16])?,
        crate::ExecutorCapacity::new(1, 2, 4096, 8192, 64)?,
    );
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )?;
    let operation = supervisor.begin(HostOperationClass::Transfer)?;
    let mut seen = 0;
    FAIL_AFTER_RECEIVING_PUBLICATION.set(true);
    let result = executor.write_receiving_transfer(None, ready, &mut || {
        seen += 1;
        if seen == 3 {
            supervisor.cancel()?;
        }
        operation.wait_slice().map(|_| ())
    });
    assert_eq!(seen, 3);
    assert!(matches!(
        result,
        Err(
            crate::executor_supervisor::ReceivingTransitionFailure::Persistence {
                source: AssignmentLedgerError::Io {
                    operation: "injected-receiving-post-publication",
                    ..
                },
                observed: false,
                reconciliation: None,
                original: Some(_),
            }
        )
    ));
    assert_eq!(
        executor.ledger().load_receiving_transfer(ready)?,
        Some(ready)
    );
    Ok(())
}

#[test]
fn exhausted_shared_inventory_capacity_refuses_the_actual_receiving_namespace() -> TestResult {
    let root = tempfile::tempdir()?;
    let ready = record()?;
    let mut ledger = DirectoryAssignmentLedger::open(root.path())?;
    assert!(matches!(
        ledger.compare_exchange_receiving_transfer(None, ready)?,
        ReceivingTransferCas::Advanced
    ));
    let mut visited = 0;
    assert!(matches!(
        ledger.visit_receiving_records(0, &mut |_| visited += 1, &mut || Ok(())),
        Err(AssignmentLedgerError::Corrupt {
            reason: "receiving-inventory-limit"
        })
    ));
    assert_eq!(visited, 0);
    assert_eq!(ledger.load_receiving_transfer(ready)?, Some(ready));
    Ok(())
}
