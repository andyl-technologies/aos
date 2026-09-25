//! Protected catalog cut for nonauthorizing physical held-snapshot readback.
//!
//! The coordinator retains the exclusive Storage journal lock while the
//! caller dispatches a read-only one-shot worker. A second cut after worker
//! quiescence must match before the physical sample can be retained. Storage
//! derives the catalog head and materialized-state digest from its own journal;
//! neither value is selected by the snapshot identity caller.
//! The native hold lineage comes from the last committed transition for the
//! exact snapshot and hold. A catalog hold with no matching HoldSnapshot
//! operation, or one superseded by ReleaseHold, cannot produce a readback.

use std::collections::BTreeSet;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::semantics::CatalogBindingV1;
use sha2::{Digest as _, Sha256};

use crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1;
use crate::state::VerifiedStorageResolverJournalV1;
use crate::{CatalogPlanV1, HoldId, ResolvedSnapshot};

use super::{StorageAdmissionCoordinator, StorageBrokerError};

const ACTIVE_HOLD_DOMAIN: &[u8] = b"aos.sandbox.storage.native-active-hold.v1\0";

/// Selects one catalogued snapshot and constrains a read-only pool observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageHeldSnapshotSelectorV1 {
    /// The opaque protected dataset handle.
    pub(crate) storage_handle: [u8; 32],
    /// The opaque immutable snapshot handle.
    pub(crate) version_handle: [u8; 32],
    /// The catalogued source dataset GUID.
    pub(crate) source_guid: u64,
    /// The catalogued immutable snapshot GUID.
    pub(crate) snapshot_guid: u64,
    /// The exact durable OpenZFS hold identity.
    pub(crate) hold_id: HoldId,
    /// A caller-proposed pool GUID that the worker must observe twice.
    ///
    /// Storage has no protected pool-GUID mapping for receipt issuance yet.
    pub(crate) pool_guid: u64,
}

/// Carries a freshly reloaded catalog identity but no SourceRoot authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageHeldSnapshotCatalogCutV1 {
    pub(crate) snapshot: ResolvedSnapshot,
    pub(crate) metadata: CheckedSnapshotMetadataRecordV1,
    /// The authenticated Snapshot operation's persisted format version.
    pub(crate) storage_version: u64,
    /// The latest committed HoldSnapshot transition for this exact hold.
    pub(crate) hold_generation: u64,
    /// Commits the operation and result that established the active hold.
    pub(crate) active_hold_digest: ObjectDigest,
    pub(crate) catalog: CatalogBindingV1,
    pub(crate) authority_sequence: u64,
    /// Commits the current materialized Storage records and sequence, not journal history.
    pub(crate) materialized_state_digest: ObjectDigest,
}

impl StorageHeldSnapshotCatalogCutV1 {
    /// Rejects any changed protected selection after the worker has quiesced.
    pub(crate) fn ensure_unchanged(&self, successor: &Self) -> Result<(), StorageBrokerError> {
        if self != successor {
            return Err(StorageBrokerError::Request);
        }
        Ok(())
    }
}

impl StorageAdmissionCoordinator {
    /// Rejoins an exact held snapshot to the fresh authenticated physical head.
    ///
    /// # Errors
    ///
    /// Rejects missing or inconsistent Snapshot operation,
    /// mismatched GUIDs or metadata, missing hold, or unreadable journal custody.
    pub(crate) fn held_snapshot_catalog_cut(
        &self,
        selector: StorageHeldSnapshotSelectorV1,
    ) -> Result<StorageHeldSnapshotCatalogCutV1, StorageBrokerError> {
        self.transactions.ensure_authority_readable()?;
        if selector.pool_guid == 0 {
            return Err(StorageBrokerError::Request);
        }
        let journal = self.transactions.verified_resolver_journal()?;
        let (snapshot, metadata) = select_from_verified_journal(&journal, selector)?;
        let storage_version = u64::from(
            journal
                .operation(&metadata.operation_id())
                .ok_or(StorageBrokerError::Request)?
                .catalog()
                .format_version(),
        );
        let (hold_generation, active_hold_digest) =
            current_hold_lineage(&journal, &snapshot, selector.hold_id)?;
        let authority_sequence = self.transactions.authority_head_sequence()?;
        let materialized_state_digest = self
            .transactions
            .held_snapshot_materialized_state_digest()?;

        Ok(StorageHeldSnapshotCatalogCutV1 {
            snapshot,
            metadata,
            storage_version,
            hold_generation,
            active_hold_digest,
            catalog: journal.physical().binding(),
            authority_sequence,
            materialized_state_digest,
        })
    }
}

fn current_hold_lineage(
    journal: &VerifiedStorageResolverJournalV1,
    snapshot: &ResolvedSnapshot,
    hold_id: HoldId,
) -> Result<(u64, ObjectDigest), StorageBrokerError> {
    if !journal
        .physical()
        .holds()
        .contains(&(snapshot.guid(), hold_id.as_bytes()))
    {
        return Err(StorageBrokerError::Request);
    }

    // The last exact hold mutation must be HoldSnapshot while the current
    // catalog still contains that hold. The journal has authenticated each
    // operation and its resulting physical-catalog head before this scan.
    let mut latest = None;
    let mut seen_generations = BTreeSet::new();
    for (operation_id, operation) in journal.operations() {
        let is_hold = match operation.catalog().plan() {
            CatalogPlanV1::HoldSnapshot {
                snapshot: held,
                hold_id: candidate,
            } if *candidate == hold_id && same_physical_snapshot(held, snapshot) => {
                if held != snapshot {
                    return Err(StorageBrokerError::Request);
                }
                true
            }
            CatalogPlanV1::ReleaseHold {
                snapshot: held,
                hold_id: candidate,
            } if *candidate == hold_id && same_physical_snapshot(held, snapshot) => {
                if held != snapshot {
                    return Err(StorageBrokerError::Request);
                }
                false
            }
            _ => continue,
        };
        let generation = operation.result().catalog().generation();
        if generation > journal.physical().binding().generation()
            || !seen_generations.insert(generation)
        {
            return Err(StorageBrokerError::Request);
        }
        if latest.is_none_or(|(prior, _, _, _)| generation > prior) {
            latest = Some((generation, is_hold, operation_id, operation));
        }
    }
    let Some((generation, true, operation_id, operation)) = latest else {
        return Err(StorageBrokerError::Request);
    };
    let result = operation.result();
    let digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(ACTIVE_HOLD_DOMAIN)
            .chain_update(operation_id)
            .chain_update(generation.to_be_bytes())
            .chain_update(result.catalog().digest().as_bytes())
            .chain_update(result.result_digest().as_bytes())
            .chain_update(snapshot.dataset().storage_handle())
            .chain_update(snapshot.guid().to_be_bytes())
            .chain_update(hold_id.as_bytes())
            .finalize()
            .into(),
    );
    Ok((generation, digest))
}

fn same_physical_snapshot(candidate: &ResolvedSnapshot, selected: &ResolvedSnapshot) -> bool {
    // ZFS transitions address names and GUIDs, not opaque Storage handles.
    // Any matching physical identity with a conflicting handle is ambiguous.
    candidate.name() == selected.name() || candidate.guid() == selected.guid()
}

fn select_from_verified_journal(
    journal: &VerifiedStorageResolverJournalV1,
    selector: StorageHeldSnapshotSelectorV1,
) -> Result<(ResolvedSnapshot, CheckedSnapshotMetadataRecordV1), StorageBrokerError> {
    let physical = journal.physical();
    let mut matching = physical
        .snapshots()
        .iter()
        .filter(|row| row.guid() == selector.snapshot_guid);
    let row = matching.next().ok_or(StorageBrokerError::Request)?;
    if matching.next().is_some()
        || physical
            .snapshots()
            .iter()
            .filter(|candidate| candidate.name() == row.name())
            .count()
            != 1
    {
        return Err(StorageBrokerError::Request);
    }
    let operation_id = row.created_by().ok_or(StorageBrokerError::Request)?;
    let operation = journal
        .operation(&operation_id)
        .ok_or(StorageBrokerError::Request)?;
    let CatalogPlanV1::Snapshot {
        source,
        destination,
    } = operation.catalog().plan()
    else {
        return Err(StorageBrokerError::Request);
    };
    let result = operation.result();
    if row.name() != destination.name()
        || row.source_name() != source.name()
        || row.source_guid() != source.guid()
        || source.guid() != selector.source_guid
        || source.storage_handle() != selector.storage_handle
        || result.object_guid() != Some(selector.snapshot_guid)
        || result.storage_handle() != Some(selector.storage_handle)
        || result.immutable_version_handle() != Some(selector.version_handle)
        || !physical.roots().contains(source.root())
        || !physical
            .holds()
            .contains(&(selector.snapshot_guid, selector.hold_id.as_bytes()))
    {
        return Err(StorageBrokerError::Request);
    }
    let mut matching_source = physical
        .datasets()
        .iter()
        .filter(|dataset| dataset.name() == source.name());
    let source_row = matching_source.next().ok_or(StorageBrokerError::Request)?;
    if matching_source.next().is_some()
        || source_row.guid() != source.guid()
        || source_row.root() != source.root()
        || source_row.domains() != source.domains()
        || !source_row_matches_operation(journal, source_row, source)
    {
        return Err(StorageBrokerError::Request);
    }
    let metadata = row.metadata().ok_or(StorageBrokerError::Request)?;
    if metadata.operation_id() != operation_id
        || metadata.request_catalog() != operation.catalog().binding()
        || metadata.snapshot_guid() != selector.snapshot_guid
        || metadata.source_dataset_guid() != selector.source_guid
        || metadata.source_storage_handle() != selector.storage_handle
        || source_row.created_by() != Some(metadata.source_creation_operation_id())
    {
        return Err(StorageBrokerError::Request);
    }
    let snapshot = ResolvedSnapshot::from_catalog(
        source.clone(),
        destination.component(),
        selector.snapshot_guid,
        selector.version_handle,
    )
    .map_err(|_| StorageBrokerError::Request)?;
    Ok((snapshot, metadata))
}

fn source_row_matches_operation(
    journal: &VerifiedStorageResolverJournalV1,
    row: &crate::catalog_transition::VerifiedPhysicalDatasetV1,
    source: &crate::ResolvedDataset,
) -> bool {
    let Some(operation_id) = row.created_by() else {
        return false;
    };
    let Some(operation) = journal.operation(&operation_id) else {
        return false;
    };
    let destination = match operation.catalog().plan() {
        CatalogPlanV1::CreateWorkspace { destination, .. }
        | CatalogPlanV1::Clone { destination, .. } => destination,
        _ => return false,
    };
    let result = operation.result();
    row.name() == destination.name()
        && row.guid() == result.object_guid().unwrap_or(0)
        && row.root() == destination.root()
        && row.domains() == destination.domains()
        && result.storage_handle() == Some(source.storage_handle())
        && result.immutable_version_handle().is_none()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::ObjectDigest;

    use super::*;
    use crate::catalog_transition::{
        VerifiedPhysicalCatalogSnapshotV1, VerifiedPhysicalDatasetV1, VerifiedPhysicalSnapshotV1,
    };
    use crate::root_policy::PortableRootAttributesV1;
    use crate::{
        ManagedDatasetRoot, PlannedDataset, PlannedSnapshot, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedCatalogCommitmentV1, ResolvedDataset, StorageDomainsV1,
        WorkspaceSpacePolicyV1,
    };

    #[derive(Clone, Copy, Default)]
    struct Fault {
        wrong_snapshot_operation: bool,
        wrong_source: bool,
        wrong_metadata: bool,
        missing_hold: bool,
        missing_hold_operation: bool,
        released_hold: bool,
        reheld: bool,
        aliased_release: bool,
        aliased_rehold: bool,
    }

    fn fixture(
        fault: Fault,
    ) -> (
        VerifiedStorageResolverJournalV1,
        StorageHeldSnapshotSelectorV1,
    ) {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 11).unwrap();
        let ancestor =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 12, [12; 32], domains)
                .unwrap();
        let source = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/workspace",
            22,
            [5; 32],
            domains,
        )
        .unwrap();
        let snapshot =
            ResolvedSnapshot::from_catalog(source.clone(), "revision", 33, [6; 32]).unwrap();
        let create = ResolvedCatalogCommitmentV1::new_for_test(
            7,
            domains,
            CatalogPlanV1::CreateWorkspace {
                destination: PlannedDataset::from_catalog(root.clone(), source.name(), domains)
                    .unwrap(),
                space: WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap(),
                ancestor: ProjectAncestorPolicyV1::new(ancestor, 65_536, 8, 16).unwrap(),
            },
        )
        .unwrap();
        let snapshot_catalog = ResolvedCatalogCommitmentV1::new_for_test(
            8,
            domains,
            CatalogPlanV1::Snapshot {
                source: source.clone(),
                destination: PlannedSnapshot::from_catalog(source.clone(), snapshot.component())
                    .unwrap(),
            },
        )
        .unwrap();
        let metadata = CheckedSnapshotMetadataRecordV1::new_for_test(
            [77; 16],
            ObjectDigest::from_bytes([8; 32]),
            ObjectDigest::from_bytes([9; 32]),
            snapshot_catalog.binding(),
            snapshot.guid(),
            if fault.wrong_metadata {
                44
            } else {
                source.guid()
            },
            source.storage_handle(),
            ObjectDigest::from_bytes([10; 32]),
            PortableRootAttributesV1::new(1000, 1000, 0o755).unwrap(),
            1000,
            1000,
            1,
            1,
            ObjectDigest::from_bytes([11; 32]),
        )
        .unwrap();
        let hold_id = HoldId::from_bytes([7; 16]).unwrap();
        let hold_catalog = ResolvedCatalogCommitmentV1::new_for_test(
            9,
            domains,
            CatalogPlanV1::HoldSnapshot {
                snapshot: snapshot.clone(),
                hold_id,
            },
        )
        .unwrap();
        let aliased_snapshot =
            ResolvedSnapshot::from_catalog(source.clone(), "revision", 33, [66; 32]).unwrap();
        let release_catalog = ResolvedCatalogCommitmentV1::new_for_test(
            10,
            domains,
            CatalogPlanV1::ReleaseHold {
                snapshot: if fault.aliased_release {
                    aliased_snapshot.clone()
                } else {
                    snapshot.clone()
                },
                hold_id,
            },
        )
        .unwrap();
        let rehold_catalog = ResolvedCatalogCommitmentV1::new_for_test(
            11,
            domains,
            CatalogPlanV1::HoldSnapshot {
                snapshot: if fault.aliased_rehold {
                    aliased_snapshot
                } else {
                    snapshot.clone()
                },
                hold_id,
            },
        )
        .unwrap();
        let generation = if fault.reheld || fault.aliased_rehold {
            11
        } else if fault.released_hold || fault.aliased_release {
            10
        } else {
            9
        };
        let head = CatalogBindingV1::from_publisher(generation, ObjectDigest::from_bytes([13; 32]))
            .unwrap();
        let physical = VerifiedPhysicalCatalogSnapshotV1::held_snapshot_for_test(
            head,
            root.clone(),
            VerifiedPhysicalDatasetV1::held_snapshot_for_test(
                source.name(),
                if fault.wrong_source {
                    23
                } else {
                    source.guid()
                },
                root,
                domains,
                [201; 16],
            ),
            VerifiedPhysicalSnapshotV1::held_snapshot_for_test(
                snapshot.name(),
                snapshot.guid(),
                source.name(),
                source.guid(),
                [77; 16],
                Some(metadata),
            ),
            if fault.missing_hold {
                Vec::new()
            } else {
                vec![(snapshot.guid(), hold_id.as_bytes())]
            },
        );
        let selected_operation = if fault.wrong_snapshot_operation {
            create.clone()
        } else {
            snapshot_catalog
        };
        let mut operations = vec![
            ([201; 16], create, Some([5; 32]), None, Some(22)),
            (
                [77; 16],
                selected_operation,
                Some([5; 32]),
                Some([6; 32]),
                Some(33),
            ),
        ];
        if !fault.missing_hold_operation {
            operations.push(([88; 16], hold_catalog, None, None, None));
        }
        if fault.released_hold || fault.reheld || fault.aliased_release || fault.aliased_rehold {
            operations.push(([89; 16], release_catalog, None, None, None));
        }
        if fault.reheld || fault.aliased_rehold {
            operations.push(([90; 16], rehold_catalog, None, None, None));
        }
        let journal =
            VerifiedStorageResolverJournalV1::held_snapshot_for_test(physical, operations);
        let selector = StorageHeldSnapshotSelectorV1 {
            storage_handle: source.storage_handle(),
            version_handle: snapshot.version_handle(),
            source_guid: source.guid(),
            snapshot_guid: snapshot.guid(),
            hold_id,
            pool_guid: 55,
        };
        (journal, selector)
    }

    #[test]
    fn protected_join_accepts_only_the_exact_committed_snapshot() {
        let (journal, selector) = fixture(Fault::default());
        let (snapshot, metadata) = select_from_verified_journal(&journal, selector).unwrap();

        assert_eq!(snapshot.guid(), selector.snapshot_guid);
        assert_eq!(metadata.source_dataset_guid(), selector.source_guid);
    }

    #[test]
    fn protected_join_rejects_wrong_operation_source_metadata_and_hold() {
        let faults = [
            Fault {
                wrong_snapshot_operation: true,
                ..Fault::default()
            },
            Fault {
                wrong_source: true,
                ..Fault::default()
            },
            Fault {
                wrong_metadata: true,
                ..Fault::default()
            },
            Fault {
                missing_hold: true,
                ..Fault::default()
            },
        ];
        for fault in faults {
            let (journal, selector) = fixture(fault);
            assert!(matches!(
                select_from_verified_journal(&journal, selector),
                Err(StorageBrokerError::Request)
            ));
        }
    }

    #[test]
    fn hold_lineage_requires_a_committed_active_hold_transition() {
        let (journal, selector) = fixture(Fault::default());
        let (snapshot, _) = select_from_verified_journal(&journal, selector).unwrap();
        let (generation, digest) =
            current_hold_lineage(&journal, &snapshot, selector.hold_id).unwrap();
        assert_eq!(generation, 9);
        assert_ne!(digest.as_bytes(), &[0; 32]);

        for fault in [
            Fault {
                missing_hold_operation: true,
                ..Fault::default()
            },
            Fault {
                released_hold: true,
                ..Fault::default()
            },
        ] {
            let (journal, selector) = fixture(fault);
            let (snapshot, _) = select_from_verified_journal(&journal, selector).unwrap();
            assert!(current_hold_lineage(&journal, &snapshot, selector.hold_id).is_err());
        }

        let (journal, selector) = fixture(Fault {
            reheld: true,
            ..Fault::default()
        });
        let (snapshot, _) = select_from_verified_journal(&journal, selector).unwrap();
        let (generation, reheld_digest) =
            current_hold_lineage(&journal, &snapshot, selector.hold_id).unwrap();
        assert_eq!(generation, 11);
        assert_ne!(reheld_digest, digest);
    }

    #[test]
    fn hold_lineage_rejects_a_physical_target_with_an_aliased_handle() {
        for fault in [
            Fault {
                aliased_release: true,
                ..Fault::default()
            },
            Fault {
                aliased_rehold: true,
                ..Fault::default()
            },
        ] {
            let (journal, selector) = fixture(fault);
            let (snapshot, _) = select_from_verified_journal(&journal, selector).unwrap();
            assert!(current_hold_lineage(&journal, &snapshot, selector.hold_id).is_err());
        }
    }

    #[test]
    fn post_worker_cut_rejects_changed_catalog_or_authority_head() {
        let (journal, selector) = fixture(Fault::default());
        let (snapshot, metadata) = select_from_verified_journal(&journal, selector).unwrap();
        let (hold_generation, active_hold_digest) =
            current_hold_lineage(&journal, &snapshot, selector.hold_id).unwrap();
        let initial = StorageHeldSnapshotCatalogCutV1 {
            snapshot,
            metadata,
            storage_version: 1,
            hold_generation,
            active_hold_digest,
            catalog: journal.physical().binding(),
            authority_sequence: 61,
            materialized_state_digest: ObjectDigest::from_bytes([15; 32]),
        };
        initial.ensure_unchanged(&initial).unwrap();

        let mut changed_catalog = initial.clone();
        changed_catalog.catalog =
            CatalogBindingV1::from_publisher(10, ObjectDigest::from_bytes([14; 32])).unwrap();
        assert!(initial.ensure_unchanged(&changed_catalog).is_err());

        let mut changed_authority = initial.clone();
        changed_authority.authority_sequence += 1;
        assert!(initial.ensure_unchanged(&changed_authority).is_err());

        let mut changed_state = initial.clone();
        changed_state.materialized_state_digest = ObjectDigest::from_bytes([16; 32]);
        assert!(initial.ensure_unchanged(&changed_state).is_err());

        let mut changed_hold = initial.clone();
        changed_hold.active_hold_digest = ObjectDigest::from_bytes([17; 32]);
        assert!(initial.ensure_unchanged(&changed_hold).is_err());
    }
}
