//! Keeps current17 administrative and inventory validation separate from old15.
//!
//! A matching format is inert DATA. Full signed closure, Source/native codecs,
//! exact parent ancestry and the terminal writer conjunction remain mandatory.

use super::*;
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::{
    COORDINATOR_CHECKPOINT17_MEDIA, CoordinatorCommitmentCheckpoint17,
};

pub(super) fn selected_record(record: &NativeArchiveRecord) -> bool {
    record.manifest().coordinator_state_ref.media_type == COORDINATOR_CHECKPOINT17_MEDIA
}

pub(super) fn selected_inventory(index: &Index) -> Result<bool, StateError> {
    let selected = index.owners.iter().any(|owner| {
        owner.key.schema.id.as_str() == "source-owned.packet-native-continuation/17"
            || owner.key.schema.id.as_str() == "source-owned.host-scheduling-continuation/17"
    });
    if !selected {
        return Ok(false);
    }
    let mut native = 0usize;
    let mut host = 0usize;
    let mut participants = BTreeSet::new();
    for owner in &index.owners {
        if owner.participants.len() != 1
            || !participants.insert(&owner.participants[0])
            || !owner.artifacts.is_empty()
        {
            return Err(refused(
                "current17 inventory omits its exact single-owner closure",
            ));
        }
        match (
            owner.key.implementation.as_str(),
            owner.key.profile.as_str(),
        ) {
            ("source-owned.packet-native/5", "source-owned.packet-complete-original-lineage/5") => {
                crucible_node_provider::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data(&owner.key.schema).map_err(schema)?;
                native += 1;
            }
            (
                "source-owned.host-scheduling-owner/2",
                "source-owned.host-scheduling-original-lineage/2",
            ) => {
                crate::node_contract::authenticate_host_scheduling_restored_continuation_schema17_data(&owner.key.schema).map_err(schema)?;
                host += 1;
            }
            _ => {
                return Err(refused(
                    "current17 inventory crossed its installed implementation or profile",
                ));
            }
        }
    }
    if native != 3 || host != 1 {
        return Err(refused(
            "current17 inventory requires its explicitly selected three Native and one Host codecs",
        ));
    }
    Ok(true)
}

pub(super) fn decode_coordinator(
    record: &NativeArchiveRecord,
    bytes: &[u8],
    journal: &RuntimeOriginalCaptureJournal,
    retained: usize,
    journal_storage: usize,
    admitted: Option<usize>,
) -> Result<CoordinatorCommitmentCheckpoint17, StateError> {
    let maximum = admitted
        .unwrap_or(record.limits.state.maximum_total_content_bytes)
        .min(record.limits.native.maximum_total_record_bytes);
    let quote = CoordinatorCommitmentCheckpoint17::prospective_storage_data(bytes.len(), maximum)
        .map_err(schema)?;
    let (retained, journal_storage) = if admitted.is_some() {
        (retained, journal_storage)
    } else {
        (
            record.capture_owned_storage().map_err(schema)?,
            crate::node_contract::NodeRuntime::capture_admin_storage(journal).map_err(schema)?,
        )
    };
    let outside = retained
        .checked_add(journal_storage)
        .and_then(|sum| sum.checked_add(bytes.len()))
        .ok_or_else(|| refused("current17 administrative coordinator overlap overflow"))?;
    super::super::storage::admit(outside, quote.requested_bytes_data(), maximum)?;
    let coordinator: CoordinatorCommitmentCheckpoint17 =
        decode_record(bytes, record.limits.state.maximum_record_bytes)?;
    let current = journal
        .attempts
        .last()
        .ok_or_else(|| refused("current17 administrative cut absent"))?;
    coordinator
        .authenticate_structure_data(&current.source_runtime, current.cut, current.ordinal)
        .map_err(schema)?;
    coordinator.authenticate_prefix_data().map_err(schema)?;
    if coordinator.safe_point.scheduling.media_type != "application/json"
        || coordinator.activation.activation_id != current.source_activation.activation_id
        || coordinator.activation.world_binding != current.source_activation.world_binding_hash
        || coordinator.activation.world_generation != current.source_activation.generation
        || coordinator.activation.boundary != current.source_activation.boundary
    {
        return Err(refused(
            "current17 administrative source differs from actual coordinator activation",
        ));
    }
    if !selected_inventory(&record.index)? {
        return Err(refused(
            "current17 coordinator cannot authenticate an original15 inventory",
        ));
    }
    // This typed cache is a pure temporary. The complete prefix/parent lineage
    // is independently verified by the strict current17 terminal reader.
    let actual = coordinator
        .retained_backing_requested_bytes_data()
        .map_err(schema)?
        .checked_add(std::mem::size_of::<CoordinatorCommitmentCheckpoint17>())
        .ok_or_else(|| refused("current17 administrative typed cache overflow"))?;
    if actual > quote.retained_requested_bytes_data() {
        return Err(refused(
            "current17 administrative cache exceeded its defining quote",
        ));
    }
    Ok(coordinator)
}

#[cfg(test)]
mod tests {
    use super::super::super::storage::NativeOwnerState;
    use super::*;
    use crate::node_contract::NativeStateKey;
    use crucible_node_contract::{Id, Phase, Position, U64, canonical};

    #[test]
    fn selected_codec_roster_rejects_mixed_versions_definitions_and_participants() {
        let reference = canonical::content_ref(b"data only", "application/json").unwrap();
        let mut owners = Vec::new();
        for index in 0..4 {
            let host = index == 3;
            owners.push(NativeOwnerState {
                owner: Id::new(format!("data/owner/{index}")).unwrap(),
                participants: vec![Id::new(format!("data/node/{index}")).unwrap()],
                key: NativeStateKey {
                    implementation: Id::new(if host {
                        "source-owned.host-scheduling-owner/2"
                    } else {
                        "source-owned.packet-native/5"
                    }).unwrap(),
                    profile: Id::new(if host {
                        "source-owned.host-scheduling-original-lineage/2"
                    } else {
                        "source-owned.packet-complete-original-lineage/5"
                    }).unwrap(),
                    schema: if host {
                        crate::node_contract::host_scheduling_restored_continuation_schema17().unwrap()
                    } else {
                        crucible_node_provider::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema().unwrap()
                    },
                },
                cut: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
                state: reference.clone(),
                evidence: Vec::new(),
                artifacts: Vec::new(),
            });
        }
        let index = Index {
            schema_version: 3,
            artifact: reference.clone(),
            objects: Vec::new(),
            owners,
            selected_extensions: None,
            original_capture_journal: Some(reference),
        };
        // This is a codec-roster DATA predicate, not archive or native acceptance.
        assert!(selected_inventory(&index).unwrap());
        let mut changed = index.clone();
        changed.owners[0].key.schema.version = 5;
        assert!(selected_inventory(&changed).is_err());
        let mut changed = index.clone();
        changed.owners[3].key.schema.definition.length = U64::new(1);
        assert!(selected_inventory(&changed).is_err());
        let mut changed = index;
        changed.owners[1].participants = changed.owners[0].participants.clone();
        assert!(selected_inventory(&changed).is_err());
    }
}
