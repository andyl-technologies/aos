//! Authenticates index-three administrative history as data before source restoration.
//!
//! The journal is mandatory and names every original request reservation. This
//! reader cannot qualify native adoption: installed source-specific native and
//! host validators remain required before fresh readiness or execution.

use std::collections::BTreeSet;

use crucible_node_contract::Validate;

use crate::node_contract::{OriginalCaptureOwnerState, RuntimeOriginalCaptureJournal};

use super::super::closure::{bounded_record, core_references};
use super::super::schema;
use super::lineage_source::OriginalLineageCoordinator;
use super::storage::Index;
use super::{NativeArchiveRecord, StateError, decode_record, refused};

#[path = "complete_original_index/current17.rs"]
mod current17;

pub(super) const JOURNAL_MEDIA: &str =
    "application/vnd.crucible.runtime-original-capture-journal+json;version=1";

pub(super) fn authenticate(
    record: &NativeArchiveRecord,
) -> Result<RuntimeOriginalCaptureJournal, StateError> {
    if record.complete_load_is_selected() {
        record
            .authenticate_complete_load_admission()
            .map_err(schema)?;
        return authenticate_admitted(record, 0, record.limits.state.maximum_total_content_bytes);
    }
    authenticate_inner(record, 0, None)
}

pub(super) fn authenticate_admitted(
    record: &NativeArchiveRecord,
    extra_retained: usize,
    maximum_total: usize,
) -> Result<RuntimeOriginalCaptureJournal, StateError> {
    authenticate_inner(record, extra_retained, Some(maximum_total))
}

fn authenticate_inner(
    record: &NativeArchiveRecord,
    extra_retained: usize,
    admitted: Option<usize>,
) -> Result<RuntimeOriginalCaptureJournal, StateError> {
    if record.index.schema_version != 3 {
        return Err(refused(
            "complete original administrative reader requires index three",
        ));
    }
    let reference = record
        .index
        .original_capture_journal
        .as_ref()
        .ok_or_else(|| refused("complete original archive omits administrative journal"))?;
    if reference.media_type != JOURNAL_MEDIA
        || record.manifest().preservation_contract.as_str()
            != "source-owned.packet-complete-original-lineage/5"
        || record.index.owners.len() != 4
    {
        return Err(refused(
            "unsupported complete original archive or journal codec",
        ));
    }
    let maximum = record.limits.state.maximum_record_bytes;
    let retained = if admitted.is_some() {
        record
            .capture_owned_storage()
            .map_err(schema)?
            .checked_add(extra_retained)
            .ok_or_else(|| refused("administrative retained overflow"))?
    } else {
        0
    };
    let bytes = match admitted {
        Some(total) => record.read_complete_object_admitted(reference, extra_retained, total)?,
        None => record.object(reference, maximum)?,
    };
    if let Some(total) = admitted {
        super::storage::admit_decode(&bytes, retained, total)?;
    }
    let journal: RuntimeOriginalCaptureJournal = decode_record(&bytes, maximum)?;
    let journal_storage = if admitted.is_some() {
        crate::node_contract::NodeRuntime::capture_admin_storage(&journal).map_err(schema)?
    } else {
        0
    };
    if let Some(total) = admitted {
        // Validation counts JSON without a DOM, formats closed decimal values,
        // and holds borrowed lifetime-ID and per-attempt participant sets.
        let identity_nodes = journal
            .attempts
            .len()
            .checked_add(5)
            .and_then(|count| {
                count.checked_mul(
                    crate::node_contract::NodeRuntime::capture_map_node_storage::<
                        &crucible_node_contract::Id,
                        (),
                    >(),
                )
            })
            .ok_or_else(|| refused("administrative identity set overflow"))?;
        super::storage::admit(
            retained
                .checked_add(bytes.capacity())
                .and_then(|n| n.checked_add(journal_storage))
                .ok_or_else(|| refused("administrative validation overflow"))?,
            identity_nodes
                .checked_add(super::storage::fixed_storage())
                .ok_or_else(|| refused("administrative fixed storage overflow"))?,
            total,
        )?;
    }
    validate_journal(&journal, maximum)?;
    drop(bytes);
    let current = journal
        .attempts
        .last()
        .ok_or_else(|| refused("complete original capture journal is empty"))?;
    let manifest = record.manifest();
    if current.capture_id != manifest.capture_id
        || current.source_activation.world_binding_hash != manifest.world_binding_hash
        || current.cut != manifest.cut
        || current.ordinal != manifest.event_ordinal
    {
        return Err(refused(
            "administrative journal names another original capture",
        ));
    }
    let coordinator_bytes = match admitted {
        Some(total) => record.read_complete_object_admitted(
            &manifest.coordinator_state_ref,
            extra_retained
                .checked_add(journal_storage)
                .ok_or_else(|| refused("coordinator retained overflow"))?,
            total,
        )?,
        None => record.object(&manifest.coordinator_state_ref, maximum)?,
    };
    if current17::selected_inventory(&record.index)? != current17::selected_record(record) {
        return Err(refused(
            "administrative coordinator and exact owner codec families differ",
        ));
    }
    let current_coordinator;
    let legacy_coordinator;
    let current_coordinator_storage;
    let (coordinator_runtime, coordinator_scheduler) = if current17::selected_record(record) {
        current_coordinator = current17::decode_coordinator(
            record,
            &coordinator_bytes,
            &journal,
            retained,
            journal_storage,
            admitted,
        )?;
        current_coordinator_storage = std::mem::size_of::<crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17>()
            .checked_add(current_coordinator.retained_backing_requested_bytes_data().map_err(schema)?)
            .ok_or_else(|| refused("current17 administrative coordinator storage overflow"))?;
        (
            &current_coordinator.safe_point.runtime,
            &current_coordinator.safe_point.scheduling,
        )
    } else {
        current_coordinator_storage = 0;
        if let Some(total) = admitted {
            super::storage::admit_decode(
                &coordinator_bytes,
                retained
                    .checked_add(journal_storage)
                    .ok_or_else(|| refused("coordinator decode overflow"))?,
                total,
            )?;
        }
        let coordinator: OriginalLineageCoordinator = decode_record(&coordinator_bytes, maximum)?;
        coordinator.runtime.validate().map_err(schema)?;
        coordinator.scheduler.validate().map_err(schema)?;
        if coordinator.schema_version != 7
            || coordinator.runtime != current.source_runtime
            || coordinator.scheduler.media_type != "application/json"
        {
            return Err(refused(
                "administrative source differs from unchanged Runtime7 coordinator",
            ));
        }
        legacy_coordinator = coordinator;
        (&legacy_coordinator.runtime, &legacy_coordinator.scheduler)
    };
    for (saved, native) in current.owners.iter().zip(&record.index.owners) {
        let OriginalCaptureOwnerState::Settled { snapshot, journal } = &saved.state else {
            return Err(refused(
                "unsettled original administrative request cannot be signed",
            ));
        };
        if saved.owner.owner != native.owner
            || saved.participants != native.participants
            || snapshot != &native.state
            || !native.evidence.contains(journal.as_ref())
        {
            return Err(refused(
                "original administrative owner settlement differs from native inventory",
            ));
        }
    }
    let object = record
        .index
        .objects
        .iter()
        .find(|object| &object.reference == reference)
        .ok_or_else(|| refused("administrative journal is outside signed typed inventory"))?;
    let matches = if let Some(total) = admitted {
        // The closed journal has one Runtime7 reference and two settlement
        // references per owner. A borrowed ordered set avoids cloning a DOM,
        // every reference subtree and a traversal Vec in this selected route.
        let count = journal
            .attempts
            .iter()
            .try_fold(1usize, |count, attempt| {
                count
                    .checked_add(1)?
                    .checked_add(attempt.owners.len().checked_mul(2)?)
            })
            .ok_or_else(|| refused("administrative reference count overflow"))?;
        let reference_nodes = count
            .checked_mul(
                crate::node_contract::NodeRuntime::capture_map_node_storage::<
                    &crucible_node_contract::ContentRef,
                    (),
                >(),
            )
            .ok_or_else(|| refused("administrative reference set overflow"))?;
        let coordinator_storage = if current17::selected_record(record) {
            current_coordinator_storage
        } else {
            let requested =
                crate::node_contract::NodeRuntime::capture_reference_storage(coordinator_runtime)
                    .map_err(schema)?
                    .checked_add(
                        crate::node_contract::NodeRuntime::capture_reference_storage(
                            coordinator_scheduler,
                        )
                        .map_err(schema)?,
                    )
                    .ok_or_else(|| refused("coordinator metadata overflow"))?;
            requested
        };
        super::storage::admit(
            retained
                .checked_add(journal_storage)
                .and_then(|n| n.checked_add(coordinator_bytes.capacity()))
                .and_then(|n| n.checked_add(coordinator_storage))
                .ok_or_else(|| refused("administrative closure peak overflow"))?,
            reference_nodes
                .checked_add(super::storage::fixed_storage())
                .ok_or_else(|| refused("administrative reference fixed overflow"))?,
            total,
        )?;
        let mut expected = BTreeSet::new();
        for attempt in &journal.attempts {
            expected.insert(&attempt.source_runtime);
            for owner in &attempt.owners {
                if let OriginalCaptureOwnerState::Settled { snapshot, journal } = &owner.state {
                    expected.insert(snapshot);
                    expected.insert(journal.as_ref());
                }
            }
        }
        object.dependencies.iter().eq(expected)
    } else {
        let mut expected = core_references(&journal, maximum)?;
        expected.sort();
        expected.dedup();
        object.dependencies == expected
    };
    if !matches {
        return Err(refused(
            "administrative journal dependency inventory is incomplete or changed",
        ));
    }
    Ok(journal)
}

pub(super) fn validate_inventory(index: &Index) -> Result<(), StateError> {
    if index.schema_version != 3 {
        return if index.original_capture_journal.is_none() {
            Ok(())
        } else {
            Err(refused(
                "legacy archive cannot carry administrative capture history",
            ))
        };
    }
    if index.original_capture_journal.is_none()
        || index.selected_extensions.is_some()
        || index.owners.len() != 4
    {
        return Err(refused(
            "complete original index requires journal and exact closed four-owner world",
        ));
    }
    if current17::selected_inventory(index)? {
        return Ok(());
    }
    let mut native = 0;
    let mut host = 0;
    let mut participants = BTreeSet::new();
    for owner in &index.owners {
        if owner.participants.len() != 1
            || !participants.insert(&owner.participants[0])
            || !owner.artifacts.is_empty()
        {
            return Err(refused(
                "complete original index omits single-owner native or host closure",
            ));
        }
        match owner.key.implementation.as_str() {
            "source-owned.packet-native/5"
                if owner.key.profile.as_str()
                    == "source-owned.packet-complete-original-lineage/5"
                    && owner.key.schema.id.as_str()
                        == "source-owned.packet-native-continuation/5"
                    && owner.key.schema.version == 5 =>
            {
                native += 1
            }
            "source-owned.host-scheduling-owner/2"
                if owner.key.profile.as_str()
                    == "source-owned.host-scheduling-original-lineage/2"
                    && owner.key.schema.id.as_str()
                        == "source-owned.host-scheduling-continuation/2"
                    && owner.key.schema.version == 2 =>
            {
                host += 1
            }
            _ => {
                return Err(refused(
                    "complete original index contains an unsupported native state key",
                ));
            }
        }
    }
    if native != 3 || host != 1 {
        return Err(refused(
            "complete original index requires independently selected native-three and host-two codecs",
        ));
    }
    Ok(())
}

fn validate_journal(
    journal: &RuntimeOriginalCaptureJournal,
    maximum: usize,
) -> Result<(), StateError> {
    // A counting writer bounds all metadata before canonical copies or new sets.
    bounded_record(journal, maximum)?;
    if journal.schema_version != 1
        || journal.maximum_attempts.get() != 64
        || journal.attempts.is_empty()
        || journal.attempts.len() > 64
    {
        return Err(refused(
            "unsupported administrative journal edition or lifetime credit",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for (index, attempt) in journal.attempts.iter().enumerate() {
        attempt.capture_id.validate().map_err(schema)?;
        attempt.source_runtime.validate().map_err(schema)?;
        attempt
            .source_activation
            .activation_id
            .validate()
            .map_err(schema)?;
        attempt
            .source_activation
            .world_binding_hash
            .validate()
            .map_err(schema)?;
        if attempt.sequence.get() != index as u64 + 1
            || !identities.insert(&attempt.capture_id)
            || attempt.source_runtime.media_type != super::ORIGINAL_LINEAGE_RUNTIME_MEDIA
            || attempt.owners.len() != 4
            || attempt.source_activation.owners.len() != 4
            || attempt.cut < attempt.source_activation.boundary
            || attempt
                .owners
                .windows(2)
                .any(|pair| pair[0].owner.owner >= pair[1].owner.owner)
        {
            return Err(refused(
                "administrative journal lifetime IDs, owner roster or cut are invalid",
            ));
        }
        if let Some(prior) = previous {
            let prior: &crate::node_contract::OriginalCaptureAttemptRecord = prior;
            if attempt.source_activation.world_binding_hash
                != prior.source_activation.world_binding_hash
                || attempt.source_activation.generation < prior.source_activation.generation
                || attempt.cut < prior.cut
                || attempt.ordinal < prior.ordinal
            {
                return Err(refused(
                    "administrative history changes world or renews an original frontier",
                ));
            }
        }
        previous = Some(attempt);
        let mut participants = BTreeSet::new();
        for (owner_index, owner) in attempt.owners.iter().enumerate() {
            owner.owner.owner.validate().map_err(schema)?;
            owner.owner.incarnation.validate().map_err(schema)?;
            if attempt.source_activation.owners.get(owner_index) != Some(&owner.owner)
                || owner.participants.len() != 1
                || !participants.insert(&owner.participants[0])
                || !matches_original_operation(
                    owner.operation.as_str(),
                    attempt.sequence.get(),
                    owner_index,
                )
            {
                return Err(refused(
                    "administrative owner history omits original incarnation or request reservation",
                ));
            }
            owner.participants[0].validate().map_err(schema)?;
            let OriginalCaptureOwnerState::Settled { snapshot, journal } = &owner.state else {
                return Err(refused(
                    "unsettled administrative history cannot qualify a durable archive",
                ));
            };
            snapshot.validate().map_err(schema)?;
            journal.validate().map_err(schema)?;
            if snapshot == journal.as_ref() {
                return Err(refused(
                    "snapshot and administrative settlement are distinct typed objects",
                ));
            }
        }
    }
    Ok(())
}

// Compares the exact runtime-generated spelling without a formatting bank.
fn matches_original_operation(value: &str, sequence: u64, index: usize) -> bool {
    let Some(suffix) = value.strip_prefix("native-capture/") else {
        return false;
    };
    let Some((number, owner)) = suffix.split_once('/') else {
        return false;
    };
    if index >= 4
        || number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
    {
        return false;
    }
    number.parse::<u64>() == Ok(sequence) && owner.as_bytes() == [b'0' + index as u8]
}

#[cfg(test)]
mod operation_spelling_tests {
    use super::*;

    #[test]
    fn canonical_operation_comparison_preserves_exact_reserved_bytes() {
        for sequence in 1..=64 {
            for index in 0..4 {
                assert!(matches_original_operation(
                    &format!("native-capture/{sequence}/{index}"),
                    sequence,
                    index
                ));
            }
        }
        for value in [
            "native-capture/01/0",
            "native-capture/+1/0",
            "native-capture/1/00",
            "native-capture/1/0/",
            "native-capture/1/4",
            "native-capture/18446744073709551616/0",
        ] {
            assert!(!matches_original_operation(value, 1, 0));
        }
    }
}

#[cfg(test)]
mod tests;

#[path = "complete_original_index/parent15.rs"]
mod parent15;
pub(super) use parent15::authenticate_initial15_parent_parts_data;

#[path = "complete_original_index/parent17.rs"]
mod parent17;
pub(super) use parent17::authenticate_current17_parent_parts_data;
