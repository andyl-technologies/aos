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

pub(super) const JOURNAL_MEDIA: &str =
    "application/vnd.crucible.runtime-original-capture-journal+json;version=1";

pub(super) fn authenticate(
    record: &NativeArchiveRecord,
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
    let bytes = record.object(reference, maximum)?;
    let journal: RuntimeOriginalCaptureJournal = decode_record(&bytes, maximum)?;
    validate_journal(&journal, maximum)?;
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
    let coordinator_bytes = record.object(&manifest.coordinator_state_ref, maximum)?;
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
    let mut expected = core_references(&journal, maximum)?;
    expected.sort();
    expected.dedup();
    let object = record
        .index
        .objects
        .iter()
        .find(|object| &object.reference == reference)
        .ok_or_else(|| refused("administrative journal is outside signed typed inventory"))?;
    if object.dependencies != expected {
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
