//! Joins all seven immutable ancestry roles to actual cold participants.
//!
//! ```text
//! {parent_archive_index,parent_manifest,first_semantic,first_journal,
//!  first_observation,restoration_commit,restoration_hold}
//! ```
//!
//! These closed historical joins preserve DATA. The owning cold group separately
//! proves signed parent Index3/DAG provenance before issuing any live authority.

use super::{
    first_observation_reader::OriginalSourceRestoredFirstObservationHistory17Read,
    producer_fields::read, source_reader::OriginalSourceRestoredSettled17ReadInputs,
};
use crate::node_contract::RuntimeError;
use crucible_node_format::{ContentRef, canonical};
use crucible_node_transport::protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17;
use serde_json::Value;

/// Checks immutable lineage correspondence without issuing archive provenance.
///
/// The native/SDK operands authenticate the first-observation and actual Commit
/// chain. The Core cold group must additionally authenticate the signed parent
/// Index3/DAG and each imported role passed here; matching refs alone do not
/// create ownership of the corresponding archive bodies.
pub(super) fn authenticate_ancestry_data(
    value: &Value,
    input: &OriginalSourceRestoredSettled17ReadInputs<'_>,
    first: &OriginalSourceRestoredFirstObservationHistory17Read,
) -> Result<(), RuntimeError> {
    let scope = first.restoration_scope_data();
    authenticate_ancestry_roles_data(
        value,
        input.journal_ancestry,
        [
            input.parent_archive_reference,
            input.parent_manifest_reference,
            input.first_semantic_reference,
            &scope.restoration.captured_journal,
            first.checkpoint_data().2,
            &scope.restoration.commit_request,
            input.restoration_hold_reference,
        ],
    )?;

    // The borrowed Hold is the actual native-checked body, never a value
    // reconstructed from the root's own reference or a matching model cursor.
    let held_bytes = canonical::canonical_json(
        &serde_json::to_value(input.held).map_err(|_| RuntimeError::InvalidReceipt)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    input
        .restoration_hold_reference
        .verify(&held_bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if input.held.restore_commit != scope.restoration.commit_request
        || input.held.captured_journal != scope.restoration.captured_journal
        || input.held.captured_owner_state != scope.restoration.captured_owner_state
        || input.held.captured_control != scope.restoration.captured_control
        || input.held.mapping != scope.restoration.mapping
        || input.held.context_digest != scope.restoration.context_digest
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

fn authenticate_ancestry_roles_data(
    value: &Value,
    journal: &PacketRestoredSettledAncestry17,
    expected: [&ContentRef; 7],
) -> Result<(), RuntimeError> {
    let ancestry: PacketRestoredSettledAncestry17 = read(value)?;
    ancestry
        .validate_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if ancestry != *journal
        || ancestry
            .references_data()
            .into_iter()
            .zip(expected)
            .any(|(actual, expected)| actual != expected)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_journal_cannot_substitute_any_imported_or_first_scope_role() {
        use serde_json::json;
        let index = canonical::content_ref(
            b"parent index",
            "application/vnd.crucible.native-signed-index-body.v3+json",
        )
        .unwrap();
        let evidence =
            canonical::content_ref(b"actual immutable evidence", "application/json").unwrap();
        let changed = canonical::content_ref(b"substituted evidence", "application/json").unwrap();
        let value = json!({"parent_archive_index":index,"parent_manifest":evidence,
            "first_semantic":evidence,"first_journal":evidence,"first_observation":evidence,
            "restoration_commit":evidence,"restoration_hold":evidence});
        let journal: PacketRestoredSettledAncestry17 = read(&value).unwrap();
        let expected = [
            &index, &evidence, &evidence, &evidence, &evidence, &evidence, &evidence,
        ];
        authenticate_ancestry_roles_data(&value, &journal, expected).unwrap();

        for role in [
            "parent_archive_index",
            "parent_manifest",
            "first_semantic",
            "first_journal",
            "first_observation",
            "restoration_commit",
            "restoration_hold",
        ] {
            let mut substituted = value.clone();
            substituted[role] = serde_json::to_value(if role == "parent_archive_index" {
                &index
            } else {
                &changed
            })
            .unwrap();
            if role == "parent_archive_index" {
                substituted[role] = serde_json::to_value(
                    canonical::content_ref(b"different parent index", &index.media_type).unwrap(),
                )
                .unwrap();
            }
            // A matching tuple in two untrusted records is still insufficient.
            let matching_journal: PacketRestoredSettledAncestry17 = read(&substituted).unwrap();
            assert!(
                authenticate_ancestry_roles_data(&substituted, &matching_journal, expected)
                    .is_err()
            );
        }
        let mut extra = value;
        extra["unchecked_lineage"] = json!(true);
        assert!(authenticate_ancestry_roles_data(&extra, &journal, expected).is_err());
    }
}
