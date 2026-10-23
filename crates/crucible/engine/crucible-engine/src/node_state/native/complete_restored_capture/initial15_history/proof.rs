//! Reads the defining five-field proof and its complete held-reference roster.
//!
//! The target uses the original five-element tuple spelling. The stored array
//! order remains literal evidence; its members must match the three actual
//! independently authenticated Hold fullrefs exactly once, without rewriting.

use super::*;
use crate::node_contract::{OriginalLineageRuntimeRecord, OwnerIdentity};
use crucible_node_format::{HashRef, Position, U64};
use crucible_node_transport::protocol_snapshot::borrowed_json::BorrowedJsonFields as Fields;
use serde::{Deserialize, Serialize};

/// Retains the defining closed proof body with its tuple target and byte arrays.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeProof17 {
    pub(super) schema: String,
    pub(super) source_artifact: ContentRef,
    pub(super) source_runtime: ContentRef,
    pub(super) target: (U64, Id, HashRef, Vec<OwnerIdentity>, Position),
    pub(super) native_held_reference_identities: [[u8; 32]; 3],
}

/// Borrows actual original custody and the three MAC-bound current Hold identities.
pub(super) struct ScopeOperands17<'a> {
    pub(super) original: OriginalInitial15ArchivedOwnerRead<'a>,
    pub(super) reference: &'a ContentRef,
    pub(super) identities: [[u8; 32]; 3],
}

impl ScopeOperands17<'_> {
    /// Borrows this same authenticated original group's complete Runtime7 DATA.
    ///
    /// # Errors
    /// Refuses another actor or an incomplete retained original group.
    pub(super) fn original_runtime_data(
        &self,
    ) -> Result<&OriginalLineageRuntimeRecord, StateError> {
        self.original
            .original_runtime_data()
            .map_err(original_failure_data)
    }
}

/// Borrows all three actual first components without admitting a live context.
///
/// # Errors
/// Refuses missing components, another parent/proof occurrence or repeated nodes/Holds.
pub(super) fn borrow_operands_data<'a>(
    parent: &ParentArchive17ReadScope<'_, '_>,
    group: &'a OriginalInitial15ArchivedGroup,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    members: &'a [Initial15ScopeMember17<'a>; 3],
) -> Result<ScopeOperands17<'a>, StateError> {
    authenticate_parent_data(parent, group, scope)?;
    let original = group
        .owner_data(members[0].node.node_data())
        .map_err(original_failure_data)?;
    let reference = &members[0]
        .prelude
        .first_observation_data()
        .restoration_scope_data()
        .scope_proof;
    let mut identities = [[0u8; 32]; 3];
    let mut nodes: [Option<&Id>; 3] = [None, None, None];
    for (index, member) in members.iter().enumerate() {
        let node = member.node.node_data();
        let current_original = group.owner_data(node).map_err(original_failure_data)?;
        let current_scope = member
            .prelude
            .first_observation_data()
            .restoration_scope_data();
        let held = member
            .native
            .restoration_hold_data()
            .map_err(crate::node_state::schema)?;
        let prepare = member
            .native
            .restoration_prepare_request_data()
            .map_err(crate::node_state::schema)?;
        let journal = current_original
            .journal_data()
            .map_err(original_failure_data)?;
        let semantic = current_original
            .semantic_data()
            .map_err(original_failure_data)?
            .0;
        let journal_reference = current_original
            .journal_reference_data()
            .map_err(original_failure_data)?;
        let (index_reference, manifest_reference) = current_original
            .parent_references_data()
            .map_err(original_failure_data)?;
        if nodes[..index]
            .iter()
            .flatten()
            .any(|previous| *previous == node)
            || &current_scope.scope_proof != reference
            || member.prelude.installation_data().descriptor.id != *node
            || member.prelude.installation_data().world_binding_hash
                != scope.runtime.source_activation.world_binding_hash
            || member
                .node
                .first_observation_data()
                .map_err(crate::node_state::schema)?
                != member.prelude.first_observation_data().scheduling_data()
            || &member.ancestry.parent_archive_index != index_reference
            || &member.ancestry.parent_manifest != manifest_reference
            || &member.ancestry.first_semantic != semantic
            || &member.ancestry.first_journal != journal_reference
            || &member.ancestry.first_observation
                != member.prelude.first_observation_data().checkpoint_data().2
            || member.ancestry.restoration_commit != current_scope.restoration.commit_request
            || current_scope.source_runtime != journal.runtime
            || current_scope.restoration.captured_journal != *journal_reference
            || current_scope.restoration.captured_owner_state != journal.native_snapshot
            || current_scope.restoration.captured_control != journal.native_control
            || prepare.restoration.archive_index != *index_reference
            || prepare.restoration.capture_manifest != *manifest_reference
            || prepare.restoration.journal != *journal_reference
            || prepare.restoration.source_runtime != journal.runtime
            || held.restore_commit != current_scope.restoration.commit_request
            || held.captured_journal != current_scope.restoration.captured_journal
            || held.captured_owner_state != current_scope.restoration.captured_owner_state
            || held.captured_control != current_scope.restoration.captured_control
            || held.mapping != current_scope.restoration.mapping
            || held.context_digest != current_scope.restoration.context_digest
            || current_original
                .parent_references_data()
                .map_err(original_failure_data)?
                != original
                    .parent_references_data()
                    .map_err(original_failure_data)?
            || journal.runtime
                != original
                    .journal_data()
                    .map_err(original_failure_data)?
                    .runtime
        {
            return Err(refused(
                "historical scope native participants or evidence roles differ",
            ));
        }
        member
            .ancestry
            .validate_data()
            .map_err(crate::node_state::schema)?;
        // The constructor independently verifies this fullref against retained
        // canonical bytes of the actual sealed Hold before issuing any scope.
        identities[index] = held_reference_identity_data(&member.ancestry.restoration_hold)?;
        nodes[index] = Some(node);
    }
    if identities[0] == identities[1]
        || identities[0] == identities[2]
        || identities[1] == identities[2]
    {
        return Err(refused(
            "historical scope native held identities are not distinct",
        ));
    }
    Ok(ScopeOperands17 {
        original,
        reference,
        identities,
    })
}

impl ScopeProof17 {
    /// Joins exact immutable source, target and held-reference proof operands.
    ///
    /// # Errors
    /// Refuses another schema, source or target, or any missing/repeated/substituted Hold.
    pub(super) fn authenticate_data(
        &self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        operands: &ScopeOperands17<'_>,
    ) -> Result<(), StateError> {
        parent.manifest_data()?;
        scope.validation_origin.authenticate(scope.archive)?;
        let (_, manifest) = operands
            .original
            .parent_references_data()
            .map_err(original_failure_data)?;
        let original = operands.original_runtime_data()?;
        let current = &scope.runtime.source_activation;
        if self.schema != "source-owned.complete-restoration-scope/1"
            || &self.source_artifact != manifest
            || self.source_runtime
                != operands
                    .original
                    .journal_data()
                    .map_err(original_failure_data)?
                    .runtime
            || self.target.0 != current.generation
            || self.target.1 != current.activation_id
            || self.target.2 != current.world_binding_hash
            || self.target.3 != current.owners
            || self.target.4 != current.boundary
            || original.owners.len() != 4
            || current.owners.len() != 4
        {
            return Err(refused(
                "historical scope proof source or exact target differs",
            ));
        }
        authenticate_identity_roster_data(
            &self.native_held_reference_identities,
            &operands.identities,
        )
    }

    /// Counts actual typed proof backing independently of its inline header.
    ///
    /// # Errors
    /// Refuses overflow reported by the defining actual Core visitors.
    pub(super) fn backing_data(&self) -> Result<usize, RuntimeError> {
        let Self {
            schema,
            source_artifact,
            source_runtime,
            target,
            native_held_reference_identities: _,
        } = self;
        [
            schema.owned_storage()?,
            source_artifact.owned_storage()?,
            source_runtime.owned_storage()?,
            target.1.owned_storage()?,
            target.2.owned_storage()?,
            target.3.owned_storage()?,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

/// Checks closed ordered fields and fixed extents before any owning parse.
///
/// # Errors
/// Refuses another schema, malformed scanner spans, extra fields or wrong roster widths.
pub(super) fn authenticate_borrowed_shape_data(bytes: &[u8]) -> Result<(), StateError> {
    let mut fields = Fields::object(bytes).map_err(crate::node_state::schema)?;
    let identities = fields
        .named("native_held_reference_identities")
        .map_err(crate::node_state::schema)?;
    let mut identities = Fields::array(identities).map_err(crate::node_state::schema)?;
    for _ in 0..3 {
        let mut identity = Fields::array(
            identities
                .next_value()
                .map_err(crate::node_state::schema)?
                .ok_or_else(|| refused("historical scope proof missing native identity"))?,
        )
        .map_err(crate::node_state::schema)?;
        for _ in 0..32 {
            identity
                .next_value()
                .map_err(crate::node_state::schema)?
                .ok_or_else(|| refused("historical scope proof identity width differs"))?;
        }
        identity.finish().map_err(crate::node_state::schema)?;
    }
    identities.finish().map_err(crate::node_state::schema)?;
    if fields.named("schema").map_err(crate::node_state::schema)?
        != br#""source-owned.complete-restoration-scope/1""#
    {
        return Err(refused("historical scope proof schema differs"));
    }
    fields
        .named("source_artifact")
        .map_err(crate::node_state::schema)?;
    fields
        .named("source_runtime")
        .map_err(crate::node_state::schema)?;
    let target = fields.named("target").map_err(crate::node_state::schema)?;
    fields.finish().map_err(crate::node_state::schema)?;
    let mut target = Fields::array(target).map_err(crate::node_state::schema)?;
    for _ in 0..3 {
        target
            .next_value()
            .map_err(crate::node_state::schema)?
            .ok_or_else(|| refused("historical scope proof target tuple differs"))?;
    }
    let mut owners = Fields::array(
        target
            .next_value()
            .map_err(crate::node_state::schema)?
            .ok_or_else(|| refused("historical scope proof target owners absent"))?,
    )
    .map_err(crate::node_state::schema)?;
    for _ in 0..4 {
        owners
            .next_value()
            .map_err(crate::node_state::schema)?
            .ok_or_else(|| refused("historical scope proof target owner roster differs"))?;
    }
    owners.finish().map_err(crate::node_state::schema)?;
    target
        .next_value()
        .map_err(crate::node_state::schema)?
        .ok_or_else(|| refused("historical scope proof target boundary absent"))?;
    target.finish().map_err(crate::node_state::schema)
}

fn authenticate_identity_roster_data(
    encoded: &[[u8; 32]; 3],
    actual: &[[u8; 32]; 3],
) -> Result<(), StateError> {
    let mut seen = 0u8;
    for encoded in encoded {
        let selected = actual
            .iter()
            .position(|actual| actual == encoded)
            .ok_or_else(|| refused("historical scope proof substitutes a native Hold"))?;
        let bit = 1u8 << selected;
        if seen & bit != 0 {
            return Err(refused("historical scope proof repeats a native Hold"));
        }
        seen |= bit;
    }
    if seen != 0b111 {
        return Err(refused("historical scope proof omits a native Hold"));
    }
    Ok(())
}

// Same full-reference construction as the defining Window continuation owner.
// Hash fields, media and length remain independent correspondence inputs.
fn held_reference_identity_data(reference: &ContentRef) -> Result<[u8; 32], StateError> {
    let mut state =
        blake3::Hasher::new_derive_key("core.original-restoration-held-reference-correspondence/1");
    for text in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ] {
        let length = u64::try_from(text.len()).map_err(crate::node_state::schema)?;
        state.update(&length.to_le_bytes());
        state.update(text.as_bytes());
    }
    state.update(&reference.length.get().to_le_bytes());
    Ok(*state.finalize().as_bytes())
}

#[cfg(test)]
#[path = "proof/tests.rs"]
mod tests;

/// Checks exact canonical content bytes with fixed hash scratch only.
///
/// `ContentRef::verify` constructs a temporary owned HashRef. These immutable
/// scope/Commit-Hold bodies have the fixed ordinary blob domain and JSON media,
/// so the defining CNP/1 framing can compare directly to fixed digest bytes.
pub(super) fn authenticate_body_data(
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), StateError> {
    if reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
        || reference.media_type != "application/json"
        || u64::try_from(bytes.len()).ok() != Some(reference.length.get())
        || reference.hash.digest.len() != 64
        || !reference
            .hash
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused("historical scope content reference differs"));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&reference.length.get().to_be_bytes());
    hasher.update(bytes);
    if hasher.finalize().to_hex().as_bytes() != reference.hash.digest.as_bytes() {
        return Err(refused("historical scope content body differs"));
    }
    Ok(())
}
