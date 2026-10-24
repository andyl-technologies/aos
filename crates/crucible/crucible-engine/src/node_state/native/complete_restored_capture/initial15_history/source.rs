//! Joins genuine initial15 custody to the independently completed Source17 root.
//!
//! Durable contracts and literal modeled state survive a fresh native owner.
//! Live admission, process and World identities are authenticated by the current
//! Source/native readers rather than copied from an obsolete process.

use super::*;
use crate::node_adapters::cnp::OriginalSourceRestoredSettled17Read;
use crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram;

/// Compares the complete imported Source and Node against their actual base.
///
/// The caller separately admits this fixed comparison window and retains every
/// native, SDK, Node, Source and original-parent decoder owner through refusal.
/// This predicate does not publish a cold group or create restoration authority.
///
/// # Errors
/// Refuses another parent/target, changed durable Source roles, renewed generic
/// ceilings, missing original custody or a transformation outside restoration.
pub(crate) fn authenticate_initial15_source_member17_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
    group: &OriginalInitial15ArchivedGroup,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    node: &CnpRestoredSettledValidatedNode17,
    source: &OriginalSourceRestoredSettled17Read,
    native: &SealedHistoricalRestoredSettledNative17,
    ancestry: &PacketRestoredSettledAncestry17,
    historical: &HistoricalInitial15Scope17,
) -> Result<(), StateError> {
    authenticate_parent_data(parent, group, scope)?;
    let restoration = historical.completed_data(scope)?;
    let original = group
        .owner_data(node.node_data())
        .map_err(original_failure_data)?;
    let launch = original
        .original_launch_data()
        .map_err(original_failure_data)?;
    let selection = &launch.selection;
    let journal = original.journal_data().map_err(original_failure_data)?;
    let journal_reference = original
        .journal_reference_data()
        .map_err(original_failure_data)?;
    let (parent_index, parent_manifest) = original
        .parent_references_data()
        .map_err(original_failure_data)?;
    let parent_owner = parent.selected_initial15_owner_data(
        node.node_data(),
        &selection.provider.implementation.implementation_id,
    )?;
    let installation = source.original_installation_data();
    let current_scope = source.first_observation_data().restoration_scope_data();
    let held = native
        .restoration_hold_data()
        .map_err(crate::node_state::schema)?;
    let prepare = native
        .restoration_prepare_request_data()
        .map_err(crate::node_state::schema)?;
    let restored = &prepare.restoration;
    let [old_descriptor] = selection.realization.descriptors.as_slice() else {
        return Err(refused("initial15 original descriptor roster differs"));
    };
    let [old_binding] = selection.realization.bindings.as_slice() else {
        return Err(refused("initial15 original binding roster differs"));
    };
    let [old_owner] = selection.realization.owner_bindings.as_slice() else {
        return Err(refused("initial15 original owner roster differs"));
    };
    let (operations, result, authorization, semantic) = original
        .original_semantic_caps_data()
        .map_err(original_failure_data)?;
    let current_owner = scope
        .archive
        .owners()
        .iter()
        .find(|owner| owner.participants.as_slice() == std::slice::from_ref(node.node_data()))
        .ok_or_else(|| refused("initial15 current native participant absent"))?;

    if installation.provider != selection.provider
        || installation.descriptor != *old_descriptor
        || installation.binding.compatibility != old_binding.compatibility
        || installation.owner != *old_owner
        || installation.owner.owner.id != current_owner.owner
        || !same_program_data(&launch.program, &installation.launch.program)
        || source.node_reference_data() != node.reference_data()
        || source.original_generic_limits_data() != (operations, semantic, result, authorization)
        || source
            .semantic_data()
            .get("source")
            .and_then(|source| source.get("inherited"))
            != Some(&Value::Null)
        || node.inherited_node_reference_data().is_some()
    {
        return Err(refused(
            "initial15 durable Source contracts or generic limits differ",
        ));
    }

    if ancestry.parent_archive_index != *parent_index
        || ancestry.parent_manifest != *parent_manifest
        || ancestry.first_semantic != *original.semantic_data().map_err(original_failure_data)?.0
        || ancestry.first_journal != *journal_reference
        || ancestry.first_observation != *source.first_observation_data().checkpoint_data().2
        || ancestry.restoration_commit != current_scope.restoration.commit_request
        || current_scope.source_runtime != journal.runtime
        || current_scope.scope_proof != restoration.proof
    {
        return Err(refused("initial15 Source parent lineage or scope differs"));
    }

    if parent_owner.owner != journal.owner
        || parent_owner.participants != journal.participants
        || parent_owner.state != journal.native_snapshot
        || !parent_owner.evidence.contains(journal_reference)
        || held.captured_owner_state != parent_owner.state
        || held.captured_control != journal.native_control
        || held.captured_journal != *journal_reference
        || restored.archive_index != *parent_index
        || restored.capture_manifest != *parent_manifest
        || restored.owner_state != parent_owner.state
        || restored.journal != *journal_reference
        || restored.source_runtime != journal.runtime
        || restored.backend_implementation != journal.backend_implementation
        || restored.backend_schema != parent_owner.key.schema
        || restored.archived_cut != journal.cut
        || restored.archived_ordinal != journal.ordinal
        || prepare.host_protocol != journal.host_protocol
        || prepare.native_protocol != journal.native_after_protocol
        || prepare.native_control != journal.native_control
        || prepare.native_anchor != journal.native_anchor
        || restored.mapping != held.mapping
        || restored.target_world != held.target_world
        || restored.target_owner != held.target_owner
        || restored.target_owner_binding != held.target_owner_binding
        || restored.target_activation != held.target_activation
        || restored.target_generation != held.target_generation
    {
        return Err(refused(
            "initial15 Source roles or original native custody differ",
        ));
    }

    // The strict Source reader already joined every current installation role
    // to its native Boot. Exact durable compatibility above preserves the old
    // profile/capability/guarantee/facet/qualification references. The defining
    // Node comparison retains every literal original and all five family rows.
    // Local new17 Producer attempts are not inferred from generic old counts.
    node.authenticate_initial15_originals_data(&original, scope.runtime, restoration)
        .map_err(crate::node_state::schema)?;
    historical.completed_data(scope)?;
    authenticate_parent_data(parent, group, scope)
}

fn same_program_data(
    old: &PacketConnectedSourceProgram,
    current: &PacketConnectedSourceProgram,
) -> bool {
    match (old, current) {
        (
            PacketConnectedSourceProgram::Producer { program: old },
            PacketConnectedSourceProgram::Producer { program: current },
        ) => old == current,
        (
            PacketConnectedSourceProgram::Reactive { program: old },
            PacketConnectedSourceProgram::Reactive { program: current },
        ) => old == current,
        _ => false,
    }
}

/// Counts fixed pure correspondence frames, separately from retained owners.
pub(crate) fn initial15_source_member17_counter_scratch_data() -> usize {
    HistoricalInitial15Scope17::counter_scratch_data()
        + CnpRestoredSettledValidatedNode17::initial15_correspondence_counter_scratch_data()
        + size_of::<&ParentArchive17ReadScope<'static, 'static>>()
        + size_of::<&OriginalInitial15ArchivedGroup>()
        + size_of::<OriginalInitial15ArchivedOwnerRead<'static>>()
        + size_of::<&OriginalSourceRestoredSettled17Read>()
        + size_of::<&SealedHistoricalRestoredSettledNative17>()
        + size_of::<&PacketRestoredSettledAncestry17>()
        + size_of::<std::slice::Iter<'static, NativeOwnerState>>()
        + size_of::<Option<&NativeOwnerState>>()
        + size_of::<Result<(), StateError>>()
        + size_of::<[usize; 4]>()
}
