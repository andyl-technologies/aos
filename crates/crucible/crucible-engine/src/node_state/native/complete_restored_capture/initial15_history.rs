//! Reconstructs the historical host-authored scope from its actual signed proof.
//!
//! ACKs are host-created DATA derived from original Runtime7 and exact fresh
//! owner mappings. The proof's fullref is independently bound by all three
//! native first-observation MACs. No native ACK cache or current ACK supplies
//! an expected value, and this owner cannot issue a live restoration context.

use super::terminal::{
    RestoredArchive17ParentWork, RestoredArchive17SourceIndex,
    RestoredArchive17ValidationConstructionData, RestoredArchive17ValidationPrewalkData,
    RestoredArchive17ValidationStep,
};
use super::*;
use crate::node_adapters::cnp::{
    CnpRestoredSettledValidatedNode17, OriginalInitial15ArchivedGroup,
    OriginalInitial15ArchivedOwnerRead, OriginalSourceRestoredSettled17Prelude,
};
use crate::node_contract::{
    OriginalLineageJournal, OriginalLineageNativeScope, OriginalLineageOwnerMapping,
    SavedOriginalInputScope, runtime_owned_counter::OwnedStorage,
};
use crate::node_scheduling::NativeInputAcknowledgement;
use crucible_node_format::{Id, canonical};
use crucible_node_transport::protocol_snapshot::{
    restored_journal17::PacketRestoredSettledAncestry17,
    restored_settled17::SealedHistoricalRestoredSettledNative17,
};
use serde_json::Value;
use std::mem::size_of;

#[path = "initial15_history/build.rs"]
mod build;
#[path = "initial15_history/storage.rs"]
mod census;
#[path = "initial15_history/proof.rs"]
mod proof;
#[path = "initial15_history/source.rs"]
mod source;
pub(crate) use source::{
    authenticate_initial15_source_member17_data, initial15_source_member17_counter_scratch_data,
};

/// Retains proof decoder products and all partial historical scope construction.
pub(crate) struct HistoricalInitial15Scope17 {
    archive_index: *const storage::Index,
    process: u32,
    thread: ThreadId,
    value: Option<Value>,
    canonical: Option<Vec<u8>>,
    proof: Option<proof::ScopeProof17>,
    holds: [Option<Value>; 3],
    hold_bytes: [Option<Vec<u8>>; 3],
    roundtrip: Option<Value>,
    owners: Vec<OriginalLineageOwnerMapping>,
    first_scopes: Vec<SavedOriginalInputScope>,
    journals: Vec<OriginalLineageJournal>,
    acknowledgements: Vec<NativeInputAcknowledgement>,
    completed: Option<OriginalLineageNativeScope>,
    // Set only after exact proof/field joins and final actual census admission.
    verified: bool,
}

/// Borrows strict completed components before the aggregate Source reader.
///
/// Every field is inert DATA from its defining native, SDK or Node validator.
/// This conjunction creates no Source, native permission or current owner.
pub(crate) struct Initial15ScopeMember17<'a> {
    /// Borrows the exact current common custody record.
    pub(crate) node: &'a CnpRestoredSettledValidatedNode17,
    /// Borrows the independently checked launch and first native/SDK proof.
    pub(crate) prelude: &'a OriginalSourceRestoredSettled17Prelude,
    /// Borrows the same member's sealed operational graph.
    pub(crate) native: &'a SealedHistoricalRestoredSettledNative17,
    /// Borrows the actual current Journal's full immutable lineage roles.
    pub(crate) ancestry: &'a PacketRestoredSettledAncestry17,
}

impl HistoricalInitial15Scope17 {
    /// Replays the defining host scope constructor from actual historical inputs.
    ///
    /// The three members lend strict Prelude/SDK/native first-observation
    /// components. A complete Source reader is deliberately not a prerequisite:
    /// its final Node/Source join consumes this independently verified scope.
    /// `additional` includes the original group, parent attempt, collection and
    /// all other retained owners,
    /// excluding only this separate output slot/backing and Core/content census.
    ///
    /// # Errors
    /// Refuses spent output, another archive, incomplete original/current parts,
    /// an absent signed proof body, changed target/held identities or finite row.
    /// Initialized proof and construction partials remain retained on refusal.
    /// The returned scalar counts the caller's prior cache plus actual new
    /// backing; it does not release or renew any previous construction debit.
    pub(crate) fn read_historical_scope_into(
        parent: &ParentArchive17ReadScope<'_, '_>,
        group: &OriginalInitial15ArchivedGroup,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        source_index: RestoredArchive17SourceIndex,
        parent_depth: usize,
        terminal_prior_cache: usize,
        members: &[Initial15ScopeMember17<'_>; 3],
        additional: usize,
        output: &mut Option<HistoricalInitial15Scope17>,
    ) -> Result<usize, StateError> {
        let step = RestoredArchive17ValidationStep::parent_data(
            source_index,
            parent_depth,
            parent.index_reference_data()?,
            RestoredArchive17ParentWork::ScopeProof,
        )?;
        // The caller supplies its actual completed cache census. A recursive
        // prewalk here would reborrow the collector and run before admission.
        let prior_cache = terminal_prior_cache;
        if let Some(admission) = scope.terminal_admission_data() {
            admission.begin_stage_data(RestoredArchive17ValidationPrewalkData::new_data(
                step,
                prior_cache,
                census::hold_projection_transient_bytes_data(),
                Self::counter_scratch_data(),
            )?)?;
        }
        authenticate_parent_data(parent, group, scope)?;
        if output.is_some() {
            return Err(refused(
                "historical initial15 scope attempt is already spent",
            ));
        }
        census::admit_data(
            parent,
            scope,
            None,
            additional,
            HistoricalInitial15Scope17::counter_scratch_data(),
        )?;
        let operands = proof::borrow_operands_data(parent, group, scope, members)?;
        let bytes = scope
            .content
            .get(operands.reference)
            .ok_or_else(|| refused("historical scope signed proof body absent"))?;
        proof::authenticate_body_data(operands.reference, bytes)?;
        if operands.reference.media_type != "application/json"
            || bytes.is_empty()
            || bytes.len() > record_maximum(parent, scope)?
        {
            return Err(refused("historical scope proof media or extent differs"));
        }
        proof::authenticate_borrowed_shape_data(bytes)?;

        let construction = census::construction_data(parent, scope, &operands, bytes, members)?;
        census::admit_data(parent, scope, None, additional, construction)?;
        if let Some(admission) = scope.terminal_admission_data() {
            // The complete structural row includes all retained and transient
            // products. Charging it independently in both columns conservatively
            // covers their overlap; no later phase can reclaim either debit.
            admission.construct_stage_data(
                RestoredArchive17ValidationConstructionData::new_data(
                    step,
                    prior_cache,
                    construction,
                    construction,
                    Self::counter_scratch_data(),
                )?,
            )?;
        }
        *output = Some(HistoricalInitial15Scope17 {
            archive_index: std::sync::Arc::as_ptr(&scope.archive.index),
            process: std::process::id(),
            thread: std::thread::current().id(),
            value: None,
            canonical: None,
            proof: None,
            holds: std::array::from_fn(|_| None),
            hold_bytes: std::array::from_fn(|_| None),
            roundtrip: None,
            owners: Vec::new(),
            first_scopes: Vec::new(),
            journals: Vec::new(),
            acknowledgements: Vec::new(),
            completed: None,
            verified: false,
        });
        let owner = output
            .as_mut()
            .ok_or_else(|| refused("historical initial15 scope attempt absent"))?;
        let maximum_record = record_maximum(parent, scope)?;
        for (index, member) in members.iter().enumerate() {
            let held = member
                .native
                .restoration_hold_data()
                .map_err(crate::node_state::schema)?;
            owner.holds[index] =
                Some(serde_json::to_value(held).map_err(crate::node_state::schema)?);
            owner.hold_bytes[index] = Some(
                canonical::canonical_json(
                    owner.holds[index]
                        .as_ref()
                        .ok_or_else(|| refused("historical native Hold DOM absent"))?,
                )
                .map_err(crate::node_state::schema)?,
            );
            proof::authenticate_body_data(
                &member.ancestry.restoration_hold,
                owner.hold_bytes[index]
                    .as_deref()
                    .ok_or_else(|| refused("historical native Hold bytes absent"))?,
            )?;
        }

        owner.value =
            Some(canonical::parse_json(bytes, maximum_record).map_err(crate::node_state::schema)?);
        owner.canonical = Some(
            canonical::canonical_json(
                owner
                    .value
                    .as_ref()
                    .ok_or_else(|| refused("scope proof DOM absent"))?,
            )
            .map_err(crate::node_state::schema)?,
        );
        if owner.canonical.as_deref() != Some(bytes) {
            return Err(refused("historical scope proof is noncanonical"));
        }
        owner.proof = Some(
            serde_json::from_value(
                owner
                    .value
                    .as_ref()
                    .ok_or_else(|| refused("scope proof DOM absent"))?
                    .clone(),
            )
            .map_err(crate::node_state::schema)?,
        );
        owner.roundtrip = Some(
            serde_json::to_value(
                owner
                    .proof
                    .as_ref()
                    .ok_or_else(|| refused("scope proof typed data absent"))?,
            )
            .map_err(crate::node_state::schema)?,
        );
        if owner.roundtrip != owner.value {
            return Err(refused("historical scope proof loses literal fields"));
        }
        owner
            .proof
            .as_ref()
            .ok_or_else(|| refused("scope proof typed data absent"))?
            .authenticate_data(parent, scope, &operands)?;
        owner.construct_data(parent, scope, &operands)?;
        census::admit_data(
            parent,
            scope,
            Some(owner),
            additional,
            HistoricalInitial15Scope17::counter_scratch_data(),
        )?;
        owner.authenticate_scope_data(scope)?;
        let actual = prior_cache
            .checked_add(
                owner
                    .retained_requested_storage_data(maximum(parent, scope)?)
                    .map_err(crate::node_state::schema)?,
            )
            .ok_or_else(|| refused("historical scope completed-cache extent overflow"))?;
        if let Some(admission) = scope.terminal_admission_data() {
            admission.finish_stage_data(step, actual)?;
        }
        owner.verified = true;
        Ok(actual)
    }
}

impl HistoricalInitial15Scope17 {
    fn authenticate_scope_data(
        &self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        scope.validation_origin.authenticate(scope.archive)?;
        self.authenticate_actor_data()
            .map_err(crate::node_state::schema)?;
        if self.archive_index != std::sync::Arc::as_ptr(&scope.archive.index) {
            return Err(refused(
                "historical scope belongs to another archive occurrence",
            ));
        }
        Ok(())
    }

    fn authenticate_actor_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the completed historical constructor output without a live grant.
    ///
    /// # Errors
    /// Refuses another archive/actor or any incomplete or refused constructor.
    pub(crate) fn completed_data(
        &self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
    ) -> Result<&OriginalLineageNativeScope, StateError> {
        self.authenticate_scope_data(scope)?;
        if !self.verified {
            return Err(refused("historical scope final admission is incomplete"));
        }
        self.completed
            .as_ref()
            .ok_or_else(|| refused("historical scope construction incomplete"))
    }
}

/// Authenticates the same immutable parent without issuing a live archive loan.
fn authenticate_parent_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
    group: &OriginalInitial15ArchivedGroup,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
) -> Result<(), StateError> {
    scope.validation_origin.authenticate(scope.archive)?;
    let manifest = parent.manifest_data()?;
    if manifest.owners.len() != 4 {
        return Err(refused("initial15 historical parent owner roster differs"));
    }
    for owner in &manifest.owners {
        let [node] = owner.participant_ids.as_slice() else {
            return Err(refused("initial15 historical participant is not singleton"));
        };
        // The host is the fourth participant and has no packet Source owner.
        if owner.capture_owner_id == scope.host.source.owner.owner.id {
            continue;
        }
        let original = group.owner_data(node).map_err(original_failure_data)?;
        if original
            .parent_references_data()
            .map_err(original_failure_data)?
            != (
                parent.index_reference_data()?,
                parent.manifest_reference_data()?,
            )
        {
            return Err(refused(
                "initial15 historical group belongs to another parent",
            ));
        }
    }
    Ok(())
}

fn original_failure_data(error: crate::node_contract::OperationFailure) -> StateError {
    refused(error.reason)
}

fn maximum(
    parent: &ParentArchive17ReadScope<'_, '_>,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
) -> Result<usize, StateError> {
    let original = parent.limits_data()?;
    let current = scope.archive_limits_data()?;
    Ok(usize::try_from(original.state.maximum_native_memory_bytes)
        .map_err(crate::node_state::schema)?
        .min(original.state.maximum_total_content_bytes)
        .min(original.native.maximum_total_record_bytes)
        .min(
            usize::try_from(current.state.maximum_native_memory_bytes)
                .map_err(crate::node_state::schema)?,
        )
        .min(current.state.maximum_total_content_bytes)
        .min(current.native.maximum_total_record_bytes))
}

fn record_maximum(
    parent: &ParentArchive17ReadScope<'_, '_>,
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
) -> Result<usize, StateError> {
    let original = parent.limits_data()?;
    let current = scope.archive_limits_data()?;
    Ok(original
        .state
        .maximum_record_bytes
        .min(original.native.maximum_record_bytes)
        .min(current.state.maximum_record_bytes)
        .min(current.native.maximum_record_bytes)
        .min(maximum(parent, scope)?))
}
