//! Retains actual current17 decoder owners before any restoration Source exists.
//!
//! Strict component decoding is a partial construction stage. Publishing a cold
//! group additionally requires the independently validated parent lineage and
//! completed Source reader for every member. No stored stage bit supplies them.

use super::terminal::{
    RestoredArchive17ParentWork, RestoredArchive17SourceIndex, RestoredArchive17ValidationStage,
    RestoredArchive17ValidationStep,
};
use super::*;
use crate::node_adapters::cnp::{
    CnpRestoredNode17DecodeAttempt, CnpRestoredNode17DecodeConstructionData,
    CnpRestoredSettledValidatedNode17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Prelude, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs, PacketCompleteSemanticSource,
};
use crate::node_contract::{NodeRoute, RuntimeError};
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::protocol_snapshot::{
    current_controller17::{
        ControllerSettledHistory17DecodePlan, ValidatedControllerSettledHistory17,
        ValidatedHistoricalRestoredSettledCapture17, current_controller17_counter_scratch_data,
        historical_restored_settled_capture17_counter_scratch_data,
        historical_restored_settled_capture17_selected_counter_scratch_data,
        historical_restored_settled_capture17_selected_retained_construction_bytes_data,
        historical_restored_settled_capture17_selected_validation_transient_bytes_data,
    },
    restored_journal17::{
        PacketRestoredSettledAncestry17, PacketRestoredSettledHistoryCut17,
        PacketRestoredSettledJournal17Objects, PacketRestoredSettledJournal17Plan,
        PacketRestoredSettledSemantic17Plan,
    },
    restored_settled17::{
        RestoredSettledNative17DecodeAttempt, RestoredSettledNative17Input,
        RestoredSettledNative17Limits, RestoredSettledNative17Plan,
        SealedHistoricalRestoredSettledNative17, restored_settled_native17_counter_scratch_data,
        restored_settled_native17_decode_construction_transient_bytes_data,
    },
};
use serde_json::Value;
use std::mem::size_of;

/// Retains distinct actual decoder slots beneath their selected archive origin.
///
/// No constructor is available outside the authenticated validation scope. This
/// owner contains no Source handle, ticket or fresh target and cannot form an Rc
/// cycle when its completed data later moves into a restoration Source.
pub(crate) struct RetainedCold17Collection {
    archive_index: *const storage::Index,
    process: u32,
    thread: ThreadId,
    // Only a selected, independently admitted Journal allocates its one member.
    // Unstarted Source/Prepared headers contain three empty Vecs, not decoder
    // and output payloads for six future member views in validation/publication.
    members: [Vec<RetainedCold17Member>; 3],
    parents: Vec<Option<parent_index::ParentIndex17Attempt>>,
    initial15_group: Option<crate::node_adapters::cnp::OriginalInitial15ArchivedGroup>,
    historical_scope: Option<super::initial15_history::HistoricalInitial15Scope17>,
    terminal_cache: usize,
    production_declaration: Option<[usize; 3]>,
}

/// Preserves successful children and failed raw/typed partials independently.
struct RetainedCold17Member {
    owner_index: usize,
    journal_reference: Option<ContentRef>,
    journal: Option<Value>,
    objects: Option<PacketRestoredSettledJournal17Objects>,
    ancestry: Option<PacketRestoredSettledAncestry17>,
    cut: Option<PacketRestoredSettledHistoryCut17>,
    controller: Option<ValidatedControllerSettledHistory17>,
    sdk_capture: Option<ValidatedHistoricalRestoredSettledCapture17>,
    native_limits: Option<RestoredSettledNative17Limits>,
    native_attempt: Option<RestoredSettledNative17DecodeAttempt>,
    native: Option<SealedHistoricalRestoredSettledNative17>,
    node_reference: Option<ContentRef>,
    route: Option<NodeRoute>,
    node_attempt: Option<CnpRestoredNode17DecodeAttempt>,
    node: Option<CnpRestoredSettledValidatedNode17>,
    prelude: Option<OriginalSourceRestoredSettled17Prelude>,
    source_attempt: Option<OriginalSourceRestoredSettled17DecodeAttempt>,
    source: Option<OriginalSourceRestoredSettled17Read>,
    // Exact final Source-history decoder axes, saved before that constructor.
    source_decode_axes: Option<[usize; 3]>,
}

/// Borrows already completed cold DATA without creating restoration authority.
pub(crate) struct RetainedCold17MemberView<'a> {
    pub(crate) owner_index: usize,
    pub(crate) controller_reference: &'a ContentRef,
    pub(crate) native_before_reference: &'a ContentRef,
    pub(crate) references: [&'a ContentRef; 5],
    pub(crate) native: &'a SealedHistoricalRestoredSettledNative17,
    pub(crate) native_limits: RestoredSettledNative17Limits,
    pub(crate) source_decode_axes: [usize; 3],
    pub(crate) controller: &'a ValidatedControllerSettledHistory17,
    pub(crate) node: &'a CnpRestoredSettledValidatedNode17,
    pub(crate) source_history: &'a OriginalSourceRestoredSettled17Read,
}

impl RetainedCold17Collection {
    fn new(scope: &CompleteRestoredSettledArchiveValidation<'_>) -> Result<Self, StateError> {
        scope.validation_origin.authenticate(scope.archive)?;
        Ok(Self {
            archive_index: std::sync::Arc::as_ptr(&scope.archive.index),
            process: std::process::id(),
            thread: std::thread::current().id(),
            members: std::array::from_fn(|_| Vec::new()),
            parents: Vec::new(),
            initial15_group: None,
            historical_scope: None,
            terminal_cache: terminal_cache_seed(scope, 0)?,
            production_declaration: None,
        })
    }

    pub(crate) fn authenticate_archive_data(
        &self,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || self.archive_index != std::sync::Arc::as_ptr(&archive.index)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Reads genuine current components while retaining refusal products in place.
    ///
    /// Component completion is deliberately distinct from all-owner publication.
    /// The actual Source and parent-lineage validators must still consume these
    /// same owners before this collection can be moved into a Source.
    pub(super) fn collect_current_into(
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        additional: usize,
        output: &mut Option<Self>,
    ) -> Result<(), StateError> {
        if output.is_some() {
            return Err(refused("cold17 collection attempt is already spent"));
        }
        scope.validation_origin.authenticate(scope.archive)?;
        // Installing this inline pure-cache root performs no owning allocation.
        // The first Journal prewalk admits its counter before any census walk.
        *output = Some(Self::new(scope)?);
        let collection = output
            .as_mut()
            .ok_or_else(|| refused("cold17 collection absent"))?;
        collection.terminal_cache = terminal_cache_seed(scope, additional)?;
        let mut member = 0usize;
        for (owner_index, owner) in scope.archive.owners().iter().enumerate() {
            if owner.owner == scope.host.source.owner.owner.id {
                continue;
            }
            if member >= 3 || owner.participants.len() != 1 {
                return Err(refused("cold17 native member roster differs"));
            }
            collection.read_current_member(scope, owner_index, member, additional)?;
            member += 1;
        }
        if member != 3 {
            return Err(refused("cold17 native member roster is incomplete"));
        }
        for selected in 0..3 {
            collection.read_parent_index_data(scope, selected, additional)?;
        }
        collection.read_initial15_group_data(scope)?;
        for selected in 0..3 {
            collection.read_completed_source_data(scope, selected, additional)?;
        }
        collection
            .authenticate_archive_data(scope.archive)
            .map_err(super::super::super::schema)?;
        scope.validation_origin.authenticate(scope.archive)
    }

    fn read_current_member(
        &mut self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        owner_index: usize,
        selected: usize,
        additional: usize,
    ) -> Result<(), StateError> {
        self.authenticate_archive_data(scope.archive)
            .map_err(super::super::super::schema)?;
        let owner = scope
            .archive
            .owners()
            .get(owner_index)
            .ok_or_else(|| refused("cold17 actual native owner absent"))?;
        let current = scope
            .administrative
            .attempts
            .last()
            .ok_or_else(|| refused("cold17 administrative cut absent"))?;
        let mut records = current
            .owners
            .iter()
            .filter(|record| record.owner.owner == owner.owner);
        let record = records
            .next()
            .ok_or_else(|| refused("cold17 administrative native owner absent"))?;
        let crate::node_contract::OriginalCaptureOwnerState::Settled { snapshot, journal } =
            &record.state
        else {
            return Err(refused("cold17 administrative native owner is unsettled"));
        };
        if records.next().is_some()
            || snapshot != &owner.state
            || record.participants != owner.participants
            || !owner.evidence.contains(journal)
            || !self.members[selected].is_empty()
            || self.members[selected].capacity() != 0
        {
            return Err(refused("cold17 native and administrative roles differ"));
        }
        let source_index = RestoredArchive17SourceIndex::from_data(selected)?;
        let journal_step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::Journal(source_index),
        )?;
        self.begin_terminal_stage_data(
            scope,
            journal_step,
            0,
            counter_scratch_data()
                .checked_add(core_decode_credit::scanner_storage())
                .ok_or_else(|| refused("cold17 Journal prewalk overflow"))?,
        )?;
        let bytes = body(scope, journal)?;
        let maximum = maximum(scope)?;
        admit(
            scope,
            Some(self),
            additional,
            counter_scratch_data()
                .checked_add(core_decode_credit::scanner_storage())
                .ok_or_else(|| refused("cold17 journal scanner credit overflow"))?,
        )?;
        let plan = PacketRestoredSettledJournal17Plan::validate(bytes, record_maximum(scope)?)
            .map_err(super::super::super::schema)?;
        let typed_slot = size_of::<PacketRestoredSettledJournal17Objects>()
            + size_of::<PacketRestoredSettledAncestry17>()
            + size_of::<PacketRestoredSettledHistoryCut17>();
        let quote = NodeRuntime::capture_selected_json_decode_storage(
            bytes,
            typed_slot,
            NodeRuntime::capture_map_node_storage::<String, Value>(),
            maximum,
        )
        .map_err(super::super::super::schema)?;
        let member_slot = member_bank_requested_storage_data(1)
            .map_err(super::super::super::schema)?;
        let member_work = member_construction_transient_storage_data()?;
        let retained = quote
            .checked_add(
                NodeRuntime::capture_reference_storage(journal)
                    .map_err(super::super::super::schema)?,
            )
            .and_then(|bytes| bytes.checked_add(member_slot))
            .ok_or_else(|| refused("cold17 Journal member storage overflow"))?;
        admit(
            scope,
            Some(self),
            additional,
            retained.checked_add(member_work)
                .ok_or_else(|| refused("cold17 Journal member work overflow"))?,
        )?;
        self.construct_terminal_stage_data(
            scope,
            journal_step,
            retained,
            member_work,
            counter_scratch_data(),
        )?;
        // Both the new bank and actual by-value construction/push work were
        // admitted above. The bank stays in this collection even if reservation
        // or its actual-capacity check refuses before a member is initialized.
        reserve_member_slot_data(&mut self.members[selected])?;
        initialize_member_data(&mut self.members[selected], owner_index, journal);
        {
            let member = self.member_mut(selected)?;
            member.journal = Some(
                canonical::parse_json(bytes, record_maximum(scope)?)
                    .map_err(super::super::super::schema)?,
            );
            // Each typed bank is installed before any later semantic check.
            member.objects = Some(
                serde_json::from_slice(plan.objects_bytes())
                    .map_err(super::super::super::schema)?,
            );
            member.ancestry = Some(
                serde_json::from_slice(plan.ancestry_bytes())
                    .map_err(super::super::super::schema)?,
            );
            member.cut = Some(
                serde_json::from_slice(plan.history_cut_bytes())
                    .map_err(super::super::super::schema)?,
            );
        }
        self.finish_terminal_stage_data(scope, journal_step, additional)?;
        let objects = self
            .member(selected)?
            .objects
            .as_ref()
            .ok_or_else(|| refused("cold17 object roles absent"))?;
        objects
            .validate_data()
            .map_err(super::super::super::schema)?;
        if objects.snapshot != owner.state {
            return Err(refused("cold17 Journal snapshot role differs"));
        }
        for reference in [
            &objects.snapshot,
            &objects.before,
            &objects.control,
            &objects.anchor,
            &objects.after,
            &objects.host_protocol,
            &objects.semantic,
        ] {
            body(scope, reference)?;
            if !owner.evidence.contains(reference) && reference != &owner.state {
                return Err(refused(
                    "cold17 member role is outside actual native evidence",
                ));
            }
        }
        if &objects.runtime_object != &scope.checkpoint.safe_point.runtime
            || &objects.coordinator_checkpoint != scope.checkpoint_reference
        {
            return Err(refused("cold17 Journal common checkpoint roles differ"));
        }
        let controller_bytes = body(scope, &objects.host_protocol)?;
        let controller_step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::Controller(source_index),
        )?;
        self.begin_terminal_stage_data(scope, controller_step, 0, counter_scratch_data())?;
        admit(scope, Some(self), additional, counter_scratch_data())?;
        let controller = ControllerSettledHistory17DecodePlan::validate(
            controller_bytes,
            record_maximum(scope)?,
            remaining(scope, self, additional)?
                .checked_sub(counter_scratch_data())
                .ok_or_else(|| refused("cold17 defining fixed scratch exceeds admission"))?,
        )
        .map_err(super::super::super::schema)?;
        admit(
            scope,
            Some(self),
            additional,
            controller.demand_data().requested_bytes_data(),
        )?;
        self.construct_terminal_stage_data(
            scope,
            controller_step,
            controller.demand_data().retained_requested_bytes_data(),
            controller
                .demand_data()
                .maximum_simultaneous_transient_bytes_data(),
            controller
                .demand_data()
                .counter_scratch_bytes_data()
                .checked_add(counter_scratch_data())
                .ok_or_else(|| refused("cold17 Controller census workspace overflow"))?,
        )?;
        controller
            .reconstruct_into(
                controller.demand_data(),
                &mut self.member_mut(selected)?.controller,
            )
            .map_err(super::super::super::schema)?;
        self.finish_terminal_stage_data(scope, controller_step, additional)?;
        let sdk_step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::SdkCapture(source_index),
        )?;
        let sdk_scratch = historical_restored_settled_capture17_selected_counter_scratch_data()
            .checked_add(counter_scratch_data())
            .ok_or_else(|| refused("cold17 SDK Capture workspace overflow"))?;
        self.begin_terminal_stage_data(scope, sdk_step, 0, sdk_scratch)?;
        let controller = self
            .member(selected)?
            .controller
            .as_ref()
            .ok_or_else(|| refused("cold17 Controller output absent"))?;
        let sdk_retained =
            historical_restored_settled_capture17_selected_retained_construction_bytes_data(
                controller, maximum,
            )
            .map_err(super::super::super::schema)?;
        let sdk_transient =
            historical_restored_settled_capture17_selected_validation_transient_bytes_data(
                controller, maximum,
            )
            .map_err(super::super::super::schema)?;
        self.construct_terminal_stage_data(
            scope,
            sdk_step,
            sdk_retained,
            sdk_transient,
            sdk_scratch,
        )?;
        admit(
            scope,
            Some(self),
            additional,
            sdk_retained
                .checked_add(sdk_transient)
                .and_then(|bytes| bytes.checked_add(sdk_scratch))
                .ok_or_else(|| refused("cold17 SDK Capture constructor overflow"))?,
        )?;
        let member = self.member_mut(selected)?;
        member.sdk_capture = Some(
            ValidatedHistoricalRestoredSettledCapture17::validate_data(
                member
                    .controller
                    .as_ref()
                    .ok_or_else(|| refused("cold17 Controller output absent"))?,
            )
            .map_err(super::super::super::schema)?,
        );
        self.finish_terminal_stage_data(scope, sdk_step, additional)?;

        let member = self.member(selected)?;
        let input = native_input(scope, member)?;
        let native_maximum = remaining(scope, self, additional)?
            .checked_sub(counter_scratch_data())
            .and_then(|remaining| {
                remaining.checked_sub(
                    restored_settled_native17_decode_construction_transient_bytes_data(),
                )
            })
            .ok_or_else(|| refused("cold17 native construction and scratch exceed admission"))?;
        let limits = RestoredSettledNative17Limits::new(
            input.roles_data().map(|(_, bytes)| bytes.len()),
            scope
                .lineage_limits
                .maximum_bytes
                .min(scope.archive.limits.state.maximum_total_content_bytes),
            scope.content.object_count(),
            scope.archive.limits.state.maximum_dependency_depth.min(64),
            input
                .roles_data()
                .into_iter()
                .try_fold(0usize, |nodes, (_, bytes)| nodes.checked_add(bytes.len()))
                .ok_or_else(|| refused("cold17 native syntax-node bound overflow"))?,
            native_maximum,
        )
        .map_err(super::super::super::schema)?;
        let native_terminal = scope
            .terminal_admission_data()
            .is_some()
            .then(|| {
                native_admission::NativeTerminal17::new_data(
                    scope,
                    source_index,
                    self.terminal_cache,
                )
            })
            .transpose()?;
        let native_plan = match &native_terminal {
            Some(admission) => RestoredSettledNative17Plan::validate_with_admission_data(
                &input, &limits, admission,
            ),
            None => RestoredSettledNative17Plan::validate_data(&input, &limits),
        }
        .map_err(super::super::super::schema)?;
        // The native defining decoder checks actual retained graph ownership
        // against this same independently available remainder before each copy.
        admit(
            scope,
            Some(self),
            additional,
            restored_settled_native17_counter_scratch_data()
                .checked_add(restored_settled_native17_decode_construction_transient_bytes_data())
                .ok_or_else(|| refused("cold17 native constructor workspace overflow"))?,
        )?;
        let member = self.member_mut(selected)?;
        member.native_limits = Some(limits);
        let sdk = member
            .sdk_capture
            .as_ref()
            .ok_or_else(|| refused("cold17 SDK Capture absent"))?;
        let controller = member
            .controller
            .as_ref()
            .ok_or_else(|| refused("cold17 Controller absent"))?;
        match &native_terminal {
            Some(admission) => native_plan.validate_retained_with_admission_into(
                &mut member.native_attempt,
                &mut member.native,
                sdk,
                controller,
                admission,
            ),
            None => native_plan.validate_retained_into(
                &mut member.native_attempt,
                &mut member.native,
                sdk,
                controller,
            ),
        }
        .map_err(super::super::super::schema)?;
        // Every scoped constructor reports its actual retained cache only after
        // its own guards and admitted census. The limit above is a ceiling,
        // never a terminal construction row or a completed-demand substitute.
        self.terminal_cache = match &native_terminal {
            Some(admission) => admission.completed_cache_data()?,
            None => terminal_cache_seed(scope, additional)?
                .checked_add(
                    self.retained_requested_storage_data(maximum)
                        .map_err(super::super::super::schema)?,
                )
                .ok_or_else(|| refused("cold17 loaded native cache overflow"))?,
        };
        let semantic_step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::SemanticEnvelope(source_index),
        )?;
        let semantic_scratch = counter_scratch_data()
            .checked_add(
                OriginalSourceRestoredSettled17Read::completed_decode_counter_scratch_data(),
            )
            .and_then(|bytes| {
                bytes.checked_add(OriginalSourceRestoredSettled17Prelude::counter_scratch_data())
            })
            .ok_or_else(|| refused("cold17 semantic prelude workspace overflow"))?;
        self.begin_terminal_stage_data(scope, semantic_step, 0, semantic_scratch)?;
        let member = self.member(selected)?;
        let objects = member
            .objects
            .as_ref()
            .ok_or_else(|| refused("cold17 semantic role absent"))?;
        let semantic_bytes = body(scope, &objects.semantic)?;
        let semantic =
            PacketRestoredSettledSemantic17Plan::validate(semantic_bytes, record_maximum(scope)?)
                .map_err(super::super::super::schema)?;
        let node_bytes = semantic.node_bytes();
        let prelude_quote =
            OriginalSourceRestoredSettled17Read::first_component_decode_construction_data(
                semantic_bytes,
                member
                    .controller
                    .as_ref()
                    .ok_or_else(|| refused("cold17 Controller absent"))?,
                member
                    .native
                    .as_ref()
                    .ok_or_else(|| refused("cold17 native owner absent"))?,
                member
                    .sdk_capture
                    .as_ref()
                    .ok_or_else(|| refused("cold17 SDK Capture absent"))?,
                maximum,
            )
            .map_err(super::super::super::schema)?;
        let owner_identity = scope
            .runtime
            .source_activation
            .owners
            .iter()
            .find(|identity| identity.owner == owner.owner)
            .ok_or_else(|| refused("cold17 archived Runtime owner absent"))?;
        let route_clone = size_of::<crate::node_contract::OwnerIdentity>()
            .checked_add(owner.participants[0].allocated_capacity())
            .and_then(|n| n.checked_add(owner_identity.owner.allocated_capacity()))
            .and_then(|n| n.checked_add(owner_identity.incarnation.allocated_capacity()))
            .and_then(|n| {
                n.checked_add(
                    "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len(),
                )
            })
            .and_then(|n| n.checked_add(counter_scratch_data()))
            .ok_or_else(|| refused("cold17 Node route/reference constructor overflow"))?;
        admit(scope, Some(self), additional, route_clone)?;
        // This route comes from the authenticated owner roster and Runtime7,
        // never from a caller-supplied route or a deserialized live authority.
        let semantic_retained = route_clone
            .checked_add(prelude_quote.retained_requested_bytes_data())
            .ok_or_else(|| refused("cold17 semantic constructor retained overflow"))?;
        let semantic_transient = prelude_quote.maximum_simultaneous_transient_bytes_data();
        let semantic_scratch = semantic_scratch
            .checked_add(prelude_quote.declared_counter_scratch_bytes_data())
            .ok_or_else(|| refused("cold17 semantic constructor workspace overflow"))?;
        self.construct_terminal_stage_data(
            scope,
            semantic_step,
            semantic_retained,
            semantic_transient,
            semantic_scratch,
        )?;
        admit(
            scope,
            Some(self),
            additional,
            semantic_retained
                .checked_add(semantic_transient)
                .and_then(|bytes| bytes.checked_add(semantic_scratch))
                .ok_or_else(|| refused("cold17 semantic constructor overflow"))?,
        )?;
        let member = self.member(selected)?;
        let prelude = OriginalSourceRestoredSettled17Prelude::read_data(
            semantic_bytes,
            member
                .controller
                .as_ref()
                .ok_or_else(|| refused("cold17 Controller absent"))?,
            member
                .native
                .as_ref()
                .ok_or_else(|| refused("cold17 native owner absent"))?,
            &scope.runtime.source_activation,
            record_maximum(scope)?,
        )
        .map_err(super::super::super::schema)?;
        self.member_mut(selected)?.prelude = Some(prelude);
        let route = NodeRoute {
            node: owner.participants[0].clone(),
            owners: vec![owner_identity.clone()],
        };
        let node_reference = canonical::content_ref(node_bytes, "application/json")
            .map_err(super::super::super::schema)?;
        {
            let member = self.member_mut(selected)?;
            member.node_reference = Some(node_reference);
            member.route = Some(route);
        }
        let node_reference = self
            .member(selected)?
            .node_reference
            .as_ref()
            .ok_or_else(|| refused("cold17 retained Node reference absent"))?;
        if body(scope, node_reference)? != node_bytes {
            return Err(refused(
                "cold17 standalone Node body differs from semantic Node",
            ));
        }
        self.finish_terminal_stage_data(scope, semantic_step, additional)?;
        let node_step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::Node(source_index),
        )?;
        self.begin_terminal_stage_data(scope, node_step, 0, counter_scratch_data())?;
        let node_maximum = remaining(scope, self, additional)?
            .checked_sub(counter_scratch_data())
            .ok_or_else(|| refused("cold17 Node defining scratch exceeds admission"))?;
        let member = self.member(selected)?;
        let quote = CnpRestoredNode17DecodeConstructionData::quote(
            member
                .node_reference
                .as_ref()
                .ok_or_else(|| refused("cold17 Node reference absent"))?,
            node_bytes,
            member
                .route
                .as_ref()
                .ok_or_else(|| refused("cold17 Node route absent"))?,
            node_maximum,
        )
        .map_err(super::super::super::schema)?;
        let demand = quote
            .retained_requested_bytes_data()
            .checked_add(quote.maximum_simultaneous_transient_bytes_data())
            .and_then(|n| n.checked_add(quote.declared_counter_scratch_bytes_data()))
            .ok_or_else(|| refused("cold17 Node constructor credit overflow"))?;
        admit(scope, Some(self), additional, demand)?;
        self.construct_terminal_stage_data(
            scope,
            node_step,
            quote.retained_requested_bytes_data(),
            quote.maximum_simultaneous_transient_bytes_data(),
            quote
                .declared_counter_scratch_bytes_data()
                .checked_add(counter_scratch_data())
                .ok_or_else(|| refused("cold17 Node census workspace overflow"))?,
        )?;
        let member = self.member_mut(selected)?;
        CnpRestoredSettledValidatedNode17::decode_current_into_data(
            member
                .node_reference
                .as_ref()
                .ok_or_else(|| refused("cold17 Node reference absent"))?,
            node_bytes,
            member
                .route
                .as_ref()
                .ok_or_else(|| refused("cold17 Node route absent"))?,
            scope.runtime,
            scope.scheduling,
            node_maximum,
            &mut member.node_attempt,
            &mut member.node,
        )
        .map_err(super::super::super::schema)?;
        let member = self.member(selected)?;
        if member
            .prelude
            .as_ref()
            .ok_or_else(|| refused("cold17 first component absent"))?
            .first_observation_data()
            .scheduling_data()
            != member
                .node
                .as_ref()
                .ok_or_else(|| refused("cold17 Node absent"))?
                .first_observation_data()
                .map_err(super::super::super::schema)?
        {
            return Err(refused(
                "cold17 first observation and actual Node mapping differ",
            ));
        }
        admit(scope, Some(self), additional, counter_scratch_data())?;
        self.finish_terminal_stage_data(scope, node_step, additional)
    }

    /// Retains one exact signed parent occurrence beneath this member's lineage.
    fn read_parent_index_data(
        &mut self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
        selected: usize,
        additional: usize,
    ) -> Result<(), StateError> {
        let source = RestoredArchive17SourceIndex::from_data(selected)?;
        let ancestry = self
            .member(selected)?
            .ancestry
            .as_ref()
            .ok_or_else(|| refused("cold17 parent ancestry absent"))?;
        let reference = pair(scope, &ancestry.parent_archive_index)?.0;
        let slot_step = RestoredArchive17ValidationStep::parent_data(
            source,
            0,
            reference,
            RestoredArchive17ParentWork::Slot,
        )?;
        self.begin_terminal_stage_data(
            scope,
            slot_step,
            0,
            counter_scratch_data()
                .checked_add(parent_index::counter_scratch_data())
                .ok_or_else(|| refused("cold17 parent slot prewalk overflow"))?,
        )?;
        let target = self
            .parents
            .len()
            .checked_add(1)
            .ok_or_else(|| refused("cold17 parent slot length overflow"))?;
        let new_backing = target
            .checked_mul(size_of::<Option<parent_index::ParentIndex17Attempt>>())
            .ok_or_else(|| refused("cold17 parent slot backing overflow"))?;
        self.construct_terminal_stage_data(
            scope,
            slot_step,
            new_backing,
            0,
            counter_scratch_data(),
        )?;
        admit(scope, Some(self), additional, new_backing)?;
        self.parents
            .try_reserve_exact(1)
            .map_err(|_| refused("cold17 parent slot allocation refused"))?;
        if self.parents.capacity() > target {
            return Err(refused("cold17 parent slot capacity exceeds its exact row"));
        }
        self.parents.push(None);
        self.finish_terminal_stage_data(scope, slot_step, additional)?;

        // All prior component/parent caches coexist with the new parent. This
        // immutable accounting value is DATA; native keys stay in their actual
        // independently decoded parent owners.
        let parent_additional = self
            .terminal_cache
            .checked_sub(scope.terminal_prefix_retained_storage_data()?)
            .ok_or_else(|| refused("cold17 parent enclosing cache overflow"))?;
        let prior_cache = self.terminal_cache;
        let output = self
            .parents
            .last_mut()
            .ok_or_else(|| refused("cold17 parent slot absent"))?;
        let completed_cache = parent_index::ParentIndex17Attempt::read_into(
            scope,
            reference,
            0,
            source,
            prior_cache,
            parent_additional,
            output,
        )?;
        self.terminal_cache = completed_cache;
        scope.validation_origin.authenticate(scope.archive)
    }

    fn member(&self, selected: usize) -> Result<&RetainedCold17Member, StateError> {
        self.members
            .get(selected)
            .and_then(|bank| match bank.as_slice() {
                [member] => Some(member),
                _ => None,
            })
            .ok_or_else(|| refused("cold17 retained member absent"))
    }

    fn member_mut(&mut self, selected: usize) -> Result<&mut RetainedCold17Member, StateError> {
        self.members
            .get_mut(selected)
            .and_then(|bank| match bank.as_mut_slice() {
                [member] => Some(member),
                _ => None,
            })
            .ok_or_else(|| refused("cold17 retained member absent"))
    }

    pub(super) fn production_cache_data(&self) -> usize {
        self.terminal_cache
    }

    pub(super) fn production_owner_indices_data(&self) -> Result<[usize; 3], RuntimeError> {
        // The opaque declaration loan is issued only after this real private
        // field has passed authenticate_production_declaration_data.
        self.production_declaration
            .ok_or(RuntimeError::OutstandingObligations)
    }

    pub(crate) fn authenticate_production_declaration_data(
        &self,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_completed_data(archive)?;
        let indices = self
            .production_declaration
            .ok_or(RuntimeError::OutstandingObligations)?;
        for (index, owner_index) in indices.into_iter().enumerate() {
            if indices[..index].contains(&owner_index) {
                return Err(RuntimeError::ForeignAuthority);
            }
            self.member_data(archive, owner_index)?;
        }
        Ok(())
    }

    pub(super) fn complete_production_declaration_data(
        &mut self,
        archive: &NativeArchiveRecord,
        indices: [usize; 3],
    ) -> Result<(), RuntimeError> {
        self.authenticate_completed_data(archive)?;
        if self.production_declaration.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        for (index, owner_index) in indices.into_iter().enumerate() {
            if indices[..index].contains(&owner_index) {
                return Err(RuntimeError::ForeignAuthority);
            }
            self.member_data(archive, owner_index)?;
        }
        self.production_declaration = Some(indices);
        Ok(())
    }

    pub(crate) fn member_data(
        &self,
        archive: &NativeArchiveRecord,
        owner_index: usize,
    ) -> Result<RetainedCold17MemberView<'_>, RuntimeError> {
        self.authenticate_completed_data(archive)?;
        let mut members = self
            .members
            .iter()
            .flatten()
            .filter(|member| member.owner_index == owner_index);
        let member = members.next().ok_or(RuntimeError::ForeignAuthority)?;
        if members.next().is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let objects = member
            .objects
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        Ok(RetainedCold17MemberView {
            owner_index,
            controller_reference: &objects.host_protocol,
            native_before_reference: &objects.before,
            references: [
                &objects.snapshot,
                &objects.after,
                &objects.control,
                &objects.anchor,
                member
                    .journal_reference
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            ],
            native_limits: member.native_limits.ok_or(RuntimeError::OwnerUnavailable)?,
            source_decode_axes: member
                .source_decode_axes
                .ok_or(RuntimeError::OwnerUnavailable)?,
            native: member
                .native
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            controller: member
                .controller
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            node: member.node.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            source_history: member
                .source
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        })
    }

    /// Refuses publication until every genuine defining reader is retained.
    pub(crate) fn authenticate_completed_data(
        &self,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_archive_data(archive)?;
        if self.parents.len() != 3
            || self.parents.iter().any(Option::is_none)
            || self.initial15_group.is_none()
            || self.historical_scope.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        for member in &self.members {
            let [member] = member.as_slice() else {
                return Err(RuntimeError::OutstandingObligations);
            };
            if member.native.is_none()
                || member.controller.is_none()
                || member.node.is_none()
                || member.source.is_none()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        Ok(())
    }
}

// The single requested Vec slot is an independent retained allocation. Actual
// capacity, including a failed constructor's empty bank, is counted separately.
fn member_bank_requested_storage_data(capacity: usize) -> Result<usize, RuntimeError> {
    capacity
        .checked_mul(size_of::<RetainedCold17Member>())
        .ok_or(RuntimeError::ResourceLimit)
}

fn member_construction_transient_storage_data() -> Result<usize, StateError> {
    // Conservatively retain each by-value header along the defining path:
    // the literal, Vec::push, its push_mut delegate, and ptr::write. The latter
    // returns (), while push_mut returns a borrowed member rather than an
    // additional owning value. No push can grow the already reserved bank.
    size_of::<RetainedCold17Member>()
        .checked_add(size_of::<RetainedCold17Member>())
        .and_then(|bytes| bytes.checked_add(size_of::<RetainedCold17Member>()))
        .and_then(|bytes| bytes.checked_add(size_of::<RetainedCold17Member>()))
        .and_then(|bytes| bytes.checked_add(size_of::<&mut RetainedCold17Member>()))
        .and_then(|bytes| bytes.checked_add(size_of::<*mut RetainedCold17Member>()))
        .and_then(|bytes| {
            bytes.checked_add(size_of::<Result<(), std::collections::TryReserveError>>())
        })
        .and_then(|bytes| bytes.checked_add(size_of::<()>()))
        .ok_or_else(|| refused("cold17 member construction work overflow"))
}

fn reserve_member_slot_data(bank: &mut Vec<RetainedCold17Member>) -> Result<(), StateError> {
    if !bank.is_empty() || bank.capacity() != 0 {
        return Err(refused("cold17 member bank was already attempted"));
    }
    bank.try_reserve_exact(1)
        .map_err(|_| refused("cold17 member bank allocation refused"))?;
    if bank.capacity() != 1 {
        return Err(refused("cold17 member bank exceeds admitted slot"));
    }
    Ok(())
}

// Keep the owning literal out of the already large component decoder frame.
// There is no Box::new of a complete future Attempt or Collection here.
#[inline(never)]
fn initialize_member_data(
    bank: &mut Vec<RetainedCold17Member>,
    owner_index: usize,
    journal: &ContentRef,
) {
    bank.push(RetainedCold17Member {
        owner_index,
        journal_reference: Some(journal.clone()),
        journal: None,
        objects: None,
        ancestry: None,
        cut: None,
        controller: None,
        sdk_capture: None,
        native_limits: None,
        native_attempt: None,
        native: None,
        node_reference: None,
        route: None,
        node_attempt: None,
        node: None,
        prelude: None,
        source_attempt: None,
        source: None,
        source_decode_axes: None,
    });
}

fn native_input<'a>(
    scope: &'a CompleteRestoredSettledArchiveValidation<'_>,
    member: &RetainedCold17Member,
) -> Result<RestoredSettledNative17Input<'a>, StateError> {
    let owner = scope
        .archive
        .owners()
        .get(member.owner_index)
        .ok_or_else(|| refused("cold17 actual native owner absent"))?;
    let current = scope
        .administrative
        .attempts
        .last()
        .ok_or_else(|| refused("cold17 administrative cut absent"))?;
    let journal = current
        .owners
        .iter()
        .find_map(|record| {
            if record.owner.owner != owner.owner {
                return None;
            }
            match &record.state {
                crate::node_contract::OriginalCaptureOwnerState::Settled { journal, .. } => {
                    Some(journal)
                }
                _ => None,
            }
        })
        .ok_or_else(|| refused("cold17 actual Journal absent"))?;
    let objects = member
        .objects
        .as_ref()
        .ok_or_else(|| refused("cold17 actual object roles absent"))?;
    // Resolve every fullref back to the immutable signed index. The plan then
    // borrows only the original scope, so retaining decoder partials cannot
    // invalidate an aliased borrow into this mutable collection.
    Ok(RestoredSettledNative17Input {
        snapshot: pair(scope, &owner.state)?,
        current_protocol: pair(scope, &objects.after)?,
        control: pair(scope, &objects.control)?,
        anchor: pair(scope, &objects.anchor)?,
        journal: pair(scope, journal)?,
    })
}

fn pair<'a>(
    scope: &'a CompleteRestoredSettledArchiveValidation<'_>,
    reference: &ContentRef,
) -> Result<(&'a ContentRef, &'a [u8]), StateError> {
    let row = scope
        .archive
        .index
        .objects
        .iter()
        .find(|row| &row.reference == reference)
        .ok_or_else(|| refused("cold17 full reference is outside signed typed inventory"))?;
    Ok((&row.reference, body(scope, &row.reference)?))
}

fn body<'a>(
    scope: &'a CompleteRestoredSettledArchiveValidation<'_>,
    reference: &ContentRef,
) -> Result<&'a [u8], StateError> {
    if !scope
        .archive
        .index
        .objects
        .iter()
        .any(|row| &row.reference == reference)
    {
        return Err(refused("cold17 role is outside signed typed inventory"));
    }
    scope
        .content
        .get(reference)
        .ok_or_else(|| refused("cold17 verified body absent"))
}

fn record_maximum(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
) -> Result<usize, StateError> {
    let limits = scope.archive_limits_data()?;
    Ok(limits
        .state
        .maximum_record_bytes
        .min(limits.native.maximum_record_bytes))
}

fn maximum(scope: &CompleteRestoredSettledArchiveValidation<'_>) -> Result<usize, StateError> {
    let limits = scope.archive_limits_data()?;
    Ok(limits
        .state
        .maximum_total_content_bytes
        .min(limits.native.maximum_total_record_bytes)
        .min(
            usize::try_from(limits.state.maximum_native_memory_bytes)
                .map_err(super::super::super::schema)?,
        ))
}

fn remaining(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    collection: &RetainedCold17Collection,
    additional: usize,
) -> Result<usize, StateError> {
    let maximum = maximum(scope)?;
    let terms = [
        scope.retained_core_bytes_excluding_collection_data()?,
        scope.retained_verified_content_allocation_bytes()?,
        additional,
        collection
            .retained_requested_storage_data(maximum)
            .map_err(super::super::super::schema)?,
        size_of::<Option<RetainedCold17Collection>>(),
    ];
    terms.into_iter().try_fold(maximum, |available, next| {
        available
            .checked_sub(next)
            .ok_or_else(|| refused("cold17 component allocation remainder exhausted"))
    })
}

fn admit(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    collection: Option<&RetainedCold17Collection>,
    additional: usize,
    temporary: usize,
) -> Result<(), StateError> {
    let maximum = maximum(scope)?;
    let actual = collection
        .map(|collection| remaining(scope, collection, additional))
        .transpose()?;
    let available = match actual {
        Some(available) => available,
        None => {
            let owned = scope
                .retained_core_bytes_excluding_collection_data()?
                .checked_add(scope.retained_verified_content_allocation_bytes()?)
                .and_then(|n| n.checked_add(additional))
                .and_then(|n| n.checked_add(size_of::<Option<RetainedCold17Collection>>()))
                .ok_or_else(|| refused("cold17 enclosing constructor storage overflow"))?;
            maximum
                .checked_sub(owned)
                .ok_or_else(|| refused("cold17 enclosing constructor storage exhausted"))?
        }
    };
    let temporary = temporary
        .checked_add(counter_scratch_data())
        .ok_or_else(|| refused("cold17 defining decoder scratch overflow"))?;
    if temporary > available {
        return Err(refused("cold17 simultaneous decoder storage exhausted"));
    }
    Ok(())
}

#[path = "collector/native_admission.rs"]
mod native_admission;

#[path = "collector/initial15.rs"]
mod original_group;

#[path = "collector/source.rs"]
mod completed_source;

#[path = "collector/custody.rs"]
mod custody;
pub(super) use custody::{CollectorPhase17, collect_terminal_into_data};

#[path = "collector/terminal.rs"]
mod terminal_admission;
use terminal_admission::terminal_cache_seed;

#[path = "collector/storage.rs"]
mod storage_census;

pub(crate) fn counter_scratch_data() -> usize {
    size_of::<RetainedCold17Collection>()
        + size_of::<Option<RetainedCold17Collection>>()
        + size_of::<Vec<RetainedCold17Member>>()
        + size_of::<&mut Vec<RetainedCold17Member>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<[usize; 3]>()
        + size_of::<NodeRoute>()
        + size_of::<ContentRef>()
        + size_of::<Result<(), StateError>>()
        + size_of::<[usize; 5]>()
        + size_of::<ControllerSettledHistory17DecodePlan<'static>>()
        + size_of::<
            Result<
                ControllerSettledHistory17DecodePlan<'static>,
                crucible_node_provider::ProviderError,
            >,
        >()
        + current_controller17_counter_scratch_data()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + historical_restored_settled_capture17_counter_scratch_data()
        + restored_settled_native17_counter_scratch_data()
        + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
        + NodeRuntime::original_json_value_counter_scratch_data()
        + RetainedCold17Collection::retained_counter_scratch_data()
        + terminal_admission::counter_scratch_data()
        + custody::counter_scratch_data()
        + native_admission::counter_scratch_data()
        + crate::node_adapters::cnp::OriginalInitial15ArchivedGroup::terminal_counter_scratch_data()
        + super::initial15_history::HistoricalInitial15Scope17::counter_scratch_data()
}
