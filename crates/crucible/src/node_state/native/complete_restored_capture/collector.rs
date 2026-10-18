//! Retains actual current17 decoder owners before any restoration Source exists.
//!
//! Strict component decoding is a partial construction stage. Publishing a cold
//! group additionally requires the independently validated parent lineage and
//! completed Source reader for every member. No stored stage bit supplies them.

use super::*;
use crate::node_adapters::cnp::{
    CnpRestoredNode17DecodeAttempt, CnpRestoredNode17DecodeConstructionData,
    CnpRestoredSettledValidatedNode17, OriginalSourceRestoredSettled17Read,
    PacketCompleteSemanticSource,
};
use crate::node_contract::{NodeRoute, RuntimeError};
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::protocol_snapshot::{
    current_controller17::{
        ControllerSettledHistory17DecodePlan, ValidatedControllerSettledHistory17,
        ValidatedHistoricalRestoredSettledCapture17, current_controller17_counter_scratch_data,
        historical_restored_settled_capture17_counter_scratch_data,
        historical_restored_settled_capture17_validation_transient_bytes_data,
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
use std::{mem::size_of, rc::Rc};

/// Retains distinct actual decoder slots beneath their selected archive origin.
///
/// No constructor is available outside the authenticated validation scope. This
/// owner contains no Source handle, ticket or fresh target and cannot form an Rc
/// cycle when its completed data later moves into a restoration Source.
pub(crate) struct RetainedCold17Collection {
    archive_index: *const storage::Index,
    process: u32,
    thread: ThreadId,
    members: [Option<RetainedCold17Member>; 3],
    parents: Vec<Option<parent_index::ParentIndex17Attempt>>,
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
    semantic: Option<Rc<Value>>,
    source: Option<OriginalSourceRestoredSettled17Read>,
}

/// Borrows already completed cold DATA without creating restoration authority.
pub(crate) struct RetainedCold17MemberView<'a> {
    pub(crate) owner_index: usize,
    pub(crate) references: [&'a ContentRef; 5],
    pub(crate) native: &'a SealedHistoricalRestoredSettledNative17,
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
            members: std::array::from_fn(|_| None),
            parents: Vec::new(),
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
        admit(scope, None, additional, counter_scratch_data())?;
        *output = Some(Self::new(scope)?);
        let collection = output
            .as_mut()
            .ok_or_else(|| refused("cold17 collection absent"))?;
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
            || self.members[selected].is_some()
        {
            return Err(refused("cold17 native and administrative roles differ"));
        }
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
        admit(
            scope,
            Some(self),
            additional,
            quote
                .checked_add(
                    NodeRuntime::capture_reference_storage(journal)
                        .map_err(super::super::super::schema)?,
                )
                .ok_or_else(|| refused("cold17 Journal reference clone overflow"))?,
        )?;
        self.members[selected] = Some(RetainedCold17Member {
            owner_index,
            journal_reference: Some(journal.as_ref().clone()),
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
            semantic: None,
            source: None,
        });
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
        controller
            .reconstruct_into(
                controller.demand_data(),
                &mut self.member_mut(selected)?.controller,
            )
            .map_err(super::super::super::schema)?;
        let sdk = historical_restored_settled_capture17_validation_transient_bytes_data(
            controller_bytes.len(),
        )
        .map_err(super::super::super::schema)?;
        admit(scope, Some(self), additional, sdk)?;
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

        let member = self.member(selected)?;
        let input = native_input(scope, member)?;
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
            remaining(scope, self, additional)?
                .checked_sub(counter_scratch_data())
                .and_then(|remaining| {
                    remaining.checked_sub(
                        restored_settled_native17_decode_construction_transient_bytes_data(),
                    )
                })
                .ok_or_else(|| {
                    refused("cold17 native construction and scratch exceed admission")
                })?,
        )
        .map_err(super::super::super::schema)?;
        let native_plan = RestoredSettledNative17Plan::validate_data(&input, &limits)
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
        native_plan
            .validate_retained_into(
                &mut member.native_attempt,
                &mut member.native,
                member
                    .sdk_capture
                    .as_ref()
                    .ok_or_else(|| refused("cold17 SDK Capture absent"))?,
                member
                    .controller
                    .as_ref()
                    .ok_or_else(|| refused("cold17 Controller absent"))?,
            )
            .map_err(super::super::super::schema)?;

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
        admit(scope, Some(self), additional, counter_scratch_data())?;
        scope.validation_origin.authenticate(scope.archive)
    }

    fn member(&self, selected: usize) -> Result<&RetainedCold17Member, StateError> {
        self.members
            .get(selected)
            .and_then(Option::as_ref)
            .ok_or_else(|| refused("cold17 retained member absent"))
    }

    fn member_mut(&mut self, selected: usize) -> Result<&mut RetainedCold17Member, StateError> {
        self.members
            .get_mut(selected)
            .and_then(Option::as_mut)
            .ok_or_else(|| refused("cold17 retained member absent"))
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
        for member in &self.members {
            let member = member
                .as_ref()
                .ok_or(RuntimeError::OutstandingObligations)?;
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

#[path = "collector/storage.rs"]
mod storage_census;

pub(crate) fn counter_scratch_data() -> usize {
    size_of::<RetainedCold17Collection>()
        + size_of::<Option<RetainedCold17Collection>>()
        + size_of::<RetainedCold17Member>()
        + size_of::<Option<RetainedCold17Member>>()
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
}
