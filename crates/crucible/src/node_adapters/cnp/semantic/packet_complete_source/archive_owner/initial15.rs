//! Reconstructs a genuine initial15 parent as inert owned historical DATA.
//!
//! The only constructor consumes the collector's actual private parent loan.
//! Completed and refused outputs contain no borrowed parent, live Source,
//! live signing authority, local archive handle or restoration permission.

use super::super::{
    archive_native_input::{NativeInputData, NativeInputSelection},
    archive_semantics::{PacketCompleteArchivedSemantics, initial15::Initial15SemanticAttempt},
};
use super::*;
use crate::{node_scheduling::SchedulingSnapshot, node_state::ParentArchive17ReadScope};
use crucible_node_provider::reference_packet::service::{
    PacketConnectedSourceProgram, PacketNative5SourceLaunch,
};
use serde_json::Value;
use std::cell::Cell;

#[path = "initial15/declaration.rs"]
mod declaration;
#[path = "initial15/decoded.rs"]
mod decoded;
#[path = "initial15/parent_roles.rs"]
mod parent_roles;
#[path = "initial15/storage.rs"]
mod storage;
#[path = "initial15/terminal.rs"]
pub(super) mod terminal;
use decoded::{Initial15DecodeStaging, Initial15DecodedOwner};
use terminal::{Initial15Terminal17, protocol_prepare_terminal_storage_data};

#[derive(Clone, Copy)]
struct OriginalSemanticCaps {
    operations: usize,
    result: usize,
    authorization: usize,
    semantic: usize,
}

/// Owns an independently verified initial15 base and every refused partial.
///
/// Its private constructor path creates historical DATA only. A new live
/// Context/Window and complete signed ancestry remain separate requirements.
pub(crate) struct OriginalInitial15ArchivedGroup {
    process: u32,
    thread: ThreadId,
    parent_index: Option<ContentRef>,
    parent_manifest: Option<ContentRef>,
    // Provenance, plan, descriptor/contracts/fixtures, coordinator, runtime,
    // scheduler and administrative DOMs remain owned through later refusal.
    values: [Option<Value>; 9],
    collecting: Option<crate::node_state::CollectingCompleteCaptureProvenance>,
    coordinator: Option<declaration::Initial15Coordinator>,
    runtime: Option<OriginalLineageRuntimeRecord>,
    scheduling: Option<SchedulingSnapshot>,
    administrative: Option<RuntimeOriginalCaptureJournal>,
    launches: [Option<PacketNative5SourceLaunch>; 3],
    storage: [Option<PacketNative5StorageSelection>; 3],
    caps: [Option<OriginalSemanticCaps>; 3],
    protocols: [Initial15DecodedOwner; 3],
    semantics: [Initial15SemanticAttempt; 3],
    maximum: usize,
    verified: bool,
}

/// Borrows one exact completed initial15 source without a live conversion.
pub(crate) struct OriginalInitial15ArchivedOwnerRead<'a> {
    group: &'a OriginalInitial15ArchivedGroup,
    index: usize,
}

/// Lends original selection fields only while the real parent scope is alive.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct OriginalInitial15ArchivedSelection<
    'a,
> {
    scope: &'a ParentArchive17ReadScope<'a, 'a>,
    launch: &'a PacketNative5SourceLaunch,
    storage: &'a PacketNative5StorageSelection,
    caps: OriginalSemanticCaps,
}

impl OriginalInitial15ArchivedSelection<'_> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_origin_data(
        &self,
    ) -> Result<(), OperationFailure> {
        let manifest = self.scope.manifest_data().map_err(unknown)?;
        if self.launch.selection.world != manifest.world_binding_hash {
            return Err(refused(
                "initial15 selection belongs to another original world",
            ));
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn node_data(&self) -> &Id {
        // The defining declaration pass requires exactly one descriptor before
        // this private view is constructed; callers cannot construct it.
        &self.launch.selection.realize.requested_node_ids[0]
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn reactive_definition_data(
        &self,
    ) -> Option<&PacketConnectedDefinition> {
        match &self.launch.program {
            PacketConnectedSourceProgram::Producer { .. } => None,
            PacketConnectedSourceProgram::Reactive { program } => Some(program),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn storage_data(
        &self,
    ) -> &PacketNative5StorageSelection {
        self.storage
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn maximum_authorization_bytes_data(
        &self,
    ) -> usize {
        self.caps.authorization
    }
}

impl OriginalInitial15ArchivedGroup {
    /// Retains all three original owners before reconstructing any protocol graph.
    ///
    /// `additional` includes every other retained collector/factory owner. The
    /// actual original content bank is independently counted by the scope. No
    /// configured fresh installation can provide missing historical limits.
    ///
    /// # Errors
    /// Refuses spent output, missing signed declaration roles, incompatible
    /// original classes, malformed protocol/native/common data or finite credit.
    /// All initialized products remain owned in `output` after refusal.
    pub(crate) fn read_into(
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        output: &mut Option<Self>,
    ) -> Result<(), OperationFailure> {
        Self::read_into_data(scope, additional, output, None)
    }

    /// Reads the genuine original group under this writer's concrete phase ledger.
    ///
    /// `terminal_prior_cache` is the caller's already measured complete cache,
    /// including this inline output slot. The returned total adds only actual
    /// new backing; original limits and spent phases are never renewed.
    ///
    /// # Errors
    /// Refuses a spent slot or phase, malformed original declaration/protocol,
    /// changed source closure, any defining state predicate or finite credit.
    /// Every initialized partial remains owned by `output` after refusal.
    pub(crate) fn read_into_with_terminal_data(
        scope: &ParentArchive17ReadScope<'_, '_>,
        current: &crate::node_state::CompleteRestoredSettledArchiveValidation<'_>,
        source_index: crate::node_state::RestoredArchive17SourceIndex,
        parent_depth: usize,
        terminal_prior_cache: usize,
        additional: usize,
        output: &mut Option<Self>,
    ) -> Result<usize, OperationFailure> {
        let terminal = Initial15Terminal17::new_data(
            current,
            scope,
            source_index,
            parent_depth,
            terminal_prior_cache,
        )?;
        Self::read_into_data(scope, additional, output, Some(&terminal))?;
        terminal.completed_cache_data()
    }

    /// Reports the actual constructor cursor, borrowed plans and fixed visitors.
    ///
    /// The enclosing caller admits this fixed workspace before entering the
    /// terminal reader. This DATA getter performs no parse or source operation.
    pub(crate) fn terminal_counter_scratch_data() -> usize {
        Initial15Terminal17::counter_scratch_data()
    }

    fn read_into_data(
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        output: &mut Option<Self>,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
    ) -> Result<(), OperationFailure> {
        if let Some(terminal) = terminal {
            terminal.begin_data(crate::node_state::RestoredArchive17Initial15Work::Header, 0)?;
        }
        let limits = scope.limits_data().map_err(unknown)?;
        // Nested decoders obey the collector's content and record ceilings
        // before allocating, rather than relying on a later whole-row check.
        let maximum = usize::try_from(limits.state.maximum_native_memory_bytes)
            .map_err(unknown)?
            .min(usize::try_from(limits.state.maximum_total_content_bytes).map_err(unknown)?)
            .min(usize::try_from(limits.native.maximum_total_record_bytes).map_err(unknown)?)
            .min(MAXIMUM_WHOLE_BYTES);
        if output.is_some() {
            return Err(refused("initial15 owning attempt already exists"));
        }
        let manifest = scope.manifest_data().map_err(unknown)?;
        if manifest.preservation_contract.as_str()
            != "source-owned.packet-complete-original-lineage/5"
            || manifest.coordinator_state_ref.media_type
                != crate::node_state::ORIGINAL_LINEAGE_COORDINATOR_MEDIA
        {
            return Err(refused(
                "initial15 manifest selects another preservation family",
            ));
        }
        checked_sum(
            [
                additional,
                scope
                    .retained_content_requested_storage_data()
                    .map_err(unknown)?,
                size_of::<Self>(),
                Self::counter_scratch_data(),
                NodeRuntime::capture_reference_storage(
                    scope.index_reference_data().map_err(unknown)?,
                )
                .map_err(unknown)?,
                NodeRuntime::capture_reference_storage(
                    scope.manifest_reference_data().map_err(unknown)?,
                )
                .map_err(unknown)?,
            ],
            maximum,
        )?;
        if let Some(terminal) = terminal {
            let references = checked_sum(
                [
                    NodeRuntime::capture_reference_storage(
                        scope.index_reference_data().map_err(unknown)?,
                    )
                    .map_err(unknown)?,
                    NodeRuntime::capture_reference_storage(
                        scope.manifest_reference_data().map_err(unknown)?,
                    )
                    .map_err(unknown)?,
                ],
                maximum,
            )?;
            terminal.construct_data(references, 0)?;
        }
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            parent_index: None,
            parent_manifest: None,
            values: std::array::from_fn(|_| None),
            collecting: None,
            coordinator: None,
            runtime: None,
            scheduling: None,
            administrative: None,
            launches: std::array::from_fn(|_| None),
            storage: std::array::from_fn(|_| None),
            caps: std::array::from_fn(|_| None),
            protocols: std::array::from_fn(|_| Initial15DecodedOwner::new_data()),
            semantics: std::array::from_fn(|_| Initial15SemanticAttempt::new_data()),
            maximum,
            verified: false,
        });
        let group = output
            .as_mut()
            .ok_or_else(|| refused("initial15 attempt absent"))?;
        group.parent_index = Some(scope.index_reference_data().map_err(unknown)?.clone());
        group.parent_manifest = Some(scope.manifest_reference_data().map_err(unknown)?.clone());
        scope.manifest_data().map_err(unknown)?;
        if let Some(terminal) = terminal {
            terminal.finish_data(group, 0)?;
        }
        group.read_declarations_data(scope, additional, terminal)?;
        group.reconstruct_protocols_data(scope, additional, terminal)?;
        group.authenticate_semantics_data(scope, additional, terminal)?;
        if terminal.is_none() {
            group.admit_data(scope, additional, 0)?;
        }
        scope.manifest_data().map_err(unknown)?;
        group.verified = true;
        Ok(())
    }

    fn reconstruct_protocols_data(
        &mut self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
    ) -> Result<(), OperationFailure> {
        let limits = scope.limits_data().map_err(unknown)?;
        if let Some(terminal) = terminal {
            terminal.begin_data(
                crate::node_state::RestoredArchive17Initial15Work::ProtocolJournal(
                    crate::node_state::RestoredArchive17SourceIndex::from_data(0)
                        .map_err(unknown)?,
                ),
                0,
            )?;
        }
        // The guard moves every initialized private shared decoder field into
        // the final owning slots on both normal return and early refusal.
        let retained = self.retained_requested_storage_data(self.maximum)?;
        let terminal_base = retained
            .checked_sub(size_of::<Self>())
            .ok_or_else(|| refused("initial15 protocol root census overflow"))?;
        let mut staging = Initial15DecodeStaging::new_data(&mut self.protocols);
        let mut prepared = checked_sum(
            [additional, retained, Self::counter_scratch_data()],
            self.maximum,
        )?;
        for index in 0..3 {
            let launch = self.launches[index]
                .as_ref()
                .ok_or_else(|| refused("initial15 launch absent"))?;
            let descriptor = launch
                .selection
                .realization
                .descriptors
                .first()
                .ok_or_else(|| refused("initial15 node absent"))?;
            let owner = scope
                .selected_initial15_owner_data(
                    &descriptor.id,
                    &launch.selection.provider.implementation.implementation_id,
                )
                .map_err(unknown)?;
            let runtime = self
                .runtime
                .as_ref()
                .ok_or_else(|| refused("initial15 runtime absent"))?;
            let runtime_ref = &self
                .coordinator
                .as_ref()
                .ok_or_else(|| refused("initial15 coordinator absent"))?
                .runtime;
            let journal_ref = declaration::settlement_reference_data(
                self.administrative
                    .as_ref()
                    .ok_or_else(|| refused("initial15 administrative absent"))?,
                &owner.owner,
            )?;
            // All four aliases are priced from actual archived row populations.
            // Unused live parser-bank capacity never becomes semantic allowance.
            let journal_bytes = scope.body_data(journal_ref).map_err(unknown)?;
            let source_index = crate::node_state::RestoredArchive17SourceIndex::from_data(index)
                .map_err(unknown)?;
            if index != 0 {
                if let Some(terminal) = terminal {
                    terminal.begin_data(
                        crate::node_state::RestoredArchive17Initial15Work::ProtocolJournal(
                            source_index,
                        ),
                        0,
                    )?;
                }
            }
            let journal_transient = NodeRuntime::capture_selected_json_decode_storage(
                journal_bytes,
                size_of::<PacketCompleteSettledJournal>(),
                NodeRuntime::capture_map_node_storage::<String, Value>(),
                self.maximum,
            )
            .map_err(unknown)?
            .checked_mul(3)
            .ok_or_else(|| refused("initial15 temporary journal extent overflow"))?;
            checked_sum(
                [
                    prepared,
                    scope
                        .retained_content_requested_storage_data()
                        .map_err(unknown)?,
                    journal_transient,
                ],
                self.maximum,
            )?;
            if let Some(terminal) = terminal {
                terminal.construct_data(journal_transient, journal_transient)?;
            }
            let journal = PacketCompleteSettledJournal::decode_data(
                journal_bytes,
                limits.state.maximum_record_bytes,
            )?;
            if let Some(terminal) = terminal {
                terminal.finish_protocol_data(
                    terminal_base,
                    &staging.slots,
                    Some(&journal),
                    self.maximum,
                )?;
                terminal.begin_data(
                    crate::node_state::RestoredArchive17Initial15Work::ProtocolPrepare(
                        source_index,
                    ),
                    20,
                )?;
            }
            let profile = &launch.capture_profile;
            let metadata = launch
                .protocol_metadata_limits
                .ok_or_else(|| refused("initial15 native metadata selection absent"))?;
            let maximum = self.maximum;
            let host_rows = declaration::metadata_rows_data(
                scope.body_data(&journal.host_protocol).map_err(unknown)?,
                maximum,
            )?;
            let registry_ref = journal.require_complete_registry_data()?;
            let registry_bytes = scope.body_data(registry_ref).map_err(unknown)?;
            let registry_rows = declaration::metadata_rows_data(registry_bytes, maximum)?;
            let host_limits = decoder_limits(
                profile.host_bytes(&launch.storage),
                host_rows,
                limits,
                maximum,
            )?;
            let native_limits = decoder_limits(
                profile.native_after_bytes(&launch.storage),
                usize::try_from(metadata.native_after_rows.get()).map_err(unknown)?,
                limits,
                maximum,
            )?;
            let before_limits = decoder_limits(
                profile.native_before_bytes(&launch.storage),
                usize::try_from(metadata.native_before_rows.get()).map_err(unknown)?,
                limits,
                maximum,
            )?;
            let registry_limits = decoder_limits(
                U64::new(u64::try_from(registry_bytes.len()).map_err(unknown)?),
                registry_rows,
                limits,
                maximum,
            )?;
            // The temporary full journal is independent of the shared decoder's
            // retained journal and therefore receives its own construction row.

            checked_sum(
                [
                    prepared,
                    scope
                        .retained_content_requested_storage_data()
                        .map_err(unknown)?,
                    journal_transient,
                ],
                maximum,
            )?;
            if let Some(terminal) = terminal {
                let (growth, transient, scratch) = protocol_prepare_terminal_storage_data(
                    scope,
                    &journal,
                    journal_bytes,
                    launch,
                    owner,
                    host_limits,
                    native_limits,
                    before_limits,
                    registry_limits,
                    maximum,
                )?;
                terminal.construct_with_scratch_data(growth, transient, scratch)?;
            }
            PacketCompleteArchivedOwnerData::prepare_data_into(
                None,
                CompleteNativeSnapshotClass::InvocationCapture15,
                &launch.selection.provider.implementation,
                owner,
                runtime,
                runtime_ref,
                ArchivedContentData::Parent(scope),
                journal_ref,
                limits,
                checked_sum([prepared, journal_transient], maximum)?,
                host_limits,
                native_limits,
                before_limits,
                registry_limits,
                maximum,
                &mut staging.slots[index],
            )?;
            drop(journal);
            prepared = checked_sum(
                [
                    prepared,
                    staging.slots[index]
                        .as_ref()
                        .ok_or_else(|| refused("initial15 decoder absent"))?
                        .retained_data_bank_bytes()?,
                ],
                maximum,
            )?;
            if let Some(terminal) = terminal {
                terminal.finish_protocol_data(terminal_base, &staging.slots, None, maximum)?;
            }
        }
        PacketCompleteArchivedOwnerData::reconstruct_group_with_terminal_data(
            &mut staging.slots,
            checked_sum(
                [additional, retained, Self::counter_scratch_data()],
                self.maximum,
            )?,
            terminal,
            terminal_base,
        )?;
        Ok(())
    }

    fn authenticate_semantics_data(
        &mut self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
    ) -> Result<(), OperationFailure> {
        let limits = scope.limits_data().map_err(unknown)?;
        for index in 0..3 {
            let source_index = crate::node_state::RestoredArchive17SourceIndex::from_data(index)
                .map_err(unknown)?;
            if let Some(terminal) = terminal {
                terminal.begin_data(
                    crate::node_state::RestoredArchive17Initial15Work::SemanticDecode(source_index),
                    0,
                )?;
            }
            let retained = self.retained_requested_storage_data(self.maximum)?;
            let protocol = &self.protocols[index];
            let journal = protocol.journal_data()?;
            let semantic = scope.body_data(&journal.semantic).map_err(unknown)?;
            let ancestry = scope.body_data(&journal.ancestry).map_err(unknown)?;
            if let Some(terminal) = terminal {
                let demand = PacketCompleteArchivedSemantics::decode_demand_data(
                    semantic,
                    ancestry,
                    limits.state.maximum_record_bytes,
                    self.maximum,
                )?
                .checked_mul(2)
                .ok_or_else(|| refused("initial15 semantic terminal extent overflow"))?;
                terminal.construct_data(demand, demand)?;
            }
            self.semantics[index].read_data(
                semantic,
                ancestry,
                limits.state.maximum_record_bytes,
                checked_sum(
                    [
                        additional,
                        retained,
                        scope
                            .retained_content_requested_storage_data()
                            .map_err(unknown)?,
                        Self::counter_scratch_data(),
                    ],
                    self.maximum,
                )?,
                self.maximum,
            )?;
            if let Some(terminal) = terminal {
                terminal.finish_data(self, 0)?;
                let launch = self.launches[index]
                    .as_ref()
                    .ok_or_else(|| refused("initial15 semantic launch absent"))?;
                let (launch_formatter, quote_scratch) = launch
                    .validation_construction_projection_storage_data()
                    .map_err(unknown)?;
                let formatter = PacketCompleteArchivedSemantics::runtime_protocol_terminal_quote_transient_data()
                    .max(launch_formatter);
                terminal.begin_with_scratch_data(
                    crate::node_state::RestoredArchive17Initial15Work::SemanticJoin(source_index),
                    formatter,
                    quote_scratch,
                )?;
                let (transient, scratch) =
                    self.semantic_join_terminal_transient_data(scope, index)?;
                terminal.construct_with_scratch_data(0, transient, scratch)?;
            }
            let semantics = self.semantics[index].read_data_ref()?;
            let launch = self.launches[index]
                .as_ref()
                .ok_or_else(|| refused("initial15 launch absent"))?;
            let selection = OriginalInitial15ArchivedSelection {
                scope,
                launch,
                storage: self.storage[index]
                    .as_ref()
                    .ok_or_else(|| refused("initial15 storage absent"))?,
                caps: self.caps[index].ok_or_else(|| refused("initial15 original caps absent"))?,
            };
            let retained = checked_sum(
                [
                    additional,
                    self.retained_requested_storage_data(self.maximum)?,
                    scope
                        .retained_content_requested_storage_data()
                        .map_err(unknown)?,
                    Self::counter_scratch_data(),
                ],
                self.maximum,
            )?;
            semantics.authenticate_runtime_from_content_data(
                selection.node_data(),
                self.runtime
                    .as_ref()
                    .ok_or_else(|| refused("initial15 runtime absent"))?,
                ArchivedContentData::Parent(scope),
                limits.state.maximum_record_bytes,
                retained,
                self.maximum,
                None,
            )?;
            semantics.authenticate_protocol_data(
                protocol.host_data()?.historical().map_err(unknown)?,
                retained,
                self.maximum,
            )?;
            let data = NativeInputData {
                selection: NativeInputSelection::Archived(&selection),
                host: protocol.host_data()?.historical().map_err(unknown)?,
                native: protocol
                    .native_after_data()?
                    .historical()
                    .map_err(unknown)?,
                content: ArchivedContentData::Parent(scope),
                retained,
                maximum: self.maximum,
                scratch: Cell::new(0),
                construction: None,
            };
            data.authenticate_input_history_data(semantics)?;
            data.authenticate_semantic_history_data(journal, semantics)?;
            data.capture_boundary_data(journal)?;
            self.admit_serialization_data(scope, additional, launch)?;
            declaration::authenticate_original_native_selection_data(&selection, protocol)?;
            declaration::authenticate_original_caps_data(semantics, selection.caps)?;
            self.admit_data(scope, additional, 0)?;
            scope.manifest_data().map_err(unknown)?;
            if let Some(terminal) = terminal {
                terminal.finish_data(self, 0)?;
            }
        }
        Ok(())
    }

    fn authenticate_origin_data(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused(
                "initial15 historical owner belongs to another actor",
            ));
        }
        Ok(())
    }

    /// Lends one exact verified source by its original archived logical node ID.
    ///
    /// # Errors
    /// Refuses a foreign actor, incomplete group, missing or ambiguous source.
    pub(crate) fn owner_data(
        &self,
        node: &Id,
    ) -> Result<OriginalInitial15ArchivedOwnerRead<'_>, OperationFailure> {
        self.authenticate_origin_data()?;
        if !self.verified {
            return Err(refused("initial15 base group is incomplete"));
        }
        let mut selected = None;
        for (index, launch) in self.launches.iter().enumerate() {
            let launch = launch
                .as_ref()
                .ok_or_else(|| refused("initial15 launch absent"))?;
            if launch.selection.realize.requested_node_ids.as_slice() == std::slice::from_ref(node)
            {
                if selected.replace(index).is_some() {
                    return Err(refused("initial15 logical node ambiguous"));
                }
            }
        }
        Ok(OriginalInitial15ArchivedOwnerRead {
            group: self,
            index: selected.ok_or_else(|| refused("initial15 logical node absent"))?,
        })
    }
}

impl OriginalInitial15ArchivedOwnerRead<'_> {
    fn authenticate_data(&self) -> Result<(), OperationFailure> {
        self.group.authenticate_origin_data()?;
        if !self.group.verified || self.index >= 3 {
            return Err(refused("initial15 borrowed base incomplete"));
        }
        Ok(())
    }

    /// Borrows the exact original parent Index and manifest fullrefs, in that order.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn parent_references_data(
        &self,
    ) -> Result<(&ContentRef, &ContentRef), OperationFailure> {
        self.authenticate_data()?;
        Ok((
            self.group
                .parent_index
                .as_ref()
                .ok_or_else(|| refused("initial15 parent Index absent"))?,
            self.group
                .parent_manifest
                .as_ref()
                .ok_or_else(|| refused("initial15 parent manifest absent"))?,
        ))
    }

    /// Borrows the exact semantic5 fullref and its strictly read historical custody.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn semantic_data(
        &self,
    ) -> Result<(&ContentRef, &PacketCompleteArchivedSemantics), OperationFailure> {
        self.authenticate_data()?;
        Ok((
            &self.group.protocols[self.index].journal_data()?.semantic,
            self.group.semantics[self.index].read_data_ref()?,
        ))
    }

    /// Reports original operations, result, authorization and semantic ceilings, in that order.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn original_semantic_caps_data(
        &self,
    ) -> Result<(usize, usize, usize, usize), OperationFailure> {
        self.authenticate_data()?;
        let caps = self.group.caps[self.index].ok_or_else(|| refused("initial15 caps absent"))?;
        Ok((
            caps.operations,
            caps.result,
            caps.authorization,
            caps.semantic,
        ))
    }

    /// Borrows the same original sealed Host, Native before, Native after and Registry.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn native_owners_data(
        &self,
    ) -> Result<
        (
            &SealedHistoricalControllerState,
            &SealedHistoricalNativeState,
            &SealedHistoricalNativeState,
            &SealedHistoricalHostExtensionRegistry,
        ),
        OperationFailure,
    > {
        self.authenticate_data()?;
        let state = &self.group.protocols[self.index];
        Ok((
            state.host_data()?,
            state.native_before_data()?,
            state.native_after_data()?,
            state.registry_data()?,
        ))
    }

    /// Borrows the original complete Scheduler1 DATA for this same parent Runtime7.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn original_scheduling_data(&self) -> Result<&SchedulingSnapshot, OperationFailure> {
        self.authenticate_data()?;
        self.group
            .scheduling
            .as_ref()
            .ok_or_else(|| refused("initial15 scheduling absent"))
    }

    /// Borrows the exact original source-local completed Capture settlement journal.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn journal_data(&self) -> Result<&PacketCompleteSettledJournal, OperationFailure> {
        self.authenticate_data()?;
        self.group.protocols[self.index].journal_data()
    }

    /// Borrows the original complete Runtime7 DATA without issuing runtime authority.
    ///
    /// # Errors
    /// Refuses a foreign actor or an incomplete original base/owner.
    pub(crate) fn original_runtime_data(
        &self,
    ) -> Result<&OriginalLineageRuntimeRecord, OperationFailure> {
        self.authenticate_data()?;
        self.group
            .runtime
            .as_ref()
            .ok_or_else(|| refused("initial15 runtime absent"))
    }
}
