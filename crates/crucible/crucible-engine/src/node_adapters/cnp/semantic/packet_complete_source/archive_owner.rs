//! Precharges all three cold archive owners before any protocol reconstruction.
//!
//! The actual installed factory calls this before Core issues source tickets.
//! It borrows the authenticated content closure and retains separate encoded,
//! alias and historical result slots. No old live Source or decoded authority is
//! used. Root's semantic/ancestry predicate and full Core admission remain
//! mandatory after this exact journal/protocol data check.

use super::*;
use crate::node_state::{NativeArchiveLimits, NativeOwnerState, VerifiedStateContent};
use crucible_node_transport::{
    client::{compact_cursor::CompactContentLimits, compact_metadata8::CompactMetadata8Limits},
    protocol_snapshot::owned11::{
        aliases::HistoricalAliasSummary,
        json_value::HistoricalJsonLimits,
        native::outer::{
            HistoricalNativeState, SealedHistoricalNativeState, ValidatedNativeOwnedProtocol11,
        },
        outer::{
            HistoricalControllerState, OwnedProtocol11AllocationDemand, OwnedProtocol11DataLimits,
            SealedHistoricalControllerState, ValidatedOwnedProtocol11,
        },
    },
};
use std::{mem::size_of, thread::ThreadId};

#[path = "archive_owner/content.rs"]
mod content;
pub(super) use content::ArchivedContentData;

#[path = "archive_owner/initial15.rs"]
pub(super) mod initial15;
pub(crate) use initial15::{OriginalInitial15ArchivedGroup, OriginalInitial15ArchivedOwnerRead};

const MAXIMUM_WHOLE_BYTES: usize = 512 * 1024 * 1024;

#[path = "archive_owner/registry.rs"]
mod registry;
#[path = "archive_owner/snapshot.rs"]
mod snapshot;
use crucible_node_transport::protocol_snapshot::owned11::host_registry::SealedHistoricalHostExtensionRegistry;
pub(super) use snapshot::{CompleteNativeSnapshotClass, CompleteSnapshotPlan};

#[path = "archive_owner/retained.rs"]
mod retained;
#[path = "archive_owner/settled.rs"]
mod settled;
pub(crate) use retained::{
    OriginalInitial15FutureControlAttempt, OriginalInitial15FutureControlConstructionData,
    OriginalInitial15FutureControlLoan, OriginalRestorationColdGroup,
    OriginalRestorationColdOwnerView,
};
pub use settled::CompleteHistoricalArchiveFamily;
pub(crate) use settled::{
    OriginalCompleteHistoricalColdGroup, OriginalRestoredSettledColdGroup,
    OriginalRestoredSettledColdOwnerMetadata, OriginalRestoredSettledColdOwnerView,
};

/// Retains one bounded owner linked to the actual immutable archive closure.
///
/// Preparation does not construct a historical protocol graph. The fixed-three
/// group method validates every demand and their simultaneous aggregate first.
/// Parsed historical data remains inert after reconstruction; the actual factory
/// separately checks full semantics/ancestry and admits the signed Core source.
pub struct PacketCompleteArchivedOwnerData<'a> {
    process: u32,
    thread: ThreadId,
    source: Option<&'a PacketCompleteSemanticSource>,
    snapshot_class: CompleteNativeSnapshotClass,
    owner: &'a NativeOwnerState,
    content: ArchivedContentData<'a>,
    journal_reference: &'a ContentRef,
    journal: Option<PacketCompleteSettledJournal>,
    host_limits: OwnedProtocol11DataLimits,
    native_limits: OwnedProtocol11DataLimits,
    before_limits: OwnedProtocol11DataLimits,
    registry_limits: OwnedProtocol11DataLimits,
    maximum: usize,
    journal_storage: usize,
    host_aliases: Vec<HistoricalAliasSummary>,
    native_aliases: Vec<HistoricalAliasSummary>,
    before_aliases: Vec<HistoricalAliasSummary>,
    registry_aliases: Vec<HistoricalAliasSummary>,
    before_reference: Option<ContentRef>,
    before_raw: Vec<u8>,
    before_encoded: Option<Vec<u8>>,
    before: Option<SealedHistoricalNativeState>,
    host_encoded: Option<Vec<u8>>,
    native_encoded: Option<Vec<u8>>,
    registry_encoded: Option<Vec<u8>>,
    registry: Option<SealedHistoricalHostExtensionRegistry>,
    host: Option<SealedHistoricalControllerState>,
    native: Option<SealedHistoricalNativeState>,
    known_requested: Option<usize>,
    native_restoration_demand: Option<crucible_node_transport::protocol_snapshot::owned11::native::outer::NativeOwnedProtocol11AllocationDemand>,
    attempted: bool,
    failed: bool,
}

impl PacketCompleteSemanticSource {
    /// Prepares actual bounded cold protocol banks without a Core ticket cycle.
    ///
    /// The caller retains the exact selected archive/content and all fixed-three
    /// output slots. `additional_retained_bytes` covers the actual factory,
    /// scheduling/Host owner and other live banks; this method separately counts
    /// the same Core content closure. No typed protocol graph is allocated yet.
    ///
    /// # Errors
    /// Refuses a foreign source, unmatched installed owner/backend/profile,
    /// missing born banks, ambiguous journal, invalid signed roles or insufficient
    /// simultaneous credit. Partial banks stay in the destination on refusal.
    #[expect(
        clippy::too_many_arguments,
        reason = "borrows distinct actual archive roles without a portable permission bundle"
    )]
    pub fn prepare_complete_archived_owner_data_into<'a>(
        &'a self,
        owner: &'a NativeOwnerState,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_reference: &ContentRef,
        content: &'a VerifiedStateContent,
        journal_reference: &'a ContentRef,
        limits: NativeArchiveLimits,
        additional_retained_bytes: usize,
        completed: &mut Option<PacketCompleteArchivedOwnerData<'a>>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if completed.is_some() {
            return Err(refused("cold archive owner slot occupied"));
        }
        let installation = self.installation();
        let profile = self.selected_capture_profile()?;
        let snapshot_class = self.selected_complete_native_snapshot_class()?;
        if owner.owner != installation.owner.owner.id
            || owner.participants != installation.owner.owner.participant_ids
            || owner.key.implementation != installation.provider.implementation.implementation_id
            || owner.key.profile.as_str() != "source-owned.packet-complete-original-lineage/5"
            || owner.key.schema != snapshot_class.schema()?
            || snapshot_class.has_allocation()
                && (!installation
                    .provider
                    .implementation
                    .formats
                    .contains(&owner.key.schema)
                    || !installation
                        .binding
                        .compatibility
                        .implementation
                        .formats
                        .contains(&owner.key.schema))
            || !matches!(profile, PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            || !owner.evidence.contains(journal_reference)
        {
            return Err(refused(
                "cold archive owner differs from installed complete source",
            ));
        }
        let metadata = self
            .selected_protocol_metadata_limits()?
            .ok_or_else(|| refused("cold native metadata selection absent"))?;
        let selected = self.selected_storage_selection()?;
        let host_rows = {
            let banks = self
                .capture_banks
                .try_borrow()
                .map_err(|_| refused("cold host bank is busy"))?;
            let banks = banks
                .as_ref()
                .ok_or_else(|| refused("cold host born banks absent"))?;
            let facts = if let Some(reservation) = banks.protocol.as_ref() {
                reservation
                    .original_metadata_record_allocation_facts()
                    .map_err(unknown)?
            } else if let Some(snapshot) = banks.settled_protocol.as_ref() {
                snapshot
                    .original_metadata_record_allocation_facts()
                    .map_err(unknown)?
            } else if let Some((payload, _)) = banks.protocol_payload.as_ref() {
                payload
                    .original_metadata_record_allocation_facts()
                    .map_err(unknown)?
            } else {
                return Err(refused("cold host physical metadata owner absent"));
            };
            facts
                .ok_or_else(|| refused("cold host metadata bank absent"))?
                .maximum_rows
        };
        let maximum = usize::try_from(limits.state.maximum_native_memory_bytes)
            .map_err(|_| refused("cold archive whole limit unrepresentable"))?
            .min(MAXIMUM_WHOLE_BYTES);
        let host_limits = decoder_limits(
            profile.host_bytes(&selected.storage),
            host_rows,
            limits,
            maximum,
        )?;
        let native_limits = decoder_limits(
            profile.native_after_bytes(&selected.storage),
            usize::try_from(metadata.native_after_rows.get()).map_err(unknown)?,
            limits,
            maximum,
        )?;
        let before_limits = decoder_limits(
            profile.native_before_bytes(&selected.storage),
            usize::try_from(metadata.native_before_rows.get()).map_err(unknown)?,
            limits,
            maximum,
        )?;
        let (registry_maximum, registry_rows) = self.original_registry_decoder_selection_data()?;
        let registry_limits = decoder_limits(
            U64::new(u64::try_from(registry_maximum).map_err(unknown)?),
            registry_rows,
            limits,
            maximum,
        )?;
        PacketCompleteArchivedOwnerData::prepare_data_into(
            Some(self),
            snapshot_class,
            &installation.provider.implementation,
            owner,
            runtime,
            runtime_reference,
            ArchivedContentData::Verified(content),
            journal_reference,
            limits,
            additional_retained_bytes,
            host_limits,
            native_limits,
            before_limits,
            registry_limits,
            maximum,
            completed,
        )
    }
}

impl<'a> PacketCompleteArchivedOwnerData<'a> {
    fn prepare_data_into(
        source: Option<&'a PacketCompleteSemanticSource>,
        snapshot_class: CompleteNativeSnapshotClass,
        implementation: &ImplementationIdentity,
        owner: &'a NativeOwnerState,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_reference: &ContentRef,
        content: ArchivedContentData<'a>,
        journal_reference: &'a ContentRef,
        limits: NativeArchiveLimits,
        additional_retained_bytes: usize,
        host_limits: OwnedProtocol11DataLimits,
        native_limits: OwnedProtocol11DataLimits,
        before_limits: OwnedProtocol11DataLimits,
        registry_limits: OwnedProtocol11DataLimits,
        maximum: usize,
        completed: &mut Option<Self>,
    ) -> Result<(), OperationFailure> {
        if completed.is_some() {
            return Err(refused("cold archive owner slot occupied"));
        }
        let journal_bytes = content
            .get(journal_reference)
            .ok_or_else(|| refused("cold signed journal body absent"))?;
        journal_reference.verify(journal_bytes).map_err(unknown)?;
        if journal_bytes.len() > limits.state.maximum_record_bytes {
            return Err(refused("cold signed journal exceeds record bound"));
        }
        // Reuse the defining combined parser/tree/string/vector allowance.
        // Complete protocol plans use the separate borrowed SDK walkers below.
        let journal_storage =
            PacketCompleteSettledJournal::decode_construction_storage_data(journal_bytes)?;
        checked_sum(
            [
                additional_retained_bytes,
                content.capture_owned_storage()?,
                size_of::<PacketCompleteArchivedOwnerData<'_>>(),
                journal_storage,
            ],
            maximum,
        )?;

        *completed = Some(PacketCompleteArchivedOwnerData {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source,
            snapshot_class,
            owner,
            content,
            journal_reference,
            journal: None,
            host_limits,
            native_limits,
            before_limits,
            registry_limits,
            maximum,
            journal_storage,
            host_aliases: Vec::new(),
            native_aliases: Vec::new(),
            before_aliases: Vec::new(),
            registry_aliases: Vec::new(),
            before_reference: None,
            before_raw: Vec::new(),
            before_encoded: Some(Vec::new()),
            before: None,
            host_encoded: Some(Vec::new()),
            native_encoded: Some(Vec::new()),
            registry_encoded: Some(Vec::new()),
            registry: None,
            host: None,
            native: None,
            known_requested: None,
            native_restoration_demand: None,
            attempted: false,
            failed: false,
        });
        let state = completed
            .as_mut()
            .ok_or_else(|| refused("cold owner slot absent"))?;
        let result = (|| {
            state.journal = Some(PacketCompleteSettledJournal::decode_data(
                journal_bytes,
                limits.state.maximum_record_bytes,
            )?);
            let journal = state
                .journal
                .as_ref()
                .ok_or_else(|| refused("cold journal lost"))?;
            journal.authenticate_owner_from_content_data(
                owner,
                runtime,
                runtime_reference,
                content,
            )?;
            journal.authenticate_backend_from_content_data(implementation, &owner.key, content)?;
            state.journal_storage = state
                .journal_storage
                .checked_add(
                    NodeRuntime::capture_future_decode_storage(journal, maximum)
                        .map_err(unknown)?,
                )
                .ok_or_else(|| refused("cold journal typed extent overflow"))?;
            let registry_reference = journal.require_complete_registry_data()?;
            let registry_bytes = content
                .get(registry_reference)
                .ok_or_else(|| refused("cold registry protocol absent"))?;
            registry_reference.verify(registry_bytes).map_err(unknown)?;
            if registry_bytes.len() > registry_limits.json.maximum_input_bytes {
                return Err(refused(
                    "cold registry exceeds original selected encoded bound",
                ));
            }
            let host_bytes = content
                .get(&journal.host_protocol)
                .ok_or_else(|| refused("cold host protocol absent"))?;
            let native_bytes = content
                .get(&journal.native_after_protocol)
                .ok_or_else(|| refused("cold native after protocol absent"))?;
            if host_bytes.len() > host_limits.json.maximum_input_bytes
                || native_bytes.len() > native_limits.json.maximum_input_bytes
            {
                return Err(refused(
                    "cold protocol body exceeds installed encoded selection",
                ));
            }
            let parser_layout = snapshot_parser_known_storage_for_class(snapshot_class, maximum)?;
            state.journal_storage = state
                .journal_storage
                .checked_add(parser_layout)
                .ok_or_else(|| refused("cold snapshot parser layout overflow"))?;
            checked_sum(
                [
                    additional_retained_bytes,
                    content.capture_owned_storage()?,
                    state.actual_banks()?,
                ],
                maximum,
            )?;
            let snapshot_bytes = content
                .get(&journal.native_snapshot)
                .ok_or_else(|| refused("cold native snapshot input absent"))?;
            let snapshot = snapshot_class
                .validate_snapshot(
                    snapshot_bytes,
                    limits.state.maximum_content_bytes,
                    before_limits.json.maximum_input_bytes,
                )
                .map_err(unknown)?;
            let before = snapshot.before();
            // The source stores this full reference in its slot, independent of
            // the complete SDK sealed owner constructed later. Its decoder's
            // typed/string/tree scratch is admitted before parsing the field.
            let reference_decode = NodeRuntime::capture_selected_json_decode_storage(
                before.reference_bytes(),
                size_of::<ContentRef>(),
                NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
                maximum,
            )
            .map_err(unknown)?;
            state.journal_storage = state
                .journal_storage
                .checked_add(reference_decode)
                .ok_or_else(|| refused("cold before reference decode extent overflow"))?;
            let aliases = host_limits
                .maximum_metadata_rows
                .checked_add(native_limits.maximum_metadata_rows)
                .and_then(|n| n.checked_add(before_limits.maximum_metadata_rows))
                .and_then(|n| n.checked_add(registry_limits.maximum_metadata_rows))
                .and_then(|n| n.checked_mul(size_of::<HistoricalAliasSummary>()))
                .ok_or_else(|| refused("cold alias initial extent overflow"))?;
            checked_sum(
                [
                    additional_retained_bytes,
                    content.capture_owned_storage()?,
                    size_of::<PacketCompleteArchivedOwnerData<'_>>(),
                    state.journal_storage,
                    aliases,
                    host_bytes.len(),
                    native_bytes.len(),
                    registry_bytes.len(),
                    before.original_capacity(),
                    before.encoded_length(),
                ],
                maximum,
            )?;
            state.before_reference =
                Some(serde_json::from_slice(before.reference_bytes()).map_err(unknown)?);
            state
                .before_aliases
                .try_reserve_exact(before_limits.maximum_metadata_rows)
                .map_err(unknown)?;
            state
                .before_raw
                .try_reserve_exact(before.original_capacity())
                .map_err(unknown)?;
            state
                .before_encoded
                .as_mut()
                .ok_or_else(|| refused("cold sealed before bank lost"))?
                .try_reserve_exact(before.encoded_length())
                .map_err(unknown)?;
            state
                .registry_aliases
                .try_reserve_exact(registry_limits.maximum_metadata_rows)
                .map_err(unknown)?;
            state
                .registry_encoded
                .as_mut()
                .ok_or_else(|| refused("cold registry bank lost"))?
                .try_reserve_exact(registry_bytes.len())
                .map_err(unknown)?;
            state
                .host_aliases
                .try_reserve_exact(host_limits.maximum_metadata_rows)
                .map_err(unknown)?;
            state
                .native_aliases
                .try_reserve_exact(native_limits.maximum_metadata_rows)
                .map_err(unknown)?;
            state
                .host_encoded
                .as_mut()
                .ok_or_else(|| refused("cold host bank lost"))?
                .try_reserve_exact(host_bytes.len())
                .map_err(unknown)?;
            state
                .native_encoded
                .as_mut()
                .ok_or_else(|| refused("cold native bank lost"))?
                .try_reserve_exact(native_bytes.len())
                .map_err(unknown)?;
            checked_sum(
                [
                    additional_retained_bytes,
                    content.capture_owned_storage()?,
                    state.actual_banks()?,
                ],
                maximum,
            )?;
            before
                .fill_preowned(&mut state.before_raw)
                .map_err(unknown)?;
            state.before_aliases.resize(
                before_limits.maximum_metadata_rows,
                HistoricalAliasSummary::default(),
            );
            state.host_aliases.resize(
                host_limits.maximum_metadata_rows,
                HistoricalAliasSummary::default(),
            );
            state.native_aliases.resize(
                native_limits.maximum_metadata_rows,
                HistoricalAliasSummary::default(),
            );
            state.registry_aliases.resize(
                registry_limits.maximum_metadata_rows,
                HistoricalAliasSummary::default(),
            );
            state.ensure_origin()
        })();
        if result.is_err() {
            state.failed = true;
        }
        result
    }
}

impl PacketCompleteArchivedOwnerData<'_> {
    /// Admits all three actual demands before reconstructing the first protocol.
    ///
    /// The same Core content allocation is charged once, with every separate
    /// source/result/alias bank charged in full. All completed and partial owners
    /// remain in their original slots on later failure.
    ///
    /// # Errors
    /// Refuses missing/repeated owners, changed content closure, malformed full
    /// classes, actual capacity excess, arithmetic overflow or reconstruction.
    pub fn reconstruct_group(
        owners: &mut [Option<Self>; 3],
        additional_retained_bytes: usize,
    ) -> Result<(), OperationFailure> {
        Self::reconstruct_group_with_terminal_data(owners, additional_retained_bytes, None, 0)
    }

    fn reconstruct_group_with_terminal_data(
        owners: &mut [Option<Self>; 3],
        additional_retained_bytes: usize,
        terminal: Option<&initial15::terminal::Initial15Terminal17<'_, '_>>,
        terminal_base_backing: usize,
    ) -> Result<(), OperationFailure> {
        if let Some(terminal) = terminal {
            // Demand walkers use preowned aliases; fullref verification owns one
            // temporary hash tuple before the aggregate construction is known.
            terminal.begin_data(
                crate::node_state::RestoredArchive17Initial15Work::ProtocolReconstruct,
                "blake3-256".len() + "cnp.blob.v1".len() + 64,
            )?;
        }
        let mut maximum = MAXIMUM_WHOLE_BYTES;
        let mut total = additional_retained_bytes;
        for (index, slot) in owners.iter().enumerate() {
            let owner = slot
                .as_ref()
                .ok_or_else(|| refused("cold fixed-three owner absent"))?;
            owner.ensure_origin()?;
            if owner.attempted
                || owner.failed
                || owner.host.is_some()
                || owner.native.is_some()
                || owner.before.is_some()
                || owner.registry.is_some()
            {
                return Err(refused("cold owner reconstruction spent"));
            }
            maximum = maximum.min(owner.maximum);
            if index == 0 {
                total = checked_sum([total, owner.content.capture_owned_storage()?], maximum)?;
            }
            for previous in &owners[..index] {
                let previous = previous
                    .as_ref()
                    .ok_or_else(|| refused("cold previous owner absent"))?;
                if !previous.content.same_data(owner.content)
                    || previous
                        .source
                        .zip(owner.source)
                        .is_some_and(|(left, right)| std::ptr::eq(left, right))
                    || previous.owner.owner == owner.owner.owner
                    || previous
                        .owner
                        .participants
                        .iter()
                        .any(|id| owner.owner.participants.contains(id))
                {
                    return Err(refused(
                        "cold group repeats owner/source or differs in content closure",
                    ));
                }
            }
        }
        let before_demands = total;
        // Every actual input/result slot is retained before the first validating
        // walker. No protocol reconstruction is reachable until all totals pass.
        for slot in owners.iter_mut() {
            let owner = slot
                .as_mut()
                .ok_or_else(|| refused("cold group owner lost"))?;
            owner.attempted = true;
            let result = owner.prepare_demand();
            if result.is_err() {
                owner.failed = true;
            }
            total = checked_sum([total, result?], maximum)?;
        }
        if let Some(terminal) = terminal {
            // The defining SDK demands include payload trees, validation scratch
            // and sealed result backing. Charge their full sum in both columns;
            // existing prepared banks are conservatively included again.
            let demanded = total
                .checked_sub(before_demands)
                .ok_or_else(|| refused("initial15 protocol demand accounting overflow"))?;
            terminal.construct_data(demanded, demanded)?;
        }
        for slot in owners.iter_mut() {
            let owner = slot
                .as_mut()
                .ok_or_else(|| refused("cold group owner lost"))?;
            let result = owner.reconstruct();
            if result.is_err() {
                owner.failed = true;
            }
            result?;
        }
        if let Some(terminal) = terminal {
            terminal.finish_protocol_data(terminal_base_backing, owners, None, maximum)?;
        }
        Ok(())
    }

    // Sibling source predicates borrow the same immutable archive closure. They
    // cannot substitute an equal public owner or an independently decoded graph.
    pub(super) fn source_content_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<&VerifiedStateContent, OperationFailure> {
        self.ensure_complete()?;
        if !self
            .source
            .is_some_and(|actual| std::ptr::eq(actual, source))
        {
            return Err(refused("cold native predicate belongs to another source"));
        }
        self.content.live_data()
    }

    /// Reports actual prepared banks before typed reconstruction begins.
    ///
    /// Fixed-three callers add every earlier prepared slot's returned storage to
    /// the next preparation's additional retained bytes. This is not a completed
    /// decode or source-authority predicate.
    ///
    /// # Errors
    /// Refuses foreign origin, a reconstruction attempt or layout overflow.
    pub fn retained_data_bank_bytes(&self) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        if self.attempted {
            return Err(refused(
                "cold prepared bank quote after reconstruction attempt",
            ));
        }
        self.actual_banks()
    }

    /// Borrows the complete historical native incoming-Capture owner.
    ///
    /// # Errors
    /// Refuses foreign custody, failed or incomplete predecessor reconstruction.
    pub fn sealed_native_before(&self) -> Result<&SealedHistoricalNativeState, OperationFailure> {
        self.ensure_complete()?;
        self.before
            .as_ref()
            .ok_or_else(|| refused("cold native before absent"))
    }

    /// Borrows the exact source-local journal after successful reconstruction.
    ///
    /// # Errors
    /// Refuses foreign custody, partial or failed data.
    pub fn journal(&self) -> Result<&PacketCompleteSettledJournal, OperationFailure> {
        self.ensure_complete()?;
        self.journal
            .as_ref()
            .ok_or_else(|| refused("cold journal absent"))
    }

    /// Borrows the complete historical host graph, never a live authority.
    ///
    /// # Errors
    /// Refuses foreign custody or incomplete/failed reconstruction.
    pub fn host(&self) -> Result<&HistoricalControllerState, OperationFailure> {
        self.ensure_complete()?;
        self.host
            .as_ref()
            .ok_or_else(|| refused("cold host absent"))?
            .historical()
            .map_err(unknown)
    }

    /// Borrows the complete historical native after graph, never a current peer.
    ///
    /// # Errors
    /// Refuses foreign custody or incomplete/failed reconstruction.
    pub fn native_after(&self) -> Result<&HistoricalNativeState, OperationFailure> {
        self.ensure_complete()?;
        self.native
            .as_ref()
            .ok_or_else(|| refused("cold native after absent"))?
            .historical()
            .map_err(unknown)
    }

    /// Borrows the full journal reference retained in the selected owner evidence.
    ///
    /// # Errors
    /// Refuses foreign custody, incomplete or failed reconstruction.
    pub fn journal_reference(&self) -> Result<&ContentRef, OperationFailure> {
        self.ensure_complete()?;
        Ok(self.journal_reference)
    }

    /// Reports admitted simultaneous requested layouts without a physical peak claim.
    ///
    /// # Errors
    /// Refuses foreign custody or a missing demand admission.
    pub fn known_requested_bytes(&self) -> Result<usize, OperationFailure> {
        self.ensure_complete()?;
        self.known_requested
            .ok_or_else(|| refused("cold owner demand absent"))
    }

    /// Borrows the exact decoder/body-linked host owner for mapping preparation.
    ///
    /// # Errors
    /// Refuses foreign custody or partial/failed historical reconstruction.
    pub fn sealed_host(&self) -> Result<&SealedHistoricalControllerState, OperationFailure> {
        self.ensure_complete()?;
        self.host
            .as_ref()
            .ok_or_else(|| refused("cold sealed host absent"))
    }

    /// Borrows the exact decoder/body-linked native after owner for mapping.
    ///
    /// # Errors
    /// Refuses foreign custody or partial/failed historical reconstruction.
    pub fn sealed_native_after(&self) -> Result<&SealedHistoricalNativeState, OperationFailure> {
        self.ensure_complete()?;
        self.native
            .as_ref()
            .ok_or_else(|| refused("cold sealed native absent"))
    }

    /// Returns actual native-after reconstruction demand after full cold checks.
    ///
    /// This fixed DATA row preserves the independently decoded native demand;
    /// it is neither the whole cold known_requested sum nor a native grant.
    /// The actual archive factory binds it to its original owner slot before
    /// these temporary historical decoder owners are released.
    ///
    /// # Errors
    /// Refuses an incomplete/foreign cold owner or an absent original native plan.
    pub fn original_native_restoration_data(
        &self,
    ) -> Result<crate::node_state::ValidatedCompleteNativeRestorationData<'_>, OperationFailure>
    {
        self.ensure_complete()?;
        self.source
            .ok_or_else(|| refused("inert history cannot issue future restoration data"))?
            .ensure_origin()?;
        let live_content = self.content.live_data()?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| refused("cold journal absent"))?;
        let demand = self
            .native_restoration_demand
            .ok_or_else(|| refused("cold native restoration demand absent"))?;
        let mut lengths = [0usize; 5];
        for (slot, reference) in lengths.iter_mut().zip([
            &journal.native_after_protocol,
            &journal.native_control,
            &journal.native_anchor,
            &self.owner.state,
            self.journal_reference,
        ]) {
            *slot = self
                .content
                .get(reference)
                .ok_or_else(|| refused("cold restoration body absent"))?
                .len();
        }
        let selected_owner = if matches!(
            self.snapshot_class,
            CompleteNativeSnapshotClass::StartupCapture14
                | CompleteNativeSnapshotClass::InvocationCapture15
        ) {
            use crucible_node_transport::reference_packet::service::complete_restore::transfer::{
                PacketCompleteRestoreSelectedOwnerInputs,
                complete_restore_invocation_owner_construction_storage_data,
                complete_restore_selected_owner_construction_storage_data,
            };
            let body = |reference| {
                self.content
                    .get(reference)
                    .ok_or_else(|| refused("cold restoration body absent"))
            };
            let inputs = PacketCompleteRestoreSelectedOwnerInputs {
                owner_state: body(&self.owner.state)?,
                journal: body(self.journal_reference)?,
                control: body(&journal.native_control)?,
                anchor: body(&journal.native_anchor)?,
                maximum_input_bytes: self.maximum,
                maximum_before_bytes: self.before_limits.json.maximum_input_bytes,
                maximum_requested_bytes: self.maximum,
            };
            let result = match self.snapshot_class {
                CompleteNativeSnapshotClass::StartupCapture14 => {
                    complete_restore_selected_owner_construction_storage_data(&inputs)
                }
                CompleteNativeSnapshotClass::InvocationCapture15 => {
                    complete_restore_invocation_owner_construction_storage_data(&inputs)
                }
                _ => return Err(refused("cold selected restoration class differs")),
            };
            match result {
                Ok(data) => Some(data),
                // Valid archive data is not promoted into future restoration
                // permission. Preserve an unavailable future row explicitly.
                Err(crucible_node_transport::ProviderError::ResourceExhausted(_)) => None,
                Err(error) => return Err(unknown(error)),
            }
        } else {
            None
        };
        Ok(
            crate::node_state::ValidatedCompleteNativeRestorationData::from_validated_native_data(
                demand,
                self.native_limits,
                lengths,
                [
                    &journal.native_after_protocol,
                    &journal.native_control,
                    &journal.native_anchor,
                    &self.owner.state,
                    self.journal_reference,
                ],
                self.known_requested_bytes()?,
                checked_sum(
                    [
                        NodeRuntime::capture_reference_storage(&journal.host_protocol)
                            .map_err(unknown)?,
                        NodeRuntime::capture_reference_storage(&journal.native_after_protocol)
                            .map_err(unknown)?,
                    ],
                    self.maximum,
                )?,
                selected_owner,
                self.owner,
                live_content,
            ),
        )
    }

    fn prepare_demand(&mut self) -> Result<usize, OperationFailure> {
        self.ensure_origin()?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| refused("cold journal absent"))?;
        let mut total = self.actual_banks()?;
        let before_reference = self
            .before_reference
            .as_ref()
            .ok_or_else(|| refused("cold before full reference absent"))?;
        for reference in [
            &journal.host_protocol,
            &journal.native_after_protocol,
            before_reference,
        ] {
            total = checked_sum(
                [
                    total,
                    NodeRuntime::capture_reference_storage(reference).map_err(unknown)?,
                ],
                self.maximum,
            )?;
        }
        {
            let host = ValidatedOwnedProtocol11::validate(
                self.content
                    .get(&journal.host_protocol)
                    .ok_or_else(|| refused("cold host input absent"))?,
                self.host_limits,
                &mut self.host_aliases,
            )
            .map_err(unknown)?;
            host.require_complete_reader_state().map_err(unknown)?;
            total = checked_sum(
                [
                    total,
                    protocol_demand(host.allocation_demand(), self.maximum)?,
                ],
                self.maximum,
            )?;
        }
        {
            let before = ValidatedNativeOwnedProtocol11::validate(
                &self.before_raw,
                self.before_limits,
                &mut self.before_aliases,
            )
            .map_err(unknown)?;
            self.snapshot_class.authenticate_native(&before)?;
            let demand = before.allocation_demand();
            total = checked_sum(
                [
                    total,
                    protocol_demand(&demand.recorded, self.maximum)?,
                    demand.native_group_lookup_bytes,
                    demand.historical_payload_layout_bytes,
                    demand.semantic_validation_stack_bytes,
                ],
                self.maximum,
            )?;
        }
        {
            let native = ValidatedNativeOwnedProtocol11::validate(
                self.content
                    .get(&journal.native_after_protocol)
                    .ok_or_else(|| refused("cold native input absent"))?,
                self.native_limits,
                &mut self.native_aliases,
            )
            .map_err(unknown)?;
            self.snapshot_class.authenticate_native(&native)?;
            let demand = native.allocation_demand();
            self.native_restoration_demand = Some(*demand);
            total = checked_sum(
                [
                    total,
                    protocol_demand(&demand.recorded, self.maximum)?,
                    demand.native_group_lookup_bytes,
                    demand.historical_payload_layout_bytes,
                    demand.semantic_validation_stack_bytes,
                ],
                self.maximum,
            )?;
        }
        // All four class demands join the fixed-three source aggregate before
        // reconstruct_group permits the first historical owner allocation.
        total = checked_sum([total, self.registry_demand_data()?], self.maximum)?;
        self.known_requested = Some(total);
        Ok(total)
    }

    fn reconstruct(&mut self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.known_requested.is_none() || self.failed {
            return Err(refused("cold demand not admitted"));
        }
        {
            let journal = self
                .journal
                .as_ref()
                .ok_or_else(|| refused("cold journal absent"))?;
            let mut before = ValidatedNativeOwnedProtocol11::validate(
                &self.before_raw,
                self.before_limits,
                &mut self.before_aliases,
            )
            .map_err(unknown)?;
            self.snapshot_class.reconstruct(
                &mut before,
                self.before_reference
                    .as_ref()
                    .ok_or_else(|| refused("cold before reference lost"))?,
                &mut self.before_encoded,
                &mut self.before,
            )?;
            let mut host = ValidatedOwnedProtocol11::validate(
                self.content
                    .get(&journal.host_protocol)
                    .ok_or_else(|| refused("cold host input absent"))?,
                self.host_limits,
                &mut self.host_aliases,
            )
            .map_err(unknown)?;
            host.reconstruct_sealed_into(
                &journal.host_protocol,
                &mut self.host_encoded,
                &mut self.host,
            )
            .map_err(unknown)?;
            let mut native = ValidatedNativeOwnedProtocol11::validate(
                self.content
                    .get(&journal.native_after_protocol)
                    .ok_or_else(|| refused("cold native input absent"))?,
                self.native_limits,
                &mut self.native_aliases,
            )
            .map_err(unknown)?;
            self.snapshot_class.reconstruct(
                &mut native,
                &journal.native_after_protocol,
                &mut self.native_encoded,
                &mut self.native,
            )?;
        }
        self.reconstruct_registry_data()?;
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| refused("cold registry journal lost"))?;
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("cold host result absent"))?
            .historical()
            .map_err(unknown)?;
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| refused("cold native result absent"))?
            .historical()
            .map_err(unknown)?;
        journal.authenticate_protocol_data(host, native)?;
        let capture = host
            .custody
            .controller
            .get(&journal.confirmation.capture.capture_request_id)
            .ok_or_else(|| refused("cold predecessor Capture original absent"))?;
        let terminal = capture
            .response
            .as_ref()
            .ok_or_else(|| refused("cold predecessor Capture terminal absent"))?;
        self.before
            .as_ref()
            .ok_or_else(|| refused("cold predecessor before absent"))?
            .authenticate_capture_predecessor_data(
                self.native
                    .as_ref()
                    .ok_or_else(|| refused("cold predecessor after absent"))?,
                &capture.request,
                terminal,
                [
                    &journal.native_snapshot,
                    &journal.native_anchor,
                    &journal.native_control,
                ],
            )
            .map_err(unknown)?;
        self.authenticate_snapshot_report_data()?;
        self.ensure_origin()
    }

    fn actual_banks(&self) -> Result<usize, OperationFailure> {
        let aliases = self
            .host_aliases
            .capacity()
            .checked_add(self.native_aliases.capacity())
            .and_then(|n| n.checked_add(self.before_aliases.capacity()))
            .and_then(|n| n.checked_add(self.registry_aliases.capacity()))
            .and_then(|n| n.checked_mul(size_of::<HistoricalAliasSummary>()))
            .ok_or_else(|| refused("cold actual aliases overflow"))?;
        checked_sum(
            [
                size_of::<Self>(),
                self.journal_storage,
                aliases,
                self.host_encoded.as_ref().map_or(0, Vec::capacity),
                self.host
                    .as_ref()
                    .map_or(0, SealedHistoricalControllerState::encoded_capacity),
                self.native_encoded.as_ref().map_or(0, Vec::capacity),
                self.native
                    .as_ref()
                    .map_or(0, SealedHistoricalNativeState::encoded_capacity),
                self.registry_encoded.as_ref().map_or(0, Vec::capacity),
                self.registry
                    .as_ref()
                    .map_or(0, SealedHistoricalHostExtensionRegistry::encoded_capacity),
                self.before_raw.capacity(),
                self.before_encoded.as_ref().map_or(0, Vec::capacity),
                self.before
                    .as_ref()
                    .map_or(0, SealedHistoricalNativeState::encoded_capacity),
                self.before_reference
                    .as_ref()
                    .map(NodeRuntime::capture_reference_storage)
                    .transpose()
                    .map_err(unknown)?
                    .unwrap_or(0),
            ],
            self.maximum,
        )
    }

    fn ensure_origin(&self) -> Result<(), OperationFailure> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused("cold archive owner foreign origin"));
        }
        match self.source {
            Some(source) => source.ensure_origin(),
            None => Ok(()),
        }
    }

    fn ensure_complete(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.failed
            || !self.attempted
            || self.host.is_none()
            || self.native.is_none()
            || self.before.is_none()
            || self.registry.is_none()
        {
            return Err(refused("cold archive owner incomplete"));
        }
        Ok(())
    }
}

// These named wrappers/declared arrays are known requested layout, not a bound
// for compiler frames or the entire thread stack. The root plan contains both
// child plans (and the compact plan), so their diagnostic sizes are not added.
#[cfg(test)]
fn snapshot_parser_known_storage(maximum: usize) -> Result<usize, OperationFailure> {
    snapshot_parser_known_storage_for_class(CompleteNativeSnapshotClass::Legacy11, maximum)
}

pub(super) fn snapshot_parser_known_storage_for_class(
    class: CompleteNativeSnapshotClass,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    let layouts = class.parser_layouts();
    let cursors = layouts
        .field_cursor_bytes
        .checked_mul(layouts.maximum_simultaneous_field_cursors)
        .ok_or_else(|| refused("cold snapshot parser cursor layout overflow"))?;
    checked_sum(
        [
            layouts.plan_header_bytes,
            cursors,
            layouts.field_scan_declared_array_bytes,
            layouts.raw_chunk_array_bytes,
            layouts.streaming_hash_header_bytes,
            layouts.streaming_hash_output_bytes,
            // The selected facade retains its borrowed full reference across
            // decode and Report authentication, alongside the parser itself.
            size_of::<&CompleteSnapshotPlan<'_>>(),
            size_of::<CompleteNativeSnapshotClass>(),
            size_of::<&[u8]>(),
            size_of::<Option<&[u8]>>(),
            size_of::<Result<&[u8], OperationFailure>>(),
            size_of::<Result<(), OperationFailure>>(),
            size_of::<Result<usize, OperationFailure>>(),
        ],
        maximum,
    )
}

fn protocol_demand(
    demand: &OwnedProtocol11AllocationDemand,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    let tree = NodeRuntime::capture_protocol_tree_storage(
        demand.tree_containers,
        demand.tree_entries,
        demand.maximum_tree_key_value_bytes,
        demand.maximum_tree_entry_alignment,
        maximum,
    )
    .map_err(unknown)?;
    let shared = NodeRuntime::capture_protocol_shared_header_storage(
        demand.shared_backing_views,
        demand.maximum_shared_value_alignment,
        maximum,
    )
    .map_err(unknown)?;
    checked_sum(
        [
            demand.recorded_string_bytes,
            demand.recorded_vector_bytes,
            demand.literal_backing_bytes,
            demand.tree_entry_layout_bytes,
            tree,
            demand.boxed_value_bytes,
            demand.shared_view_bytes,
            shared,
            demand.selected_group_lookup_bytes,
            demand.content_group_lookup_bytes,
            demand.selected_slice_staging_bytes,
        ],
        maximum,
    )
}

fn decoder_limits(
    input: U64,
    rows: usize,
    limits: NativeArchiveLimits,
    maximum: usize,
) -> Result<OwnedProtocol11DataLimits, OperationFailure> {
    let input = usize::try_from(input.get())
        .map_err(unknown)?
        .min(limits.state.maximum_content_bytes);
    if maximum == 0 || rows == 0 || rows > 131072 || input == 0 {
        return Err(refused("cold decoder selection unsupported"));
    }
    Ok(OwnedProtocol11DataLimits {
        json: HistoricalJsonLimits {
            maximum_input_bytes: input,
            maximum_nodes: limits.state.maximum_dependency_edges,
            maximum_depth: limits.state.maximum_dependency_depth.min(64),
            maximum_owned_backing_bytes: maximum,
            maximum_tree_entries: limits.state.maximum_dependency_edges,
        },
        content: CompactMetadata8Limits {
            content: CompactContentLimits {
                max_input_bytes: input,
                max_rows: limits.state.maximum_content_objects.min(8192),
                max_groups: limits.state.maximum_content_objects.min(8192),
                max_first_group_capacity_bytes: maximum,
            },
            maximum_metadata_capacity_bytes: maximum,
        },
        maximum_metadata_rows: rows,
        maximum_literal_backing_bytes: maximum,
    })
}

fn checked_sum<const N: usize>(
    terms: [usize; N],
    maximum: usize,
) -> Result<usize, OperationFailure> {
    terms.into_iter().try_fold(0usize, |sum, term| {
        sum.checked_add(term)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("cold archive simultaneous allocation exceeds admission"))
    })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "cold aggregate admission boundary controls"
)]
mod tests {
    use super::*;

    #[test]
    fn raw_before_and_sealed_before_have_independent_allocation_credit() {
        let host_and_after = 700usize;
        let before_original_capacity = 4096usize;
        let before_sealed_capacity = 3000usize;
        let before_alias_capacity_bytes = 512usize;
        let terms = [
            host_and_after,
            before_original_capacity,
            before_sealed_capacity,
            before_alias_capacity_bytes,
        ];
        let total = terms.iter().sum::<usize>();

        assert_eq!(checked_sum(terms, total).unwrap(), total);
        assert!(checked_sum(terms, total - 1).is_err());
        assert!(
            checked_sum(
                terms,
                host_and_after + before_sealed_capacity + before_alias_capacity_bytes
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_declared_layout_is_admitted_at_exact_whole_term() {
        let total = snapshot_parser_known_storage(usize::MAX).unwrap();
        let layouts = crucible_node_transport::reference_packet::service::native_snapshot::packet_native_owned11_snapshot_validation_layouts();

        assert!(total >= layouts.raw_chunk_array_bytes + layouts.plan_header_bytes);
        assert_eq!(snapshot_parser_known_storage(total).unwrap(), total);
        assert!(snapshot_parser_known_storage(total - 1).is_err());
    }

    #[test]
    fn core_and_every_separate_owner_bank_share_one_aggregate_allowance() {
        // Core content, caller Host/factory and three independent protocol-owner
        // terms coexist. No equal digest discounts another encoded/alias bank.
        let terms = [100usize, 200, 300, 300, 300];
        assert_eq!(checked_sum(terms, 1200).unwrap(), 1200);
        assert!(checked_sum(terms, 1199).is_err());
        assert!(checked_sum([100usize, 200, 301, 300, 300], 1200).is_err());
    }

    #[test]
    fn aggregate_refuses_overflow_even_when_each_individual_term_fits() {
        assert!(checked_sum([usize::MAX, 1], usize::MAX).is_err());
        assert!(checked_sum([20usize, 20, 20], 59).is_err());
    }
}
