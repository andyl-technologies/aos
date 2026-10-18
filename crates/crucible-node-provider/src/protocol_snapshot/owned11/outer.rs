//! Reconstructs the complete historical host controller tuple as final typed data.
//!
//! Full outer framing, capacity rows, literal bank allowances and typed fields
//! are validated before owner construction. Live association, current cuts and
//! source-issued fresh factory permits remain outside this data decoder.
//!
//! ```text
//! ["source-private.cnp-protocol/11",controller_data,capacity_records,shared_aliases]
//! ```

use super::codec::HistoricalControllerCodec;
use super::state::{HistoricalAuthority, HistoricalCorrelations, next, tag};
use super::typed::{Fields, HistoricalType, Ledger, invalid};
use crate::ProviderError;
use crate::client::compact_metadata8::{CompactMetadata8Limits, ValidatedCompactMetadata8};
use crate::client::{ClientContent, ClientOriginal};
use crate::retained_metadata::records::{MetadataRecordKind, ValidatedMetadataRecords};
use crate::transport::{DecodedCompactOriginalFrames, ValidatedCompactOriginalFrames};
use crucible_node_contract::{ContentRef, Id, U64};
use std::collections::BTreeMap;

/// Bounds historical reconstruction independently from live source permissions.
#[derive(Clone, Copy)]
pub struct OwnedProtocol11DataLimits {
    /// Admits bounded body grammar and aggregate recorded String/Vec backing.
    pub json: super::json_value::HistoricalJsonLimits,
    /// Admits complete content-eight byte groups and metadata capacities.
    pub content: CompactMetadata8Limits,
    /// Bounds the complete metadata capacity roster before any owner copies.
    pub maximum_metadata_rows: usize,
    /// Bounds connection plus Hello byte/descriptor backing together.
    pub maximum_literal_backing_bytes: usize,
}

/// Identifies the reader-complete connection grammar required by full targets.
///
/// Older eleven data tuples are historical compatibility inputs only. A source
/// factory binds this exact class with its measured backend and signed closure;
/// this string alone cannot enroll a current registrar or authorize restoration.
pub const COMPLETE_CONNECTION_FORMAT: &str = "source-private.connection-with-reader/11";

/// Identifies the explicit controller class with a genuine supervisor data loan.
pub const COMPLETE_CONTROLLER_FORMAT: &str = "source-private.controller-restorable-complete/11";

/// Owns the historical connection data without an active stream or registrar.
pub struct HistoricalConnection {
    /// Preserves the exact original connection authority data.
    pub authority: HistoricalAuthority,
    /// Preserves the complete original correlation guard state.
    pub correlations: HistoricalCorrelations,
    /// Preserves all immutable controller codec owners.
    pub codec: HistoricalControllerCodec,
    /// Preserves exact literal bytes, slot progress, IDs and spare capacities.
    pub frames: DecodedCompactOriginalFrames,
    /// Preserves actual reader facts in the explicit reader-complete tuple.
    ///
    /// Older data-only eleven tuples retain None, never inferred receiving state.
    pub reader: Option<super::reader::HistoricalFrameReaderFacts>,
    /// Preserves whether the packet schema was installed.
    pub packet_schema: bool,
    /// Preserves whether the connected packet schema was installed.
    pub connected_packet_schema: bool,
    /// Preserves the sticky original transport fence.
    pub fenced: bool,
}

impl HistoricalType for HistoricalConnection {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let connection_tag = super::typed::plain_string(next(&mut fields)?)?;
        let with_reader = match connection_tag {
            "source-private.connection/11" => false,
            "source-private.connection-with-reader/11" => true,
            _ => return Err(invalid()),
        };
        let authority = ledger.read::<HistoricalAuthority>(next(&mut fields)?, build)?;
        let correlations = ledger.read::<HistoricalCorrelations>(next(&mut fields)?, build)?;
        let shared_start = ledger.rows.encoded_position();
        let extent = ledger.row(MetadataRecordKind::Shared, 1)?;
        if extent != crate::connection::owned_codec_enum_layout() {
            return Err(invalid());
        }
        let codec_view = next(&mut fields)?;
        let codec = ledger.read::<HistoricalControllerCodec>(codec_view, build)?;
        ledger.shared(
            crate::retained_metadata::aliases::MetadataSharedKind::Codec,
            extent,
            codec_view,
            ledger.rows.encoded_between(shared_start)?,
        )?;
        let frame_bytes = next(&mut fields)?;
        let frames = literal(frame_bytes, ledger, build)?;
        let reader = if with_reader {
            ledger.read::<super::reader::HistoricalFrameReaderFacts>(next(&mut fields)?, build)?
        } else {
            None
        };
        let packet_schema = ledger.read::<bool>(next(&mut fields)?, build)?;
        let connected_packet_schema = ledger.read::<bool>(next(&mut fields)?, build)?;
        let fenced = ledger.read::<bool>(next(&mut fields)?, build)?;
        tag(&mut fields, "controller")?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            authority: authority.ok_or_else(invalid)?,
            correlations: correlations.ok_or_else(invalid)?,
            codec: codec.ok_or_else(invalid)?,
            frames: frames.ok_or_else(invalid)?,
            reader,
            packet_schema: packet_schema.ok_or_else(invalid)?,
            connected_packet_schema: connected_packet_schema.ok_or_else(invalid)?,
            fenced: fenced.ok_or_else(invalid)?,
        }))
    }
}

/// Owns original client sequencing, peer facts and the complete Hello journal.
pub struct HistoricalClientSession {
    /// Preserves every historical connection field.
    pub connection: HistoricalConnection,
    /// Preserves the separately owned authority clone and its String capacities.
    pub authority: HistoricalAuthority,
    /// Preserves the actual next controller sequence.
    pub sequence: U64,
    /// Preserves the original peer PID as historical data.
    pub peer_pid: u32,
    /// Preserves the full measured peer executable reference.
    pub peer_executable: ContentRef,
    /// Preserves both full original Hello frames and bank capacities.
    pub hello: DecodedCompactOriginalFrames,
}

impl HistoricalType for HistoricalClientSession {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.client-session/11")?;
        let connection = ledger.read::<HistoricalConnection>(next(&mut fields)?, build)?;
        let authority = ledger.read::<HistoricalAuthority>(next(&mut fields)?, build)?;
        let sequence = ledger.read::<U64>(next(&mut fields)?, build)?;
        let peer_pid = ledger.read::<u32>(next(&mut fields)?, build)?;
        let peer_executable = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
        let hello_bytes = next(&mut fields)?;
        let shared = ledger.row(MetadataRecordKind::Shared, 1)?;
        if shared != crate::transport::original_frame_bank_layout() {
            return Err(invalid());
        }
        ledger.shared(
            crate::retained_metadata::aliases::MetadataSharedKind::HelloBank,
            shared,
            hello_bytes,
            b"",
        )?;
        let hello = literal(hello_bytes, ledger, build)?;
        tag(
            &mut fields,
            "original-physical-cut-retained-by-source-not-portable-time",
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            connection: connection.ok_or_else(invalid)?,
            authority: authority.ok_or_else(invalid)?,
            sequence: sequence.ok_or_else(invalid)?,
            peer_pid: peer_pid.ok_or_else(invalid)?,
            peer_executable: peer_executable.ok_or_else(invalid)?,
            hello: hello.ok_or_else(invalid)?,
        }))
    }
}

/// Owns all historical client requests, responses and content-eight owners.
pub struct HistoricalClientCustody {
    /// Preserves the lifetime original ceiling in each namespace.
    pub maximum_requests: usize,
    /// Preserves the nonrenewing raw journal byte ceiling.
    pub maximum_bytes: usize,
    /// Preserves consumed original raw journal credit.
    pub retained_bytes: usize,
    /// Preserves complete original controller request and response history.
    pub controller: BTreeMap<Id, ClientOriginal>,
    /// Preserves complete original provider request and response history.
    pub provider: BTreeMap<Id, ClientOriginal>,
    /// Preserves all content bytes, full references, aliases and capacities.
    pub content: ClientContent,
}

impl HistoricalType for HistoricalClientCustody {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let maximum_requests = ledger.read::<usize>(next(&mut fields)?, build)?;
        let maximum_bytes = ledger.read::<usize>(next(&mut fields)?, build)?;
        let retained_bytes = ledger.read::<usize>(next(&mut fields)?, build)?;
        let controller = ledger.read::<BTreeMap<Id, ClientOriginal>>(next(&mut fields)?, build)?;
        let provider = ledger.read::<BTreeMap<Id, ClientOriginal>>(next(&mut fields)?, build)?;
        let content_bytes = next(&mut fields)?;
        let limits = ledger.content_limits.ok_or_else(invalid)?;
        let plan = ValidatedCompactMetadata8::validate(content_bytes, limits)?;
        let lookup_entries = plan
            .data()
            .transfer_count()
            .checked_add(plan.data().object_count())
            .ok_or_else(invalid)?;
        let lookup_bytes = lookup_entries
            .checked_mul(std::mem::size_of::<Option<std::rc::Rc<Vec<u8>>>>())
            .ok_or_else(invalid)?;
        ledger.content_group_lookup_bytes = ledger
            .content_group_lookup_bytes
            .checked_add(lookup_bytes)
            .ok_or_else(invalid)?;
        let content_rows = ledger.rows.clone();
        ledger.rows = plan.validate_owned11_capacity_rows(content_rows.clone())?;
        let mut rows = content_rows;
        for (transfer, entries) in [
            (true, plan.data().transfer_count()),
            (false, plan.data().object_count()),
        ] {
            let tree = rows.next().ok_or_else(invalid)??;
            if tree.kind != MetadataRecordKind::Tree || tree.extent != entries {
                return Err(invalid());
            }
            let mut check = |row: crate::client::compact_cursor::BorrowedContentRow<'_>| -> Result<(), ProviderError> {
                for _ in 0..5 { rows.next().ok_or_else(invalid)??; }
                let start = rows.encoded_position();
                let shared = rows.next().ok_or_else(invalid)??;
                let vector = rows.next().ok_or_else(invalid)??;
                if shared.kind != MetadataRecordKind::Shared || vector.kind != MetadataRecordKind::Vector { return Err(invalid()); }
                ledger.shared_content(row.edge, shared.extent,
                    row.reference.digest().as_bytes(), rows.encoded_between(start)?)?;
                Ok(())
            };
            if transfer {
                for row in plan.data().transfers() {
                    check(row?)?;
                }
            } else {
                for row in plan.data().objects() {
                    check(row?)?;
                }
            }
        }
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            maximum_requests: maximum_requests.ok_or_else(invalid)?,
            maximum_bytes: maximum_bytes.ok_or_else(invalid)?,
            retained_bytes: retained_bytes.ok_or_else(invalid)?,
            controller: controller.ok_or_else(invalid)?,
            provider: provider.ok_or_else(invalid)?,
            content: ClientContent::decode_compact_metadata8_data(content_bytes, limits)?,
        }))
    }
}

/// Owns complete historical host state without a live protocol capability.
pub struct HistoricalControllerState {
    /// Preserves the source-selected node routing identifier.
    pub node: Id,
    /// Preserves the optional source-selected execution owner.
    pub execution_owner: Id,
    /// Preserves the original duration seconds without creating a deadline.
    pub budget_seconds: U64,
    /// Preserves the original duration nanoseconds.
    pub budget_nanoseconds: u32,
    /// Preserves the sticky controller fence.
    pub fenced: bool,
    /// Preserves the explicitly selected complete owning profile.
    pub profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    /// Preserves the full session, connection and Hello data owners.
    pub session: HistoricalClientSession,
    /// Preserves lifetime request history and content custody.
    pub custody: HistoricalClientCustody,
    /// Preserves the complete assigned request, proof, canonical bytes and raw reply.
    pub assigned: Option<super::assigned::HistoricalAssignedAdmit>,
    /// Retains actual supervisor state in the complete controller class only.
    pub supervisor: Option<super::supervisor::HistoricalOriginalSupervisor>,
    /// Retains the separate completed restore owner without historical authority.
    pub complete_restore: Option<super::assigned_restore::HistoricalCompleteRestoreOwner>,
    restore_owner_covered: bool,
}

impl HistoricalType for HistoricalControllerState {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let first = next(&mut fields)?;
        let restore_owner_covered =
            first == b"\"source-private.controller-restorable-complete/11\"";
        let complete =
            restore_owner_covered || first == b"\"source-private.controller-complete/11\"";
        if !complete {
            fields = Fields::array(input)?;
        }
        let node = ledger.read::<Id>(next(&mut fields)?, build)?;
        let execution_owner = ledger.read::<Id>(next(&mut fields)?, build)?;
        let budget_seconds = ledger.read::<U64>(next(&mut fields)?, build)?;
        let nanos = next(&mut fields)?;
        if super::typed::unsigned(nanos)? >= 1_000_000_000 {
            return Err(invalid());
        }
        let budget_nanoseconds = ledger.read::<u32>(nanos, build)?;
        let fenced = ledger.read::<bool>(next(&mut fields)?, build)?;
        let owner = ledger.row(MetadataRecordKind::Shared, 1)?;
        if owner != crate::protocol_snapshot::protocol_capture_owner_layout() {
            return Err(invalid());
        }
        ledger.shared(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            owner,
            b"historical-source-owner",
            b"",
        )?;
        let profile_bytes = next(&mut fields)?;
        let mut profile_fields = Fields::object(profile_bytes)?;
        if super::typed::plain_string(profile_fields.named("encoding")?)? != "owned_protocol11" {
            return Err(invalid());
        }
        let profile = ledger
            .read::<crate::reference_packet::service::PacketNative5CaptureProfile>(
                profile_bytes,
                build,
            )?;
        let session = ledger.read::<HistoricalClientSession>(next(&mut fields)?, build)?;
        let custody = ledger.read::<HistoricalClientCustody>(next(&mut fields)?, build)?;
        let assigned_bytes = next(&mut fields)?;
        let assigned = if assigned_bytes == b"null" {
            build.then_some(None)
        } else {
            let mut tuple = Fields::array(assigned_bytes)?;
            tag(&mut tuple, "complete")?;
            let original = next(&mut tuple)?;
            let bytes = next(&mut tuple)?;
            let capacity = usize::try_from(super::typed::unsigned(next(&mut tuple)?)?)
                .map_err(|_| invalid())?;
            let slot = usize::try_from(super::typed::unsigned(next(&mut tuple)?)?)
                .map_err(|_| invalid())?;
            let response = next(&mut tuple)?;
            tag(
                &mut tuple,
                "original-physical-cut-retained-by-opaque-owner-not-portable-time",
            )?;
            tuple.finish()?;
            let plan = super::assigned::ValidatedHistoricalAssignedAdmit::validate_fields(
                original,
                bytes,
                capacity,
                slot,
                response,
                ledger.rows.clone(),
                ledger.limits,
            )?;
            ledger.rows = plan.remaining_records();
            if build {
                Some(Some(plan.reconstruct()?))
            } else {
                None
            }
        };
        let supervisor = if complete {
            ledger.read::<super::supervisor::HistoricalOriginalSupervisor>(
                next(&mut fields)?,
                build,
            )?
        } else {
            None
        };
        let complete_restore = if restore_owner_covered {
            read_restore_owner(next(&mut fields)?, ledger, build)?
        } else {
            None
        };
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            node: node.ok_or_else(invalid)?,
            execution_owner: execution_owner.ok_or_else(invalid)?,
            budget_seconds: budget_seconds.ok_or_else(invalid)?,
            budget_nanoseconds: budget_nanoseconds.ok_or_else(invalid)?,
            fenced: fenced.ok_or_else(invalid)?,
            profile: profile.ok_or_else(invalid)?,
            session: session.ok_or_else(invalid)?,
            custody: custody.ok_or_else(invalid)?,
            assigned: assigned.ok_or_else(invalid)?,
            supervisor,
            complete_restore,
            restore_owner_covered,
        }))
    }
}

impl HistoricalControllerState {
    /// Requires actual captured reader fields for a complete historical target.
    ///
    /// # Errors
    /// Refuses an older partial eleven tuple. This checks data class only and
    /// creates no original stream, registrar, physical cut or source permit.
    pub fn require_complete_reader_state(&self) -> Result<(), ProviderError> {
        if self.session.connection.reader.is_none()
            || self.supervisor.is_none()
            || !self.restore_owner_covered
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Reports conservative requested backing and explicit unmeasured physical terms.
///
/// Recorded backing views can repeat actual shared owners. They are a safe upper
/// allowance rather than deduplication credit or measured allocator geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedProtocol11AllocationDemand {
    /// Counts requested capacities from every recorded String backing view.
    pub recorded_string_bytes: usize,
    /// Counts requested capacities from every recorded Vec backing view.
    pub recorded_vector_bytes: usize,
    /// Reports both literal banks' exact byte and descriptor requested backing.
    pub literal_backing_bytes: usize,
    /// Counts logical typed tree entries without inferring physical node bytes.
    pub tree_entries: usize,
    /// Sums typed key/value inline layouts across all logical tree entries.
    pub tree_entry_layout_bytes: usize,
    /// Counts actual tree roots, including empty retained containers.
    pub tree_containers: usize,
    /// Bounds actual key-plus-value size independently from entry population.
    pub maximum_tree_key_value_bytes: usize,
    /// Reports actual maximum key/value alignment, including zero-sized keys.
    pub maximum_tree_entry_alignment: usize,
    /// Counts all shared backing views without alias discounts.
    pub shared_backing_views: usize,
    /// Reports actual maximum shared payload alignment, including empty slices.
    pub maximum_shared_value_alignment: usize,
    /// Counts retained Box payload layouts separately from allocation headers.
    pub boxed_value_bytes: usize,
    /// Sums retained shared-view payload layouts conservatively per view.
    pub shared_view_bytes: usize,
    /// Counts independent checked historical shared groups.
    pub alias_groups: usize,
    /// Counts all checked shared edges, including aliases.
    pub alias_rows: usize,
    /// Reports the required caller-precharged summary slice length.
    pub alias_summary_entries: usize,
    /// Reports the named summary bank size independently from its actual capacity.
    pub alias_summary_layout_bytes: usize,
    /// Bounds final selected-slice group lookup entries before final owner copies.
    pub selected_group_lookup_bytes: usize,
    /// Counts both temporary content row-to-Rc lookup banks during reconstruction.
    pub content_group_lookup_bytes: usize,
    /// Bounds Vec/boxed-slice staging that can coexist with the final selected Arc.
    pub selected_slice_staging_bytes: usize,
}

/// Borrows the fully preflighted host tuple and complete capacity roster.
pub struct ValidatedOwnedProtocol11<'a, 'scratch> {
    input: &'a [u8],
    data: &'a [u8],
    records: ValidatedMetadataRecords<'a>,
    aliases: super::aliases::ValidatedHistoricalAliases<'a, 'scratch>,
    limits: OwnedProtocol11DataLimits,
    demand: OwnedProtocol11AllocationDemand,
}

impl<'a, 'scratch> ValidatedOwnedProtocol11<'a, 'scratch> {
    /// Validates closed outer data, complete capacity rows and every typed field.
    ///
    /// Caller-precharged alias summaries check the entire shared graph and all
    /// repeated views during the same pass. This plan grants historical data only.
    ///
    /// # Errors
    /// Refuses another edition, malformed/trailing data, row mismatch, missing
    /// owners, capacity overflow or excess literal/content/backing credit.
    pub fn validate(
        input: &'a [u8],
        limits: OwnedProtocol11DataLimits,
        alias_summaries: &'scratch mut [super::aliases::HistoricalAliasSummary],
    ) -> Result<Self, ProviderError> {
        if input.len() > limits.json.maximum_input_bytes {
            return Err(invalid());
        }
        validate_outer_work(input, limits.json.maximum_nodes)?;
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.cnp-protocol/11")?;
        let data = next(&mut fields)?;
        let encoded_records = next(&mut fields)?;
        let encoded_aliases = next(&mut fields)?;
        fields.finish()?;
        let records = ValidatedMetadataRecords::validate(
            encoded_records,
            limits.maximum_metadata_rows,
            limits.json.maximum_owned_backing_bytes,
        )?;
        let mut aliases = super::aliases::ValidatedHistoricalAliases::validate(
            encoded_aliases,
            alias_summaries,
            limits.maximum_metadata_rows,
        )?;
        let mut demand = demand_records(&records)?;
        if demand.tree_entries > limits.json.maximum_tree_entries {
            return Err(invalid());
        }
        let mut ledger = make_ledger(&records, limits);
        ledger.aliases = Some(aliases.views()?);
        ledger.read::<HistoricalControllerState>(data, false)?;
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.aliases.take().ok_or_else(invalid)?.finish()?;
        demand.literal_backing_bytes = ledger.literal_bytes;
        demand.content_group_lookup_bytes = ledger.content_group_lookup_bytes;
        demand.selected_slice_staging_bytes = ledger.selected_slice_staging_bytes;
        demand.alias_groups = aliases.group_count();
        demand.alias_rows = aliases.row_count();
        demand.alias_summary_entries = aliases.group_count();
        demand.alias_summary_layout_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<super::aliases::HistoricalAliasSummary>())
            .ok_or_else(invalid)?;
        demand.selected_group_lookup_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<
                Option<std::sync::Arc<[crucible_node_contract::ExtensionSelection]>>,
            >())
            .ok_or_else(invalid)?;
        Ok(Self {
            input,
            data,
            records,
            aliases,
            limits,
            demand,
        })
    }

    /// Borrows complete checked logical allocation demand without allocating.
    pub const fn allocation_demand(&self) -> &OwnedProtocol11AllocationDemand {
        &self.demand
    }

    /// Requires the explicit reader-complete class before full-state reconstruction.
    ///
    /// This allocation-free check runs after complete typed framing, rows and
    /// aliases have been validated. It never infers an old reader from limits.
    ///
    /// # Errors
    /// Refuses historical compatibility tuples without the exact reader fields.
    pub fn require_complete_reader_state(&self) -> Result<(), ProviderError> {
        let mut controller = Fields::array(self.data)?;
        tag(&mut controller, COMPLETE_CONTROLLER_FORMAT)?;
        for _ in 0..6 {
            next(&mut controller)?;
        }
        let mut session = Fields::array(next(&mut controller)?)?;
        tag(&mut session, "source-private.client-session/11")?;
        let mut connection = Fields::array(next(&mut session)?)?;
        tag(&mut connection, COMPLETE_CONNECTION_FORMAT)
    }

    /// Returns both required format identities after complete-class validation.
    ///
    /// # Errors
    /// Refuses historical tuples missing actual reader or supervisor state.
    pub fn complete_schema_identity(&self) -> Result<(&'static str, &'static str), ProviderError> {
        self.require_complete_reader_state()?;
        Ok((COMPLETE_CONTROLLER_FORMAT, COMPLETE_CONNECTION_FORMAT))
    }

    /// Retains complete-class historical owners before defensive correspondence checks.
    ///
    /// Source ticket, measured backend, physical admission and fresh association
    /// checks remain independent. No portable class field grants live authority.
    ///
    /// # Errors
    /// Refuses an old partial class, nonempty slot, allocation or correspondence
    /// failure. Any completed data owner remains in the caller's result slot.
    pub fn reconstruct_complete_into(
        &mut self,
        completed: &mut Option<HistoricalControllerState>,
    ) -> Result<(), ProviderError> {
        self.require_complete_reader_state()?;
        self.reconstruct_into(completed)?;
        completed
            .as_ref()
            .ok_or_else(invalid)?
            .require_complete_reader_state()
    }

    /// Reconstructs the checked final typed historical owners without activation.
    ///
    /// # Errors
    /// Refuses exact reservation failure or any second-pass correspondence change.
    /// Live factory enrollment remains refused without its authentic source token.
    pub fn reconstruct_data(&mut self) -> Result<HistoricalControllerState, ProviderError> {
        let mut completed = None;
        self.reconstruct_into(&mut completed)?;
        completed.ok_or_else(invalid)
    }

    /// Retains final historical owners in the caller's original completion slot.
    ///
    /// The Source consumer admits the full demand report and its physical map,
    /// control-block and stack terms before calling. This data-only method cannot
    /// substitute a portable scalar for that source admission association.
    ///
    /// # Errors
    /// Refuses a nonempty destination, failed exact reservation or a second-pass
    /// disagreement. A completed owner is stored before defensive tail checks.
    pub fn reconstruct_into(
        &mut self,
        completed: &mut Option<HistoricalControllerState>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(invalid());
        }
        let mut selected_groups = Vec::new();
        selected_groups
            .try_reserve_exact(self.aliases.group_count())
            .map_err(|_| invalid())?;
        if selected_groups.capacity() != self.aliases.group_count() {
            return Err(invalid());
        }
        selected_groups.resize_with(self.aliases.group_count(), || None);
        let mut ledger = make_ledger(&self.records, self.limits);
        ledger.aliases = Some(self.aliases.views()?);
        ledger.selected_groups = Some(&mut selected_groups);
        let state = ledger
            .read::<HistoricalControllerState>(self.data, true)?
            .ok_or_else(invalid)?;
        *completed = Some(state);
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.aliases.take().ok_or_else(invalid)?.finish()?;
        let state = completed.as_ref().ok_or_else(invalid)?;
        if let Some(assigned) = &state.assigned {
            assigned.authenticate_literals(&state.session.connection.frames)?;
        }
        if let Some(restore) = &state.complete_restore {
            restore
                .assigned
                .authenticate_literals(&state.session.connection.frames)?;
        }
        Ok(())
    }
}

pub(super) fn make_ledger<'a, 'scratch, 'input>(
    records: &ValidatedMetadataRecords<'a>,
    limits: OwnedProtocol11DataLimits,
) -> Ledger<'a, 'scratch, 'input> {
    let mut ledger = Ledger::new(records.rows(), limits.json);
    ledger.content_limits = Some(limits.content);
    ledger.maximum_literal_bytes = limits.maximum_literal_backing_bytes;
    ledger
}

fn literal(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<DecodedCompactOriginalFrames>, ProviderError> {
    let plan = ValidatedCompactOriginalFrames::validate(
        input,
        ledger.limits.maximum_input_bytes,
        ledger.maximum_literal_bytes,
    )?;
    ledger.literal_bytes = ledger
        .literal_bytes
        .checked_add(plan.allocated_bytes())
        .ok_or_else(invalid)?;
    if ledger.literal_bytes > ledger.maximum_literal_bytes {
        return Err(invalid());
    }
    if build {
        Ok(Some(plan.reconstruct()?))
    } else {
        Ok(None)
    }
}

pub(super) fn demand_records(
    records: &ValidatedMetadataRecords<'_>,
) -> Result<OwnedProtocol11AllocationDemand, ProviderError> {
    let mut demand = OwnedProtocol11AllocationDemand {
        recorded_string_bytes: 0,
        recorded_vector_bytes: 0,
        literal_backing_bytes: 0,
        tree_entries: 0,
        tree_entry_layout_bytes: 0,
        tree_containers: 0,
        maximum_tree_key_value_bytes: 0,
        maximum_tree_entry_alignment: 0,
        shared_backing_views: 0,
        maximum_shared_value_alignment: 0,
        boxed_value_bytes: 0,
        shared_view_bytes: 0,
        alias_groups: 0,
        alias_rows: 0,
        alias_summary_entries: 0,
        alias_summary_layout_bytes: 0,
        selected_group_lookup_bytes: 0,
        content_group_lookup_bytes: 0,
        selected_slice_staging_bytes: 0,
    };
    for row in records.rows() {
        let row = row?;
        let bytes = row
            .extent
            .checked_mul(row.element_bytes)
            .ok_or_else(invalid)?;
        let term = match row.kind {
            MetadataRecordKind::String => &mut demand.recorded_string_bytes,
            MetadataRecordKind::Vector => &mut demand.recorded_vector_bytes,
            MetadataRecordKind::Tree => {
                demand.tree_containers =
                    demand.tree_containers.checked_add(1).ok_or_else(invalid)?;
                demand.maximum_tree_key_value_bytes =
                    demand.maximum_tree_key_value_bytes.max(row.element_bytes);
                demand.maximum_tree_entry_alignment =
                    demand.maximum_tree_entry_alignment.max(row.alignment);
                demand.tree_entries = demand
                    .tree_entries
                    .checked_add(row.extent)
                    .ok_or_else(invalid)?;
                &mut demand.tree_entry_layout_bytes
            }
            MetadataRecordKind::Shared => {
                demand.shared_backing_views = demand
                    .shared_backing_views
                    .checked_add(1)
                    .ok_or_else(invalid)?;
                demand.maximum_shared_value_alignment =
                    demand.maximum_shared_value_alignment.max(row.alignment);
                &mut demand.shared_view_bytes
            }
            MetadataRecordKind::Boxed => &mut demand.boxed_value_bytes,
        };
        *term = term.checked_add(bytes).ok_or_else(invalid)?;
    }
    Ok(demand)
}

pub(crate) const OUTER_WORK_MAXIMUM_DEPTH: usize = 128;

pub(super) fn validate_outer_work(input: &[u8], maximum_nodes: usize) -> Result<(), ProviderError> {
    std::str::from_utf8(input).map_err(|_| invalid())?;
    let mut nodes = 0usize;
    let mut depth = 0usize;
    let mut stack = [0u8; OUTER_WORK_MAXIMUM_DEPTH];
    let mut quoted = false;
    let mut escaped = false;
    let mut primitive = false;
    for byte in input {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match *byte {
            b'"' => {
                quoted = true;
                primitive = false;
                nodes = nodes.checked_add(1).ok_or_else(invalid)?;
            }
            b'[' | b'{' => {
                *stack.get_mut(depth).ok_or_else(invalid)? =
                    if *byte == b'[' { b']' } else { b'}' };
                depth += 1;
                primitive = false;
                nodes = nodes.checked_add(1).ok_or_else(invalid)?;
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or_else(invalid)?;
                if stack[depth] != *byte {
                    return Err(invalid());
                }
                primitive = false;
            }
            b',' | b':' => primitive = false,
            b' ' | b'\t' | b'\r' | b'\n' => return Err(invalid()),
            _ if !primitive => {
                primitive = true;
                nodes = nodes.checked_add(1).ok_or_else(invalid)?;
            }
            _ => {}
        }
        if nodes > maximum_nodes {
            return Err(invalid());
        }
    }
    if quoted || escaped || depth != 0 {
        return Err(invalid());
    }
    Ok(())
}

impl HistoricalControllerState {
    /// Borrows complete historical literals without claiming a current actor.
    pub fn original_frames_data(
        &self,
    ) -> impl Iterator<Item = crate::transport::original_frames::OriginalFrame<'_>> {
        self.session.connection.frames.frames()
    }

    /// Checks exact typed correspondence at one archived literal position.
    ///
    /// The signed source journal verifies all positions and uniqueness. This
    /// predicate supplies data correspondence only, with no current authority.
    ///
    /// # Errors
    /// Refuses an absent/wrong slot, partial I/O, incorrect framed extent or any
    /// canonical envelope disagreement without allocating a DOM or byte buffer.
    pub fn authenticate_original_envelope_data(
        &self,
        original: &crate::envelope::Envelope,
        direction: crate::transport::original_frames::FrameDirection,
        index: usize,
    ) -> Result<(), ProviderError> {
        let frame = self
            .session
            .connection
            .frames
            .frame(index)
            .ok_or_else(invalid)?;
        if frame.direction != direction
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() < 4
        {
            return Err(invalid());
        }
        let header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| invalid())?;
        if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
            return Err(invalid());
        }
        super::correspondence::envelope(original, &frame.bytes[4..])
    }
}

/// Retains a decoder-produced state beside its exact verified encoded body.
///
/// This opaque data owner provides no original cut, key, registrar or native
/// installation right. Its immutable loan prevents arbitrary public historical
/// fields from being substituted after body verification. Fresh source/key
/// proof and target context remain separate requirements.
pub struct SealedHistoricalControllerState {
    reference: crucible_node_contract::ContentRef,
    encoded: Vec<u8>,
    historical: Option<HistoricalControllerState>,
    complete: bool,
}

impl SealedHistoricalControllerState {
    /// Borrows the complete verified original body commitment.
    pub const fn body_reference(&self) -> &crucible_node_contract::ContentRef {
        &self.reference
    }
    /// Borrows the same retained encoded body bank without a mutable escape.
    pub fn encoded_body(&self) -> &[u8] {
        &self.encoded
    }
    /// Reports current encoded Vec capacity, separately from old issuance facts.
    pub fn encoded_capacity(&self) -> usize {
        self.encoded.capacity()
    }
    /// Borrows only the completed decoder-produced historical owner.
    ///
    /// # Errors
    /// Refuses partial construction or incomplete tail correspondence.
    pub fn historical(&self) -> Result<&HistoricalControllerState, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        self.historical.as_ref().ok_or_else(invalid)
    }
}

impl ValidatedOwnedProtocol11<'_, '_> {
    /// Reports the minimum precharged encoded bank extent for sealed provenance.
    ///
    /// The caller counts its actual Vec capacity separately. This minimum is
    /// not another allocation or a portable approval to exceed the full demand.
    pub fn sealed_encoded_body_bytes(&self) -> usize {
        self.input.len()
    }

    /// Retains exact verified input and its final decoded owner in one opaque slot.
    ///
    /// The caller admits all demand plus the actual empty preowned byte bank
    /// before calling. No body Vec is reserved, grown, shrunk or copied twice.
    ///
    /// # Errors
    /// Refuses a nonempty output/bank, insufficient current capacity, wrong full
    /// reference or decoding/tail failure. Once the byte bank moves, the partial
    /// sealed owner remains in the destination on every subsequent refusal.
    pub fn reconstruct_sealed_into(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalControllerState>,
    ) -> Result<(), ProviderError> {
        self.require_complete_reader_state()?;
        if completed.is_some()
            || encoded_bank
                .as_ref()
                .is_none_or(|bank| !bank.is_empty() || bank.capacity() < self.input.len())
        {
            return Err(invalid());
        }
        reference.verify(self.input).map_err(|_| invalid())?;
        let encoded = encoded_bank.take().ok_or_else(invalid)?;
        *completed = Some(SealedHistoricalControllerState {
            reference: reference.clone(),
            encoded,
            historical: None,
            complete: false,
        });
        let owner = completed.as_mut().ok_or_else(invalid)?;
        owner.encoded.extend_from_slice(self.input);
        self.reconstruct_complete_into(&mut owner.historical)?;
        // The immutable plan and same final encoded bank remain in custody;
        // completed data cannot subsequently escape through a mutable getter.
        owner
            .reference
            .verify(&owner.encoded)
            .map_err(|_| invalid())?;
        owner.complete = true;
        Ok(())
    }
}

fn read_restore_owner(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<super::assigned_restore::HistoricalCompleteRestoreOwner>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let mut fields = Fields::array(input)?;
    tag(&mut fields, "complete-restore")?;
    let mut tuple = Fields::array(next(&mut fields)?)?;
    tag(&mut tuple, "complete")?;
    let original = next(&mut tuple)?;
    let bytes = next(&mut tuple)?;
    let capacity =
        usize::try_from(super::typed::unsigned(next(&mut tuple)?)?).map_err(|_| invalid())?;
    let slot =
        usize::try_from(super::typed::unsigned(next(&mut tuple)?)?).map_err(|_| invalid())?;
    let response = next(&mut tuple)?;
    tag(
        &mut tuple,
        "original-physical-cut-retained-by-opaque-owner-not-portable-time",
    )?;
    tuple.finish()?;
    let plan =
        super::assigned_restore::ValidatedHistoricalAssignedCompleteRestore::validate_fields(
            original,
            bytes,
            capacity,
            slot,
            response,
            ledger.rows.clone(),
            ledger.limits,
        )?;
    ledger.rows = plan.remaining_records();
    let assigned = if build {
        Some(plan.reconstruct()?)
    } else {
        None
    };
    let mapping = ledger.read::<crucible_node_contract::ContentRef>(next(&mut fields)?, build)?;
    let mut nonce_fields = Fields::array(next(&mut fields)?)?;
    let mut nonce = [0u8; 32];
    for byte in &mut nonce {
        *byte = u8::try_from(super::typed::unsigned(next(&mut nonce_fields)?)?)
            .map_err(|_| invalid())?;
    }
    nonce_fields.finish()?;
    tag(&mut fields, "original-prepared-mapping-retained")?;
    let layout = ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        std::mem::align_of::<crate::protocol_snapshot::ArchivedProtocolMappingIdentity>(),
    )?;
    if layout != std::mem::size_of::<crate::protocol_snapshot::ArchivedProtocolMappingIdentity>() {
        return Err(invalid());
    }
    ledger.shared(
        crate::retained_metadata::aliases::MetadataSharedKind::ArchivedMapping,
        layout,
        b"historical-prepared-mapping",
        b"",
    )?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(
        super::assigned_restore::HistoricalCompleteRestoreOwner {
            assigned: assigned.ok_or_else(invalid)?,
            mapping: mapping.ok_or_else(invalid)?,
            nonce,
        },
    ))
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalConnection,
    authority,
    correlations,
    codec,
    frames,
    reader,
    packet_schema,
    connected_packet_schema,
    fenced
);
super::retained_storage::fields!(
    HistoricalClientSession,
    connection,
    authority,
    sequence,
    peer_pid,
    peer_executable,
    hello
);
super::retained_storage::fields!(
    HistoricalClientCustody,
    maximum_requests,
    maximum_bytes,
    retained_bytes,
    controller,
    provider,
    content
);
super::retained_storage::fields!(
    HistoricalControllerState,
    node,
    execution_owner,
    budget_seconds,
    budget_nanoseconds,
    fenced,
    profile,
    session,
    custody,
    assigned,
    supervisor,
    complete_restore,
    restore_owner_covered
);

super::retained_storage::fields!(
    SealedHistoricalControllerState,
    reference,
    encoded,
    historical,
    complete
);

impl SealedHistoricalControllerState {
    /// Observes this actual sealed historical owner's initialized retained graph.
    ///
    /// Includes partial decoder roots and actual encoded/typed capacities. This
    /// raw data loan invokes no live callback, decoder, serializer, I/O or grant.
    /// The enclosing original owner checks its own creator before this loan.
    ///
    /// # Errors
    /// Refuses typed traversal limits or checked metadata/layout overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, crate::ProviderError> {
        super::retained_storage::facts(self)
    }

    /// Names the fixed explicit counter/views before the raw historical walk.
    pub fn original_retained_metadata_counter_scratch_data() -> usize {
        super::retained_storage::counter_scratch_data()
    }
}

#[cfg(test)]
mod retained_owner_tests {
    use super::*;

    #[test]
    fn partial_sealed_owner_observes_actual_growth_without_completing_decode() {
        let reference =
            crucible_node_contract::canonical::content_ref(b"[]", "application/json").unwrap();
        let mut owner = SealedHistoricalControllerState {
            reference,
            encoded: Vec::with_capacity(17),
            historical: None,
            complete: false,
        };
        owner.encoded.extend_from_slice(b"[");
        let original_capacity = owner.encoded.capacity();

        let before = owner.original_retained_metadata_facts().unwrap();
        owner
            .encoded
            .try_reserve_exact(original_capacity + 1)
            .unwrap();
        let after = owner.original_retained_metadata_facts().unwrap();

        assert_eq!(before.vector_capacity_bytes, original_capacity);
        assert_eq!(after.vector_capacity_bytes, owner.encoded.capacity());
        assert!(after.vector_capacity_bytes > before.vector_capacity_bytes);
        assert_eq!(owner.encoded, b"[");
        assert!(owner.historical().is_err());
        assert!(!owner.complete);
    }
}
