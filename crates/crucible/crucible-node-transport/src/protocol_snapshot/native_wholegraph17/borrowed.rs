//! Validates the full immutable wire while borrowing concrete narrow consumers.

mod control;
mod groups;
pub(super) use control::SelectedControl17Pass;

use super::{
    NativeCurrentGraph17ReadLimits, NativeCurrentGraph17RootSpans,
    actor::{HistoricalNativeActor17, read_actor17_data},
};
use crate::ProviderError;
use crate::connection::{
    NativeBlobReceiver17GroupIds, NativeConnection17GroupIds, read_native17_blob_receiver_data,
    read_native17_codec_root_data, read_native17_frame_root_data,
    read_rooted_native17_connection_fields_data,
};
use crate::protocol_snapshot::{
    owned11::{
        json_value::HistoricalJsonLimits,
        typed::{Fields, Ledger, invalid, plain_string, unsigned},
    },
    restored_settled17::{
        aliases::{RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases},
        current_lineage17::{
            BorrowedCurrentBootLineage17, BorrowedMappingLineage17,
            read_shared_current_boot_lineage17_data, read_shared_current_mapping_lineage17_data,
        },
    },
};
use crate::reference_packet::{
    control::{
        CurrentControl17GroupIds, read_current_control_hold_root17_fields_data,
        read_current_control_identity17_data, read_current_rooted_control17_fields_data,
    },
    endpoint::{CurrentEndpoint17GroupIds, read_rooted_endpoint17_fields_data},
    service::{
        CurrentNativeService17GroupIds, NativeRegistrar17GroupIds,
        read_current_native17_registrar_root_data, read_current_native17_supervisor_root_data,
        read_rooted_current_native17_service_fields_data,
    },
};
use crate::retained_metadata::{
    aliases::MetadataSharedKind,
    records::{MetadataRecordKind, MetadataRecordRows, ValidatedMetadataRecords},
};
use groups::NativeCurrentGraph17Groups;
use std::{
    cell::Cell,
    mem::{align_of, size_of},
};

/// Pins one whole component to its actual source metadata cursor and row range.
pub(crate) struct NativeCurrentGraph17RowRange<'input> {
    start: MetadataRecordRows<'input>,
    encoded: &'input [u8],
    end: usize,
}

impl<'input> NativeCurrentGraph17RowRange<'input> {
    /// Borrows the exact source row bytes consumed for this component.
    pub(crate) fn encoded_data(&self) -> &'input [u8] {
        self.encoded
    }

    /// Replays from the exact original component position without a new bank.
    pub(crate) fn starting_rows_data(&self) -> MetadataRecordRows<'input> {
        self.start.clone()
    }

    /// Reports the exact endpoint of the checked component's source rows.
    pub(crate) fn ending_position_data(&self) -> usize {
        self.end
    }
}

/// Retains concrete whole-component row ranges for the narrow reconstruction.
pub(crate) struct NativeCurrentGraph17Rows<'input> {
    mapping: NativeCurrentGraph17RowRange<'input>,
    boot: NativeCurrentGraph17RowRange<'input>,
    connection: NativeCurrentGraph17RowRange<'input>,
    endpoint: NativeCurrentGraph17RowRange<'input>,
    control: NativeCurrentGraph17RowRange<'input>,
    service: NativeCurrentGraph17RowRange<'input>,
}

impl<'input> NativeCurrentGraph17Rows<'input> {
    /// Borrows the checked mapping component row range.
    pub(crate) fn mapping_data(&self) -> &NativeCurrentGraph17RowRange<'input> {
        &self.mapping
    }

    /// Borrows the checked Boot component row range.
    pub(crate) fn boot_data(&self) -> &NativeCurrentGraph17RowRange<'input> {
        &self.boot
    }

    /// Borrows the checked Connection component row range.
    pub(crate) fn connection_data(&self) -> &NativeCurrentGraph17RowRange<'input> {
        &self.connection
    }

    /// Borrows the checked Endpoint component row range.
    pub(crate) fn endpoint_data(&self) -> &NativeCurrentGraph17RowRange<'input> {
        &self.endpoint
    }

    /// Borrows the checked current Control/model component row range.
    pub(crate) fn control_data(&self) -> &NativeCurrentGraph17RowRange<'input> {
        &self.control
    }

    /// Borrows the checked Service component row range.
    pub(crate) fn service_data(&self) -> &NativeCurrentGraph17RowRange<'input> {
        &self.service
    }
}

/// Borrows fully checked immutable evidence and exact narrow consumer fields.
///
/// The constructor walks every known source field and all source aliases with
/// target ownership disabled. Old host heaps stay in the raw evidence. Only the
/// separately preflighted current Control/model and needed signed-lineage DTOs
/// enter the selected owning decoder; none of these data loans installs a live
/// endpoint, registrar lease, socket, native token or allocation grant.
pub(crate) struct BorrowedNativeCurrentGraph17Plan<'input, 'scratch> {
    roots: NativeCurrentGraph17RootSpans<'input>,
    records: ValidatedMetadataRecords<'input>,
    aliases: ValidatedRestoredSettledNative17Aliases<'input, 'scratch>,
    groups: NativeCurrentGraph17Groups,
    actor: HistoricalNativeActor17,
    mapping: BorrowedMappingLineage17<'input, 'input>,
    boot: BorrowedCurrentBootLineage17<'input, 'input>,
    rows: NativeCurrentGraph17Rows<'input>,
    maximum_requested: usize,
    input_length: usize,
    capture_original: Option<&'input [u8]>,
}

impl<'input, 'scratch> BorrowedNativeCurrentGraph17Plan<'input, 'scratch> {
    /// Checks the complete source graph before exposing any selected data loan.
    ///
    /// The caller retains and independently prices its raw input and alias
    /// scratch. `maximum_requested` bounds the later narrow target reconstruction,
    /// not the distinct immutable source owner's capacity layouts.
    ///
    /// # Errors
    /// Refuses malformed fields/rows, alias disagreement, unsupported active host
    /// state or any concrete Connection/Endpoint/Service correspondence failure.
    pub(crate) fn validate_data(
        input: &'input [u8],
        maximum_requested: usize,
        summaries: &'scratch mut [RestoredSettledNative17AliasSummary],
    ) -> Result<Self, ProviderError> {
        Self::validate_with_limits_data(
            input,
            NativeCurrentGraph17ReadLimits {
                maximum_requested,
                maximum_target_requested: maximum_requested,
                maximum_nodes: input.len().max(1),
                maximum_depth: 64,
            },
            summaries,
        )
    }

    /// Checks the complete wire under independently admitted parser axes.
    ///
    /// # Errors
    /// Refuses either parser-axis exhaustion or any complete graph disagreement.
    pub(crate) fn validate_with_limits_data(
        input: &'input [u8],
        limits: NativeCurrentGraph17ReadLimits,
        summaries: &'scratch mut [RestoredSettledNative17AliasSummary],
    ) -> Result<Self, ProviderError> {
        limits.authenticate_wire_data(input)?;
        let maximum_requested = limits.maximum_requested;
        let roots = NativeCurrentGraph17RootSpans::read(input)?;
        let records = ValidatedMetadataRecords::validate(roots.records, 131072, usize::MAX)?;
        let mut aliases = ValidatedRestoredSettledNative17Aliases::validate(
            roots.aliases,
            summaries,
            records.row_count(),
        )?;
        let mut ledger = make_ledger(&records, input.len(), limits);
        ledger.settled_aliases = Some(aliases.views()?);

        let (_, registrar) =
            read_current_native17_registrar_root_data(roots.registrar, &mut ledger, false)?;
        // The actor header is fixed inline DATA; it allocates no old owner.
        let (actor, actor_group) = read_actor17_data(roots.actor, &mut ledger, true)?;
        let actor = actor.ok_or_else(invalid)?;
        let (_, supervisor) =
            read_current_native17_supervisor_root_data(roots.supervisor, &mut ledger, false)?;
        let (_, codec, policy) = read_native17_codec_root_data(roots.codec, &mut ledger, false)?;
        let control_identity =
            read_current_control_identity17_data(roots.control_identity, &mut ledger)?;
        let hold = if roots.hold == b"null" {
            None
        } else {
            let (_, hold) =
                read_current_control_hold_root17_fields_data(roots.hold, &mut ledger, false)?;
            if hold.capture_identity != control_identity {
                return Err(invalid());
            }
            Some(hold.hold)
        };
        let (_, frames) = read_native17_frame_root_data(roots.frames, &mut ledger, false)?;
        let deadline = read_deadline(roots.deadline, &mut ledger)?;
        let start = ledger.rows.clone();
        let mapping = read_shared_current_mapping_lineage17_data(roots.mapping, &mut ledger)?;
        let mapping_rows = range(start, &ledger)?;

        let (_, receiver) = read_native17_blob_receiver_data(roots.receiver, &mut ledger, false)?;
        let start = ledger.rows.clone();
        let boot = read_shared_current_boot_lineage17_data(roots.boot, &mut ledger)?;
        let boot_rows = range(start, &ledger)?;

        let start = ledger.rows.clone();
        let (_, connection) =
            read_rooted_native17_connection_fields_data(&roots, &mut ledger, false)?;
        let connection_rows = range(start, &ledger)?;

        let start = ledger.rows.clone();
        let (_, endpoint) = read_rooted_endpoint17_fields_data(&roots, &mut ledger, false)?;
        let endpoint_rows = range(start, &ledger)?;

        let start = ledger.rows.clone();
        let (_, control) = read_current_rooted_control17_fields_data(&roots, &mut ledger, false)?;
        let control_rows = range(start, &ledger)?;

        let start = ledger.rows.clone();
        let (_, service) =
            read_rooted_current_native17_service_fields_data(&roots, &mut ledger, false)?;
        let service_rows = range(start, &ledger)?;
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.finish_aliases()?;

        let groups = NativeCurrentGraph17Groups {
            registrar,
            actor: actor_group,
            supervisor,
            codec,
            policy,
            control_identity,
            hold,
            frames,
            deadline,
            mapping: mapping.group_data(),
            receiver,
            boot: boot.group_data(),
            connection,
            endpoint,
            control,
            service,
        };
        groups.authenticate_roles_data()?;
        if actor.process != boot.creator || boot.policy_group_data() != policy {
            return Err(invalid());
        }

        let capture_original = capture_original(roots.boot_data())?;
        let plan = Self {
            roots,
            records,
            aliases,
            groups,
            actor,
            boot,
            mapping,
            rows: NativeCurrentGraph17Rows {
                mapping: mapping_rows,
                boot: boot_rows,
                connection: connection_rows,
                endpoint: endpoint_rows,
                control: control_rows,
                service: service_rows,
            },
            maximum_requested,
            input_length: input.len(),
            capture_original,
        };

        // These concrete borrowers check the formerly build-only semantic joins.
        // They return only actual fields of this same private whole plan.
        crate::connection::borrow_native17_connection_logical_data(&plan)?;
        crate::reference_packet::endpoint::borrow_native17_endpoint_logical_data(&plan)?;
        crate::reference_packet::service::borrow_current_native17_service_lineage_data(&plan)?;
        Ok(plan)
    }

    /// Preflights only the actual operational model and needed signed lineage.
    ///
    /// Caller-owned raw bytes, alias summaries and selected-slice cache banks
    /// remain separately priced. This count conveys no live native permission.
    ///
    /// # Errors
    /// Refuses changed source views, malformed cache state or exhausted credit.
    pub(crate) fn selected_target_demand_data(
        &mut self,
        limits: NativeCurrentGraph17ReadLimits,
        target_groups: &mut [bool],
        selected_groups: &mut [Option<
            std::sync::Arc<[crucible_node_format::ExtensionSelection]>,
        >],
    ) -> Result<usize, ProviderError> {
        self.replay_selected_control17_data(
            limits,
            SelectedControl17Pass::Preflight,
            target_groups,
            selected_groups,
        )
    }

    /// Borrows roots selected only by the enclosing exact graph grammar.
    pub(crate) fn root_spans_data(&self) -> &NativeCurrentGraph17RootSpans<'input> {
        &self.roots
    }

    /// Borrows actual metadata cursor ranges obtained in the complete same pass.
    pub(crate) fn rows_data(&self) -> &NativeCurrentGraph17Rows<'input> {
        &self.rows
    }

    /// Borrows canonical mapping normalization without cloning imported heaps.
    pub(crate) fn mapping_lineage_data(&self) -> &BorrowedMappingLineage17<'input, 'input> {
        &self.mapping
    }

    /// Borrows signed lineage selected inside the actual Boot source walk.
    pub(crate) fn boot_lineage_data(&self) -> &BorrowedCurrentBootLineage17<'input, 'input> {
        &self.boot
    }

    /// Returns actual Connection roles, never live registration or native rights.
    pub(crate) fn connection_groups_data(&self) -> NativeConnection17GroupIds {
        self.groups.connection
    }

    /// Returns actual Endpoint roles and source-preserved partial associations.
    pub(crate) fn endpoint_groups_data(&self) -> CurrentEndpoint17GroupIds {
        self.groups.endpoint
    }

    /// Returns actual Service/bootstrap lineage role associations.
    pub(crate) fn service_groups_data(&self) -> CurrentNativeService17GroupIds {
        self.groups.service
    }

    /// Returns actual registrar root ordinals from the complete source pass.
    pub(crate) fn registrar_groups_data(&self) -> NativeRegistrar17GroupIds {
        self.groups.registrar
    }

    /// Returns the actual same-pass current Control associations.
    pub(crate) fn control_groups_data(&self) -> CurrentControl17GroupIds {
        self.groups.control
    }

    /// Returns the actual current Boot's archive-local ordinal.
    pub(crate) fn boot_group_data(&self) -> usize {
        self.groups.boot
    }

    /// Returns the actual installed mapping's archive-local ordinal.
    pub(crate) fn mapping_group_data(&self) -> usize {
        self.groups.mapping
    }

    /// Returns the actual original actor's archive-local ordinal.
    pub(crate) fn actor_group_data(&self) -> usize {
        self.groups.actor
    }

    /// Returns the actual immutable policy's archive-local ordinal.
    pub(crate) fn policy_group_data(&self) -> usize {
        self.groups.policy
    }

    /// Returns the actual current frame bank's archive-local ordinal.
    pub(crate) fn frame_group_data(&self) -> usize {
        self.groups.frames
    }

    /// Returns the original creator scalar without reconstructing a live actor.
    pub(crate) fn creator_data(&self) -> u32 {
        self.actor.process
    }

    /// Borrows the actual current selected Capture original from the Boot reserve.
    pub(crate) fn capture_original_data(&self) -> Option<&'input [u8]> {
        self.capture_original
    }

    /// Borrows the actual active-recorder request, including a current Poll.
    pub(crate) fn current_action_original_data(&self) -> Option<&'input [u8]> {
        self.capture_original
    }

    /// Borrows the actual selected Capture-family phase fields from the same Boot walk.
    pub(crate) fn current_capture_phase17_data(
        &self
    ) -> Option<
        &crate::protocol_snapshot::restored_settled17::current_capture17_borrowed::BorrowedCurrentCapture17<
            'input, 'input
        >
    >{
        self.boot
            .reserve
            .current
            .as_ref()
            .and_then(|current| current.capture.as_ref())
    }

    /// Returns the independently supplied ceiling for actual narrow construction.
    pub(crate) fn maximum_requested_storage_data(&self) -> usize {
        self.maximum_requested
    }
}

fn range<'input>(
    start: MetadataRecordRows<'input>,
    ledger: &Ledger<'input, '_, '_>,
) -> Result<NativeCurrentGraph17RowRange<'input>, ProviderError> {
    Ok(NativeCurrentGraph17RowRange {
        encoded: ledger.rows.encoded_between(start.encoded_position())?,
        start,
        end: ledger.rows.encoded_position(),
    })
}

fn read_deadline(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    let marker = plain_string(input)?;
    if marker != "native-shared-operational-deadline-history-only" {
        return Err(invalid());
    }
    type Payload = Cell<crate::operational_time::OperationalDeadline>;
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Payload>())?
        != size_of::<Payload>()
    {
        return Err(invalid());
    }
    ledger.shared(
        MetadataSharedKind::OperationalDeadline,
        size_of::<Payload>(),
        marker.as_bytes(),
        b"",
    )
}

fn make_ledger<'input, 'scratch>(
    records: &ValidatedMetadataRecords<'input>,
    maximum_input_bytes: usize,
    limits: NativeCurrentGraph17ReadLimits,
) -> Ledger<'input, 'scratch, 'input> {
    let mut ledger = Ledger::new(
        records.rows(),
        HistoricalJsonLimits {
            maximum_input_bytes,
            maximum_nodes: limits.maximum_nodes,
            maximum_depth: limits.maximum_depth,
            maximum_owned_backing_bytes: usize::MAX,
            maximum_tree_entries: maximum_input_bytes,
        },
    );
    // Source-only duplicate literal/custody views do not allocate target heaps.
    ledger.maximum_literal_bytes = usize::MAX;
    ledger.content_limits = Some(crate::client::compact_metadata8::CompactMetadata8Limits {
        content: crate::client::compact_cursor::CompactContentLimits {
            max_input_bytes: maximum_input_bytes,
            max_rows: 8192,
            max_groups: 8192,
            max_first_group_capacity_bytes: usize::MAX,
        },
        maximum_metadata_capacity_bytes: usize::MAX,
    });
    ledger
}

// These selectors run only after the complete defining grammar/rows/aliases
// succeeded. They expose no alternative schema or independently supplied root.
fn field<'a>(input: &'a [u8], name: &str) -> Result<&'a [u8], ProviderError> {
    let mut fields = Fields::object(input)?;
    while let Some((key, value)) = fields.pair()? {
        if plain_string(key)? == name {
            return Ok(value);
        }
    }
    Err(invalid())
}

fn capture_original(input: &[u8]) -> Result<Option<&[u8]>, ProviderError> {
    let reserve = field(input, "settled_reserve")?;
    if reserve == b"null" {
        return Ok(None);
    }
    let current = field(reserve, "current")?;
    if current == b"null" {
        return Ok(None);
    }
    let current = usize::try_from(unsigned(current)?).map_err(|_| invalid())?;
    let mut attempts = Fields::array(field(reserve, "attempts")?)?;
    let mut index = 0usize;
    while let Some(attempt) = attempts.next_value()? {
        if index == current {
            let selected = field(attempt, "selected")?;
            if selected == b"null" {
                return Ok(None);
            }
            if plain_string(field(selected, "family")?)? != "capture" {
                return Ok(None);
            }
            let capture = field(selected, "data")?;
            let outputs = field(capture, "outputs")?;
            if outputs == b"null" {
                return Ok(None);
            }
            // A completed old occurrence is evidence, not the selected current
            // incoming Capture. Only the explicit active-recorder cut selects it.
            let mut fields = Fields::object(outputs)?;
            let Some((key, schema)) = fields.pair()? else {
                return Err(invalid());
            };
            if plain_string(key)? != "schema"
                || plain_string(schema)? != "source-private.native-capture-active-recorder-cut/17"
            {
                return Ok(None);
            }
            if field(attempt, "original")? != b"null"
                || field(attempt, "decoded")? != b"true"
                || field(attempt, "failed")? != b"false"
                || field(attempt, "ordinal")? != field(capture, "ordinal")?
            {
                return Err(invalid());
            }
            let original = field(capture, "original")?;
            if original == b"null" {
                return Err(invalid());
            }
            return Ok(Some(original));
        }
        index = index.checked_add(1).ok_or_else(invalid)?;
    }
    Err(invalid())
}
