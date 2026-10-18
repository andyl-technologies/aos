//! Admits and reconstructs complete native eleven archives as historical data.
//!
//! ```text
//! ["source-private.cnp-protocol/11",["source-private.native-state/11",connection,blobs,service],records,aliases]
//! ```
//!
//! The decoder never creates a current connection, cut, boot issuer or source
//! association. A measured source factory authenticates signed provenance and
//! fresh target context separately before any live enrollment.

use super::super::{
    aliases::{HistoricalAliasSummary, ValidatedHistoricalAliases},
    outer::{OwnedProtocol11AllocationDemand, OwnedProtocol11DataLimits},
    state::{next, tag},
    typed::{Fields, invalid},
};
use super::{
    blob::HistoricalNativeBlobReceiver,
    connection::HistoricalNativeConnection,
    service::HistoricalNativeService,
    shared::{NativeArchiveClass, NativeLedger, NativeSharedEntry},
};
use crate::{ProviderError, retained_metadata::records::ValidatedMetadataRecords};

/// Identifies the explicit native class containing actual reader and token data.
pub const COMPLETE_NATIVE_CONNECTION_FORMAT: &str = "source-private.native-connection-complete/11";
/// Identifies the complete service-root class, including original typed registrar.
pub const COMPLETE_NATIVE_SERVICE_FORMAT: &str = "source-private.native-service/11";
/// Identifies the four-leaf class retaining the completed original Observe owner.
pub const COMPLETE_NATIVE_CAPTURE_ALLOCATION_FORMAT: &str = "source-private.native-state/12";
/// Identifies the three-leaf class owning the complete original boot6 startup.
pub const COMPLETE_NATIVE_STARTUP_FORMAT: &str = "source-private.native-state/13";
/// Identifies the four-leaf class owning boot6 and the actual Capture original.
pub const COMPLETE_NATIVE_STARTUP_CAPTURE_FORMAT: &str = "source-private.native-state/14";
/// Identifies the startup-aware complete connection leaf.
pub const COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT: &str =
    "source-private.native-connection-complete-startup/14";
/// Identifies the startup-aware complete service leaf.
pub const COMPLETE_NATIVE_STARTUP_SERVICE_FORMAT: &str = "source-private.native-service/14";

/// Identifies only the genuine original-purpose boot7/four-owner archive.
pub const COMPLETE_NATIVE_INVOCATION_CAPTURE_FORMAT: &str = "source-private.native-state/15";
/// Identifies the complete purpose-aware connection leaf.
pub const COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT: &str =
    "source-private.native-connection-complete-invocation/15";
/// Identifies the complete purpose-aware service leaf.
pub const COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT: &str = "source-private.native-service/15";

/// Reports all known native requested backing and reconstruction temporary terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedProtocol11AllocationDemand {
    /// Reports complete recorded backing, typed trees and alias summary demands.
    pub recorded: OwnedProtocol11AllocationDemand,
    /// Reports the simultaneous native group-to-final-Rc lookup bank.
    pub native_group_lookup_bytes: usize,
    /// Reports reconstructed historical shared payload layouts per retained view.
    pub historical_payload_layout_bytes: usize,
    /// Reports the declared fixed pin-identity scratch used after reconstruction.
    pub semantic_validation_stack_bytes: usize,
}

/// Owns complete historical native data without live transport or install rights.
pub struct HistoricalNativeState {
    /// Retains actual connection, reader, admission and literal history data.
    pub connection: HistoricalNativeConnection,
    /// Retains full native receiver, transfer, pin and retirement histories.
    pub blobs: HistoricalNativeBlobReceiver,
    /// Retains all successful closed service roots and aliases.
    pub service: HistoricalNativeService,
    /// Retains the complete original Observe allocation owner in the selected class.
    pub capture_allocation: Option<super::capture_owner::HistoricalNativeCaptureAllocationOwner>,
}

impl HistoricalNativeState {
    /// Checks exact repeated owner/literal relationships after storing this owner.
    ///
    /// # Errors
    /// Refuses changed original bytes, alias groups or inconsistent service roots.
    pub fn authenticate_capture_correspondence(&self) -> Result<(), ProviderError> {
        use std::rc::Rc;
        let connection = &self.connection;
        connection.admission.authenticate_correspondence()?;
        self.blobs.authenticate_state()?;
        self.service
            .bootstrap
            .authenticate_correspondence(&connection.admission)?;
        if connection.actor_group != connection.admission.identity.actor_group
            || !Rc::ptr_eq(&connection.policy, &connection.admission.policy)
            || !Rc::ptr_eq(&connection.frames, &connection.admission.identity.frames)
            || !Rc::ptr_eq(&self.service.endpoint_boot, &connection.admission.boot)
            || !Rc::ptr_eq(&self.service.endpoint_policy, &connection.policy)
            || !Rc::ptr_eq(&connection.blob_ledger, &self.blobs.state)
            || connection.supervisor_group != self.blobs.supervisor_group
            || connection.supervisor_group != self.service.supervisor_group
        {
            return Err(invalid());
        }
        if let Some(phase) = &connection.admission.boot.invocation {
            phase.authenticate_connection(connection)?;
        }
        match (&self.capture_allocation, connection.policy.capture_allocation_selection) {
            (None, None) => {}
            (Some(owner), Some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)) => owner.authenticate_connection(connection)?,
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

/// Borrows a fully checked native archive and caller-precharged alias summaries.
pub struct ValidatedNativeOwnedProtocol11<'a, 'scratch> {
    input: &'a [u8],
    data: &'a [u8],
    records: ValidatedMetadataRecords<'a>,
    aliases: ValidatedHistoricalAliases<'a, 'scratch>,
    limits: OwnedProtocol11DataLimits,
    demand: NativeOwnedProtocol11AllocationDemand,
    correlation_capacity_span: (usize, usize),
}

fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeState>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let format = super::super::typed::plain_string(next(&mut fields)?)?;
    let class = NativeArchiveClass::read(format)?;
    ledger.select_class(class)?;
    let connection = super::connection::read(next(&mut fields)?, ledger, build)?;
    let blobs = super::blob::read_receiver(
        next(&mut fields)?,
        ledger,
        build,
        crate::reference_packet::service::original_native_supervisor_layout(),
    )?;
    let service = super::service::read(next(&mut fields)?, ledger, build)?;
    let capture_allocation = if class.capture() {
        super::capture_owner::read(next(&mut fields)?, ledger, build)?
    } else {
        None
    };
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeState {
        connection: connection.ok_or_else(invalid)?,
        blobs: blobs.ok_or_else(invalid)?,
        service: service.ok_or_else(invalid)?,
        capture_allocation,
    }))
}

impl<'a, 'scratch> ValidatedNativeOwnedProtocol11<'a, 'scratch> {
    pub(crate) const fn validated_input_bytes_data(&self) -> &'a [u8] {
        self.input
    }

    pub(crate) const fn validated_data_limits_data(&self) -> OwnedProtocol11DataLimits {
        self.limits
    }

    /// Checks complete framing, all typed owners, alias views and capacity rows.
    ///
    /// # Errors
    /// Refuses malformed or partial classes, excess limits, changed shared views,
    /// unfinished reader state, missing original owners or unconsumed rows.
    pub fn validate(
        input: &'a [u8],
        limits: OwnedProtocol11DataLimits,
        summaries: &'scratch mut [HistoricalAliasSummary],
    ) -> Result<Self, ProviderError> {
        if input.len() > limits.json.maximum_input_bytes {
            return Err(invalid());
        }
        super::super::outer::validate_outer_work(input, limits.json.maximum_nodes)?;
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.cnp-protocol/11")?;
        let data = next(&mut fields)?;
        let records = ValidatedMetadataRecords::validate(
            next(&mut fields)?,
            limits.maximum_metadata_rows,
            limits.json.maximum_owned_backing_bytes,
        )?;
        let mut aliases = ValidatedHistoricalAliases::validate(
            next(&mut fields)?,
            summaries,
            limits.maximum_metadata_rows,
        )?;
        fields.finish()?;
        let mut recorded = super::super::outer::demand_records(&records)?;
        if recorded.tree_entries > limits.json.maximum_tree_entries {
            return Err(invalid());
        }
        let mut ledger = super::super::outer::make_ledger(&records, limits);
        ledger.aliases = Some(aliases.views()?);
        let mut native = NativeLedger {
            class: None,
            ledger: &mut ledger,
            groups: None,
            historical_payload_layout_bytes: 0,
            correlation_capacity_span: None,
        };
        read(data, &mut native, false)?;
        let startup_class = native.requires_startup_class()?;
        let invocation_class = native.requires_invocation_class()?;
        let historical_payload_layout_bytes = native.historical_payload_layout_bytes;
        let correlation_capacity_span = native.correlation_capacity_span.ok_or_else(invalid)?;
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.aliases.take().ok_or_else(invalid)?.finish()?;
        recorded.literal_backing_bytes = ledger.literal_bytes;
        recorded.content_group_lookup_bytes = ledger.content_group_lookup_bytes;
        recorded.selected_slice_staging_bytes = ledger.selected_slice_staging_bytes;
        recorded.alias_groups = aliases.group_count();
        recorded.alias_rows = aliases.row_count();
        recorded.alias_summary_entries = aliases.group_count();
        recorded.alias_summary_layout_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<HistoricalAliasSummary>())
            .ok_or_else(invalid)?;
        recorded.selected_group_lookup_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<
                Option<std::sync::Arc<[crucible_node_contract::ExtensionSelection]>>,
            >())
            .ok_or_else(invalid)?;
        let native_group_lookup_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<NativeSharedEntry>())
            .ok_or_else(invalid)?;
        Ok(Self {
            input,
            data,
            records,
            aliases,
            limits,
            correlation_capacity_span,
            demand: NativeOwnedProtocol11AllocationDemand {
                recorded,
                native_group_lookup_bytes,
                historical_payload_layout_bytes,
                semantic_validation_stack_bytes: super::blob::PIN_IDENTITY_SCRATCH_BYTES
                    .checked_add(if invocation_class {
                        super::invocation::declared_scratch_bytes()
                    } else if startup_class {
                        super::startup::declared_scratch_bytes()
                    } else {
                        0
                    })
                    .ok_or_else(invalid)?,
            },
        })
    }

    /// Borrows the simultaneous known allocation demand without copying owners.
    pub const fn allocation_demand(&self) -> &NativeOwnedProtocol11AllocationDemand {
        &self.demand
    }

    /// Returns the required native connection and service format identities.
    ///
    /// # Errors
    /// Refuses a partial compatibility class; validation never infers missing fields.
    pub fn complete_schema_identity(&self) -> Result<(&'static str, &'static str), ProviderError> {
        self.authenticate_class(NativeArchiveClass::Legacy11)?;
        Ok((
            COMPLETE_NATIVE_CONNECTION_FORMAT,
            COMPLETE_NATIVE_SERVICE_FORMAT,
        ))
    }

    /// Returns the exact old four-owner class and its connection/service identities.
    ///
    /// # Errors
    /// Refuses startup editions or a missing actual Capture original.
    pub fn complete_capture_allocation_schema_identity(
        &self,
    ) -> Result<(&'static str, &'static str, &'static str), ProviderError> {
        self.authenticate_class(NativeArchiveClass::Capture12)?;
        Ok((
            COMPLETE_NATIVE_CAPTURE_ALLOCATION_FORMAT,
            COMPLETE_NATIVE_CONNECTION_FORMAT,
            COMPLETE_NATIVE_SERVICE_FORMAT,
        ))
    }

    /// Returns the explicit startup three-root historical class.
    ///
    /// # Errors
    /// Refuses another edition, missing startup leaves or selected Capture state.
    pub fn complete_native_startup_schema_identity(
        &self,
    ) -> Result<(&'static str, &'static str, &'static str), ProviderError> {
        self.authenticate_class(NativeArchiveClass::Startup13)?;
        Ok((
            COMPLETE_NATIVE_STARTUP_FORMAT,
            COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT,
            COMPLETE_NATIVE_STARTUP_SERVICE_FORMAT,
        ))
    }

    /// Returns the explicit startup four-root historical Capture class.
    ///
    /// # Errors
    /// Refuses another edition or an absent actual Capture original.
    pub fn complete_native_startup_capture_allocation_schema_identity(
        &self,
    ) -> Result<(&'static str, &'static str, &'static str), ProviderError> {
        self.authenticate_class(NativeArchiveClass::StartupCapture14)?;
        Ok((
            COMPLETE_NATIVE_STARTUP_CAPTURE_FORMAT,
            COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT,
            COMPLETE_NATIVE_STARTUP_SERVICE_FORMAT,
        ))
    }

    /// Returns the explicit original-invocation class and exact complete leaves.
    ///
    /// This identifies validated historical data only. Full typed/alias owner
    /// reconstruction and original literal correspondence remain mandatory.
    ///
    /// # Errors
    /// Refuses every legacy/prototype class, wrong policy family or absent
    /// genuine-original phase and actual Capture owner.
    pub fn complete_native_invocation_capture_schema_identity(
        &self,
    ) -> Result<(&'static str, &'static str, &'static str), ProviderError> {
        self.authenticate_class(NativeArchiveClass::InvocationCapture15)?;
        Ok((
            COMPLETE_NATIVE_INVOCATION_CAPTURE_FORMAT,
            COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
            COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT,
        ))
    }

    fn authenticate_class(&self, expected: NativeArchiveClass) -> Result<(), ProviderError> {
        let mut fields = Fields::array(self.data)?;
        if NativeArchiveClass::read(super::super::typed::plain_string(next(&mut fields)?)?)?
            != expected
        {
            return Err(invalid());
        }
        let mut connection = Fields::array(next(&mut fields)?)?;
        tag(
            &mut connection,
            if expected.invocation() {
                COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT
            } else if expected.startup() {
                COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT
            } else {
                COMPLETE_NATIVE_CONNECTION_FORMAT
            },
        )?;
        for _ in 0..3 {
            next(&mut connection)?;
        }
        let mut codec = Fields::array(next(&mut connection)?)?;
        tag(&mut codec, "source-private.native-codec/11")?;
        let mut policy = Fields::array(next(&mut codec)?)?;
        let policy_tag = super::super::typed::plain_string(next(&mut policy)?)?;
        // Invocation15 owns only genuine-original history with no Query or
        // transfer cache. Legacy classes remain closed to fresh policy18.
        if expected.invocation() {
            if policy_tag != "source-private.native5-policy-owned-fresh-restore-allocation/18" {
                return Err(invalid());
            }
        } else if policy_tag == "source-private.native5-policy-owned-fresh-restore-allocation/18"
            || (policy_tag == "source-private.native5-policy-owned-capture-allocation/17")
                != expected.capture()
        {
            return Err(invalid());
        }
        next(&mut fields)?;
        let mut service = Fields::array(next(&mut fields)?)?;
        tag(
            &mut service,
            if expected.invocation() {
                COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT
            } else if expected.startup() {
                COMPLETE_NATIVE_STARTUP_SERVICE_FORMAT
            } else {
                COMPLETE_NATIVE_SERVICE_FORMAT
            },
        )?;
        if expected.capture() {
            let mut owner = Fields::array(next(&mut fields)?)?;
            tag(
                &mut owner,
                "source-private.native-capture-allocation-owner/12",
            )?;
            for _ in 0..9 {
                next(&mut owner)?;
            }
            if next(&mut owner)? == b"null" {
                return Err(invalid());
            }
            owner.finish()?;
        }
        fields.finish()
    }

    /// Reconstructs the explicit original-invocation historical owning graph.
    ///
    /// # Errors
    /// Refuses another class, foreign purpose/phase, incomplete graph or changed
    /// aliases/literals. The owning output remains retained on later refusal.
    pub fn reconstruct_native_invocation_capture_into(
        &mut self,
        completed: &mut Option<HistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_native_invocation_capture_schema_identity()?;
        self.reconstruct_after_class_check(completed)
    }

    /// Reconstructs only the explicit startup three-root historical class.
    ///
    /// # Errors
    /// Refuses another class, occupied output or failed exact correspondence.
    pub fn reconstruct_native_startup_into(
        &mut self,
        completed: &mut Option<HistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_native_startup_schema_identity()?;
        self.reconstruct_after_class_check(completed)
    }

    /// Reconstructs only the explicit startup four-root historical Capture class.
    ///
    /// # Errors
    /// Refuses another class, occupied output or failed exact correspondence.
    pub fn reconstruct_native_startup_capture_allocation_into(
        &mut self,
        completed: &mut Option<HistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_native_startup_capture_allocation_schema_identity()?;
        self.reconstruct_after_class_check(completed)
    }

    /// Reconstructs the explicitly admitted four-owner historical class.
    ///
    /// # Errors
    /// Refuses another class, occupied output, allocation or correspondence errors.
    /// Completed or partial owning data remains in the caller's output slot.
    pub fn reconstruct_capture_allocation_into(
        &mut self,
        completed: &mut Option<HistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_capture_allocation_schema_identity()?;
        self.reconstruct_after_class_check(completed)
    }

    /// Retains final data owners before checking repeated physical correspondence.
    ///
    /// The source admits this complete report plus encoded payload, actual alias
    /// bank and physical tree/control-block/stack terms before reconstruction.
    ///
    /// # Errors
    /// Refuses occupied output, failed exact allocations or correspondence. A
    /// completed owner remains in the caller's slot on defensive refusal.
    pub fn reconstruct_complete_into(
        &mut self,
        completed: &mut Option<HistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_schema_identity()?;
        self.reconstruct_after_class_check(completed)
    }

    fn reconstruct_after_class_check(
        &mut self,
        completed: &mut Option<HistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(invalid());
        }
        let count = self.aliases.group_count();
        let mut groups = Vec::new();
        groups.try_reserve_exact(count).map_err(|_| invalid())?;
        if groups.capacity() != count {
            return Err(invalid());
        }
        groups.resize_with(count, NativeSharedEntry::default);
        let mut selected = Vec::new();
        selected.try_reserve_exact(count).map_err(|_| invalid())?;
        if selected.capacity() != count {
            return Err(invalid());
        }
        selected.resize_with(count, || None);
        let mut ledger = super::super::outer::make_ledger(&self.records, self.limits);
        ledger.aliases = Some(self.aliases.views()?);
        ledger.selected_groups = Some(&mut selected);
        let mut native = NativeLedger {
            class: None,
            ledger: &mut ledger,
            groups: Some(&mut groups),
            historical_payload_layout_bytes: 0,
            correlation_capacity_span: None,
        };
        *completed = Some(read(self.data, &mut native, true)?.ok_or_else(invalid)?);
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.aliases.take().ok_or_else(invalid)?.finish()?;
        completed
            .as_ref()
            .ok_or_else(invalid)?
            .authenticate_capture_correspondence()
    }
}

/// Retains a decoder-produced state beside its exact verified encoded body.
///
/// This opaque data owner provides no original cut, key, registrar or native
/// installation right. Its immutable loan prevents arbitrary public historical
/// fields from being substituted after body verification. Fresh source/key
/// proof and target context remain separate requirements.
pub struct SealedHistoricalNativeState {
    reference: crucible_node_contract::ContentRef,
    encoded: Vec<u8>,
    historical: Option<HistoricalNativeState>,
    correlation_capacity_span: (usize, usize),
    complete: bool,
}

impl SealedHistoricalNativeState {
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
    pub fn historical(&self) -> Result<&HistoricalNativeState, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        self.historical.as_ref().ok_or_else(invalid)
    }
}

impl ValidatedNativeOwnedProtocol11<'_, '_> {
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
        completed: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_schema_identity()?;
        self.reconstruct_sealed_after_class_check(
            reference,
            encoded_bank,
            completed,
            NativeArchiveClass::Legacy11,
        )
    }

    /// Retains exact verified bytes and the admitted four-owner historical class.
    ///
    /// # Errors
    /// Refuses another class, occupied output, insufficient preowned bank, changed
    /// full reference, failed allocation or any typed/raw/alias correspondence.
    pub fn reconstruct_capture_allocation_sealed_into(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_capture_allocation_schema_identity()?;
        self.reconstruct_sealed_after_class_check(
            reference,
            encoded_bank,
            completed,
            NativeArchiveClass::Capture12,
        )
    }

    /// Seals the explicit startup three-root historical class into preowned storage.
    ///
    /// # Errors
    /// Refuses wrong class, full reference, output occupancy or allocation/correspondence failure.
    pub fn reconstruct_native_startup_sealed_into(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_native_startup_schema_identity()?;
        self.reconstruct_sealed_after_class_check(
            reference,
            encoded_bank,
            completed,
            NativeArchiveClass::Startup13,
        )
    }

    /// Seals the explicit startup four-root historical class into preowned storage.
    ///
    /// # Errors
    /// Refuses wrong class, full reference, output occupancy or allocation/correspondence failure.
    pub fn reconstruct_native_startup_capture_allocation_sealed_into(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_native_startup_capture_allocation_schema_identity()?;
        self.reconstruct_sealed_after_class_check(
            reference,
            encoded_bank,
            completed,
            NativeArchiveClass::StartupCapture14,
        )
    }

    /// Seals only the complete original-invocation class in preowned byte storage.
    ///
    /// # Errors
    /// Refuses changed full references, another class, occupied storage, capacity
    /// overrun or any typed/alias/original correspondence failure. Partial owners
    /// stay in the same output slot; inert data supplies no restoration rights.
    pub fn reconstruct_native_invocation_capture_sealed_into(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), ProviderError> {
        self.complete_native_invocation_capture_schema_identity()?;
        self.reconstruct_sealed_after_class_check(
            reference,
            encoded_bank,
            completed,
            NativeArchiveClass::InvocationCapture15,
        )
    }

    fn reconstruct_sealed_after_class_check(
        &mut self,
        reference: &crucible_node_contract::ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalNativeState>,
        class: NativeArchiveClass,
    ) -> Result<(), ProviderError> {
        if completed.is_some()
            || encoded_bank
                .as_ref()
                .is_none_or(|bank| !bank.is_empty() || bank.capacity() < self.input.len())
        {
            return Err(invalid());
        }
        reference.verify(self.input).map_err(|_| invalid())?;
        let encoded = encoded_bank.take().ok_or_else(invalid)?;
        *completed = Some(SealedHistoricalNativeState {
            reference: reference.clone(),
            encoded,
            historical: None,
            correlation_capacity_span: self.correlation_capacity_span,
            complete: false,
        });
        let owner = completed.as_mut().ok_or_else(invalid)?;
        owner.encoded.extend_from_slice(self.input);
        self.authenticate_class(class)?;
        self.reconstruct_after_class_check(&mut owner.historical)?;
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

/// Reports actual compiled layouts used by the independent restore preflight.
///
/// These sizes describe this historical decoder, not an allocator allowance or
/// a portable layout ABI. The installed source/backend identity pins this code.
pub(crate) fn original_restore_decoder_layouts() -> (usize, usize, usize, usize) {
    use std::mem::{align_of, size_of};
    let payload = [
        size_of::<super::policy::HistoricalNativePolicy>(),
        size_of::<super::boot::HistoricalNativeBoot>(),
        size_of::<crate::transport::DecodedCompactOriginalFrames>(),
        size_of::<super::blob::HistoricalNativeBlobLedger>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let alignment = [
        align_of::<super::policy::HistoricalNativePolicy>(),
        align_of::<super::boot::HistoricalNativeBoot>(),
        align_of::<crate::transport::DecodedCompactOriginalFrames>(),
        align_of::<super::blob::HistoricalNativeBlobLedger>(),
        align_of::<crucible_node_contract::ExtensionSelection>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(1);
    (
        size_of::<NativeSharedEntry>(),
        payload,
        alignment,
        size_of::<HistoricalNativeState>(),
    )
}

#[path = "predecessor.rs"]
mod predecessor;

#[cfg(test)]
mod startup_class_tests {
    use super::*;
    use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};

    #[test]
    fn invocation_class_and_legacy_leaves_refuse_each_other_before_capacity_consumption() {
        let records = ValidatedMetadataRecords::validate(b"[]", 8, 8192).unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 8192,
            maximum_nodes: 256,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 8192,
            maximum_tree_entries: 64,
        };
        // Incomplete parser banks exercise only the class/leaf boundary. They
        // are neither native owners nor signed, reconstructible captures.
        for (format, leaf) in [
            (
                COMPLETE_NATIVE_INVOCATION_CAPTURE_FORMAT,
                COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT,
            ),
            (
                COMPLETE_NATIVE_STARTUP_CAPTURE_FORMAT,
                COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
            ),
            (
                COMPLETE_NATIVE_STARTUP_FORMAT,
                COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT,
            ),
        ] {
            let encoded = serde_json::to_vec(&(format, (leaf,), (), ())).unwrap();
            let mut ledger = Ledger::new(records.rows(), limits);
            let mut native = NativeLedger {
                class: None,
                ledger: &mut ledger,
                groups: None,
                historical_payload_layout_bytes: 0,
                correlation_capacity_span: None,
            };

            assert!(read(&encoded, &mut native, false).is_err());
            assert_eq!(
                native.requires_invocation_class().unwrap(),
                format == COMPLETE_NATIVE_INVOCATION_CAPTURE_FORMAT
            );
            assert_eq!(native.historical_payload_layout_bytes, 0);
            assert!(native.ledger.rows.next().is_none());
        }
    }

    #[test]
    fn original_startup_class_rejects_legacy_connection_before_capacity_consumption() {
        let records = ValidatedMetadataRecords::validate(b"[]", 8, 8192).unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 8192,
            maximum_nodes: 256,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 8192,
            maximum_tree_entries: 64,
        };
        for format in [
            "source-private.native-state/13",
            "source-private.native-state/14",
        ] {
            let encoded =
                serde_json::to_vec(&(format, (COMPLETE_NATIVE_CONNECTION_FORMAT,), (), ()))
                    .unwrap();
            let mut ledger = Ledger::new(records.rows(), limits);
            let mut native = NativeLedger {
                class: None,
                ledger: &mut ledger,
                groups: None,
                historical_payload_layout_bytes: 0,
                correlation_capacity_span: None,
            };

            assert!(read(&encoded, &mut native, false).is_err());
            assert!(native.requires_startup_class().unwrap());
            assert_eq!(native.historical_payload_layout_bytes, 0);
            assert!(native.ledger.rows.next().is_none());
        }
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeState,
    connection,
    blobs,
    service,
    capture_allocation
);

super::super::retained_storage::fields!(
    SealedHistoricalNativeState,
    reference,
    encoded,
    historical,
    correlation_capacity_span,
    complete
);

impl SealedHistoricalNativeState {
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
        super::super::retained_storage::facts(self)
    }

    /// Names the fixed explicit counter/views before the raw historical walk.
    pub fn original_retained_metadata_counter_scratch_data() -> usize {
        super::super::retained_storage::counter_scratch_data()
    }
}

impl SealedHistoricalNativeState {
    /// Checks the exact selected encoded class against its completed typed owner.
    ///
    /// This allocation-free DATA loan creates no Source, native token, mapping
    /// permission or renewed historical registration. Old/partial classes refuse.
    pub(crate) fn original_selected_restoration_mapping_class_data(
        &self,
    ) -> Result<crate::protocol_snapshot::RestorationMappingClass, ProviderError> {
        let historical = self.historical()?;
        let boot = &historical.connection.admission.boot;
        if historical.capture_allocation.is_none() || boot.startup.is_none() {
            return Err(invalid());
        }
        let mut outer = Fields::array(self.encoded_body())?;
        tag(&mut outer, "source-private.cnp-protocol/11")?;
        let mut data = Fields::array(next(&mut outer)?)?;
        let class = super::super::typed::plain_string(next(&mut data)?)?;
        match (class, boot.invocation.is_some()) {
            (COMPLETE_NATIVE_STARTUP_CAPTURE_FORMAT, false) => {
                Ok(crate::protocol_snapshot::RestorationMappingClass::StartupCapture14)
            }
            (COMPLETE_NATIVE_INVOCATION_CAPTURE_FORMAT, true) => {
                Ok(crate::protocol_snapshot::RestorationMappingClass::InvocationCapture15)
            }
            _ => Err(invalid()),
        }
    }

    /// Names the exact fixed selected-class cursor views before their data loan.
    pub(crate) fn original_selected_restoration_mapping_counter_scratch_data() -> usize {
        std::mem::size_of::<[Fields<'static>; 2]>()
            + 3 * std::mem::size_of::<&[u8]>()
            + std::mem::size_of::<(&str, bool)>()
            + std::mem::size_of::<&HistoricalNativeState>()
            + std::mem::size_of::<&super::boot::HistoricalNativeBoot>()
            + std::mem::size_of::<crate::protocol_snapshot::RestorationMappingClass>()
            + std::mem::size_of::<
                Result<crate::protocol_snapshot::RestorationMappingClass, ProviderError>,
            >()
    }
}

pub(crate) mod current17;
