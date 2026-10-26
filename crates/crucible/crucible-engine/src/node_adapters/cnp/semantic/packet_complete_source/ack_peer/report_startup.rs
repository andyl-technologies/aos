//! Finalizes the same private birth only with Core's original startup member.
//!
//! Construction retains the previous complete birth bank and all new partial
//! owners. The member is spent before this function is entered; any refusal
//! leaves its Source slot failed and prevents boot. Successful replacement keeps
//! the original key, birth ID, host registration and launch association.

use super::super::*;
use super::OriginalAckPeerBirth;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crate::node_admission::{OriginalReportStartupMember, StartupRows};
use crucible_node_transport::{
    reference_packet::service::{
        PacketNative5SourceLaunch, report_startup::PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA,
    },
    retained_metadata::{RetainedCompleteSourceMetadata, RetainedProtocolMetadataFacts},
};
use serde::{Serialize, ser::SerializeMap};
use std::{mem::size_of, rc::Rc};

pub(super) struct OriginalReportStartupFinalization {
    member: OriginalReportStartupMember,
    replacement: Vec<u8>,
    body: Option<serde_json::Value>,
    additions: Option<serde_json::Value>,
    complete: bool,
}

impl OriginalReportStartupFinalization {
    pub(super) fn authenticated_rows_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<StartupRows, crate::node_contract::RuntimeError> {
        if !self.complete {
            return Err(crate::node_contract::RuntimeError::OwnerUnavailable);
        }
        self.member
            .authenticate(source)
            .map_err(|_| crate::node_contract::RuntimeError::ForeignAuthority)?;
        Ok(self.member.rows)
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, OperationFailure> {
        self.retained_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let Self {
            member,
            replacement,
            body,
            additions,
            complete: _,
        } = self;
        retained_values::sum_with_error::<E, _>(
            [
                replacement.capacity(),
                body.as_ref()
                    .map(|value| retained_values::value_storage_with_error::<E>(value, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
                additions
                    .as_ref()
                    .map(|value| retained_values::value_storage_with_error::<E>(value, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
                E::member_headers(member)?,
            ],
            maximum,
        )
    }
}

impl PacketCompleteSemanticSource {
    /// Names fixed pre-Child Source observation/decoder/serializer scratch.
    ///
    /// These are actual compiled view, counter and fixed scanner layouts. They
    /// do not certify compiler frames, recursive serde stack, allocator rounding
    /// or external Host/factory counters, which remain separate resource terms.
    pub fn original_report_startup_observer_scratch_data() -> usize {
        let original_purpose = match Self::original_capture_invocation_counter_scratch_data() {
            Ok(bytes) => bytes,
            Err(_) => usize::MAX,
        };
        (size_of::<RetainedCompleteSourceMetadata<'_>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + Self::original_complete_installation_capacity_counter_scratch_data()
            + Self::original_complete_holder_capacity_counter_scratch_data()
            + Self::original_complete_host_startup_marker_capacity_counter_scratch_data()
            + retained_values::value_capacity_counter_scratch_data()
            + crucible_node_transport::retained_metadata::original_metadata_observer_layout_bytes()
            + size_of::<[usize; 7]>()
            + size_of::<StartupAdditions<'_>>()
            + size_of::<super::PacketCompleteAckPeerBootMaterial<'_>>()
            + size_of::<serde_json::Value>()
            + NodeRuntime::capture_selected_json_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + size_of::<blake3::Hasher>()
            + size_of::<[u8; super::HOST_EXECUTABLE_STREAM_BYTES]>()
            + 2 * size_of::<std::fs::File>()
            + 2 * size_of::<super::HostRevision>()
            + returned_layout(blake3::Hash::to_hex)
            + Self::original_invocation_snapshot_declaration_counter_scratch_data()
            + size_of::<Result<usize, crate::node_contract::RuntimeError>>()
            + size_of::<usize>())
        .saturating_add(original_purpose)
    }

    pub(crate) fn authenticate_original_report_startup_launch_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        self.authenticate_ack_birth_launch(launch)?;
        self.original_complete_report_startup_retained_storage_data(usize::MAX)?;
        if launch.capture_allocation_selection.is_none()
            && launch.fresh_restore_allocation_selection.is_none()
        {
            return Err(refused("original report startup has no selected purpose"));
        }
        Ok(())
    }

    pub(crate) fn original_report_startup_finalization_storage_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        rows: StartupRows,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.authenticate_original_report_startup_launch_data(launch)?;
        let slot = self.ack_peer_birth.try_borrow().map_err(unknown)?;
        let birth = slot
            .as_ref()
            .ok_or_else(|| refused("original report startup birth is absent"))?;
        if birth.report_startup.is_some() || !birth.report_startup_required {
            return Err(refused(
                "original report startup birth is already finalized or unselected",
            ));
        }
        let decode = NodeRuntime::capture_selected_json_decode_storage(
            &birth.source_birth,
            size_of::<serde_json::Value>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            maximum,
        )
        .map_err(unknown)?;
        let additions =
            NodeRuntime::capture_serialization_storage(&StartupAdditions { launch, rows }, maximum)
                .map_err(unknown)?;
        let registration = NodeRuntime::capture_selected_json_decode_storage(
            &birth.expected_host_registration,
            size_of::<serde_json::Value>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            maximum,
        )
        .map_err(unknown)?;
        let boot_fields = NodeRuntime::capture_serialization_storage(
            &BootFieldProjection {
                schema: "source-owned.packet-canonical-ack-private-boot/5",
                private_launch: &birth.private_launch,
                host_executable: &birth.host_executable,
                // Bytes serializes 32 octets as exactly 43 unpadded URL-safe ASCII
                // characters. These borrowed shape tokens count storage only; no
                // key, CNP Envelope or semantic value is manufactured by the quote.
                private_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                birth_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            maximum,
        )
        .map_err(unknown)?;
        let private_boot = retained_values::sum(
            [
                decode,
                additions,
                registration,
                boot_fields,
                // Two actual Bytes::new(key.to_vec()) inputs coexist with the DOM.
                2 * 32,
                super::super::frame::MAXIMUM_ACK_PRIVATE_BOOT_BYTES + 4,
                size_of::<PacketCompleteAckPeerBootFrame>(),
                // Two outer embedding edges add their actual map nodes and keys.
                2 * NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
                "source_birth".len() + "expected_host_registration".len(),
            ],
            maximum,
        )?;
        let weak = NodeRuntime::capture_shared_allocation_storage::<Self>();
        retained_values::sum([
            decode, additions, private_boot, birth.source_birth.capacity(), weak,
            // A member's Weak keeps the actual Plan allocation. Its owning
            // children are retained independently by the registered holder.
            crate::node_admission::InstalledConformancePlan::original_report_startup_plan_header_storage_data(),
            size_of::<OriginalReportStartupFinalization>(),
        ], maximum)
    }

    pub(crate) fn complete_original_report_startup_birth(
        self: &Rc<Self>,
        maximum_retained: usize,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        {
            let slot = self.ack_peer_birth.try_borrow().map_err(unknown)?;
            let birth = slot
                .as_ref()
                .ok_or_else(|| refused("original startup birth absent"))?;
            birth.authenticate_unstarted_storage_phase()?;
            let state = birth
                .report_startup
                .as_ref()
                .ok_or_else(|| refused("original startup member absent"))?;
            state.member.authenticate(self).map_err(unknown)?;
        }
        self.original_complete_report_startup_retained_storage_data(maximum_retained)?;
        let mut slot = self.ack_peer_birth.try_borrow_mut().map_err(unknown)?;
        let birth = slot
            .as_mut()
            .ok_or_else(|| refused("original startup birth absent"))?;
        birth.authenticate_unstarted_storage_phase()?;
        let state = birth
            .report_startup
            .as_mut()
            .ok_or_else(|| refused("original startup member absent"))?;
        if state.complete
            || state.body.is_some()
            || state.additions.is_some()
            || !state.replacement.is_empty()
        {
            return Err(refused(
                "original startup construction is incomplete or repeated",
            ));
        }
        state.complete = true;
        Ok(())
    }

    pub(crate) fn finalize_original_report_startup_birth(
        self: &Rc<Self>,
        member: OriginalReportStartupMember,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), OperationFailure> {
        member.authenticate(self.as_ref()).map_err(unknown)?;
        self.authenticate_original_report_startup_launch_data(launch)?;
        let requested = self.original_report_startup_finalization_storage_data(
            launch,
            member.rows,
            member.finalization_bytes,
        )?;
        if requested > member.finalization_bytes {
            return Err(refused("original report startup finalization widened"));
        }
        let mut slot = self.ack_peer_birth.try_borrow_mut().map_err(unknown)?;
        let birth = slot
            .as_mut()
            .ok_or_else(|| refused("original report startup birth is absent"))?;
        let capacity = birth.source_birth.capacity();
        let rows = member.rows;
        let maximum = member.finalization_bytes;
        // Install before the first new bank/DOM allocation. The old bank is
        // unchanged until the complete replacement and all local guards pass.
        birth.report_startup = Some(OriginalReportStartupFinalization {
            member,
            replacement: Vec::new(),
            body: None,
            additions: None,
            complete: false,
        });
        let result = finalize_bank(birth, launch, rows, capacity, maximum);
        if result.is_err() {
            birth.failed = true;
        }
        result
    }
}

impl OriginalAckPeerBirth {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_reserved_launch_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if !self.ready || self.failed {
            return Err(refused("reserved private birth is incomplete or failed"));
        }
        self.authenticate_report_startup_before_boot(source)?;
        self.authenticate_native_startup_before_boot(source)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_report_startup_before_boot(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if !self.report_startup_required {
            if self.report_startup.is_some() {
                return Err(refused(
                    "unselected private birth has a report startup owner",
                ));
            }
            return Ok(());
        }
        let state = self
            .report_startup
            .as_ref()
            .ok_or_else(|| refused("selected private birth has no original startup admission"))?;
        if !state.complete || self.failed {
            return Err(refused(
                "original report startup finalization is incomplete",
            ));
        }
        state.member.authenticate(source).map_err(unknown)
    }
}

fn finalize_bank(
    birth: &mut OriginalAckPeerBirth,
    launch: &PacketNative5SourceLaunch,
    rows: StartupRows,
    capacity: usize,
    maximum: usize,
) -> Result<(), OperationFailure> {
    birth.authenticate_unstarted_storage_phase()?;
    let state = birth
        .report_startup
        .as_mut()
        .ok_or_else(|| refused("original report startup construction slot is absent"))?;
    state
        .replacement
        .try_reserve_exact(capacity)
        .map_err(|_| refused("original report startup birth bank reservation unavailable"))?;
    if state.replacement.capacity() > capacity {
        return Err(refused(
            "original report startup bank capacity exceeded admission",
        ));
    }
    state.body = Some(
        canonical::parse_json(&birth.source_birth, birth.source_birth.len()).map_err(unknown)?,
    );
    state.additions =
        Some(serde_json::to_value(StartupAdditions { launch, rows }).map_err(unknown)?);
    let body = state
        .body
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| refused("original report startup birth is not an object"))?;
    let additions = state
        .additions
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| refused("original report startup additions are not an object"))?;
    // Drain the already retained additions; no clone or second body bank exists.
    for (key, value) in std::mem::take(additions) {
        body.insert(key, value);
    }
    if body.len() != 17 {
        return Err(refused(
            "original report startup binding13 has a different closed shape",
        ));
    }
    encode_canonical_birth_bank(
        state
            .body
            .as_ref()
            .ok_or_else(|| refused("original startup body absent"))?,
        capacity,
        &mut state.replacement,
    )?;
    state.retained_storage_data(maximum)?;
    // Both DOMs can be dropped only after the actual bank-capacity check. The
    // old bank is released only after the complete replacement is retained.
    state.body = None;
    state.additions = None;
    std::mem::swap(&mut birth.source_birth, &mut state.replacement);
    state.replacement = Vec::new();
    // Core rechecks the actual holder and Source conjunction before marking
    // this member complete. Until then begin_private_boot remains refused.
    Ok(())
}

struct StartupAdditions<'a> {
    launch: &'a PacketNative5SourceLaunch,
    rows: StartupRows,
}

impl Serialize for StartupAdditions<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_map(Some(8))?;
        fields.serialize_entry(
            "schema",
            "source-owned.packet-canonical-ack-source-binding/13",
        )?;
        fields.serialize_entry(
            "native_codec_metadata_extent",
            &self.launch.native_codec_metadata_extent,
        )?;
        fields.serialize_entry(
            "protocol_metadata_limits",
            &self.launch.protocol_metadata_limits,
        )?;
        fields.serialize_entry(
            "complete_restore_selection",
            &self.launch.complete_restore_selection,
        )?;
        fields.serialize_entry(
            "restore_input_emitter_selection",
            &self.launch.restore_input_emitter_selection,
        )?;
        fields.serialize_entry(
            "capture_allocation_selection",
            &self.launch.capture_allocation_selection,
        )?;
        fields.serialize_entry(
            "fresh_restore_allocation_selection",
            &self.launch.fresh_restore_allocation_selection,
        )?;
        fields.serialize_entry(
            "report_startup_allocation",
            &StartupAllocationView::new(self.rows),
        )?;
        fields.end()
    }
}

#[derive(Serialize)]
pub(super) struct StartupAllocationView {
    schema: &'static str,
    original_observe12: Option<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>,
    fresh_completed_admit13: Option<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>,
}

impl StartupAllocationView {
    pub(super) fn new(rows: StartupRows) -> Self {
        Self {
            schema: PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA,
            original_observe12: rows.original_observe12,
            fresh_completed_admit13: rows.fresh_completed_admit13,
        }
    }
}

#[derive(Serialize)]
struct BootFieldProjection<'a> {
    schema: &'static str,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
    private_key: &'static str,
    birth_id: &'static str,
}

// Infers the actual public return layout without constructing or hashing data.
fn returned_layout<T>(_: fn(&blake3::Hash) -> T) -> usize {
    size_of::<T>()
}

/// Observes a test-only birth bank and finalization phase without secret bytes.
///
/// This fixed data has no Source/grant constructor and is never consumed by a
/// production decision. Its digest covers the exact encoded source binding,
/// which excludes the private key and private birth ID.
#[cfg(any(test, feature = "test-double"))]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketCompleteReportStartupAuditData {
    /// Counts the exact currently retained encoded source binding bytes.
    pub encoded_birth_length: usize,
    /// Counts its actual reservation capacity.
    pub encoded_birth_capacity: usize,
    /// Records a fixed raw BLAKE3 digest without constructing a ContentRef.
    pub encoded_birth_digest: [u8; 32],
    /// Distinguishes an actual report-selected private birth.
    pub report_required: bool,
    /// Observes the retained attempted-finalization slot, including partial owners.
    pub finalization_present: bool,
    /// Observes the final Core-checked completion bit.
    pub complete: bool,
    /// Observes the original birth's sticky refusal bit.
    pub refused: bool,
    /// Observes whether the original boot loan was already spent.
    pub boot_started: bool,
}

impl PacketCompleteSemanticSource {
    /// Observes nonsecret actual bank identity and phase for constructor controls.
    ///
    /// This performs no file/entropy/kernel action and grants no permission.
    /// A fixed nonallocating hash authenticates no external body; it only lets
    /// tests compare the same retained bank across an expected refusal.
    ///
    /// # Errors
    /// Refuses a foreign creator, busy slot or absent original private birth.
    #[cfg(any(test, feature = "test-double"))]
    #[doc(hidden)]
    pub fn original_report_startup_audit_data(
        &self,
    ) -> Result<PacketCompleteReportStartupAuditData, OperationFailure> {
        self.ensure_origin()?;
        let slot = self.ack_peer_birth.try_borrow().map_err(unknown)?;
        let birth = slot
            .as_ref()
            .ok_or_else(|| refused("original private birth audit is absent"))?;
        birth.ensure_origin()?;
        Ok(PacketCompleteReportStartupAuditData {
            encoded_birth_length: birth.source_birth.len(),
            encoded_birth_capacity: birth.source_birth.capacity(),
            encoded_birth_digest: *blake3::hash(&birth.source_birth).as_bytes(),
            report_required: birth.report_startup_required,
            finalization_present: birth.report_startup.is_some(),
            complete: birth
                .report_startup
                .as_ref()
                .is_some_and(|state| state.complete),
            refused: birth.failed,
            boot_started: birth.boot_started.get(),
        })
    }
}

impl OriginalAckPeerBirth {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_fresh_query_key_data(
        &self,
    ) -> Result<&[u8; 32], crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !self.ready
            || self.failed
            || !self.boot_started.get()
            || !self.report_startup_required
            || self
                .report_startup
                .as_ref()
                .is_none_or(|state| !state.complete)
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(&self.key)
    }
}

#[path = "report_startup/settled17.rs"]
mod settled17;
