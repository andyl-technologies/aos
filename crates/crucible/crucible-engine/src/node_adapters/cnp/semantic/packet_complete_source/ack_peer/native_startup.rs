//! Consumes Core's same-Source native startup member before changing its birth.
//!
//! The previous full bank and new partial owners stay attached through failures.
//! Report publication remains a separately authenticated prospective obligation;
//! the baseline action cannot turn an existing report row into native rights.

use super::*;
use crate::node_adapters::cnp::CnpSemanticSource;
use crate::node_adapters::cnp::semantic::packet_complete_source::{
    CompletePacketOriginal, PacketCompleteSemanticSource, retained_values,
};
use crate::node_admission::{
    NativeStartupRows, OriginalHostFinalizationBarrier, OriginalNativeStartupMember,
    OriginalNativeStartupQuote,
};
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_format::{U64, canonical};
use crucible_node_transport::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::service::{
        PacketNative5CaptureProfile, PacketNative5SourceLaunch,
        ack_emitter::PacketNative5AckEmitterSelection,
        native_startup::{
            PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA, PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA,
            PacketNativeBirthStartupInputs, PacketNativeStartupAllocationRow,
            original_native_birth_startup_counter_scratch_data,
            original_native_birth_startup_storage_data,
            original_native_preflight_birth_startup_storage_data,
        },
        original_native_prepare_startup_counter_scratch_data,
        original_native_prepare_startup_storage_data,
    },
};
use serde::{Serialize, ser::SerializeMap};
use std::{
    cell::{Ref, RefMut},
    mem::size_of,
    rc::Rc,
};

#[path = "native_startup/import18.rs"]
mod import18;
pub(super) use import18::OriginalNativeImport18Finalization;

#[path = "native_startup/capture_construction.rs"]
mod capture_construction;

pub(super) struct OriginalNativeStartupFinalization {
    pub(super) member: OriginalNativeStartupMember,
    replacement: Vec<u8>,
    body: Option<serde_json::Value>,
    additions: Option<serde_json::Value>,
    pub(super) complete: bool,
}

impl OriginalNativeStartupFinalization {
    // Future owners follow the actual completed private member. Both full row
    // DTOs and current Source banks remain independently counted; a purpose
    // cannot create the opposite native report's future publication owners.
    pub(super) fn authenticated_publication_rows_data(
        &self,
        source: &PacketCompleteSemanticSource,
        broad: crate::node_admission::StartupRows,
    ) -> Result<crate::node_admission::StartupRows, RuntimeError> {
        self.member.authenticate_boot_ready(source)?;
        if !self.complete {
            return Err(RuntimeError::OwnerUnavailable);
        }
        if let Some(invocation) = self.original_invocation_data()? {
            if self.member.rows.initial_report_rows.is_some()
                || self.additions.is_some()
                || self.replacement.capacity() != 0
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            // NativeAckBoot authenticates this same private Source15 purpose
            // before allocating a report token or publication attempt. Keep
            // the authorized purpose's complete BROAD row, not an initial14
            // model projection. No wire row or existing owner is removed.
            let selected = if invocation.is_original_execution_data() {
                crate::node_admission::StartupRows {
                    original_observe12: broad.original_observe12,
                    fresh_completed_admit13: None,
                }
            } else {
                crate::node_admission::StartupRows {
                    original_observe12: None,
                    fresh_completed_admit13: broad.fresh_completed_admit13,
                }
            };
            self.member.authenticate_boot_ready(source)?;
            return Ok(selected);
        }
        let Some(selected) = self.member.rows.initial_report_rows else {
            return Ok(broad);
        };
        if self.member.requires_original_invocation_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.body.is_some() || self.additions.is_some() || self.replacement.capacity() != 0 {
            return Err(RuntimeError::OwnerUnavailable);
        }

        let allowed = broad
            .original_observe12
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let actual = selected
            .original_observe12
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        allowed
            .authenticate_actual_data(actual)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if selected.fresh_completed_admit13 != broad.fresh_completed_admit13 {
            return Err(RuntimeError::ForeignAuthority);
        }

        self.member.authenticate_boot_ready(source)?;
        Ok(selected)
    }

    pub(super) fn publication_rows_counter_scratch_data() -> usize {
        type Row = crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow;
        crucible_node_transport::reference_packet::service::native_startup::original_native_invocation_value_counter_scratch_data()
            + size_of::<Option<crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData>>()
            + size_of::<Result<Option<crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData>, RuntimeError>>()
            + size_of::<Result<Option<crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData>, crucible_node_transport::ProviderError>>()
            + 2 * size_of::<Option<&serde_json::Value>>()
            + size_of::<Result<Option<&serde_json::Value>, RuntimeError>>()
            + size_of::<Result<&serde_json::Value, RuntimeError>>()
            + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
            + size_of::<&serde_json::Map<String, serde_json::Value>>()
            + size_of::<Option<&str>>()
            + 2 * size_of::<crate::node_admission::StartupRows>()
            + size_of::<Option<crate::node_admission::StartupRows>>()
            + size_of::<Result<crate::node_admission::StartupRows, RuntimeError>>()
            + 2 * size_of::<&Row>()
            + 2 * size_of::<Option<&Row>>()
            + 2 * size_of::<Result<&Row, RuntimeError>>()
            + size_of::<Result<(), crucible_node_transport::ProviderError>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<&Self>()
            + size_of::<&PacketCompleteSemanticSource>()
    }

    pub(super) fn retained_storage_data_with_error<E: StorageError>(
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
                    .map(|v| retained_values::value_storage_with_error::<E>(v, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
                additions
                    .as_ref()
                    .map(|v| retained_values::value_storage_with_error::<E>(v, 0, maximum))
                    .transpose()?
                    .unwrap_or(0),
                member.retained_shared_storage_data().map_err(E::runtime)?,
            ],
            maximum,
        )
    }
}

fn row(
    retained: usize,
    transient: usize,
    scratch: usize,
) -> Result<PacketNativeStartupAllocationRow, RuntimeError> {
    let quantity = |n| {
        u64::try_from(n)
            .map(U64::new)
            .map_err(|_| RuntimeError::ResourceLimit)
    };
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    };
    row.requested_peak_data()
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(row)
}

// These loans exist only during atomic attachment. No authority callback or
// Source observer is called while they are held; all checks before assignment
// inspect the original creator and already retained ready/unstarted birth.
/// Retains all original birth loans until their shared gate is attached.
pub(crate) struct OriginalNativeHostBarrierSlots<'a> {
    births: [RefMut<'a, OriginalAckPeerBirth>; 3],
}

impl OriginalNativeHostBarrierSlots<'_> {
    /// Attaches every original slot without allocation or fallible callbacks.
    pub(crate) fn attach(mut self, barrier: &Rc<OriginalHostFinalizationBarrier>) {
        for (index, birth) in self.births.iter_mut().enumerate() {
            birth.native_host_finalization = Some(barrier.source_link(index));
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Counts the concrete simultaneous attachment loan headers.
    pub(crate) fn original_native_host_barrier_slot_scratch_data() -> usize {
        size_of::<OriginalNativeHostBarrierSlots<'static>>()
            + size_of::<Result<OriginalNativeHostBarrierSlots<'static>, RuntimeError>>()
            + size_of::<[RefMut<'static, OriginalAckPeerBirth>; 3]>()
            + size_of::<Result<RefMut<'static, Option<OriginalAckPeerBirth>>, std::cell::BorrowMutError>>()
            + size_of::<Result<RefMut<'static, OriginalAckPeerBirth>, RefMut<'static, Option<OriginalAckPeerBirth>>>>()
            + size_of::<Option<&'static mut OriginalAckPeerBirth>>()
            + size_of::<Result<RefMut<'static, OriginalAckPeerBirth>, RuntimeError>>()
            // Both the direct cursor and its enumerate wrapper are named at
            // the infallible attachment site; no recursive frame estimate.
            + size_of::<std::slice::IterMut<'static, RefMut<'static, OriginalAckPeerBirth>>>()
            + size_of::<std::iter::Enumerate<std::slice::IterMut<'static, RefMut<'static, OriginalAckPeerBirth>>>>()
            + size_of::<Option<(usize, &'static mut RefMut<'static, OriginalAckPeerBirth>)>>()
    }

    /// Borrows all ready original births before any gate allocation or mutation.
    ///
    /// # Errors
    /// Refuses foreign creators, busy/absent births, an earlier gate or startup,
    /// and births that are failed, incomplete or already consumed by boot.
    pub(crate) fn original_native_host_barrier_slots(
        sources: &[Rc<Self>; 3],
    ) -> Result<OriginalNativeHostBarrierSlots<'_>, RuntimeError> {
        fn original_birth(
            source: &PacketCompleteSemanticSource,
        ) -> Result<RefMut<'_, OriginalAckPeerBirth>, RuntimeError> {
            source.storage_origin_with_error::<RuntimeError>()?;
            let slot = source
                .ack_peer_birth
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let birth = RefMut::filter_map(slot, Option::as_mut)
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            birth.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
            if birth.native_host_finalization.is_some() || birth.native_startup.is_some() {
                return Err(RuntimeError::DuplicateOperation);
            }
            Ok(birth)
        }
        let first = original_birth(&sources[0])?;
        let second = original_birth(&sources[1])?;
        let third = original_birth(&sources[2])?;
        Ok(OriginalNativeHostBarrierSlots {
            births: [first, second, third],
        })
    }

    /// Counts the original birth loan and fixed shared-gate authentication views.
    pub(crate) fn original_native_host_barrier_authentication_scratch_data() -> usize {
        size_of::<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>>()
            + size_of::<Result<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>, std::cell::BorrowError>>()
            + size_of::<Option<&'static OriginalAckPeerBirth>>()
            + size_of::<Option<&'static crate::node_admission::OriginalHostFinalizationSource>>()
            + size_of::<Result<(), OperationFailure>>()
            // At most one of these literal refusal messages is allocated.
            + "original host finalization birth is busy".len()
                .max("original host finalization roster is incomplete".len())
            + crate::node_admission::OriginalHostFinalizationSource::authentication_scratch_data()
    }

    /// Rechecks the attached host roster before an existing ACK alias can act.
    ///
    /// # Errors
    /// Refuses a busy birth or foreign, incomplete, aborted or abandoned gate.
    /// An old birth with no startup gate keeps its existing authentication path.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_native_host_barrier(
        &self,
    ) -> Result<(), OperationFailure> {
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("original host finalization birth is busy"))?;
        if let Some(barrier) = slot
            .as_ref()
            .and_then(|birth| birth.native_host_finalization.as_ref())
        {
            barrier
                .authenticate_ready(self)
                .map_err(|_| refused("original host finalization roster is incomplete"))?;
        }
        Ok(())
    }

    /// Quotes the fixed concrete Source/native producer and finalization window.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow before any observer or serializer.
    pub fn original_native_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms: [usize; 41] = [
            size_of::<[usize; 41]>(),
            size_of::<std::array::IntoIter<usize, 41>>(),
            size_of::<Result<usize, RuntimeError>>(),
            original_native_birth_startup_counter_scratch_data(),
            original_native_prepare_startup_counter_scratch_data(),
            Self::original_report_startup_observer_scratch_data(),
            crucible_node_transport::reference_packet::service::report_startup::original_report_startup_counter_scratch_data(),
            size_of::<crate::node_admission::StartupRows>(),
            size_of::<Option<crate::node_admission::StartupRows>>(),
            size_of::<super::report_startup::StartupAllocationView>(),
            size_of::<Result<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupStorageData, crucible_node_transport::ProviderError>>(),
            size_of::<Result<(), crucible_node_transport::ProviderError>>(),
            size_of::<Result<Option<crate::node_admission::StartupRows>, RuntimeError>>(),
            size_of::<Option<&crate::node_admission::StartupRows>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<U64, RuntimeError>>(),
            size_of::<Result<u64, std::num::TryFromIntError>>(),
            size_of::<&crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>(),
            size_of::<Result<crate::node_admission::StartupRows, RuntimeError>>(),
            size_of::<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>(),
            size_of::<Result<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupStorageData, RuntimeError>>(),
            size_of::<Ref<'static, OriginalAckPeerBirth>>(),
            size_of::<Result<Ref<'static, OriginalAckPeerBirth>, std::cell::BorrowError>>(),
            size_of::<Result<Ref<'static, OriginalAckPeerBirth>, RuntimeError>>(),
            size_of::<Option<&super::report_startup::OriginalReportStartupFinalization>>(),
            size_of::<Result<&super::report_startup::OriginalReportStartupFinalization, RuntimeError>>(),
            size_of::<Option<&crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>>(),
            size_of::<Result<&crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow, RuntimeError>>(),
            size_of::<Result<bool, RuntimeError>>(),
            size_of::<NativeAdditions<'_>>(),
            size_of::<bool>(),
            size_of::<OriginalNativeStartupFinalization>(),
            size_of::<PacketNativeBirthStartupInputs<'_>>(),
            super::HOST_EXECUTABLE_STREAM_BYTES,
            size_of::<blake3::Hasher>(),
            size_of::<[u8; 336]>(),
            Self::original_complete_capture_execution_counter_scratch_data(),
            Self::original_native_host_barrier_authentication_scratch_data(),
            // The complete finalization term array and its consumed iterator
            // coexist with the returned scalar; charge full layouts, not delta.
            size_of::<[usize; 10]>(),
            size_of::<std::array::IntoIter<usize, 10>>(),
            // Quote and pre-reservation recheck each return this fixed view.
            // Their bank storage is independently included in finalization.
            2 * size_of::<(usize, usize, usize)>(),
        ];
        terms.into_iter().try_fold(0usize, |sum, n| {
            sum.checked_add(n).ok_or(RuntimeError::ResourceLimit)
        })
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn authenticate_native_launch_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let actual = self.installation();
        let (profile, confirmation, storage) = match &self.original {
            CompletePacketOriginal::Producer(source) => (
                source.complete_capture_profile.as_ref(),
                source.complete_confirmation_selection.flatten(),
                source.complete_selected_storage(),
            ),
            CompletePacketOriginal::Reactive(source) => (
                source.complete_capture_profile.as_ref(),
                source.complete_confirmation_selection.flatten(),
                source.complete_selected_storage(),
            ),
        };
        let storage = storage.ok_or(RuntimeError::OwnerUnavailable)?;
        match (&self.original, &launch.program) {
            (CompletePacketOriginal::Producer(source),
                crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram::Producer { program }) => {
                let (actual, _, _) = source.complete_retained_declaration_parts_with_error::<RuntimeError>()?;
                if actual != program { return Err(RuntimeError::ForeignAuthority); }
            }
            (CompletePacketOriginal::Reactive(source),
                crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram::Reactive { program }) => {
                let (actual, _, _) = source.complete_retained_declaration_parts_with_error::<RuntimeError>()?;
                if actual != program { return Err(RuntimeError::ForeignAuthority); }
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }

        if profile != Some(&launch.capture_profile)
            || !matches!(
                launch.capture_profile,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || confirmation != launch.confirmation_selection
            || self.ack_emitter_selection.flatten()
                != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || self.ack_emitter_selection.flatten() != launch.ack_emitter_selection
            || self.ack_codec_metadata_extent
                != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || self.native_ack_codec_metadata_extent != launch.native_codec_metadata_extent
            || self.protocol_metadata_limits != launch.protocol_metadata_limits
            || self.complete_restore_selection.flatten() != launch.complete_restore_selection
            || self.restore_input_emitter_selection.flatten()
                != launch.restore_input_emitter_selection
            || self.capture_allocation_selection.flatten() != launch.capture_allocation_selection
            || self.fresh_restore_allocation_selection.flatten()
                != launch.fresh_restore_allocation_selection
            || storage.storage != launch.storage
            || storage.limits != launch.limits
            || launch.controller_pid.get() != u64::from(std::process::id())
            || launch.controller_uid.get() != u64::from(rustix::process::geteuid().as_raw())
            || launch.selection.provider != actual.provider
            || launch.selection.realize != actual.realize
            || launch.selection.realization.bindings.as_slice()
                != std::slice::from_ref(&actual.binding)
            || launch.selection.realization.owner_bindings.as_slice()
                != std::slice::from_ref(&actual.owner)
            || launch.selection.realization.descriptors.as_slice()
                != std::slice::from_ref(&actual.descriptor)
            || launch.selection.admission != actual.admission
            || launch.selection.transaction != actual.transaction
            || launch.selection.gate != actual.gate
            || launch.selection.world != actual.world_binding_hash
            || launch.selection.admission_receipt != actual.admission_receipt
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn original_native_startup_quote_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        encoded_launch: &[u8],
        maximum: usize,
    ) -> Result<OriginalNativeStartupQuote, RuntimeError> {
        self.original_native_startup_quote_with_producer_data(
            launch,
            encoded_launch,
            maximum,
            false,
        )
    }

    pub(crate) fn original_native_preflight_startup_quote_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        encoded_launch: &[u8],
        maximum: usize,
    ) -> Result<OriginalNativeStartupQuote, RuntimeError> {
        self.original_native_startup_quote_with_producer_data(launch, encoded_launch, maximum, true)
    }

    fn original_native_startup_quote_with_producer_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        encoded_launch: &[u8],
        maximum: usize,
        preflight: bool,
    ) -> Result<OriginalNativeStartupQuote, RuntimeError> {
        self.authenticate_native_launch_data(launch)?;
        self.original_complete_report_startup_retained_storage_precredit_data(maximum)?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if birth.native_startup.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let report = if birth.report_startup_required {
            birth
                .report_startup
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticated_rows_data(self)?
        } else {
            crate::node_admission::StartupRows::default()
        };
        let input = PacketNativeBirthStartupInputs {
            launch,
            private_launch: &birth.private_launch,
            encoded_launch,
            source_birth: &birth.source_birth,
            host_registration: &birth.expected_host_registration,
        };
        let native = if preflight {
            original_native_preflight_birth_startup_storage_data(&input, maximum)
        } else {
            original_native_birth_startup_storage_data(&input, maximum)
        }
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let private_bootstrap = row(
            native.private_bootstrap_retained_requested_bytes(),
            native.private_bootstrap_maximum_simultaneous_transient_bytes(),
            native.declared_counter_scratch_bytes(),
        )?;
        let native_birth = row(
            native.retained_requested_bytes(),
            native.maximum_simultaneous_transient_bytes(),
            native.declared_counter_scratch_bytes(),
        )?;
        let restore_prepare=if launch.complete_restore_selection==Some(
            crucible_node_transport::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            let data=original_native_prepare_startup_storage_data(launch,encoded_launch)
                .map_err(|_|RuntimeError::ResourceLimit)?;
            Some(row(data.retained_growth_bytes(),data.maximum_simultaneous_transient_bytes(),
                data.declared_counter_scratch_bytes())?)
        }else{None};
        let retained_overlap = native
            .authenticated_retained_overlap_data(&input)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let initial_report_rows = if preflight && report.original_observe12.is_some() {
            let data = crucible_node_transport::reference_packet::service::report_startup::original_initial_report_startup_storage_data(
                launch,
                crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::OriginalObserve12,
            ).map_err(|_| RuntimeError::ResourceLimit)?;
            let quantity = |n| {
                u64::try_from(n)
                    .map(U64::new)
                    .map_err(|_| RuntimeError::ResourceLimit)
            };
            let selected = crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow {
                raw_report_capacity: quantity(data.raw_report_capacity())?,
                retained_growth_bytes: quantity(data.retained_growth_bytes())?,
                maximum_simultaneous_transient_bytes: quantity(data.maximum_simultaneous_transient_bytes())?,
                declared_counter_scratch_bytes: quantity(data.declared_counter_scratch_bytes())?,
            };
            report
                .original_observe12
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .authenticate_actual_data(&selected)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            Some(crate::node_admission::StartupRows {
                original_observe12: Some(selected),
                fresh_completed_admit13: report.fresh_completed_admit13,
            })
        } else {
            None
        };
        let rows = NativeStartupRows {
            private_bootstrap,
            native_birth,
            restore_prepare,
            retained_overlap: Some(retained_overlap),
            initial_report_rows,
        };
        let additions =
            NodeRuntime::capture_serialization_storage(&NativeAdditions { launch, rows }, maximum)?;
        let decoded = NodeRuntime::capture_selected_json_decode_storage(
            &birth.source_birth,
            size_of::<serde_json::Value>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            maximum,
        )?;
        let registration_decode = NodeRuntime::capture_selected_json_decode_storage(
            &birth.expected_host_registration,
            size_of::<serde_json::Value>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            maximum,
        )?;
        // The actual boot-frame constructor clones these two canonical trees;
        // the finalizer's earlier trees need not be reused to obtain this bound.
        // The two independent wire banks remain in the daemon launch holder.
        let wire_bytes=retained_values::sum_with_error::<RuntimeError,_>([
            size_of::<super::native_wire::PacketCompleteNativeStartupWire>(),
            512 * 1024 + 4, encoded_launch.len().checked_add(4).ok_or(RuntimeError::ResourceLimit)?,
            decoded, additions, registration_decode,
            crucible_node_transport::reference_packet::service::native_startup::original_native_private_boot_fields_storage_data(&input,maximum)
                .map_err(|_|RuntimeError::ResourceLimit)?,
        ],maximum)?;
        let (
            source_capture_backend_bytes,
            source_capture_execution_bytes,
            source_capture_execution_scratch,
        ) = self.original_native_source_capture_construction_data(launch, maximum)?;
        let finalization_bytes=retained_values::sum_with_error::<RuntimeError,_>([
            wire_bytes,
            source_capture_execution_bytes,
            source_capture_execution_scratch,

            birth.source_birth.capacity(),decoded,additions,
            size_of::<OriginalNativeStartupFinalization>(),
            NodeRuntime::capture_shared_allocation_storage::<Self>(),
            crate::node_admission::InstalledConformancePlan::original_report_startup_plan_header_storage_data(),
            // The actual member postwalk retains this same shared allocation.
            // Keep per-member views conservative; the upfront roster charge
            // remains independently present before the allocation occurs.
            OriginalNativeStartupMember::host_finalization_allocation_requested_data(),
        ],maximum)?;
        let mut publication_bytes = 0usize;
        let publication = rows.initial_report_rows.unwrap_or(report);
        for row in [
            publication.original_observe12,
            publication.fresh_completed_admit13,
        ]
        .into_iter()
        .flatten()
        {
            publication_bytes = publication_bytes
                .checked_add(
                    usize::try_from(
                        row.requested_peak_data()
                            .map_err(|_| RuntimeError::ResourceLimit)?,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(OriginalNativeStartupQuote {
            rows,
            finalization_bytes,
            source_capture_backend_bytes,
            source_capture_execution_bytes,
            source_capture_execution_scratch,
            wire_requested_bytes: wire_bytes,
            publication_bytes,
            publication_rows: publication,
            launch_digest: *blake3::hash(encoded_launch).as_bytes(),
            maximum_boot_bytes: native.maximum_private_boot_body_bytes(),
        })
    }

    pub(crate) fn finalize_original_native_startup_birth(
        self: &Rc<Self>,
        member: OriginalNativeStartupMember,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), RuntimeError> {
        member.authenticate(self)?;
        self.authenticate_native_launch_data(launch)?;
        if let Some(selected) = member.rows.initial_report_rows {
            if member.requires_original_invocation_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
            let broad = {
                let slot = self
                    .ack_peer_birth
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                birth
                    .report_startup
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .authenticated_rows_data(self)?
            };
            let allowed = broad
                .original_observe12
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let observed = selected
                .original_observe12
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            allowed
                .authenticate_actual_data(observed)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if selected.fresh_completed_admit13 != broad.fresh_completed_admit13 {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let mut slot = self
            .ack_peer_birth
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if birth.native_startup.is_some()
            || !birth.ready
            || birth.failed
            || birth.boot_started.get()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        let capacity = birth.source_birth.capacity();
        let rows = member.rows;
        let maximum = member.finalization_bytes;
        // Install the spent member before the first new bank or DOM allocation.
        birth.native_startup = Some(OriginalNativeStartupFinalization {
            member,
            replacement: Vec::new(),
            body: None,
            additions: None,
            complete: false,
        });
        let result = (|| {
            // The exact original member is already spent and Source-retained.
            // Its whole-action quote admitted these separate host allocations
            // before any reserve call; no row14/report scalar authorizes them.
            self.reserve_original_native_source_capture_construction_data(
                &birth
                    .native_startup
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .member,
                launch,
            )?;
            finalize_bank(birth, launch, rows, capacity, maximum)
        })();
        if result.is_err() {
            birth.failed = true;
        }
        result
    }

    pub(crate) fn complete_original_native_startup_birth(
        self: &Rc<Self>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        {
            let slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let state = birth
                .native_startup
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            state.member.authenticate(self)?;
            if state.member.requires_original_invocation_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let mut slot = self
            .ack_peer_birth
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let state = birth
            .native_startup
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.complete
            || state.body.is_some()
            || state.additions.is_some()
            || !state.replacement.is_empty()
            || birth.failed
            || birth.boot_started.get()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        state.complete = true;
        Ok(())
    }
}

impl OriginalAckPeerBirth {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn authenticate_selected_native_startup(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original()?;
        if self.native_startup.is_none() {
            return Err(refused(
                "selected startup snapshot has no original startup member",
            ));
        }
        self.authenticate_native_startup_before_boot(source)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn authenticate_native_startup_before_boot(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), OperationFailure> {
        let import18 = source
            .is_original_native_import18_declaration_data()
            .map_err(|_| refused("import18 declaration unavailable"))?;
        if import18 {
            if self.native_startup.is_some() || self.failed {
                return Err(refused("import18 cannot use a legacy startup member"));
            }
            let state = self
                .native_import18
                .as_ref()
                .ok_or_else(|| refused("import18 startup member absent"))?;
            if !state.complete {
                return Err(refused("import18 startup member incomplete"));
            }
            state
                .member
                .authenticate_boot_ready(source)
                .map_err(|_| refused("import18 original member expired"))?;
        } else if self.native_import18.is_some() {
            return Err(refused("import18 member has another declaration"));
        }
        // The link exists on every roster birth before any member is issued.
        // Incomplete, aborted or abandoned admissions therefore block aliases
        // even when this Source has not yet installed native_startup state.
        if let Some(barrier) = &self.native_host_finalization {
            barrier
                .authenticate_ready(source)
                .map_err(|_| refused("original host finalization roster is incomplete"))?;
        }
        if let Some(state) = &self.native_startup {
            if !state.complete || self.failed {
                return Err(refused("original native startup is incomplete"));
            }
            state
                .member
                .authenticate_boot_ready(source)
                .map_err(|_| refused("original native startup member expired"))?;
        }
        Ok(())
    }
}

fn finalize_bank(
    birth: &mut OriginalAckPeerBirth,
    launch: &PacketNative5SourceLaunch,
    rows: NativeStartupRows,
    capacity: usize,
    maximum: usize,
) -> Result<(), RuntimeError> {
    let state = birth
        .native_startup
        .as_mut()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    state
        .replacement
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if state.replacement.capacity() > capacity {
        return Err(RuntimeError::ResourceLimit);
    }
    state.body = Some(
        canonical::parse_json(&birth.source_birth, birth.source_birth.len())
            .map_err(|_| RuntimeError::ResourceLimit)?,
    );
    state.additions = Some(
        serde_json::to_value(NativeAdditions { launch, rows })
            .map_err(|_| RuntimeError::ResourceLimit)?,
    );
    let body = state
        .body
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(RuntimeError::ForeignAuthority)?;
    let additions = state
        .additions
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(RuntimeError::ForeignAuthority)?;
    for (key, value) in std::mem::take(additions) {
        body.insert(key, value);
    }
    if body.len() != 18 {
        return Err(RuntimeError::ForeignAuthority);
    }
    super::super::encode_canonical_birth_bank(
        state.body.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
        capacity,
        &mut state.replacement,
    )
    .map_err(|_| RuntimeError::ResourceLimit)?;
    if state.replacement.len() > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    std::mem::swap(&mut birth.source_birth, &mut state.replacement);
    state.replacement.clear();
    // Drop the obsolete bank/DOM only after installing the full new literal.
    state.replacement = Vec::new();
    state.body = None;
    state.additions = None;
    Ok(())
}

struct NativeAdditions<'a> {
    launch: &'a PacketNative5SourceLaunch,
    rows: NativeStartupRows,
}

impl Serialize for NativeAdditions<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let launch = self.launch;
        let report_absent = launch.capture_allocation_selection.is_none()
            && launch.fresh_restore_allocation_selection.is_none();
        let initial_report = self.rows.initial_report_rows.as_ref();
        let mut map =
            serializer.serialize_map(Some(if report_absent || initial_report.is_some() {
                9
            } else {
                8
            }))?;
        map.serialize_entry("schema", PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)?;
        map.serialize_entry(
            "native_codec_metadata_extent",
            &launch.native_codec_metadata_extent,
        )?;
        map.serialize_entry("protocol_metadata_limits", &launch.protocol_metadata_limits)?;
        map.serialize_entry(
            "complete_restore_selection",
            &launch.complete_restore_selection,
        )?;
        map.serialize_entry(
            "restore_input_emitter_selection",
            &launch.restore_input_emitter_selection,
        )?;
        map.serialize_entry(
            "capture_allocation_selection",
            &launch.capture_allocation_selection,
        )?;
        map.serialize_entry(
            "fresh_restore_allocation_selection",
            &launch.fresh_restore_allocation_selection,
        )?;
        if launch.capture_allocation_selection.is_none()
            && launch.fresh_restore_allocation_selection.is_none()
        {
            map.serialize_entry("report_startup_allocation", &Option::<()>::None)?;
        }
        if let Some(rows) = initial_report {
            if report_absent {
                return Err(serde::ser::Error::custom(
                    "initial report projection has no original report owner",
                ));
            }
            map.serialize_entry(
                "report_startup_allocation",
                &super::report_startup::StartupAllocationView::new(*rows),
            )?;
        }
        // Otherwise the original broad authenticated report object remains.
        struct Allocation<'a>(&'a NativeStartupRows);
        impl Serialize for Allocation<'_> {
            fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("schema", PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA)?;
                map.serialize_entry("private_bootstrap", &self.0.private_bootstrap)?;
                map.serialize_entry("native_birth", &self.0.native_birth)?;
                map.serialize_entry("restore_prepare", &self.0.restore_prepare)?;
                map.end()
            }
        }
        map.serialize_entry("native_startup_allocation", &Allocation(&self.rows))?;
        map.end()
    }
}

#[path = "native_startup/invocation.rs"]
mod invocation;

#[cfg(any(test, feature = "test-double"))]
impl PacketCompleteSemanticSource {
    /// Reads actual broad, selected and emitted rows from one original Source.
    ///
    /// This test-only DATA never creates a startup member or native permission.
    ///
    /// # Errors
    /// Refuses a foreign member, absent/unfinished source, malformed binding or
    /// changed actual emitted selected report row.
    #[doc(hidden)]
    pub fn original_initial_report_refinement_audit_data(
        &self,
        expected_source: &Self,
    ) -> Result<Option<(
        crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow,
        crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow,
        crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow,
    )>, RuntimeError>{
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        state.member.authenticate(expected_source)?;
        if !state.complete || birth.failed || birth.boot_started.get() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let Some(selected) = state.member.rows.initial_report_rows else {
            return Ok(None);
        };
        let broad = birth
            .report_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticated_rows_data(expected_source)?;
        let body = canonical::parse_json(&birth.source_birth, birth.source_birth.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if body.get("schema").and_then(serde_json::Value::as_str)
            != Some(PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let raw = body
            .get("report_startup_allocation")
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let wire: crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocation =
            serde_json::from_value(raw.clone()).map_err(|_| RuntimeError::ForeignAuthority)?;
        let broad = broad
            .original_observe12
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = selected
            .original_observe12
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let wire = *wire.row_data(crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::OriginalObserve12)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if wire != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(Some((broad, selected, wire)))
    }
}

#[path = "native_startup/restored_suffix.rs"]
mod restored_suffix;

#[cfg(any(test, feature = "test-double"))]
impl PacketCompleteSemanticSource {
    /// Audits genuine completed Source report commitments as inert test DATA.
    ///
    /// The explicit expected Source tests actual member identity. No row or
    /// returned tag constructs a private member, native token or live grant.
    ///
    /// # Errors
    /// Refuses a foreign Source, incomplete member/barrier, missing report or
    /// invalid retained invocation body. No kernel-current proof is supplied.
    #[doc(hidden)]
    pub fn original_native_report_commitment_audit_data(
        &self,
        expected_source: &Self,
    ) -> Result<(
        Option<bool>,
        Option<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>,
        Option<crucible_node_transport::reference_packet::service::report_startup::PacketNativeReportStartupAllocationRow>,
    ), RuntimeError>{
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        state.member.authenticate_boot_ready(expected_source)?;
        let broad = birth
            .report_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticated_rows_data(expected_source)?;
        let rows = state.authenticated_publication_rows_data(expected_source, broad)?;
        Ok((
            state
                .original_invocation_data()?
                .map(|purpose| purpose.is_original_execution_data()),
            rows.original_observe12,
            rows.fresh_completed_admit13,
        ))
    }
}

#[path = "native_startup/settled17.rs"]
mod settled17;

#[path = "native_startup/source17_writer.rs"]
mod source17_writer;

#[path = "native_startup/restored_settled.rs"]
mod restored_settled;
