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
    NativeStartupRows, OriginalNativeStartupMember, OriginalNativeStartupQuote,
};
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_contract::{U64, canonical};
use crucible_node_provider::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::service::{
        PacketNative5CaptureProfile, PacketNative5SourceLaunch,
        ack_emitter::PacketNative5AckEmitterSelection,
        native_startup::{
            PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA, PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA,
            PacketNativeBirthStartupInputs, PacketNativeStartupAllocationRow,
            original_native_birth_startup_counter_scratch_data,
            original_native_birth_startup_storage_data,
        },
        original_native_prepare_startup_counter_scratch_data,
        original_native_prepare_startup_storage_data,
    },
};
use serde::{Serialize, ser::SerializeMap};
use std::{mem::size_of, rc::Rc};

pub(super) struct OriginalNativeStartupFinalization {
    pub(super) member: OriginalNativeStartupMember,
    replacement: Vec<u8>,
    body: Option<serde_json::Value>,
    additions: Option<serde_json::Value>,
    pub(super) complete: bool,
}

impl OriginalNativeStartupFinalization {
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

impl PacketCompleteSemanticSource {
    /// Quotes the fixed concrete Source/native producer and finalization window.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow before any observer or serializer.
    pub fn original_native_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        [
            original_native_birth_startup_counter_scratch_data(),
            original_native_prepare_startup_counter_scratch_data(),
            Self::original_report_startup_observer_scratch_data(),
            size_of::<NativeAdditions<'_>>(),
            size_of::<OriginalNativeStartupFinalization>(),
            size_of::<PacketNativeBirthStartupInputs<'_>>(),
            16 * 1024,
            size_of::<blake3::Hasher>(),
            size_of::<[u8; 336]>(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, n| {
            sum.checked_add(n).ok_or(RuntimeError::ResourceLimit)
        })
    }

    pub(super) fn authenticate_native_launch_data(
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
                crucible_node_provider::reference_packet::service::PacketConnectedSourceProgram::Producer { program }) => {
                let (actual, _, _) = source.complete_retained_declaration_parts_with_error::<RuntimeError>()?;
                if actual != program { return Err(RuntimeError::ForeignAuthority); }
            }
            (CompletePacketOriginal::Reactive(source),
                crucible_node_provider::reference_packet::service::PacketConnectedSourceProgram::Reactive { program }) => {
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
        let native = original_native_birth_startup_storage_data(&input, maximum)
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
            crucible_node_provider::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            let data=original_native_prepare_startup_storage_data(launch,encoded_launch)
                .map_err(|_|RuntimeError::ResourceLimit)?;
            Some(row(data.retained_growth_bytes(),data.maximum_simultaneous_transient_bytes(),
                data.declared_counter_scratch_bytes())?)
        }else{None};
        let rows = NativeStartupRows {
            private_bootstrap,
            native_birth,
            restore_prepare,
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
            crucible_node_provider::reference_packet::service::native_startup::original_native_private_boot_fields_storage_data(&input,maximum)
                .map_err(|_|RuntimeError::ResourceLimit)?,
        ],maximum)?;
        let finalization_bytes=retained_values::sum_with_error::<RuntimeError,_>([
            wire_bytes,

            birth.source_birth.capacity(),decoded,additions,
            size_of::<OriginalNativeStartupFinalization>(),
            NodeRuntime::capture_shared_allocation_storage::<Self>(),
            crate::node_admission::InstalledConformancePlan::original_report_startup_plan_header_storage_data(),
        ],maximum)?;
        let mut publication_bytes = 0usize;
        for row in [report.original_observe12, report.fresh_completed_admit13]
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
            wire_requested_bytes: wire_bytes,
            publication_bytes,
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
        let result = finalize_bank(birth, launch, rows, capacity, maximum);
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
        if let Some(state) = &self.native_startup {
            if !state.complete || self.failed {
                return Err(refused("original native startup is incomplete"));
            }
            state
                .member
                .authenticate(source)
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
        let mut map = serializer.serialize_map(Some(if report_absent { 9 } else { 8 }))?;
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
        // An existing authenticated report object remains in the original map.
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
