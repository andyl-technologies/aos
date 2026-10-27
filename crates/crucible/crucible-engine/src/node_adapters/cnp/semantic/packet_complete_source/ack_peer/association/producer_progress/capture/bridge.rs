//! Binds unchanged model state to Capture's genuinely advanced SDK frontier.
//!
//! The prior Observe remains immutable historical evidence. This separate local
//! bridge requires the actual completed Capture/confirmation pair and the same
//! validated confirmed fourth native output. It grants no new operation or Capture, and an
//! advanced later SDK frontier makes this bridge historical as well.

#[path = "bridge/capacities.rs"]
mod capacities;

use super::signing::CaptureSigningOwners;
use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureSigningInputs},
    node_contract::{ActivationRecord, RuntimeError, WorldActivation},
};
use crucible_node_format::{ContentRef, Id, U64};
use crucible_node_transport::{
    client::{
        CnpController, OriginalCanonicalBlobAckEmitter, OriginalCompletedRestoredSettledCaptureData,
    },
    protocol_snapshot::restored_settled17::ValidatedRestoredSettledNative17CaptureOutputs,
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::PacketNativeRestoredRecord,
    },
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::{
    io::{self, Write},
    thread::ThreadId,
};

pub(super) struct CaptureAdminBridge {
    process: u32,
    thread: ThreadId,
    source: *const PacketCompleteSemanticSource,
    controller: *const CnpController,
    world: WorldActivation,
    measurement: ContentRef,
    model: ContentRef,
    native_after: ContentRef,
    capture_request: ContentRef,
    capture_id: Id,
    capture_operation: Id,
    prefix_frontier: U64,
    frontier: U64,
    signature: Option<[u8; 32]>,
}

impl CaptureAdminBridge {
    /// Retains a partial bridge before native/SDK/current correspondence checks.
    ///
    /// The parent holds the actual SourceRead and a genuine admitted claim. It
    /// retains the separately decoded native17 output owner through this operation and
    /// all subsequent failures. This method cannot construct that sealed owner.
    pub(super) fn retain_into(
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        claim: &OriginalRestoredCaptureClaim<'_>,
        completed: &OriginalCompletedRestoredSettledCaptureData<'_>,
        native: &ValidatedRestoredSettledNative17CaptureOutputs,
        signatures: &CaptureSigningOwners,
        maximum_frame: usize,
        record: &PacketNativeRestoredRecord,
        underlying: &PacketNative5UnderlyingRecord,
        measurement: &ContentRef,
        key: &[u8; 32],
        retained: &mut Option<Self>,
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if retained.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        claim.authenticate_current_data(source, controller as *const _)?;
        claim.authenticate_inputs_data(inputs)?;
        inputs.authenticate_current_data()?;
        let request = completed.request_data();
        let receipt = completed.receipt_data();
        let prefix_frontier = completed
            .prefix_frontier_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        *retained = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source,
            controller,
            world: inputs.world.clone(),
            measurement: measurement.clone(),
            model: record.native_receipt.native_record.clone(),
            native_after: receipt.native_after_ref.clone(),
            capture_request: completed
                .confirmation_request_data()
                .settled_capture_request
                .clone(),
            capture_id: request.capture.capture_id.clone(),
            capture_operation: request.capture_operation.clone(),
            prefix_frontier,
            frontier: completed.frontier_data(),
            signature: None,
        });
        let bridge = retained.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if bridge.capture_id != *claim.ticket_data().capture_id()
            || bridge.capture_operation != *claim.capture_operation_data()
            || request.current_record != bridge.measurement
            || request.current_model != bridge.model
            || request.history_next_sequence != bridge.prefix_frontier
            || request.runtime_object != claim.runtime_object_data().reference
            || bridge.prefix_frontier.get() >= bridge.frontier.get()
            || native
                .body_reference()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                != &bridge.native_after
            || !inputs.world.same_authority(claim.world_data())
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        recheck_read()?;
        signatures.authenticate_capture_data(completed, key, maximum_frame)?;
        native
            .authenticate_current_checkpoint_data(record, underlying, measurement)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        bridge.signature = Some(bridge.signature_data(completed, key)?);
        inputs.authenticate_current_data()?;
        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()
    }

    /// Selects this proof only for the exact retained pre-Capture model identity.
    ///
    /// The parent's latest-frontier chooser compares all actual saved proof
    /// frontiers first. A matching measurement does not make this bridge current.
    pub(super) fn checkpoint_identity_data(&self) -> (&ContentRef, &ContentRef, U64) {
        (&self.measurement, &self.model, self.frontier)
    }

    /// Names the unchanged typed checkpoint consumed before Capture-owned traffic.
    ///
    /// The prefix is the SDK once owner's real saved pre-upload frontier. This
    /// identity only locates the still-retained typed Source owner; the bridge's
    /// actual current SDK/native/MAC guards remain mandatory around its use.
    pub(super) fn pre_checkpoint_identity_data(&self) -> (&ContentRef, &ContentRef, U64) {
        (&self.measurement, &self.model, self.prefix_frontier)
    }

    pub(super) fn authenticate_current_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        world: &WorldActivation,
        key: &[u8; 32],
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || !self.world.same_authority(world)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        // This real SDK lender checks both exact actual journal pairs and the
        // unchanged private final frontier. No old Observe pair is relabeled.
        let completed = controller
            .original_completed_restored_settled_capture_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if completed.frontier_data() != self.frontier
            || completed
                .prefix_frontier_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                != self.prefix_frontier
            || completed.request_data().current_record != self.measurement
            || completed.request_data().current_model != self.model
            || completed.receipt_data().native_after_ref != self.native_after
            || completed
                .confirmation_request_data()
                .settled_capture_request
                != self.capture_request
            || self.signature != Some(self.signature_data(&completed, key)?)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    /// Lends exact administrative facts without serializing process authority.
    ///
    /// A partial bridge remains visible when a later proof or fence failed.
    /// The enclosing current-history reader still requires its actual SDK and
    /// native correspondence; this view cannot complete that reader alone.
    pub(super) fn historical_data(&self) -> Result<CaptureAdminBridgeHistory<'_>, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(CaptureAdminBridgeHistory(self))
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            process: _,
            thread: _,
            source: _,
            controller: _,
            world,
            measurement,
            model,
            native_after,
            capture_request,
            capture_id,
            capture_operation,
            prefix_frontier: _,
            frontier: _,
            signature: _,
        } = self;
        let backing = world.retained_requested_storage_data(maximum)?;
        let mut total = backing.independent_bytes();
        for shared in backing.shared_allocations() {
            total = add(total, shared.requested_bytes(), maximum)?;
        }
        for reference in [measurement, model, native_after, capture_request] {
            total = add(
                total,
                crate::node_contract::NodeRuntime::capture_reference_storage(reference)?,
                maximum,
            )?;
        }
        for id in [capture_id, capture_operation] {
            total = add(total, id.allocated_capacity(), maximum)?;
        }
        Ok(total)
    }

    pub(super) fn counter_scratch_data() -> usize {
        use crucible_node_transport::{ProviderError, bodies::ResponseBody, envelope::Envelope};
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&CnpController>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&OriginalRestoredCaptureSigningInputs<'static>>()
            + size_of::<&OriginalRestoredCaptureClaim<'static>>()
            + size_of::<&OriginalCompletedRestoredSettledCaptureData<'static>>()
            + size_of::<OriginalCompletedRestoredSettledCaptureData<'static>>()
            + size_of::<Result<OriginalCompletedRestoredSettledCaptureData<'static>, ProviderError>>(
            )
            + size_of::<&ValidatedRestoredSettledNative17CaptureOutputs>()
            + size_of::<&CaptureSigningOwners>()
            + size_of::<&PacketNativeRestoredRecord>()
            + size_of::<&PacketNative5UnderlyingRecord>()
            + size_of::<&ContentRef>()
            + size_of::<Result<&ContentRef, ProviderError>>()
            + size_of::<&WorldActivation>()
            + size_of::<&[u8; 32]>()
            + size_of::<[u8; 32]>()
            + size_of::<Option<[u8; 32]>>()
            + size_of::<Result<[u8; 32], RuntimeError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<HashWriter<'static>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<(&Envelope, &Envelope, &ResponseBody)>() * 2
            + size_of::<(&ContentRef, &ContentRef, U64)>()
            + size_of::<[&ContentRef; 4]>()
            + size_of::<std::array::IntoIter<&'static ContentRef, 4>>()
            + size_of::<[&Id; 2]>()
            + size_of::<std::array::IntoIter<&'static Id, 2>>()
            + size_of::<CaptureAdminBridgeHistory<'static>>()
            + size_of::<Result<CaptureAdminBridgeHistory<'static>, RuntimeError>>()
            + size_of::<&CaptureAdminBridgeHistory<'static>>()
            + size_of::<BridgeWorldData<'static>>()
            + size_of::<&BridgeWorldData<'static>>()
            + size_of::<&mut dyn FnMut() -> Result<(), RuntimeError>>()
    }

    fn signature_data(
        &self,
        completed: &OriginalCompletedRestoredSettledCaptureData<'_>,
        key: &[u8; 32],
    ) -> Result<[u8; 32], RuntimeError> {
        let mut hash = blake3::Hasher::new_keyed(key);
        hash.update(b"crucible.source-restored-capture-admin-bridge/17");
        let mut writer = HashWriter(&mut hash);
        let (capture, terminal, _) = completed.capture_pair_data();
        let (confirmation, final_terminal, _) = completed.confirmation_pair_data();
        serde_json::to_writer(
            &mut writer,
            &(
                BridgeWorldData(self.world.record()),
                &self.measurement,
                &self.model,
                &self.native_after,
                &self.capture_request,
                &self.capture_id,
                &self.capture_operation,
                self.prefix_frontier,
                self.frontier,
                capture,
                terminal,
                confirmation,
                final_terminal,
            ),
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(*hash.finalize().as_bytes())
    }
}

/// Borrows the actual fixed current World facts used by the Source signature.
struct BridgeWorldData<'a>(&'a ActivationRecord);

impl Serialize for BridgeWorldData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ActivationRecord {
            generation,
            activation_id,
            world_binding_hash,
            owners,
            boundary,
        } = self.0;
        let mut value = serializer.serialize_struct("SourceCaptureBridgeWorld17", 5)?;
        value.serialize_field("generation", generation)?;
        value.serialize_field("activation_id", activation_id)?;
        value.serialize_field("world_binding_hash", world_binding_hash)?;
        value.serialize_field("owners", owners)?;
        value.serialize_field("boundary", boundary)?;
        value.end()
    }
}

pub(super) struct CaptureAdminBridgeHistory<'a>(&'a CaptureAdminBridge);

impl Serialize for CaptureAdminBridgeHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let CaptureAdminBridge {
            process,
            thread,
            source: _,
            controller: _,
            world,
            measurement,
            model,
            native_after,
            capture_request,
            capture_id,
            capture_operation,
            prefix_frontier,
            frontier,
            signature,
        } = self.0;
        if *process != std::process::id() || *thread != std::thread::current().id() {
            return Err(S::Error::custom("foreign Source Capture bridge"));
        }
        let mut value = serializer.serialize_struct("SourceCaptureAdminBridge17", 11)?;
        value.serialize_field(
            "schema",
            "source-private.source-restored-capture-admin-bridge/17",
        )?;
        value.serialize_field("world", &BridgeWorldData(world.record()))?;
        value.serialize_field("measurement", measurement)?;
        value.serialize_field("model", model)?;
        value.serialize_field("native_after", native_after)?;
        value.serialize_field("capture_request", capture_request)?;
        value.serialize_field("capture_id", capture_id)?;
        value.serialize_field("capture_operation", capture_operation)?;
        value.serialize_field("prefix_frontier", prefix_frontier)?;
        value.serialize_field("frontier", frontier)?;
        value.serialize_field("signature", signature)?;
        value.end()
    }
}

struct HashWriter<'a>(&'a mut blake3::Hasher);

impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

#[path = "bridge/precredit.rs"]
mod precredit;
