//! Retains the Source copies around the actual once-owned SDK Capture effect.
//!
//! The parent installs this owner before fallible work and admits its complete
//! Source row plus the defining future SDK row under the genuine Window claim.
//! These helpers use only selected Capture/auxiliary SDK methods. They neither
//! obtain an administrative ticket nor turn resource DATA into permission.

use super::{signing::CaptureSigningOwners, upload};
use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::OriginalRestoredCaptureClaim,
    node_contract::{NodeRuntime, RuntimeError},
    node_scheduling::InputPayload,
};
use crucible_node_format::Id;
use crucible_node_transport::{
    bodies::BeginRequest,
    client::{
        CnpController, OriginalCanonicalBlobAckEmitter,
        OriginalRestoredSettledCaptureConstructionData, RestoredSettledCaptureAuxiliaryBody,
        RestoredSettledCaptureTypedOwnerData,
    },
    reference_packet::service::{
        PacketNative5SourceLaunch,
        native_startup::{
            PacketRestoredSettledCaptureUploadGeometryData, PacketRestoredSettledNativeCarrierData,
        },
        restored_settled_capture::{
            PacketRestoredSettledCaptureRequest,
            upload::{
                PacketRestoredSettledCaptureUploadOrdinal,
                PacketRestoredSettledCaptureUploadRequest,
            },
        },
    },
};
use std::mem::size_of;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Retained,
    Starting,
    Captured,
}

/// Owns independent Source arguments even when an SDK precondition refuses them.
///
/// SDK owns every assigned original and raw/typed terminal separately. This
/// owner is never moved or replaced once the parent's quote binds its inputs.
pub(super) struct CaptureSdkOwners {
    request_id: Id,
    operation_id: Id,
    body: BeginRequest,
    request: PacketRestoredSettledCaptureRequest,
    uploads: [PacketRestoredSettledCaptureUploadRequest; 2],
    prefix: InputPayload,
    runtime_object: InputPayload,
    signatures: CaptureSigningOwners,
    request_ids: Vec<Id>,
    bodies: Vec<RestoredSettledCaptureAuxiliaryBody>,
    stage: Stage,
}

impl CaptureSdkOwners {
    /// Moves already admitted actual arguments; no future fullref is fabricated.
    pub(super) fn new_data(
        request_id: Id,
        operation_id: Id,
        body: BeginRequest,
        request: PacketRestoredSettledCaptureRequest,
        uploads: [PacketRestoredSettledCaptureUploadRequest; 2],
        prefix: InputPayload,
        runtime_object: InputPayload,
    ) -> Self {
        Self {
            request_id,
            operation_id,
            body,
            request,
            uploads,
            prefix,
            runtime_object,
            signatures: CaptureSigningOwners::new_data(),
            request_ids: Vec::new(),
            bodies: Vec::new(),
            stage: Stage::Retained,
        }
    }

    pub(super) fn capture_data(
        &mut self,
        source: &PacketCompleteSemanticSource,
        controller: &mut CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        claim: &OriginalRestoredCaptureClaim<'_>,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        geometry: &PacketRestoredSettledCaptureUploadGeometryData,
        key: &[u8; 32],
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.stage != Stage::Retained {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Spend before validation, reserve or assignment. The containing owner
        // remains installed on every error, including a failed Vec reservation.
        self.stage = Stage::Starting;
        claim.authenticate_current_data(source, controller as *const _)?;
        // The execution dispatcher also accepts its exact legacy16 member.
        // Capture requires the independently reserved and completed17 member.
        source.original_completed_restored_settled_startup_data()?;
        source.authenticate_original_restored_producer_launch_data(launch, canonical_launch5)?;
        sdk.authenticate_inputs_data(controller, launch, &self.request, &self.body)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.authenticate_request_data(claim)?;
        for upload in &self.uploads {
            sdk.authenticate_typed_owner_data(
                &RestoredSettledCaptureTypedOwnerData::UploadRequest(upload),
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        recheck_read()?;

        let counts = sdk
            .actual_auxiliary_originals_data(controller, launch, &self.request, &self.body)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if geometry.maximum_auxiliary_originals_data() != counts {
            return Err(RuntimeError::InvalidReceipt);
        }
        let originals = counts[0]
            .checked_add(counts[1])
            .ok_or(RuntimeError::ResourceLimit)?;
        self.request_ids
            .try_reserve_exact(originals)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.bodies
            .try_reserve_exact(originals)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if self.request_ids.capacity() > originals || self.bodies.capacity() > originals {
            return Err(RuntimeError::ResourceLimit);
        }

        let mut prepared = controller
            .reserve_original_restored_settled_capture(
                emitter,
                self.request_id.clone(),
                self.operation_id.clone(),
                self.body.clone(),
                self.request.clone(),
                counts,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if prepared
            .original_history_next_sequence_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != self.request.history_next_sequence
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let Self {
            uploads,
            prefix,
            runtime_object,
            signatures,
            request_ids,
            bodies,
            ..
        } = self;
        for (request, payload) in uploads.iter().zip([&*prefix, &*runtime_object]) {
            upload::upload_data(
                &mut prepared,
                signatures,
                emitter,
                key,
                request,
                (&payload.reference, &payload.bytes),
                geometry,
                sdk,
                request_ids,
                bodies,
                recheck_read,
            )?;
        }
        recheck_read()?;
        prepared
            .assign_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        signatures.seal_capture_data(
            &mut prepared,
            emitter,
            key,
            sdk,
            sdk.maximum_frame_bytes_data(),
        )?;
        recheck_read()?;
        prepared
            .publish_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(prepared);
        claim.authenticate_current_data(source, controller as *const _)?;
        recheck_read()?;
        source.authenticate_original_restored_producer_launch_data(launch, canonical_launch5)?;
        source.original_completed_restored_settled_startup_data()?;
        self.stage = Stage::Captured;
        Ok(())
    }

    fn authenticate_request_data(
        &self,
        claim: &OriginalRestoredCaptureClaim<'_>,
    ) -> Result<(), RuntimeError> {
        let request = &self.request;
        if request.capture_operation != *claim.capture_operation_data()
            || self.operation_id != *claim.capture_operation_data()
            || request.capture.capture_id != *claim.ticket_data().capture_id()
            || request.capture.cut != claim.ticket_data().cut()
            || request.capture.event_ordinal != claim.ticket_data().ordinal()
            || request.capture_owner != claim.ticket_data().owner().owner
            || request.capture.participant_ids.as_slice() != claim.ticket_data().participants()
            || &request.coordinator_checkpoint != claim.coordinator_checkpoint_data()?.0
            || request.runtime_object != claim.runtime_object_data().reference
            || self.runtime_object.reference != claim.runtime_object_data().reference
            || self.runtime_object.bytes != claim.runtime_object_data().bytes
            || request.history_prefix != self.prefix.reference
            || self.uploads[0].ordinal != PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix
            || self.uploads[1].ordinal != PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for (upload, payload) in self
            .uploads
            .iter()
            .zip([&self.prefix, &self.runtime_object])
        {
            if upload.capture != *request || upload.content != payload.reference {
                return Err(RuntimeError::InvalidReceipt);
            }
            payload
                .reference
                .verify(&payload.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
        Ok(())
    }

    pub(super) fn authenticate_prefix_payload_data(
        &self,
        prefix: (&crucible_node_format::ContentRef, &[u8]),
    ) -> Result<(), RuntimeError> {
        if &self.prefix.reference != prefix.0 || self.prefix.bytes.as_slice() != prefix.1 {
            return Err(RuntimeError::InvalidReceipt);
        }
        prefix
            .0
            .verify(prefix.1)
            .map_err(|_| RuntimeError::InvalidReceipt)
    }

    pub(super) fn signatures_data(&self) -> &CaptureSigningOwners {
        &self.signatures
    }

    pub(super) fn request_data(&self) -> &PacketRestoredSettledCaptureRequest {
        &self.request
    }

    pub(super) fn captured_data(&self) -> Result<(), RuntimeError> {
        if self.stage != Stage::Captured {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Walks actual Source owners; the independent SDK walk is not substituted.
    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            request_id,
            operation_id,
            body,
            request,
            uploads,
            prefix,
            runtime_object,
            signatures,
            request_ids,
            bodies,
            stage: _,
        } = self;
        let mut total = add(
            request_id.allocated_capacity(),
            operation_id.allocated_capacity(),
            maximum,
        )?;
        total = add(
            total,
            request_ids
                .capacity()
                .checked_mul(size_of::<Id>())
                .ok_or(RuntimeError::ResourceLimit)?,
            maximum,
        )?;
        total = add(
            total,
            bodies
                .capacity()
                .checked_mul(size_of::<RestoredSettledCaptureAuxiliaryBody>())
                .ok_or(RuntimeError::ResourceLimit)?,
            maximum,
        )?;
        for id in request_ids {
            total = add(total, id.allocated_capacity(), maximum)?;
        }
        for payload in [prefix, runtime_object] {
            total = add(total, payload.bytes.capacity(), maximum)?;
            total = add(
                total,
                NodeRuntime::capture_reference_storage(&payload.reference)?,
                maximum,
            )?;
        }
        let facts = crucible_node_transport::reference_packet::service::native_startup::PacketRestoredProducerTypedOwnerData::Begin(body)
            .retained_metadata_data().map_err(|_| RuntimeError::ResourceLimit)?;
        total = add(
            total,
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts, maximum,
            )?,
            maximum,
        )?;
        for value in [
            RestoredSettledCaptureTypedOwnerData::CaptureRequest(request),
            RestoredSettledCaptureTypedOwnerData::UploadRequest(&uploads[0]),
            RestoredSettledCaptureTypedOwnerData::UploadRequest(&uploads[1]),
        ] {
            let facts = value
                .retained_metadata_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            total = add(
                total,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?,
                maximum,
            )?;
        }
        total = add(
            total,
            upload::bodies_retained_storage_data(bodies, maximum)?,
            maximum,
        )?;
        add(total, signatures.retained_storage_data(maximum)?, maximum)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<Stage>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&mut CnpController>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&OriginalRestoredCaptureClaim<'static>>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&[u8]>()
            + size_of::<&OriginalRestoredSettledCaptureConstructionData>()
            + size_of::<&PacketRestoredSettledCaptureUploadGeometryData>()
            + size_of::<PacketRestoredSettledNativeCarrierData>()
            + size_of::<Result<PacketRestoredSettledNativeCarrierData, RuntimeError>>()
            + size_of::<&[u8; 32]>()
            + size_of::<&mut dyn FnMut() -> Result<(), RuntimeError>>()
            + size_of::<[usize; 2]>()
            + size_of::<Result<[usize; 2], crucible_node_transport::ProviderError>>()
            + size_of::<std::array::IntoIter<&'static InputPayload, 2>>()
            + size_of::<std::slice::Iter<'static, PacketRestoredSettledCaptureUploadRequest>>()
            + size_of::<
                std::iter::Zip<
                    std::slice::Iter<'static, PacketRestoredSettledCaptureUploadRequest>,
                    std::array::IntoIter<&'static InputPayload, 2>,
                >,
            >()
            + size_of::<[RestoredSettledCaptureTypedOwnerData<'static>; 3]>()
            + size_of::<std::array::IntoIter<RestoredSettledCaptureTypedOwnerData<'static>, 3>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<usize>()
            + CaptureSigningOwners::counter_scratch_data()
            + upload::counter_scratch_data()
    }
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|total| *total <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}
