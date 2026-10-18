//! Prices future SDK Capture17 owners before the Controller once-slot is installed.
//!
//! Every current journal and receiver ceiling stays unchanged. This independent
//! row covers new SDK metadata/partials and every permitted incoming transfer;
//! the Source and native rows remain separate. No quote is a spending permit.

use super::*;
use crate::envelope::RequestOrigin;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch,
    complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits,
    native_startup::{
        original_restored_settled_capture_auxiliary_geometry_for_lengths_data,
        original_restored_settled_capture_auxiliary_geometry_for_limits_data,
        original_restored_settled_capture_negotiated_geometry_counter_scratch_data,
    },
};
use crate::retained_metadata::{
    MetadataObserver, requested_metadata_backing_storage_data,
    serialization_storage::{
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};
use crucible_node_contract::{HashRef, Position};
use serde_json::Map;

/// Borrows known Capture data before any administrative ticket or DTO exists.
///
/// The two encoded bounds describe future objects, not fabricated references.
/// The same actual Controller and launch supply all transport/output ceilings.
pub struct OriginalRestoredSettledCaptureProspectiveData<'a> {
    /// Names the caller's actual requested administrative capture.
    pub capture_id: &'a Id,
    /// Carries the actual requested coordinator cut.
    pub cut: Position,
    /// Carries the actual requested event ordinal at that cut.
    pub event_ordinal: U64,
    /// Bounds the separately admitted immutable current-history prefix encoding.
    pub maximum_history_prefix_encoded_bytes: usize,
    /// Bounds the separately admitted actual Runtime7 encoding.
    pub maximum_runtime_record_encoded_bytes: usize,
}

/// Retains independent future SDK owner geometry, never Source/native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalRestoredSettledCaptureConstructionData {
    controller: *const CnpController,
    launch: *const PacketNative5SourceLaunch,
    capture_id: [u8; 128],
    capture_id_length: usize,
    cut: Position,
    event_ordinal: U64,
    content_lengths: [usize; 2],
    negotiated: crate::handshake::Limits,
    request_backing: usize,
    body_backing: usize,
    frame: usize,
    chunk: usize,
    auxiliary: [usize; 2],
    incoming: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
    total: usize,
}

impl OriginalRestoredSettledCaptureConstructionData {
    /// Returns the actual same Controller's unchanged negotiated frame ceiling.
    pub const fn maximum_frame_bytes_data(&self) -> usize {
        self.frame
    }

    /// Returns the actual unchanged negotiated inline Blob chunk ceiling.
    pub const fn maximum_negotiated_chunk_bytes_data(&self) -> usize {
        self.chunk
    }

    /// Returns the independently retained Begin body backing bound.
    pub const fn maximum_begin_body_backing_bytes_data(&self) -> usize {
        self.body_backing
    }

    /// Returns future CaptureRequest backing independently of its inline header.
    pub const fn maximum_capture_request_backing_bytes_data(&self) -> usize {
        self.request_backing
    }

    /// Returns future UploadRequest backing independently of its inline header.
    ///
    /// The closed family bound also covers its embedded Capture request.
    pub const fn maximum_upload_request_backing_bytes_data(&self) -> usize {
        self.request_backing
    }

    /// Returns future confirmation backing independently of its inline header.
    pub const fn maximum_confirmation_request_backing_bytes_data(&self) -> usize {
        self.body_backing
    }

    /// Returns a context's request plus independent digest/domain backing bound.
    ///
    /// # Errors
    /// Refuses checked addition overflow.
    pub fn maximum_context_backing_bytes_data(&self) -> Result<usize, ProviderError> {
        add(self.request_backing, self.body_backing)
    }

    /// Returns an artifact's request plus independent proof backing bound.
    ///
    /// # Errors
    /// Refuses checked addition overflow.
    pub fn maximum_artifact_backing_bytes_data(&self) -> Result<usize, ProviderError> {
        add(self.request_backing, self.body_backing)
    }

    /// Checks one actual independently retained typed owner before SDK transfer.
    ///
    /// Source must separately price its own copy and call this for each actual
    /// Context/Artifact/upload/confirmation before passing it into the SDK.
    /// No caller-provided capacity becomes an allocation or execution permit.
    ///
    /// # Errors
    /// Refuses actual spare backing beyond this fixed prospective family bound.
    pub fn authenticate_typed_owner_data(
        &self,
        owner: &RestoredSettledCaptureTypedOwnerData<'_>,
    ) -> Result<(), ProviderError> {
        let maximum = match owner {
            RestoredSettledCaptureTypedOwnerData::CaptureRequest(_)
            | RestoredSettledCaptureTypedOwnerData::UploadRequest(_) => self.request_backing,
            RestoredSettledCaptureTypedOwnerData::CaptureContext(_)
            | RestoredSettledCaptureTypedOwnerData::UploadContext(_) => {
                self.maximum_context_backing_bytes_data()?
            }
            RestoredSettledCaptureTypedOwnerData::CaptureArtifact(_)
            | RestoredSettledCaptureTypedOwnerData::UploadArtifact(_) => {
                self.maximum_artifact_backing_bytes_data()?
            }
            RestoredSettledCaptureTypedOwnerData::ConfirmationRequest(_)
            | RestoredSettledCaptureTypedOwnerData::ConfirmationReceipt(_) => self.body_backing,
        };
        if requested_metadata_backing_storage_data(&owner.retained_metadata_data()?)? > maximum {
            return Err(refused());
        }
        Ok(())
    }

    /// Returns the two prospective fixed-grid auxiliary original maxima.
    pub const fn maximum_auxiliary_originals_data(&self) -> [usize; 2] {
        self.auxiliary
    }

    /// Returns the remaining actual provider-original namespace ceiling priced.
    pub const fn maximum_incoming_originals_data(&self) -> usize {
        self.incoming
    }

    /// Returns independent simultaneous retained SDK/receiver partial ownership.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independent largest simultaneous parser/signing/copy work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the defining fixed getter and SDK partial-owner views.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the checked whole row, which the real caller must separately admit.
    pub const fn requested_bytes_data(&self) -> usize {
        self.total
    }

    /// Checks actual post-ticket inputs against this earlier prospective row.
    ///
    /// This callback-free check allocates no slot or future authoritative DTO.
    /// It must succeed under the real Source/Window claim before SDK reserve.
    ///
    /// # Errors
    /// Refuses a different actual Controller/launch, changed requested cut,
    /// larger content/backing/frame/count geometry or occupied Capture owner.
    pub fn authenticate_inputs_data(
        &self,
        controller: &CnpController,
        launch: &PacketNative5SourceLaunch,
        request: &PacketRestoredSettledCaptureRequest,
        body: &BeginRequest,
    ) -> Result<(), ProviderError> {
        if !std::ptr::eq(self.controller, controller)
            || !std::ptr::eq(self.launch, launch)
            || controller.original_restored_settled_capture.is_some()
            || controller.session.authority().limits() != self.negotiated
            || request.capture.capture_id.as_str().as_bytes()
                != &self.capture_id[..self.capture_id_length]
            || request.capture.cut != self.cut
            || request.capture.event_ordinal != self.event_ordinal
            || body.kind != BeginKind::Capture
            || !body.extensions.is_empty()
            || usize::try_from(request.history_prefix.length.get()).map_err(|_| refused())?
                > self.content_lengths[0]
            || usize::try_from(request.runtime_object.length.get()).map_err(|_| refused())?
                > self.content_lengths[1]
        {
            return Err(refused());
        }
        let mut observer = MetadataObserver::new();
        observer.observe(request)?;
        if requested_metadata_backing_storage_data(&observer.finish())? > self.request_backing {
            return Err(refused());
        }
        if actual_body_backing(body)? > self.body_backing {
            return Err(refused());
        }
        crate::connection::serialized_credit(
            request,
            MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES.min(self.frame),
        )?;
        crate::connection::serialized_credit(body, self.frame)?;
        self.actual_geometry_data(controller, request)?;
        Ok(())
    }

    /// Returns exact actual counts after verifying prospective domination.
    ///
    /// Source passes these exact counts, rather than their upper bound, into
    /// the dedicated reserve. Both native and SDK recompute the same grid.
    ///
    /// # Errors
    /// Refuses any input/capacity mismatch documented by `authenticate_inputs_data`.
    pub fn actual_auxiliary_originals_data(
        &self,
        controller: &CnpController,
        launch: &PacketNative5SourceLaunch,
        request: &PacketRestoredSettledCaptureRequest,
        body: &BeginRequest,
    ) -> Result<[usize; 2], ProviderError> {
        self.authenticate_inputs_data(controller, launch, request, body)?;
        Ok(self
            .actual_geometry_data(controller, request)?
            .maximum_auxiliary_originals_data())
    }

    fn actual_geometry_data(
        &self,
        controller: &CnpController,
        request: &PacketRestoredSettledCaptureRequest
    ) -> Result<
        crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData,
        ProviderError
    >{
        let maximum = controller
            .custody
            .maximum_requests()
            .checked_sub(
                controller
                    .custody
                    .originals_by_origin(RequestOrigin::Controller)
                    .count(),
            )
            .ok_or_else(refused)?;
        let geometry = original_restored_settled_capture_auxiliary_geometry_for_limits_data(
            &self.negotiated,
            &request.history_prefix,
            &request.runtime_object,
            maximum,
        )?;
        let actual = geometry.maximum_auxiliary_originals_data();
        if actual[0] > self.auxiliary[0] || actual[1] > self.auxiliary[1] {
            return Err(refused());
        }
        Ok(geometry)
    }
}

impl CnpController {
    /// Quotes selected SDK future owners before a Capture ticket or DTO exists.
    ///
    /// The known request DATA and actual Controller/launch yield finite typed
    /// family, frame, output and fixed-grid bounds. This creates no future
    /// ContentRef, operation ID, ticket, body, slot, original or transport effect.
    /// Later actual inputs must pass the row's backing/content/frame domination
    /// checks before SDK reserve. Source and native construction stay independent.
    ///
    /// # Errors
    /// Refuses an occupied slot, different negotiated launch frame, invalid full17
    /// declaration, zero/oversized object bounds, insufficient unchanged original
    /// namespace, arithmetic overflow or the supplied construction-policy limit.
    pub fn original_restored_settled_capture_future_construction_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        prospective: &OriginalRestoredSettledCaptureProspectiveData<'_>,
        maximum: usize,
    ) -> Result<OriginalRestoredSettledCaptureConstructionData, ProviderError> {
        if self.original_restored_settled_capture.is_some() {
            return Err(refused());
        }
        let frame = self.maximum_frame()?;
        let negotiated = self.session.authority().limits();
        if frame != usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())? {
            return Err(refused());
        }
        let outputs = PacketRestoredSettledCaptureOutputLimits::from_launch_data(launch)?;
        let originals = usize::try_from(launch.limits.requests.get()).map_err(|_| refused())?;
        let content_lengths = [
            prospective.maximum_history_prefix_encoded_bytes,
            prospective.maximum_runtime_record_encoded_bytes,
        ];
        let geometry = original_restored_settled_capture_auxiliary_geometry_for_lengths_data(
            &negotiated,
            content_lengths,
            originals,
        )?;
        let auxiliary = geometry.maximum_auxiliary_originals_data();
        let outgoing = add(add(auxiliary[0], auxiliary[1])?, 2)?;
        let maximum_originals = self.custody.maximum_requests();
        let used = self
            .custody
            .originals_by_origin(RequestOrigin::Controller)
            .count();
        if outgoing > maximum_originals.checked_sub(used).ok_or_else(refused)? {
            return Err(refused());
        }
        let incoming = maximum_originals
            .checked_sub(
                self.custody
                    .originals_by_origin(RequestOrigin::Provider)
                    .count(),
            )
            .ok_or_else(refused)?;
        let extent = original_json_value_storage_extent_data(frame)?;

        // These are bounds on actual future typed owners, not invented values.
        // Actual constructors can retain arbitrary spare capacities; the later
        // exhaustive backing walk refuses any owner outside this declared row.
        let request_backing =
            typed_family_backing(MAXIMUM_RESTORED_SETTLED_CAPTURE_ARTIFACT_BYTES.min(frame))?;
        let body_backing = typed_family_backing(frame)?;
        // Proof digest/MAC Bytes are fixed by the defining signed contract;
        // Chunk Bytes may be larger. One base64 temporary is live at a time.
        let maximum_bytes = geometry.maximum_chunk_bytes_data().max(32);
        let request_bytes_temporary = multiply(add(maximum_bytes, 2)? / 3, 4)?;
        let mut capture_id = [0u8; 128];
        let capture_bytes = prospective.capture_id.as_str().as_bytes();
        capture_id
            .get_mut(..capture_bytes.len())
            .ok_or_else(refused)?
            .copy_from_slice(capture_bytes);

        // Nine distinct embedded request copies: main request/context/artifact,
        // plus request/context/artifact for each of the two auxiliary ordinals.
        // The additional typed CaptureArguments and unsigned body are independent owners; the whole request backing conservatively bounds the former.
        let requests = multiply(9, request_backing)?;
        let arguments = add(body_backing, request_backing)?;
        let state_headers = add(
            size_of::<AssignedRestoredSettledCapture>(),
            add(
                2 * size_of::<upload::AssignedAuxiliaryUpload>(),
                size_of::<AssignedConfirmation>(),
            )?,
        )?;
        let slot_backing = multiply(
            add(auxiliary[0], auxiliary[1])?,
            size_of::<upload::AuxiliaryOriginal>(),
        )?;
        let root_headers = multiply(7, size_of::<ContentRef>())?;
        // Three independent contexts and three independent proof owners retain
        // domain strings and digest/MAC Bytes as well as their request copies.
        let context_and_proof_backing = multiply(6, body_backing)?;
        // The explicit confirmation request and independently decoded receipt
        // retain two more full request/reference families beside their DOMs.
        let confirmation_backing = multiply(2, body_backing)?;
        // Per original: SDK original + journal request + SDK terminal + journal
        // response + raw ResponseShape + typed result + retained proof extension.
        // Open response/outcome/extension children each have the defining DOM
        // bound; typed container headers are independently named below.
        let outgoing_dom = multiply(outgoing, multiply(7, extent.value_dom_requested_bytes)?)?;
        let typed_nodes = multiply(extent.maximum_value_nodes, typed_reply_element_layouts())?;
        let typed_headers = multiply(outgoing, add(typed_reply_headers(), typed_nodes)?)?;
        let original_ids = multiply(outgoing, frame)?;
        let canonical_and_literals = multiply(outgoing, add(frame, add(frame, 4)?)?)?;
        let chunks = add(content_lengths[0], content_lengths[1])?;
        // Every remaining provider original may fail before semantic decode.
        // Retain both actual raw journal sides, their IDs and literal frames.
        let incoming_journal = multiply(
            incoming,
            add(
                multiply(2, extent.value_dom_requested_bytes)?,
                add(frame, multiply(2, add(frame, 4)?)?)?,
            )?,
        )?;
        let journal_trees = crate::retained_metadata::requested_storage::tree_storage_data(
            2,
            add(outgoing, incoming)?,
            size_of::<Id>() + size_of::<crate::client::ClientOriginal>(),
            std::mem::align_of::<(Id, crate::client::ClientOriginal)>(),
        )?;
        let output_lengths = [
            outputs.native_snapshot_bytes,
            outputs.current_control_bytes,
            outputs.anchor_bytes,
            outputs.native_after_bytes,
        ]
        .map(|value| usize::try_from(value.get()).map_err(|_| refused()));
        let [snapshot, control, anchor, after] = output_lengths;
        let output_lengths = [snapshot?, control?, anchor?, after?];
        // Expected output roles remain independently checked; the receiver can
        // retain other partials before rejecting the terminal, so price its
        // entire actual unchanged logical ceilings rather than only four roles.
        let expected_content =
            crate::client::ClientContent::restored_settled_capture_future_content_storage_data(
                output_lengths,
                frame,
            )?;
        // Capture enters the same idle native5 Session and uses its unchanged
        // generic Blob receiver. Fresh provider IDs debit the actual finite
        // ClientCustody namespace before mutation; cached duplicate ACKs do not
        // append payload bytes. The defining causal projection therefore bounds
        // all accepted and failed receiver owners without pretending the numeric
        // ContentStore reservation allocated its entire logical quota up front.
        let receiver = self.original_observation_receive_storage_data(maximum)?;
        let content = add(expected_content, receiver.retained)?;
        let retained = sum(&[
            requests,
            arguments,
            state_headers,
            slot_backing,
            root_headers,
            context_and_proof_backing,
            confirmation_backing,
            outgoing_dom,
            typed_headers,
            original_ids,
            canonical_and_literals,
            chunks,
            incoming_journal,
            journal_trees,
            content,
        ])?;

        // Only one exchange/signature runs at once, but its canonical, DOM,
        // raw, decoded Bytes and prospective typed copies coexist. Earlier
        // completed/failed owners are already included in retained above.
        let transient = sum(&[
            multiply(4, extent.canonical_pass_requested_bytes()?)?,
            multiply(2, frame)?,
            body_backing,
            multiply(2, request_backing)?,
            add(typed_reply_headers(), typed_nodes)?,
            add(geometry.maximum_chunk_bytes_data(), request_bytes_temporary)?,
            receiver.transient,
        ])?;
        let scratch = add(
            Self::original_restored_settled_capture_counter_scratch_data(),
            receiver.scratch,
        )?;
        let total = sum(&[retained, transient, scratch])?;
        if total > maximum {
            return Err(refused());
        }
        Ok(OriginalRestoredSettledCaptureConstructionData {
            controller: self,
            launch,
            capture_id,
            capture_id_length: capture_bytes.len(),
            cut: prospective.cut,
            event_ordinal: prospective.event_ordinal,
            content_lengths,
            negotiated,
            request_backing,
            body_backing,
            frame,
            chunk: geometry.maximum_chunk_bytes_data(),
            auxiliary,
            incoming,
            retained,
            transient,
            scratch,
            total,
        })
    }
}

// DOM and typed-element layouts independently bound the closed request family.
// No serialized extent is treated as authority for arbitrary existing spare
// capacity: the actual backing walk below must fit before any SDK owner moves.
fn typed_family_backing(encoded: usize) -> Result<usize, ProviderError> {
    let extent = original_json_value_storage_extent_data(encoded)?;
    let element = size_of::<ContentRef>()
        + size_of::<HashRef>()
        + size_of::<Id>()
        + size_of::<String>()
        + size_of::<CaptureArguments>();
    add(
        extent.value_dom_requested_bytes,
        multiply(extent.maximum_value_nodes, element)?,
    )
}

fn actual_body_backing(body: &BeginRequest) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    let BeginRequest {
        kind: _,
        binding_hash,
        owner_generation,
        activation_id,
        world_generation,
        arguments,
        extensions,
    } = body;
    observer.observe(binding_hash)?;
    observer.observe(owner_generation)?;
    observer.observe(&activation_id.0)?;
    observer.observe(world_generation)?;
    observer.observe(arguments)?;
    observer.observe(extensions)?;
    requested_metadata_backing_storage_data(&observer.finish())
}

// Capture refs and even a subsequently refused Poll's observation/event/ID
// vectors are priced by real element layouts, independently of open Value DOM.
fn typed_reply_element_layouts() -> usize {
    size_of::<ContentRef>()
        + size_of::<Id>()
        + size_of::<HashRef>()
        + size_of::<crucible_node_contract::ObservationBatch>()
        + size_of::<crucible_node_contract::Event>()
}

fn typed_reply_headers() -> usize {
    size_of::<ResponseBody>()
        + size_of::<crate::bodies::CaptureResult>()
        + size_of::<crate::bodies::PollResult>()
        + size_of::<crate::bodies::BlobBeginResult>()
        + size_of::<crate::bodies::BlobChunkResult>()
        + size_of::<crate::bodies::BlobFinishResult>()
        + size_of::<crate::connection::ReceivedFrame>()
        + size_of::<crate::connection::ReceivedBody>()
        + size_of::<CaptureArguments>()
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<&Option<Id>>()
        + crate::client::ClientContent::restored_settled_capture_receiver_counter_scratch_data()
        + size_of::<&RestoredSettledCaptureTypedOwnerData<'static>>()
        + size_of::<OriginalRestoredSettledCaptureProspectiveData<'static>>()
        + size_of::<&OriginalRestoredSettledCaptureProspectiveData<'static>>()
        + size_of::<Position>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<[u8;128]>()
        + size_of::<&[u8]>()*2
        + size_of::<&mut[u8]>()
        + size_of::<Option<&mut[u8]>>()
        + size_of::<*const CnpController>()
        + size_of::<*const PacketNative5SourceLaunch>()
        + size_of::<Result<[usize;2],ProviderError>>()
        + size_of::<Result<(),ProviderError>>()
        + size_of::<[usize;2]>()
        + crate::connection::original_serialized_credit_counter_scratch_data()
        + size_of::<OriginalRestoredSettledCaptureConstructionData>()
        + size_of::<Result<OriginalRestoredSettledCaptureConstructionData,ProviderError>>()
        + size_of::<&CnpController>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketRestoredSettledCaptureRequest>()
        + size_of::<&BeginRequest>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,ProviderError>>()
        + size_of::<Result<usize,ProviderError>>()
        + size_of::<Result<usize,std::num::TryFromIntError>>()
        + size_of::<Option<usize>>()
        + size_of::<[usize;16]>()
        + size_of::<[usize;6]>()
        + size_of::<std::slice::Iter<'static,usize>>()
        + size_of::<[Result<usize,ProviderError>;4]>()
        + size_of::<[crucible_node_contract::U64;4]>()
        + size_of::<std::array::IntoIter<crucible_node_contract::U64,4>>()
        + size_of::<[usize;4]>()
        + size_of::<[usize;3]>()
        + size_of::<Result<PacketRestoredSettledCaptureOutputLimits,ProviderError>>()
        + size_of::<Result<crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData,ProviderError>>()
        + size_of::<(&HashRef,&U64,&Nullable<Id>,&U64,&Map<String,Value>,&Extensions)>()
        + size_of::<std::collections::btree_map::Values<'static,Id,crate::client::ClientOriginal>>() * 2
        + PacketRestoredSettledCaptureOutputLimits::counter_scratch_data()
        + original_restored_settled_capture_negotiated_geometry_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + crate::client::ClientContent::restored_settled_capture_future_content_counter_scratch_data()
        + RestoredSettledCaptureTypedOwnerData::counter_scratch_data()
        + typed_reply_element_layouts()
        + typed_reply_headers()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |n, value| add(n, *value))
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn identical_wire_bodies_do_not_hide_independent_spare_backing() -> TestResult {
        let mut body = BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: crucible_node_contract::canonical::json_hash(
                "cnp.owner-binding.v1",
                &Value::Null,
            )?,
            owner_generation: U64::new(1),
            activation_id: Nullable(None),
            world_generation: U64::new(1),
            arguments: Map::new(),
            extensions: Extensions::new(),
        };
        body.arguments.insert(
            "inert-test-field".into(),
            Value::String("same-wire-value".into()),
        );
        let original = serde_json::to_vec(&body)?;
        let admitted = actual_body_backing(&body)?;

        let mut spare = String::with_capacity(admitted.checked_add(1).ok_or_else(refused)?);
        spare.push_str("same-wire-value");
        body.arguments
            .insert("inert-test-field".into(), Value::String(spare));

        assert_eq!(serde_json::to_vec(&body)?, original);
        assert!(actual_body_backing(&body)? > admitted);
        Ok(())
    }
}
