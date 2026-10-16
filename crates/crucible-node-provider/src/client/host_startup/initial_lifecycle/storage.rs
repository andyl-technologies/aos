//! Counts named host codec, initial originals and proof/cache ownership phases.
//!
//! This counts HOST layouts from closed future fields. Native birth/publication
//! rows are not imported as host credit. The actual fixed protocol bank is
//! already retained by the startup owner; its additional live reader view is
//! explicitly charged without an alias refund. No raw-size heap multiplier is
//! used for typed portable data: its exact borrowed source roster is observed.

use super::*;
use crate::bodies::*;
use crate::client::{ClientOriginal, OriginalPacketHostInitialResponse};
use crate::envelope::{MessageKind, Method};
use crate::retained_metadata::requested_storage::{
    requested_metadata_backing_storage_data as backing, tree_storage_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Data, OriginalSerializationStorageProjection as Projection,
    actual_serialization_storage_data,
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata, RetainedProtocolMetadataFacts};
use std::mem::{align_of, size_of};

/// Reports prospective host allocations through the original once-Admit.
///
/// Data are independently admitted by the real Source action. Kernel resources,
/// allocator overhead and compiler/recursive frames remain separate. Existing
/// startup owners and Source validation callbacks are separate current rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNativeHostInitialLifecycleStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
    journal_growth: usize,
}

impl PacketNativeHostInitialLifecycleStorageData {
    /// Counts new codec, method, content and independently retained reply owners.
    pub fn retained_growth_bytes(&self) -> usize {
        self.retained
    }
    /// Bounds the complete simultaneous selected transport/construction phase.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }
    /// Counts explicit counter, result and borrowed-view headers required first.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }
    /// Sums the named independent requested components without granting rights.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow.
    pub fn requested_peak_data(&self) -> Result<usize, ProviderError> {
        sum(&[self.retained, self.transient, self.scratch])
    }
    pub(super) fn journal_growth_data(&self) -> usize {
        self.journal_growth
    }
    pub(super) fn within(&self, prior: &Self) -> bool {
        self.retained <= prior.retained
            && self.transient <= prior.transient
            && self.scratch <= prior.scratch
            && self.journal_growth <= prior.journal_growth
    }
}

/// Counts the fixed counter banks before the prepared owner is inspected.
///
/// No DOM, serializer, callback or transport operation runs in this getter.
/// Explicit compact-byte and decimal formatter banks are included; recursive
/// compiler frames, allocator rounding and kernel resources remain separate.
pub fn original_packet_host_initial_lifecycle_counter_scratch_data() -> usize {
    use crate::retained_metadata::serialization_storage::{
        OriginalSerializationStorageProjection,
        original_json_value_storage_extent_counter_scratch_data,
    };
    crate::reference_packet::coordinator::packet_native5_coordinator_installation_counter_scratch_data()
        + size_of::<PacketNativeHostInitialLifecycleStorageData>()
        + size_of::<crate::reference_packet::service::native_startup::OriginalHostInitialLifecycleShapes>()
        + 4 * size_of::<MetadataObserver<'static>>() + 4 * size_of::<RetainedProtocolMetadataFacts>()
        + 10 * size_of::<Data>() + 2 * size_of::<OriginalSerializationStorageProjection>()
        + size_of::<OriginalPacketHostInitialAttachmentScope<'static>>()
        + size_of::<[usize; 24]>() + size_of::<blake3::Hasher>() + 20
        + crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes()
        + original_json_value_storage_extent_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::transfer::selected_issuer_decode_counter_scratch_data()
        + crate::reference_packet::service::native_startup::data_equality::counter_scratch_data()
        + crate::client::CnpController::original_live_host_metadata_counter_scratch_data()
        + super::super::original_packet_host_startup_counter_scratch_data()
}

pub(super) fn quote(
    startup: &OriginalPacketHostStartup,
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketNativeHostInitialLifecycleStorageData, ProviderError> {
    let maximum = usize::MAX;
    let registration = startup.registration.as_ref().ok_or_else(refused)?;
    if launch.confirmation_selection != Some(crate::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        || launch.ack_emitter_selection != Some(crate::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        || launch.native_codec_metadata_extent != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        || launch.selection.provider.supported_profiles.len() != 1
        || launch.limits.frame_bytes.get() == 0 || launch.limits.frame_bytes.get() > 65_536
        || launch.limits.blob_chunk_bytes.get() == 0 || launch.limits.blob_chunk_bytes.get() > 4096
        || launch.initial_coordinator.bytes.as_slice().len() > crate::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
    { return Err(refused()); }
    let shapes = crate::reference_packet::service::native_startup::original_host_initial_lifecycle_shapes_data(launch, maximum)?;
    let (schema_phase, schema_refs) = crate::reference_packet::service::native_startup::original_host_initial_codec_schema_storage_data(launch, maximum)?;
    let selection = actual(&launch.selection)?;
    let selection_backing = metadata(&launch.selection)?;
    let coordinator_backing = metadata(&launch.initial_coordinator)?;
    let coordinator_decode = crate::reference_packet::service::complete_restore::transfer::selected_issuer_decode_storage_data(
        launch.initial_coordinator.bytes.as_slice(), size_of::<crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation>(), maximum,
    )?;
    // Borrowed actual typed rosters dominate from_value's owned children: serde
    // consumes cloned Value Strings/arrays with their exact original lengths.
    // Raw parser growth is separately charged by the full raw receive phase.
    let discovery_typed = sum(&[
        metadata(&launch.selection.provider)?,
        metadata(&launch.selection.provider.supported_profiles)?,
        metadata(&launch.selection.provider.implementation.formats)?,
        size_of::<DiscoverResult>(),
    ])?;
    let realization_typed = sum(&[
        metadata(&launch.selection.realization)?,
        metadata(&launch.selection.prepared_token)?,
        reference_data()?.projected_parser_requested_bytes,
        size_of::<RealizeResult>(),
    ])?;
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    let wire = sum(&[
        metadata(&binding.compatibility.node_id)?,
        metadata(&binding.compatibility.execution_owner.id)?,
        metadata(&binding.authority.input_epoch)?,
        hash_children("cnp.owner-binding.v1")?,
    ])?;
    let codec = sum(&[
        crate::connection::original_host_initial_codec_layout_data()?,
        selection_backing,
        coordinator_backing,
        coordinator_decode,
        metadata(&launch.capture_profile)?,
        schema_refs,
        wire,
    ])?;
    let frame_bytes =
        usize::try_from(launch.storage.frame_bank_bytes.get()).map_err(|_| refused())?;
    let frame_rows =
        usize::try_from(launch.storage.frames_per_direction.get()).map_err(|_| refused())?;
    let extra_bank_view = sum(&[
        frame_bytes,
        mul(
            mul(2, frame_rows)?,
            crate::transport::original_frames::original_frame_slot_layout(),
        )?,
        crate::transport::original_frames::original_frame_bank_layout(),
    ])?;
    // Each independent response holds a real Rc view of the same controller
    // actor. Preserve both shared views conservatively without alias credit.
    let response_actor = sum(&[
        size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            align_of::<crate::protocol_snapshot::ProtocolCaptureOwner>(),
        )?,
    ])?;
    let mut retained = sum(&[
        // The pre-Hello action retains the entire same HOST constructor window
        // until actual Controller completion. Already present prepared roots
        // are conservatively charged again; no prior future row is relabeled
        // as current backing or treated as authority for this next action.
        startup.quote.retained_requested_bytes(),
        codec,
        extra_bank_view,
        2 * size_of::<OriginalPacketHostInitialResponse>(),
        mul(2, response_actor)?,
        discovery_typed,
        realization_typed,
        discovery_typed,
        realization_typed,
    ])?;
    let mut method_phase = 0;
    let mut literal_bytes = 0;
    for (original, response) in shapes.requests.iter().zip(shapes.responses.iter()) {
        if original.maximum_encoded_bytes
            > usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?
            || response.maximum_encoded_bytes
                > usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?
        {
            return Err(refused());
        }
        literal_bytes = add(
            literal_bytes,
            add(
                original.maximum_encoded_bytes,
                response.maximum_encoded_bytes,
            )?,
        )?;
        retained = add(
            retained,
            sum(&[
                // Controller cache, correlation/original-frame metadata and Source
                // result independently own original/terminal DOMs and typed views.
                mul(3, original.dom_and_canonical_scratch_bytes)?,
                mul(3, response.dom_and_canonical_scratch_bytes)?,
                size_of::<ClientOriginal>(),
                size_of::<crate::connection::ReceivedFrame>(),
                hash_children("cnp.request.v1")?,
                growth(128)?,
            ])?,
        )?;
        method_phase = add(
            method_phase,
            sum(&[
                mul(4, original.requested_total()?)?,
                mul(4, response.requested_total()?)?,
                size_of::<crate::connection::ReceivedFrame>(),
                size_of::<ResponseBody>(),
                size_of::<RequestBody>(),
            ])?,
        )?;
    }
    let chunk = usize::try_from(launch.limits.blob_chunk_bytes.get()).map_err(|_| refused())?;
    let proof_bytes: usize = 65_536;
    let proof_requests = mul(2, add(2, proof_bytes.div_ceil(chunk))?)?;
    let mut proof_phase = 0;
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let count = if method == Method::BlobChunk {
            mul(2, proof_bytes.div_ceil(chunk))?
        } else {
            2
        };
        let request = frame(registration, method, false, chunk)?;
        let response = frame(registration, method, true, chunk)?;
        let frame_limit =
            usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?;
        if request.maximum_encoded_bytes > frame_limit
            || response.maximum_encoded_bytes > frame_limit
        {
            return Err(refused());
        }
        literal_bytes = add(
            literal_bytes,
            mul(
                count,
                add(
                    request.maximum_encoded_bytes,
                    response.maximum_encoded_bytes,
                )?,
            )?,
        )?;
        retained = add(
            retained,
            mul(
                count,
                sum(&[
                    request.dom_and_canonical_scratch_bytes,
                    response.dom_and_canonical_scratch_bytes,
                    size_of::<ClientOriginal>(),
                    growth(128)?,
                    hash_children("cnp.request.v1")?,
                ])?,
            )?,
        )?;
        proof_phase = add(
            proof_phase,
            mul(
                count,
                sum(&[
                    mul(4, request.requested_total()?)?,
                    mul(4, response.requested_total()?)?,
                    growth(chunk)?,
                    growth(chunk.div_ceil(3).checked_mul(4).ok_or_else(refused)?)?,
                    size_of::<crate::connection::ReceivedFrame>(),
                    size_of::<RequestBody>(),
                    size_of::<ResponseBody>(),
                ])?,
            )?,
        )?;
    }
    // Two real realized proof payloads: raw native record then closed receipt.
    // ContentRef verification/current source meaning remain independent.
    let one_content_view = if let Some(custody) = startup.custody.as_ref() {
        custody
            .content()
            .fresh_report_requested_layout_data(growth(proof_bytes)?)?
    } else {
        startup
            .controller
            .as_ref()
            .ok_or_else(refused)?
            .original_host_initial_content_layout_data(growth(proof_bytes)?)?
    };
    // Each completed proof has both its Transfer and object Rc views. Count
    // both conservative views for both payloads, without an alias discount.
    let content_growth = sum(&[
        mul(4, one_content_view)?,
        mul(4, reference_data()?.projected_parser_requested_bytes)?,
    ])?;
    retained = add(
        retained,
        sum(&[
            content_growth,
            tree_storage_data(
                2,
                add(proof_requests, 3)?,
                size_of::<Id>() + size_of::<ClientOriginal>(),
                align_of::<Id>().max(align_of::<ClientOriginal>()),
            )?,
            tree_storage_data(
                3,
                add(proof_requests, 3)?,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            // True assigned Admit owns an independent original, bounded canonical
            // bank and raw terminal in addition to the ordinary original cache.
            shapes.requests[2].dom_and_canonical_scratch_bytes,
            shapes.responses[2].dom_and_canonical_scratch_bytes,
            // Source output retains the independently decoded typed Admit result.
            hash_children("cnp.node-binding.v1")?,
            growth(128)?,
            size_of::<crucible_node_contract::HashRef>(),
            size_of::<AdmitResult>(),
            growth(usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?)?,
        ])?,
    )?;
    let codec_phase = sum(&[
        codec,
        schema_phase,
        selection.requested_total()?,
        // Coordinator construction/validation: decoded original, temporary
        // typed world and its canonical comparison each use their own phase.
        coordinator_decode,
        coordinator_decode,
        coordinator_decode,
        // Connected schema builds full owner/binding identities independently.
        selection.requested_total()?,
        selection.requested_total()?,
        size_of::<blake3::Hasher>(),
    ])?;
    let raw = crate::connection::original_host_initial_raw_receive_storage_data(
        usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?,
    )?;
    let transient = sum(&[
        codec_phase
            .max(add(method_phase, proof_phase)?)
            .max(startup.quote.maximum_simultaneous_transient_bytes()),
        raw,
        startup.quote.retained_requested_bytes(),
        retained,
    ])?;
    let outgoing = add(3, proof_requests)?;
    let incoming = outgoing;
    if outgoing > frame_rows
        || incoming > frame_rows
        || add(literal_bytes, mul(add(incoming, outgoing)?, 4)?)? > frame_bytes
        || add(proof_requests, 3)?
            > usize::try_from(launch.limits.journal_entries.get()).map_err(|_| refused())?
    {
        return Err(refused());
    }
    let journal_growth = add(
        literal_bytes,
        usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?,
    )?;
    let data = PacketNativeHostInitialLifecycleStorageData {
        retained,
        transient,
        scratch: original_packet_host_initial_lifecycle_counter_scratch_data(),
        journal_growth,
    };
    data.requested_peak_data()?;
    Ok(data)
}

fn metadata(value: &(impl ObserveMetadata + ?Sized)) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    backing(&observer.finish())
}
fn actual(value: &(impl serde::Serialize + ObserveMetadata)) -> Result<Data, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    actual_serialization_storage_data(value, observer.finish(), usize::MAX)
}
fn hash_children(domain: &str) -> Result<usize, ProviderError> {
    sum(&[
        growth("blake3-256".len())?,
        growth(domain.len())?,
        growth(64)?,
    ])
}
fn frame(
    registration: &super::super::hello::Registration,
    method: Method,
    response: bool,
    chunk: usize,
) -> Result<Data, ProviderError> {
    let mut p = Projection::new(usize::MAX)?;
    object(
        &mut p,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "operation_id",
            "request_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    p.add_string("CNP/1")?;
    p.add_value(&if response {
        MessageKind::Response
    } else {
        MessageKind::Request
    })?;
    p.add_value(&registration.session_id)?;
    p.add_value(&registration.incarnation_id)?;
    for _ in 0..4 {
        p.add_value(&())?;
    }
    p.add_string_extent(128)?;
    p.add_unescaped_ascii_extent(20)?;
    p.add_value(&method)?;
    if response {
        object(
            &mut p,
            &["status", "operation_state", "result", "extensions"],
        )?;
        p.add_string("completed")?;
        p.add_value(&OperationState::Completed)?;
    }
    match method {
        Method::BlobBegin => {
            if response {
                object(
                    &mut p,
                    &["transfer_id", "next_offset", "maximum_chunk_bytes"],
                )?;
                p.add_string_extent(128)?;
                p.add_unescaped_ascii_extent(20)?;
                p.add_unescaped_ascii_extent(20)?;
            } else {
                object(&mut p, &["transfer_id", "content", "extensions"])?;
                p.add_string_extent(128)?;
                reference(&mut p)?;
                p.add_object()?;
            }
        }
        Method::BlobChunk => {
            if response {
                object(&mut p, &["transfer_id", "next_offset"])?;
                p.add_string_extent(128)?;
                p.add_unescaped_ascii_extent(20)?;
            } else {
                object(&mut p, &["transfer_id", "offset", "bytes", "extensions"])?;
                p.add_string_extent(128)?;
                p.add_unescaped_ascii_extent(20)?;
                p.add_unescaped_ascii_extent(
                    chunk.div_ceil(3).checked_mul(4).ok_or_else(refused)?,
                )?;
                p.add_object()?;
            }
        }
        Method::BlobFinish => {
            if response {
                object(&mut p, &["transfer_id", "content"])?;
                p.add_string_extent(128)?;
                reference(&mut p)?;
            } else {
                object(&mut p, &["transfer_id", "extensions"])?;
                p.add_string_extent(128)?;
                p.add_object()?;
            }
        }
        _ => return Err(refused()),
    }
    if response {
        p.add_object()?;
    }
    p.add_object()?;
    p.finish(usize::MAX)
}

fn reference_data() -> Result<Data, ProviderError> {
    let mut p = Projection::new(usize::MAX)?;
    reference(&mut p)?;
    p.finish(usize::MAX)
}
fn reference(p: &mut Projection) -> Result<(), ProviderError> {
    object(p, &["hash", "length", "media_type"])?;
    object(p, &["algorithm", "domain", "digest"])?;
    p.add_string("blake3-256")?;
    p.add_string("cnp.blob.v1")?;
    p.add_unescaped_ascii_extent(64)?;
    p.add_unescaped_ascii_extent(20)?;
    p.add_string("application/json")
}
fn object(p: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for field in fields {
        p.add_field(field)?;
    }
    Ok(())
}
fn growth(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(2, bytes)?, 4)
}
fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(refused)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(refused)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, next| add(total, *next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_prepared_initial_quote_is_readonly_and_each_axis_is_independent() {
        let (inputs, root) = crate::client::host_startup::tests::prepared_initial_lifecycle_model();
        let before = root.retained_requested_storage_data(None).unwrap();
        let actual = root
            .quote_original_initial_lifecycle_storage_data(inputs.borrowed().launch)
            .unwrap();
        assert!(actual.requested_peak_data().unwrap() > actual.retained_growth_bytes());
        assert_eq!(
            actual.declared_counter_scratch_bytes(),
            original_packet_host_initial_lifecycle_counter_scratch_data()
        );
        assert!(actual.within(&actual));
        for axis in 0..3 {
            let mut one_short = actual;
            match axis {
                0 => one_short.retained -= 1,
                1 => one_short.transient -= 1,
                _ => one_short.scratch -= 1,
            }
            assert!(!actual.within(&one_short));
        }
        assert_eq!(root.retained_requested_storage_data(None).unwrap(), before);
        assert!(root.controller.is_none());
        assert!(root.frames.is_some());
        assert!(!root.initial_attachment_attempted);
    }

    #[test]
    fn hello_only_bank_refuses_initial_lifecycle_without_changing_prepared_owners() {
        let (inputs, root) = crate::client::host_startup::tests::prepared_initial_model();
        let before = root.retained_requested_storage_data(None).unwrap();

        assert_eq!(
            inputs.borrowed().launch.storage.frame_bank_bytes.get(),
            262144
        );
        assert!(matches!(
            root.quote_original_initial_lifecycle_storage_data(inputs.borrowed().launch),
            Err(ProviderError::ResourceExhausted(
                "original packet host SDK construction"
            ))
        ));

        assert_eq!(root.retained_requested_storage_data(None).unwrap(), before);
        assert!(root.prepared);
        assert!(root.custody.is_some());
        assert!(root.controller.is_none());
        assert!(root.frames.is_some());
        assert!(root.failure.is_none());
        assert!(!root.initial_attachment_attempted);
    }

    #[test]
    fn initial_quote_refuses_changed_actual_launch_and_checked_peak_overflow() {
        let (inputs, root) = crate::client::host_startup::tests::prepared_initial_lifecycle_model();
        let launch = inputs.borrowed().launch;
        assert!(
            root.quote_original_initial_lifecycle_storage_data(launch)
                .is_ok()
        );

        // Reconstruct owned fixture data without cloning a live startup owner.
        let mut foreign: PacketNative5SourceLaunch =
            serde_json::from_value(serde_json::to_value(launch).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&foreign).unwrap(),
            serde_json::to_value(launch).unwrap()
        );
        foreign.selection.prepared_token = Id::new("foreign-prepared-token").unwrap();
        assert!(
            root.quote_original_initial_lifecycle_storage_data(&foreign)
                .is_err()
        );
        assert!(root.frames.is_some());
        assert!(!root.initial_attachment_attempted);
        let overflow = PacketNativeHostInitialLifecycleStorageData {
            retained: usize::MAX,
            transient: 1,
            scratch: 1,
            journal_growth: 1,
        };
        assert!(overflow.requested_peak_data().is_err());
    }
}
