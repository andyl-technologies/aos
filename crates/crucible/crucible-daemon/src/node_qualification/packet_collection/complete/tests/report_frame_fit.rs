//! Checks the controlled declaration's full CNP envelopes and chunk framing.
//!
//! These are serialization/data controls, not generated native receipts. The
//! real Source/holder controls separately exercise pre-Child grant semantics.
//! No Hello, Child, active Control, report, cold class or Ready is constructed.

use super::*;
use crucible_node_format::{Bytes, Extensions, U64};
use crucible_node_transport::{
    bodies::{
        BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, DiscoverRequest, DiscoverResult,
        OperationState, ResponseShape,
    },
    envelope::{Envelope, MessageKind, Method, Nullable},
    reference_packet::service::PacketNative5SourceLaunch,
};
use serde::Serialize;
use serde_json::{Map, Value};

fn object(value: impl Serialize) -> Map<String, Value> {
    serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn envelope(
    launch: &PacketNative5SourceLaunch,
    method: Method,
    body: Map<String, Value>,
) -> Envelope {
    let binding = &launch.selection.realization.bindings[0];
    Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(binding.authority.session_id.clone())),
        incarnation_id: Nullable(Some(binding.authority.incarnation_id.clone())),
        node_id: Nullable(Some(binding.compatibility.node_id.clone())),
        execution_owner_id: Nullable(Some(binding.compatibility.execution_owner.id.clone())),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new("r".repeat(128)).unwrap())),
        sequence: U64::new(u64::MAX),
        method,
        body,
        extensions: Extensions::new(),
    }
}

fn encoded_body(frame: &Envelope) -> usize {
    canonical::canonical_json(&serde_json::to_value(frame).unwrap())
        .unwrap()
        .len()
}

fn fits(frame: &Envelope, maximum: usize) {
    let body = encoded_body(frame);
    assert!(
        body <= maximum,
        "{:?} complete envelope body {body} exceeds {maximum}",
        frame.method
    );
    assert!(body.checked_add(4).unwrap() <= maximum + 4);
}

#[test]
fn report_fixture_16k_bounds_actual_declaration_messages_and_chunked_16k_content() {
    let scene = Scene::report_startup(16 * 1024);
    let launches = authority::launches(&scene);
    for (member, launch) in launches.iter().enumerate() {
        let maximum = usize::try_from(launch.limits.frame_bytes.get()).unwrap();
        assert_eq!(maximum, 16 * 1024);
        assert_eq!(
            launch.limits,
            scene.roster.sources[member]
                .selected_storage_selection()
                .unwrap()
                .limits
        );
        let discover = DiscoverRequest {
            profile_ids: vec![
                launch.selection.provider.supported_profiles[0]
                    .profile_id
                    .clone(),
            ],
            cursor: None,
            extensions: Extensions::new(),
        };
        fits(
            &envelope(launch, Method::Discover, object(discover)),
            maximum,
        );
        fits(
            &envelope(launch, Method::Realize, object(&launch.selection.realize)),
            maximum,
        );

        // The actual Discover branch clones exactly these retained fields.
        let result = DiscoverResult {
            provider_manifest: launch.selection.provider.clone(),
            profiles: launch.selection.provider.supported_profiles.clone(),
            facet_schemas: launch.selection.provider.implementation.formats.clone(),
            complete: true,
            next_cursor: Nullable(None),
        };
        let mut response = envelope(
            launch,
            Method::Discover,
            object(ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: object(result),
                extensions: Extensions::new(),
            }),
        );
        response.message = MessageKind::Response;
        fits(&response, maximum);

        // A full 16 KiB Bytes field exceeds 16 KiB after base64 and the envelope.
        // The real prefix uses <=4096-byte chunks, never that whole-body form.
        // This is matched inert content, deliberately not a valid Report DTO.
        let bytes = vec![0_u8; 16 * 1024];
        let reference=canonical::content_ref(&bytes,
            crucible_node_transport::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA).unwrap();
        reference.verify(&bytes).unwrap();
        let transfer = Id::new("t".repeat(128)).unwrap();
        let blob = |method, body| {
            let mut frame = envelope(launch, method, body);
            frame.node_id = Nullable(None);
            frame.execution_owner_id = Nullable(None);
            frame
        };
        fits(
            &blob(
                Method::BlobBegin,
                object(BlobBeginRequest {
                    transfer_id: transfer.clone(),
                    content: reference,
                    extensions: Extensions::new(),
                }),
            ),
            maximum,
        );
        assert!(
            encoded_body(&blob(
                Method::BlobChunk,
                object(BlobChunkRequest {
                    transfer_id: transfer.clone(),
                    offset: U64::new(0),
                    bytes: Bytes::new(bytes.clone()),
                    extensions: Extensions::new(),
                })
            )) > maximum
        );
        let chunk = usize::try_from(launch.limits.blob_chunk_bytes.get())
            .unwrap()
            .min(4096);
        assert_eq!(chunk, 4096);
        for (index, part) in bytes.chunks(chunk).enumerate() {
            fits(
                &blob(
                    Method::BlobChunk,
                    object(BlobChunkRequest {
                        transfer_id: transfer.clone(),
                        offset: U64::new((index * chunk) as u64),
                        bytes: Bytes::new(part.to_vec()),
                        extensions: Extensions::new(),
                    }),
                ),
                maximum,
            );
        }
        fits(
            &blob(
                Method::BlobFinish,
                object(BlobFinishRequest {
                    transfer_id: transfer,
                    extensions: Extensions::new(),
                }),
            ),
            maximum,
        );
    }
}
