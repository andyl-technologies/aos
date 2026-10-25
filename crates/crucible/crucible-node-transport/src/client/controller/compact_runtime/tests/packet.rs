//! Checks the closed packet owner on real SDK sockets beneath modeled authority.
//!
//! The controls establish immutable method selection, scoped wire originals and
//! retained ownership. They issue no Source18 credit or native runtime evidence.

use super::*;
use crate::client::{PacketRuntimeController, PacketRuntimeRequest};

#[test]
fn closed_calls_preserve_runtime_replay_and_refuse_legacy_before_publication() -> TestResult {
    let (lease, mut original, mut peer, reference) = fixture(8);
    let terminal_reference = reference.clone();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        for (sequence, name) in [(2, "legacy"), (3, "runtime")] {
            let request = read(&mut reader);
            assert_eq!(request.method, Method::BlobFinish);
            assert_eq!(request.request_id.0, Some(id(name)));
            assert!(request.execution_owner_id.0.is_none());
            write(
                &mut peer,
                &completed(&request, &terminal_reference, sequence),
            );
        }
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    });
    let request = BlobFinishRequest {
        transfer_id: id("controller-transfer"),
        extensions: Extensions::new(),
    };
    let controller = original.as_mut().unwrap();
    controller.call(id("legacy"), None, Method::BlobFinish, false, &request)?;
    let before = prefix(controller);
    let pointer = controller.content(&reference)?.as_ptr();
    let quotas = controller.custody.runtime_journal_bytes_data();
    let peer_pid = controller.peer_pid();
    let executable = controller.peer_executable().clone();
    let mut output = None;

    PacketRuntimeController::retain_into(&mut original, &mut output)?;

    assert!(original.is_none());
    let runtime = output.as_mut().unwrap();
    assert_eq!(runtime.content(&reference)?.as_ptr(), pointer);
    assert_eq!(runtime.peer_pid(), peer_pid);
    assert_eq!(runtime.peer_executable(), &executable);
    assert_eq!(runtime.retained_descriptor_count_data()?, 1);
    runtime.original_registrar_read(&lease)?;
    let response = runtime.call(
        id("runtime"),
        None,
        None,
        PacketRuntimeRequest::BlobFinish(&request),
        Extensions::new(),
    )?;
    let charged = runtime.journal_byte_reservations_data();
    assert_eq!([charged[0], charged[1]], quotas);
    assert!(charged[2] > 0);

    let replay = runtime.call(
        id("runtime"),
        None,
        None,
        PacketRuntimeRequest::BlobFinish(&request),
        Extensions::new(),
    )?;

    assert_eq!(replay, response);
    assert_eq!(runtime.journal_byte_reservations_data(), charged);
    let collision = runtime.call(
        id("legacy"),
        None,
        None,
        PacketRuntimeRequest::BlobFinish(&request),
        Extensions::new(),
    );

    assert!(matches!(
        collision,
        Err(ProviderError::Conflict("packet runtime legacy request ID"))
    ));
    assert_eq!(runtime.journal_byte_reservations_data(), charged);
    assert_eq!(runtime.content(&reference)?.as_ptr(), pointer);
    assert_eq!(runtime.retained_descriptor_count_data()?, 1);
    assert!(runtime.original_registrar_read(&lease).is_err());
    assert_eq!(
        runtime.compact_originals(RequestOrigin::Controller).count(),
        1
    );
    let legacy = runtime
        .legacy_originals(RequestOrigin::Controller)
        .collect::<Vec<_>>();
    assert_eq!(legacy.len(), 1);
    assert_eq!(serde_json::to_vec(&legacy)?, before);
    server.join().unwrap();
    Ok(())
}

fn capture() -> BeginRequest {
    BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(id("activation"))),
        world_generation: U64::new(1),
        arguments: body(CaptureArguments {
            capture_id: id("capture"),
            participant_ids: vec![id("node")],
            cut_id: id("cut"),
            cut: crucible_node_format::Position::new(
                U64::new(1),
                U64::new(0),
                crucible_node_format::Phase::BoundaryControl,
            ),
            event_ordinal: U64::new(0),
            ordering_profile: "superdense-v1".into(),
            preservation_contract: id("contract"),
        }),
        extensions: Extensions::new(),
    }
}

#[test]
fn closed_capture_uses_its_actual_capture_owner_on_the_wire() -> TestResult {
    let (_lease, mut original, mut peer, _) = fixture(8);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let request = read(&mut reader);
        assert_eq!(request.method, Method::Begin);
        assert_eq!(request.node_id.0, Some(id("node")));
        assert_eq!(request.operation_id.0, Some(id("operation")));
        assert_eq!(request.capture_owner_id.0, Some(id("capture-owner")));
        assert!(request.execution_owner_id.0.is_none());
        let RequestBody::Begin(begin) = decode_request(request.method, &request.body).unwrap()
        else {
            panic!("Capture Begin");
        };
        assert_eq!(begin.kind, BeginKind::Capture);
        write(&mut peer, &refusal(&request, 2));
    });
    let mut output = None;
    PacketRuntimeController::retain_into(&mut original, &mut output)?;
    let request = capture();

    let response = output.as_mut().unwrap().call(
        id("capture"),
        Some(id("operation")),
        Some(id("capture-owner")),
        PacketRuntimeRequest::Begin(&request),
        Extensions::new(),
    )?;

    assert!(matches!(response.shape, ResponseShape::Error { .. }));
    server.join().unwrap();
    Ok(())
}

#[test]
fn inconsistent_capture_scope_fences_before_body_construction_or_publication() -> TestResult {
    for is_capture in [false, true] {
        let (_lease, mut original, mut peer, _) = fixture(8);
        let quotas = original
            .as_ref()
            .unwrap()
            .custody
            .runtime_journal_bytes_data();
        let mut output = None;
        PacketRuntimeController::retain_into(&mut original, &mut output)?;
        let runtime = output.as_mut().unwrap();
        let capture = capture();
        let blob = BlobFinishRequest {
            transfer_id: id("transfer"),
            extensions: Extensions::from([("oversized".into(), json!("x".repeat(65_536)))]),
        };
        let (request, capture_owner) = if is_capture {
            (PacketRuntimeRequest::Begin(&capture), None)
        } else {
            (
                PacketRuntimeRequest::BlobFinish(&blob),
                Some(id("wrong-owner")),
            )
        };

        let result = runtime.call(
            id("refused"),
            None,
            capture_owner,
            request,
            Extensions::new(),
        );

        assert!(matches!(
            result,
            Err(ProviderError::Correlation(
                "packet runtime capture scope disagrees with its body"
            ))
        ));
        assert_eq!(
            runtime.journal_byte_reservations_data(),
            [quotas[0], quotas[1], 0]
        );
        assert_eq!(
            runtime.compact_originals(RequestOrigin::Controller).count(),
            0
        );
        assert!(runtime.pending_envelope().is_none());
        assert!(runtime.unexpected_frame().is_none());
        assert_eq!(peer.read(&mut [0])?, 0);
    }
    Ok(())
}

#[test]
fn refused_closed_handoff_preserves_missing_occupied_and_fenced_slots() -> TestResult {
    let (_lease, mut original, _peer, _) = fixture(8);
    let mut output = None;
    PacketRuntimeController::retain_into(&mut original, &mut output)?;
    assert!(PacketRuntimeController::retain_into(&mut original, &mut None).is_err());

    let (_other_lease, mut other, _other_peer, _) = fixture(8);
    let pointer = other.as_ref().unwrap() as *const CnpController;
    assert!(PacketRuntimeController::retain_into(&mut other, &mut output).is_err());
    assert_eq!(other.as_ref().unwrap() as *const CnpController, pointer);
    assert!(output.is_some());
    other.as_mut().unwrap().fence();

    let mut empty = None;
    assert!(PacketRuntimeController::retain_into(&mut other, &mut empty).is_err());
    assert!(other.is_some());
    assert!(empty.is_none());
    Ok(())
}
