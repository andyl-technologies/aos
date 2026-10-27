//! Checks actual failure custody with the immutable codec and direct supervisor.
//!
//! The socket and retained owners are real. The fixture's registration supplies
//! no Source18 action, native permission or independently admitted future row.

use super::*;
use crate::connection::{OriginalProtocolSupervisor, OriginalRetainedSupervisor};
use crate::retained_metadata::requested_metadata_backing_storage_data;

fn retained_fixture(
    maximum_requests: usize,
) -> (
    Handshake,
    Option<CnpController>,
    OriginalRetainedSupervisor,
    OriginalProtocolSupervisor,
    UnixStream,
) {
    let (handshake, session, owner, witness, peer) = ClientSession::restoration_retained_fixture();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let content = ClientContent::new(262_144, 8, 4096).unwrap();
    let custody = ClientCustody::new(maximum_requests, content).unwrap();
    let controller = CnpController::new(
        session,
        custody,
        ControllerRoute {
            node: id("node"),
            execution_owner: id("owner"),
        },
        Duration::from_secs(2),
    )
    .unwrap();
    (handshake, Some(controller), owner, witness, peer)
}

#[test]
fn fenced_and_revoked_runtime_counts_original_pending_and_typed_custody() -> TestResult {
    let (mut handshake, mut original, owner, witness, mut peer) = retained_fixture(8);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let legacy = read(&mut reader);
        write(&mut peer, &refusal(&legacy, 2));
        let runtime = read(&mut reader);
        let mut event = runtime;
        event.message = MessageKind::Event;
        event.method = Method::ProviderFault;
        event.request_id = Nullable(None);
        event.sequence = U64::new(3);
        let notification = NotificationBody {
            operation_state: OperationState::NotStarted,
            last_observation_sequence: U64::new(0),
            details: json!({"retained_failure": "x".repeat(2048)})
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        };
        event.body = body(&notification);
        write(&mut peer, &event);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        (event, notification)
    });
    original
        .as_mut()
        .unwrap()
        .call(id("legacy"), None, Method::Discover, false, discover())?;
    let legacy = prefix(original.as_ref().unwrap());
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    let before =
        runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?;

    assert!(
        runtime
            .call(id("runtime"), None, Method::Discover, false, discover())
            .is_err()
    );
    let (event, notification) = server.join().unwrap();
    handshake.contain();

    assert!(runtime.authority().ensure_live().is_err());
    assert!(
        runtime
            .original
            .session
            .authenticate_original_retained_supervisor(&owner)
            .is_err()
    );
    let after = runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?;
    assert!(
        requested_metadata_backing_storage_data(&after)?
            > requested_metadata_backing_storage_data(&before)?
    );
    assert!(after.string_capacity_bytes >= before.string_capacity_bytes + 2 * 2048);
    let retained = runtime.unexpected_frame().unwrap();
    assert_eq!(retained.envelope, event);
    let ReceivedBody::Notification(actual) = &retained.body else {
        panic!("complete typed failure owner")
    };
    assert_eq!(actual.as_ref(), &notification);
    assert_eq!(prefix(&runtime.original), legacy);
    let debit = runtime.journal_byte_reservations_data();

    assert!(
        runtime
            .call(id("later"), None, Method::Discover, false, discover())
            .is_err()
    );

    assert_eq!(runtime.journal_byte_reservations_data(), debit);
    assert_eq!(runtime.unexpected_frame().unwrap().envelope, event);
    assert_eq!(
        runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?,
        after
    );
    Ok(())
}

#[test]
fn retained_runtime_census_refuses_foreign_supervisor_and_witness() -> TestResult {
    let (mut handshake, mut original, owner, witness, _peer) = retained_fixture(8);
    let (_foreign_handshake, _foreign_original, foreign_owner, foreign_witness, _foreign_peer) =
        retained_fixture(8);
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    runtime.fence();
    handshake.contain();

    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&foreign_owner, Some(&witness))
            .is_err()
    );
    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, Some(&foreign_witness))
            .is_err()
    );
    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))
            .is_ok()
    );
    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, None)
            .is_ok()
    );
    assert!(runtime.authority().ensure_live().is_err());
    Ok(())
}

#[test]
fn exhausted_provider_prefix_remains_in_the_whole_fenced_census() -> TestResult {
    let (mut handshake, mut original, owner, witness, mut peer) = retained_fixture(3);
    let seeded = canonical::content_ref(b"seeded", "application/octet-stream")?;
    let incoming = canonical::content_ref(b"unreceived", "application/octet-stream")?;
    let peer_seeded = seeded.clone();
    let peer_incoming = incoming.clone();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let legacy = read(&mut reader);
        for index in 0..3 {
            let request = blob(&legacy, &peer_seeded, b"seeded", index, index as u64 + 2);
            write(&mut peer, &request);
            request.matches_response(&read(&mut reader)).unwrap();
        }
        write(&mut peer, &refusal(&legacy, 5));
        let runtime = read(&mut reader);
        let mut pending = blob(&runtime, &peer_incoming, b"unreceived", 0, 6);
        pending.request_id = Nullable(Some(id("new-provider-original")));
        write(&mut peer, &pending);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        pending
    });
    original
        .as_mut()
        .unwrap()
        .call(id("legacy"), None, Method::Discover, false, discover())?;
    let legacy = prefix(original.as_ref().unwrap());
    let content_pointer = original.as_ref().unwrap().content(&seeded)?.as_ptr();
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    let before =
        runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?;

    assert!(
        runtime
            .call(id("runtime"), None, Method::Discover, false, discover())
            .is_err()
    );
    let pending = server.join().unwrap();
    handshake.contain();

    assert_eq!(
        runtime.pending_envelope(),
        Some((RequestOrigin::Provider, &pending))
    );
    assert!(runtime.unexpected_frame().is_none());
    assert_eq!(
        runtime.compact_originals(RequestOrigin::Provider).count(),
        0
    );
    assert_eq!(runtime.legacy_originals(RequestOrigin::Provider).count(), 3);
    assert_eq!(prefix(&runtime.original), legacy);
    assert_eq!(runtime.content(&seeded)?.as_ptr(), content_pointer);
    assert!(runtime.content(&incoming).is_err());
    let after = runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?;
    assert!(
        requested_metadata_backing_storage_data(&after)?
            > requested_metadata_backing_storage_data(&before)?
    );
    assert!(runtime.authority().ensure_live().is_err());
    Ok(())
}

#[test]
fn erased_model_callback_cannot_substitute_for_a_retained_supervisor() -> TestResult {
    let (mut handshake, mut original, _peer, _content) = fixture(8);
    let (_operational, owner) = OriginalRetainedSupervisor::reserve()?;
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();

    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, None)
            .is_err()
    );

    runtime.fence();
    handshake.contain();

    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn matching_supervisor_does_not_cover_an_unknown_codec() -> TestResult {
    let (mut handshake, authority) = crate::handshake::tests::controller_authority(true)?;
    let (operational, owner) = OriginalRetainedSupervisor::reserve()?;
    let (session, _peer) =
        ClientSession::controller_fixture(authority, operational, Rc::new(Schemas))?;
    let custody = ClientCustody::new(8, ClientContent::new(262_144, 8, 4096)?)?;
    let mut original = Some(CnpController::new(
        session,
        custody,
        ControllerRoute {
            node: id("node"),
            execution_owner: id("owner"),
        },
        Duration::from_secs(2),
    )?);
    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    runtime
        .original
        .session
        .authenticate_original_retained_supervisor_data(&owner)?;

    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, None)
            .is_err()
    );

    runtime.fence();
    handshake.contain();

    assert!(
        runtime
            .retained_metadata_facts_with_retained_supervisor(&owner, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn packet_runtime_censuses_dense_failure_without_spending_legacy_traversal_credit() -> TestResult {
    use crate::client::{PacketRuntimeController, PacketRuntimeRequest};

    let (mut handshake, mut original, owner, witness, mut peer) = retained_fixture(8);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        for sequence in [2, 3] {
            let request = read(&mut reader);
            let mut reply = refusal(&request, sequence);
            reply.body["error"]["details"] = json!({"dense": vec![json!([0]); 10_000]});
            write(&mut peer, &reply);
        }
        let mut event = read(&mut reader);
        event.message = MessageKind::Event;
        event.method = Method::ProviderFault;
        event.request_id = Nullable(None);
        event.sequence = U64::new(4);
        event.body = body(NotificationBody {
            operation_state: OperationState::NotStarted,
            last_observation_sequence: U64::new(0),
            details: json!({"dense": vec![json!([0]); 15_800]})
                .as_object()
                .unwrap()
                .clone(),
            extensions: Extensions::new(),
        });
        write(&mut peer, &event);
        event
    });
    for request in ["legacy-one", "legacy-two"] {
        original
            .as_mut()
            .unwrap()
            .call(id(request), None, Method::Discover, false, discover())?;
    }
    let legacy = prefix(original.as_ref().unwrap());
    let mut output = None;
    PacketRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    let before =
        runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?;
    let request = BlobFinishRequest {
        transfer_id: id("unfinished"),
        extensions: Extensions::new(),
    };

    assert!(
        runtime
            .call(
                id("runtime"),
                None,
                None,
                PacketRuntimeRequest::BlobFinish(&request),
                &Extensions::new()
            )
            .is_err()
    );
    let event = server.join().unwrap();
    handshake.contain();
    let after = runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?;

    assert!(before.observed_nodes < 131_072);
    assert!(after.observed_nodes > 131_072);
    assert!(after.capacity_records > before.capacity_records);
    assert_eq!(runtime.unexpected_frame().unwrap().envelope, event);
    assert_eq!(
        runtime.legacy_originals(RequestOrigin::Controller).count(),
        2
    );
    assert_eq!(
        serde_json::to_vec(
            &runtime
                .legacy_originals(RequestOrigin::Controller)
                .collect::<Vec<_>>()
        )?,
        legacy
    );
    assert_eq!(
        runtime.retained_metadata_facts_with_retained_supervisor(&owner, Some(&witness))?,
        after
    );
    Ok(())
}
