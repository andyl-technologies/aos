//! Standalone gateway control, replacement, and RSP relay tests.

use std::thread;

use super::*;

fn write_and_close(bytes: Vec<u8>) -> UnixStream {
    let (reader, mut writer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("Unix stream pair should open: {error}"));
    thread::spawn(move || {
        writer
            .write_all(&bytes)
            .unwrap_or_else(|error| panic!("test request should write: {error}"));
    });
    reader
}

fn serve_frames(
    process: &SharedGatewayProcess,
    frames: Vec<DebugGatewayFrame>,
) -> Vec<DebugGatewayFrame> {
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend(
            frame
                .encode()
                .unwrap_or_else(|error| panic!("request should encode: {error}")),
        );
    }
    let (mut client, server) =
        UnixStream::pair().unwrap_or_else(|error| panic!("Unix stream pair should open: {error}"));
    client
        .write_all(&bytes)
        .unwrap_or_else(|error| panic!("requests should write: {error}"));
    client
        .shutdown(std::net::Shutdown::Write)
        .unwrap_or_else(|error| panic!("test client should half-close: {error}"));
    serve_connection(process, server)
        .unwrap_or_else(|error| panic!("requests should be served: {error}"));

    let mut replies = Vec::new();
    while let Some(bytes) =
        read_frame(&mut client).unwrap_or_else(|error| panic!("reply should read: {error}"))
    {
        replies.push(
            decode_debug_gateway_frame(&bytes)
                .unwrap_or_else(|error| panic!("reply should decode: {error}")),
        );
    }
    replies
}

fn hello() -> DebugGatewayFrame {
    DebugGatewayFrame::v1(DebugGatewayMessageKind::Hello, 0, b"v1".to_vec())
        .unwrap_or_else(|error| panic!("hello should build: {error}"))
}

fn test_process() -> SharedGatewayProcess {
    Arc::new(Mutex::new(GatewayProcess::new(Some(
        "127.0.0.1:12345"
            .parse()
            .unwrap_or_else(|error| panic!("test listener should parse: {error}")),
    ))))
}

fn configure_active_backend(process: &SharedGatewayProcess, endpoint: &str) -> UnixStream {
    let (stream, peer) = UnixStream::pair()
        .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
    with_gateway(process, |gateway| {
        let prepared = gateway
            .model
            .prepare_backend(QemuRspEndpoint::new(endpoint).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        gateway
            .model
            .commit_backend(prepared.generation)
            .map_err(|error| error.to_string())?;
        gateway.active = Some((prepared.generation, stream));
        Ok(())
    })
    .unwrap_or_else(|error| panic!("active backend should configure: {error}"));
    peer
}

fn read_test_rsp_payload(stream: &mut impl Read) -> Vec<u8> {
    let mut decoder = RspStreamDecoder::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("test RSP packet should read: {error}"));
        assert_ne!(read, 0, "test RSP stream closed before a packet arrived");
        for unit in decoder
            .push(&buffer[..read])
            .unwrap_or_else(|error| panic!("test RSP packet should decode: {error}"))
        {
            if let RspUnit::Packet(packet) = unit {
                return rsp_payload(&packet).to_vec();
            }
        }
    }
}

#[test]
fn operator_disconnect_deactivates_backend_with_ambiguous_qemu_response() {
    let process = test_process();
    let _peer = configure_active_backend(&process, "/run/crucible/pending-rsp.sock");
    with_gateway(&process, |gateway| {
        gateway.rsp_responses_pending = 1;
        Ok(())
    })
    .unwrap_or_else(|error| panic!("pending response should configure: {error}"));

    restore_backend_after_operator_disconnect(&process, true)
        .unwrap_or_else(|error| panic!("ambiguous response cleanup should succeed: {error}"));

    let active = with_gateway(&process, |gateway| {
        Ok((gateway.model.active().cloned(), gateway.active.is_some()))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(active, (None, false));
}

#[test]
fn operator_disconnect_deactivates_backend_with_inflight_run_control() {
    let process = test_process();
    let _peer = configure_active_backend(&process, "/run/crucible/inflight-control.sock");
    with_gateway(&process, |gateway| {
        gateway.run_control_inflight = Some((1, gateway.operator_epoch, b"s".to_vec()));
        Ok(())
    })
    .unwrap_or_else(|error| panic!("run control should configure: {error}"));

    restore_backend_after_operator_disconnect(&process, true)
        .unwrap_or_else(|error| panic!("inflight control cleanup should succeed: {error}"));

    let active = with_gateway(&process, |gateway| {
        Ok((gateway.model.active().cloned(), gateway.active.is_some()))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(active, (None, false));
}

#[test]
fn racing_interrupt_collapses_completed_run_into_one_correlated_stop() {
    let process = test_process();
    let mut peer = configure_active_backend(&process, "/run/crucible/racing-interrupt.sock");
    let backend = thread::spawn(move || {
        assert_eq!(read_test_rsp_payload(&mut peer), b"c");
        peer.write_all(b"+")
            .unwrap_or_else(|error| panic!("scheduler resume should acknowledge: {error}"));
        let mut interrupt = [0_u8; 1];
        peer.read_exact(&mut interrupt)
            .unwrap_or_else(|error| panic!("scheduler interrupt should read: {error}"));
        assert_eq!(interrupt, [0x03]);
        peer.write_all(&encode_rsp_packet(b"T02"))
            .unwrap_or_else(|error| panic!("scheduler stop should write: {error}"));
        let mut acknowledgement = [0_u8; 1];
        peer.read_exact(&mut acknowledgement)
            .unwrap_or_else(|error| panic!("scheduler stop acknowledgement should read: {error}"));
        assert_eq!(acknowledgement, [b'+']);
    });
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("operator listener should bind: {error}"));
    let mut operator = TcpStream::connect(
        listener
            .local_addr()
            .unwrap_or_else(|error| panic!("operator listener should have an address: {error}")),
    )
    .unwrap_or_else(|error| panic!("operator client should connect: {error}"));
    let (writer, _) = listener
        .accept()
        .unwrap_or_else(|error| panic!("operator writer should accept: {error}"));
    with_gateway(&process, |gateway| {
        gateway.operator_writer = Some(writer);
        gateway
            .run_control_requests
            .push_back((1, gateway.operator_epoch, b"c".to_vec()));
        Ok(())
    })
    .unwrap_or_else(|error| panic!("run-control fixture should configure: {error}"));

    let poll = DebugGatewayFrame::v1(DebugGatewayMessageKind::RunControl, 1, Vec::new())
        .unwrap_or_else(|error| panic!("run-control poll should build: {error}"));
    let routed = poll_scheduler_run_control(&process, poll)
        .unwrap_or_else(|error| panic!("continue should route: {error}"));
    assert_eq!(routed.payload, b"c");
    queue_scheduler_run_control(&process, vec![0x03], false)
        .unwrap_or_else(|error| panic!("interrupt should queue: {error}"));
    let completion = DebugGatewayFrame::v1(DebugGatewayMessageKind::RspData, 1, b"T05".to_vec())
        .unwrap_or_else(|error| panic!("completion should build: {error}"));
    dispatch_request(&process, completion)
        .unwrap_or_else(|error| panic!("racing completion should correlate: {error}"));

    assert_eq!(read_test_rsp_payload(&mut operator), b"T02");
    let state = with_gateway(&process, |gateway| {
        Ok((
            gateway.run_control_requests.len(),
            gateway.run_control_inflight.is_some(),
            gateway.gdb_scheduler_run_active,
            gateway
                .run_control_completed
                .as_ref()
                .map(|(_, _, response)| response.clone()),
        ))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(state, (0, false, None, Some(b"T02".to_vec())));
    backend
        .join()
        .unwrap_or_else(|_| panic!("fake backend should not panic"));
}

#[test]
fn operator_disconnect_stops_active_gdb_run_without_dropping_backend() {
    let process = test_process();
    let mut peer = configure_active_backend(&process, "/run/crucible/disconnect-run.sock");
    let backend = thread::spawn(move || {
        let mut interrupt = [0_u8; 1];
        peer.read_exact(&mut interrupt)
            .unwrap_or_else(|error| panic!("disconnect interrupt should read: {error}"));
        assert_eq!(interrupt, [0x03]);
        peer.write_all(&encode_rsp_packet(b"T02"))
            .unwrap_or_else(|error| panic!("disconnect stop should write: {error}"));
        let mut acknowledgement = [0_u8; 1];
        peer.read_exact(&mut acknowledgement)
            .unwrap_or_else(|error| panic!("disconnect stop acknowledgement should read: {error}"));
        assert_eq!(acknowledgement, [b'+']);
    });
    with_gateway(&process, |gateway| {
        gateway.gdb_scheduler_run_active = Some(4);
        gateway.run_control_inflight = Some((4, gateway.operator_epoch, b"c".to_vec()));
        gateway.operator_admission_paused = true;
        Ok(())
    })
    .unwrap_or_else(|error| panic!("active run should configure: {error}"));

    restore_backend_after_operator_disconnect(&process, false)
        .unwrap_or_else(|error| panic!("active run should stop cleanly: {error}"));

    let state = with_gateway(&process, |gateway| {
        Ok((
            gateway.active.is_some(),
            gateway.model.active().is_some(),
            gateway.gdb_scheduler_run_active,
            gateway.run_control_inflight.is_some(),
            gateway.operator_admission_paused,
        ))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(state, (true, true, None, false, false));
    backend
        .join()
        .unwrap_or_else(|_| panic!("fake backend should not panic"));
}

#[test]
fn operator_disconnect_preserves_internal_scheduler_ownership() {
    let process = test_process();
    let _peer = configure_active_backend(&process, "/run/crucible/internal-lease.sock");
    with_gateway(&process, |gateway| {
        gateway.scheduler_lease_active = true;
        gateway.operator_admission_paused = true;
        gateway
            .run_control_requests
            .push_back((3, gateway.operator_epoch, b"s".to_vec()));
        Ok(())
    })
    .unwrap_or_else(|error| panic!("scheduler lease should configure: {error}"));

    restore_backend_after_operator_disconnect(&process, false)
        .unwrap_or_else(|error| panic!("scheduler lease should remain owned: {error}"));

    let state = with_gateway(&process, |gateway| {
        Ok((
            gateway.active.is_some(),
            gateway.scheduler_lease_active,
            gateway.operator_admission_paused,
            gateway.run_control_requests.len(),
        ))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(state, (true, true, true, 0));
}

#[test]
fn scheduler_poll_defers_gdb_run_control_during_internal_lease() {
    for (index, packet) in [b"c".to_vec(), vec![0x03]].into_iter().enumerate() {
        let process = test_process();
        let endpoint = format!("/run/crucible/deferred-control-{index}.sock");
        let _peer = configure_active_backend(&process, &endpoint);
        with_gateway(&process, |gateway| {
            gateway.scheduler_lease_active = true;
            gateway.operator_admission_paused = true;
            gateway
                .run_control_requests
                .push_back((7, gateway.operator_epoch, packet));
            Ok(())
        })
        .unwrap_or_else(|error| panic!("deferred control should configure: {error}"));

        let poll = DebugGatewayFrame::v1(DebugGatewayMessageKind::RunControl, 1, Vec::new())
            .unwrap_or_else(|error| panic!("run-control poll should build: {error}"));
        let response = poll_scheduler_run_control(&process, poll)
            .unwrap_or_else(|error| panic!("leased run control should defer: {error}"));

        assert!(response.payload.is_empty());
        let queued = with_gateway(&process, |gateway| {
            Ok((
                gateway.run_control_requests.len(),
                gateway.run_control_inflight.is_some(),
            ))
        })
        .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
        assert_eq!(queued, (1, false));
    }
}

#[test]
fn operator_disconnect_deactivates_backend_when_reconnect_fails() {
    let process = test_process();
    let _peer = configure_active_backend(&process, "/missing/crucible/qemu-rsp.sock");

    let error = match restore_backend_after_operator_disconnect(&process, true) {
        Ok(()) => panic!("missing backend endpoint must fail reconnect"),
        Err(error) => error,
    };

    assert!(error.contains("restore QEMU RSP backend"));
    let active = with_gateway(&process, |gateway| {
        Ok((gateway.model.active().cloned(), gateway.active.is_some()))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(active, (None, false));
}

#[test]
fn partial_header_is_a_connection_error_without_mutating_process_state() {
    let process = test_process();
    let before = with_gateway(&process, |process| Ok(process.model.clone()))
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    let error = match serve_connection(&process, write_and_close(b"CRDBG".to_vec())) {
        Ok(()) => panic!("partial header must fail"),
        Err(error) => error,
    };

    assert!(error.contains("truncated debugger gateway frame header"));
    let after = with_gateway(&process, |process| Ok(process.model.clone()))
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    assert_eq!(after, before);
}

#[test]
fn truncated_payload_is_a_connection_error_without_mutating_process_state() {
    let process = test_process();
    let before = with_gateway(&process, |process| Ok(process.model.clone()))
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    let mut bytes = DebugGatewayFrame::v1(DebugGatewayMessageKind::Hello, 0, b"v1".to_vec())
        .unwrap_or_else(|error| panic!("hello should build: {error}"))
        .encode()
        .unwrap_or_else(|error| panic!("hello should encode: {error}"));
    bytes.pop();

    assert!(serve_connection(&process, write_and_close(bytes)).is_err());
    let after = with_gateway(&process, |process| Ok(process.model.clone()))
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    assert_eq!(after, before);
}

#[test]
fn negotiation_rejection_has_a_typed_correlated_error() {
    let (mut client, server) =
        UnixStream::pair().unwrap_or_else(|error| panic!("Unix stream pair should open: {error}"));
    let request = DebugGatewayFrame::v1(DebugGatewayMessageKind::RspData, 19, b"$?#3f".to_vec())
        .unwrap_or_else(|error| panic!("request should build: {error}"))
        .encode()
        .unwrap_or_else(|error| panic!("request should encode: {error}"));
    client
        .write_all(&request)
        .unwrap_or_else(|error| panic!("request should write: {error}"));
    client
        .shutdown(std::net::Shutdown::Write)
        .unwrap_or_else(|error| panic!("test client should half-close: {error}"));

    let process = test_process();
    serve_connection(&process, server)
        .unwrap_or_else(|error| panic!("valid rejected request should be served: {error}"));
    let reply = read_frame(&mut client)
        .unwrap_or_else(|error| panic!("reply should read: {error}"))
        .unwrap_or_else(|| panic!("reply should be present"));
    let reply = decode_debug_gateway_frame(&reply)
        .unwrap_or_else(|error| panic!("reply should decode: {error}"));
    let payload = DebugGatewayErrorPayload::decode(&reply.payload)
        .unwrap_or_else(|error| panic!("error should be typed: {error}"));

    assert_eq!(reply.kind, DebugGatewayMessageKind::Error);
    assert_eq!(reply.stream_id, 19);
    assert_eq!(payload.code, DebugGatewayErrorCode::ProtocolViolation);
}

#[test]
fn diagnostics_are_bounded_on_character_boundaries() {
    let message = "é".repeat(600);
    let bounded = bounded_diagnostic(&message);
    assert_eq!(bounded.chars().count(), 515);
    assert!(bounded.ends_with("..."));
}

#[test]
fn persistent_rsp_state_requires_semantic_ok_response() {
    let process = test_process();
    let request = encode_rsp_packet(b"Z1,4000,1");
    record_semantic_response(&process, &request, &encode_rsp_packet(b"E22"))
        .unwrap_or_else(|error| panic!("semantic rejection should record: {error}"));
    let (state_after_error, epoch_after_error) = with_gateway(&process, |gateway| {
        Ok((gateway.model.rsp_state().clone(), gateway.rsp_state_epoch))
    })
    .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    assert!(state_after_error.hardware_breakpoints.is_empty());
    assert_eq!(epoch_after_error, 0);

    record_semantic_response(&process, &request, &encode_rsp_packet(b"OK"))
        .unwrap_or_else(|error| panic!("semantic success should record: {error}"));
    let (state_after_ok, epoch_after_ok) = with_gateway(&process, |gateway| {
        Ok((gateway.model.rsp_state().clone(), gateway.rsp_state_epoch))
    })
    .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    assert!(
        state_after_ok
            .hardware_breakpoints
            .contains(b"Z1,4000,1".as_slice())
    );
    assert_eq!(epoch_after_ok, 1);
}

#[test]
fn commit_rejects_candidate_hydrated_before_rsp_state_change() {
    let process = test_process();
    let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
        .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
    let (stream, peer) = UnixStream::pair()
        .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
    let prepared = with_gateway(&process, |gateway| {
        let prepared = gateway
            .model
            .prepare_backend(endpoint)
            .map_err(|error| error.to_string())?;
        gateway.prepared = Some((prepared.generation, stream, gateway.rsp_state_epoch));
        Ok(prepared)
    })
    .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
    record_semantic_response(
        &process,
        &encode_rsp_packet(b"Hg1"),
        &encode_rsp_packet(b"OK"),
    )
    .unwrap_or_else(|error| panic!("thread selection should record: {error}"));
    let commit = DebugGatewayFrame::v1(
        DebugGatewayMessageKind::BackendCommit,
        0,
        prepared.generation.0.to_be_bytes(),
    )
    .unwrap_or_else(|error| panic!("commit should build: {error}"));

    let error = match with_gateway(&process, |gateway| gateway.handle(commit)) {
        Ok(_) => panic!("stale prepared debugger state must reject commit"),
        Err(error) => error,
    };
    assert!(error.contains("stale"));
    let active = with_gateway(&process, |gateway| Ok(gateway.model.active().cloned()))
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
    assert!(active.is_none());
    drop(peer);
}

#[test]
fn commit_waits_for_every_scheduler_run_control_state_to_resolve() {
    enum PendingState {
        Queued,
        Inflight,
        AwaitingOperatorAcknowledgement,
    }

    for pending in [
        PendingState::Queued,
        PendingState::Inflight,
        PendingState::AwaitingOperatorAcknowledgement,
    ] {
        let process = test_process();
        let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
            .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
        let (stream, peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
        let prepared = with_gateway(&process, |gateway| {
            let prepared = gateway
                .model
                .prepare_backend(endpoint)
                .map_err(|error| error.to_string())?;
            gateway.prepared = Some((prepared.generation, stream, gateway.rsp_state_epoch));
            match pending {
                PendingState::Queued => gateway.run_control_requests.push_back((
                    1,
                    gateway.operator_epoch,
                    b"s".to_vec(),
                )),
                PendingState::Inflight => {
                    gateway.run_control_inflight = Some((1, gateway.operator_epoch, b"c".to_vec()));
                }
                PendingState::AwaitingOperatorAcknowledgement => {
                    gateway.scheduler_response_pending = Some(encode_rsp_packet(b"T05"));
                }
            }
            Ok(prepared)
        })
        .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
        let commit = DebugGatewayFrame::v1(
            DebugGatewayMessageKind::BackendCommit,
            0,
            prepared.generation.0.to_be_bytes(),
        )
        .unwrap_or_else(|error| panic!("commit should build: {error}"));

        let error = match with_gateway(&process, |gateway| gateway.handle(commit.clone())) {
            Ok(_) => panic!("pending scheduler state must reject backend commit"),
            Err(error) => error,
        };
        assert!(error.contains("scheduler run-control"));
        with_gateway(&process, |gateway| {
            gateway.run_control_requests.clear();
            gateway.run_control_inflight = None;
            gateway.scheduler_response_pending = None;
            gateway.handle(commit)
        })
        .unwrap_or_else(|error| {
            panic!("commit should succeed after scheduler state resolves: {error}")
        });
        drop(peer);
    }
}

#[test]
fn packet_admitted_after_commit_barrier_reaches_only_new_backend() {
    let process = test_process();
    let (old_stream, mut old_peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("old backend pair should open: {error}"));
    let (new_stream, mut new_peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("new backend pair should open: {error}"));
    old_peer
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap_or_else(|error| panic!("old backend timeout should set: {error}"));
    new_peer
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap_or_else(|error| panic!("new backend timeout should set: {error}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("operator listener should bind: {error}"));
    let operator_peer = TcpStream::connect(
        listener
            .local_addr()
            .unwrap_or_else(|error| panic!("operator address should inspect: {error}")),
    )
    .unwrap_or_else(|error| panic!("operator peer should connect: {error}"));
    let (operator_writer, _) = listener
        .accept()
        .unwrap_or_else(|error| panic!("operator writer should accept: {error}"));
    let new_generation = with_gateway(&process, |gateway| {
        let old = gateway
            .model
            .prepare_backend(
                QemuRspEndpoint::new("/run/crucible/old.sock")
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        gateway
            .model
            .commit_backend(old.generation)
            .map_err(|error| error.to_string())?;
        gateway.active = Some((old.generation, old_stream));
        let new = gateway
            .model
            .prepare_backend(
                QemuRspEndpoint::new("/run/crucible/new.sock")
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        gateway.prepared = Some((new.generation, new_stream, gateway.rsp_state_epoch));
        gateway.operator_writer = Some(operator_writer);
        Ok(new.generation)
    })
    .unwrap_or_else(|error| panic!("backend fixture should configure: {error}"));
    let commit = DebugGatewayFrame::v1(
        DebugGatewayMessageKind::BackendCommit,
        0,
        new_generation.0.to_be_bytes(),
    )
    .unwrap_or_else(|error| panic!("commit should build: {error}"));
    with_gateway(&process, |gateway| gateway.handle(commit))
        .unwrap_or_else(|error| panic!("commit barrier should complete: {error}"));
    assert!(
        write_active_backend(&process, b"$g#67")
            .unwrap_or_else(|error| panic!("post-commit packet should write: {error}"))
    );

    let mut packet = [0_u8; 5];
    new_peer
        .read_exact(&mut packet)
        .unwrap_or_else(|error| panic!("new backend should receive packet: {error}"));
    assert_eq!(&packet, b"$g#67");
    let mut old_byte = [0_u8; 1];
    match old_peer.read(&mut old_byte) {
        Ok(0) | Err(_) => {}
        Ok(length) => {
            panic!("retired backend unexpectedly received {length} post-commit byte(s)")
        }
    }
    drop(operator_peer);
}

#[test]
fn reconnect_recovers_prepare_whose_acknowledgement_was_lost() {
    let process = test_process();
    let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
        .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
    let (stream, peer) = UnixStream::pair()
        .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
    drop(peer);
    let prepared = with_gateway(&process, |process| {
        let prepared = process
            .model
            .prepare_backend(endpoint)
            .map_err(|error| error.to_string())?;
        process.prepared = Some((prepared.generation, stream, process.rsp_state_epoch));
        Ok(prepared)
    })
    .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));

    let status = DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())
        .unwrap_or_else(|error| panic!("status request should build: {error}"));
    let replies = serve_frames(&process, vec![hello(), status]);
    let recovered = DebugGatewayBackendStatus::decode(&replies[1].payload)
        .unwrap_or_else(|error| panic!("status should decode: {error}"));

    assert_eq!(replies[1].kind, DebugGatewayMessageKind::BackendStatusAck);
    assert_eq!(
        recovered.prepared.map(|identity| identity.generation),
        Some(prepared.generation.0)
    );
    assert!(recovered.active.is_none());
}

#[test]
fn reconnect_repeats_commit_whose_acknowledgement_was_lost() {
    let process = test_process();
    let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
        .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
    let (stream, peer) = UnixStream::pair()
        .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
    drop(peer);
    let prepared = with_gateway(&process, |process| {
        let prepared = process
            .model
            .prepare_backend(endpoint)
            .map_err(|error| error.to_string())?;
        process.prepared = Some((prepared.generation, stream, process.rsp_state_epoch));
        Ok(prepared)
    })
    .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
    let commit = DebugGatewayFrame::v1(
        DebugGatewayMessageKind::BackendCommit,
        0,
        prepared.generation.0.to_be_bytes(),
    )
    .unwrap_or_else(|error| panic!("commit should build: {error}"));

    let _lost_reply = with_gateway(&process, |process| process.handle(commit.clone()))
        .unwrap_or_else(|error| panic!("first commit should succeed: {error}"));
    let status = DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())
        .unwrap_or_else(|error| panic!("status request should build: {error}"));
    let replies = serve_frames(&process, vec![hello(), commit, status]);
    let recovered = DebugGatewayBackendStatus::decode(&replies[2].payload)
        .unwrap_or_else(|error| panic!("status should decode: {error}"));

    assert_eq!(replies[1].kind, DebugGatewayMessageKind::Ack);
    assert_eq!(
        recovered.active.map(|identity| identity.generation),
        Some(prepared.generation.0)
    );
    assert!(recovered.prepared.is_none());
}
