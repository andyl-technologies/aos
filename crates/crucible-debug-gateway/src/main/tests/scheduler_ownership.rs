//! Scheduler ownership and run-control race regression tests.

use super::*;

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
fn operator_socket_routes_continue_through_scheduler_and_replays_stop() {
    let process = test_process();
    let mut backend = configure_active_backend(&process, "/run/crucible/socket-run.sock");
    let (backend_release, backend_hold) = std::sync::mpsc::channel();
    let backend_thread = thread::spawn(move || {
        assert_eq!(read_test_rsp_payload(&mut backend), b"c");
        backend
            .write_all(b"+")
            .expect("acknowledge scheduler resume");
        let mut interrupt = [0_u8; 1];
        backend
            .read_exact(&mut interrupt)
            .expect("read scheduler stop");
        assert_eq!(interrupt, [0x03]);
        backend
            .write_all(&encode_rsp_packet(b"T02"))
            .expect("send backend stop");
        let mut ack = [0_u8; 1];
        backend.read_exact(&mut ack).expect("read backend stop ack");
        assert_eq!(ack, [b'+']);
        backend_hold
            .recv()
            .expect("hold backend until operator exits");
    });
    let (mut operator, relay) = UnixStream::pair().expect("operator stream pair");
    operator
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set operator test timeout");
    let relay_process = process.clone();
    let relay_thread = thread::spawn(move || serve_operator_connection(&relay_process, relay));
    assert_eq!(read_test_rsp_payload(&mut operator), b"T05");
    operator.write_all(b"+").expect("acknowledge initial stop");
    operator
        .write_all(&encode_rsp_packet(b"c"))
        .expect("send continue to gateway");
    let mut ack = [0_u8; 1];
    operator.read_exact(&mut ack).expect("read continue ack");
    assert_eq!(ack, [b'+']);

    let poll = DebugGatewayFrame::v1(DebugGatewayMessageKind::RunControl, 1, Vec::new())
        .expect("build scheduler poll");
    let deadline = Instant::now() + Duration::from_secs(2);
    let routed = loop {
        let reply = dispatch_request(&process, poll.clone()).expect("poll scheduler");
        if !reply.payload.is_empty() {
            break reply;
        }
        assert!(
            Instant::now() < deadline,
            "operator continue never reached scheduler"
        );
        thread::yield_now();
    };
    assert_eq!(routed.payload, b"c");
    let completion = DebugGatewayFrame::v1(
        DebugGatewayMessageKind::RspData,
        routed.stream_id,
        b"T05".to_vec(),
    )
    .expect("build scheduler stop");
    dispatch_request(&process, completion).expect("complete scheduler run");
    assert_eq!(read_test_rsp_payload(&mut operator), b"T05");
    operator.write_all(b"-").expect("NACK scheduler stop");
    assert_eq!(read_test_rsp_payload(&mut operator), b"T05");
    operator
        .write_all(b"+")
        .expect("acknowledge scheduler stop");

    drop(operator);
    relay_thread
        .join()
        .expect("operator relay thread")
        .expect("operator relay should close cleanly");
    backend_release.send(()).expect("release backend thread");
    backend_thread.join().expect("backend thread");
}

#[test]
fn operator_step_and_vcont_packets_enter_the_scheduler_queue() {
    for payload in [b"s".as_slice(), b"vCont;c", b"vCont;s"] {
        let process = test_process();
        let _backend = configure_active_backend(&process, "/run/crucible/step-vcont.sock");
        let (mut operator, writer) = UnixStream::pair().expect("operator stream pair");
        with_gateway(&process, |gateway| {
            gateway.operator_writer = Some(writer);
            Ok(())
        })
        .expect("install operator writer");
        let mut pending = VecDeque::new();
        let mut synthetic_stop = false;

        handle_operator_rsp_unit(
            &process,
            RspUnit::Packet(encode_rsp_packet(payload)),
            &mut pending,
            &mut synthetic_stop,
        )
        .expect("queue scheduler command");
        let mut ack = [0_u8; 1];
        operator
            .read_exact(&mut ack)
            .expect("read scheduler command ack");
        assert_eq!(ack, [b'+']);
        let queued = with_gateway(&process, |gateway| {
            Ok(gateway.run_control_requests.front().cloned())
        })
        .expect("inspect scheduler queue")
        .expect("scheduler command should be queued");
        assert_eq!(queued.2, payload);
        assert_eq!(pending.len(), 0);
    }
}

#[test]
fn operator_run_control_reaches_scheduler_once_and_replays_stop_until_acknowledged() {
    let process = test_process();
    let mut peer = configure_active_backend(&process, "/run/crucible/operator-run.sock");
    let backend = thread::spawn(move || {
        assert_eq!(read_test_rsp_payload(&mut peer), b"c");
        peer.write_all(b"+").expect("acknowledge scheduler resume");
        let mut interrupt = [0_u8; 1];
        peer.read_exact(&mut interrupt)
            .expect("read scheduler interrupt");
        assert_eq!(interrupt, [0x03]);
        peer.write_all(&encode_rsp_packet(b"T02"))
            .expect("write backend stop");
        let mut acknowledgement = [0_u8; 1];
        peer.read_exact(&mut acknowledgement)
            .expect("read backend stop acknowledgement");
        assert_eq!(acknowledgement, [b'+']);
    });
    let (mut operator, writer) = UnixStream::pair().expect("operator stream pair");
    with_gateway(&process, |gateway| {
        gateway.operator_writer = Some(writer);
        Ok(())
    })
    .expect("install operator writer");
    let mut pending = VecDeque::new();
    let mut synthetic_stop = false;

    for _ in 0..2 {
        handle_operator_rsp_unit(
            &process,
            RspUnit::Packet(encode_rsp_packet(b"c")),
            &mut pending,
            &mut synthetic_stop,
        )
        .expect("admit or deduplicate continue");
        let mut acknowledgement = [0_u8; 1];
        operator
            .read_exact(&mut acknowledgement)
            .expect("read run acknowledgement");
        assert_eq!(acknowledgement, [b'+']);
    }
    let poll = DebugGatewayFrame::v1(DebugGatewayMessageKind::RunControl, 1, Vec::new())
        .expect("build scheduler poll");
    let routed = dispatch_request(&process, poll.clone()).expect("poll scheduler run control");
    assert_eq!(routed.payload, b"c");
    assert_eq!(routed.stream_id, 1);

    handle_operator_rsp_unit(
        &process,
        RspUnit::Interrupt,
        &mut pending,
        &mut synthetic_stop,
    )
    .expect("queue interrupt");
    let repeated = dispatch_request(&process, poll).expect("repeat scheduler poll");
    assert_eq!(repeated.stream_id, routed.stream_id);
    assert_eq!(repeated.payload, [0x03]);
    let completion = DebugGatewayFrame::v1(DebugGatewayMessageKind::RspData, 1, b"T05".to_vec())
        .expect("build scheduler completion");
    dispatch_request(&process, completion.clone()).expect("complete interrupted run");
    assert_eq!(read_test_rsp_payload(&mut operator), b"T02");

    handle_operator_rsp_unit(&process, RspUnit::Nack, &mut pending, &mut synthetic_stop)
        .expect("retransmit scheduler stop");
    assert_eq!(read_test_rsp_payload(&mut operator), b"T02");
    dispatch_request(&process, completion).expect("deduplicate scheduler completion");
    handle_operator_rsp_unit(&process, RspUnit::Ack, &mut pending, &mut synthetic_stop)
        .expect("acknowledge scheduler stop");
    let state = with_gateway(&process, |gateway| {
        Ok((
            gateway.run_control_requests.len(),
            gateway.run_control_inflight.is_some(),
            gateway.scheduler_response_pending.is_some(),
        ))
    })
    .expect("inspect scheduler state");
    assert_eq!(state, (0, false, false));
    backend.join().expect("backend should complete");
}

#[test]
fn queued_continue_is_superseded_by_operator_interrupt() {
    let process = test_process();
    let _peer = configure_active_backend(&process, "/run/crucible/queued-interrupt.sock");
    let (mut operator, writer) = UnixStream::pair().expect("operator stream pair");
    with_gateway(&process, |gateway| {
        gateway.operator_writer = Some(writer);
        Ok(())
    })
    .expect("install operator writer");
    let mut pending = VecDeque::new();
    let mut synthetic_stop = false;
    handle_operator_rsp_unit(
        &process,
        RspUnit::Packet(encode_rsp_packet(b"c")),
        &mut pending,
        &mut synthetic_stop,
    )
    .expect("queue continue");
    let mut acknowledgement = [0_u8; 1];
    operator
        .read_exact(&mut acknowledgement)
        .expect("read continue acknowledgement");
    assert_eq!(acknowledgement, [b'+']);
    handle_operator_rsp_unit(
        &process,
        RspUnit::Interrupt,
        &mut pending,
        &mut synthetic_stop,
    )
    .expect("supersede queued continue");

    let poll = DebugGatewayFrame::v1(DebugGatewayMessageKind::RunControl, 1, Vec::new())
        .expect("build scheduler poll");
    let routed = dispatch_request(&process, poll).expect("poll superseding interrupt");
    assert_eq!(routed.payload, [0x03]);
    assert_eq!(routed.stream_id, 2);
    let completion = DebugGatewayFrame::v1(
        DebugGatewayMessageKind::RspData,
        routed.stream_id,
        b"T02".to_vec(),
    )
    .expect("build interrupt completion");
    dispatch_request(&process, completion).expect("complete interrupt");
    assert_eq!(read_test_rsp_payload(&mut operator), b"T02");
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
    let (mut operator, writer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("operator pair should open: {error}"));
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
    with_gateway(&process, |gateway| {
        gateway
            .run_control_requests
            .push_back((2, gateway.operator_epoch, vec![0x03]));
        Ok(())
    })
    .unwrap_or_else(|error| panic!("interrupt fixture should queue: {error}"));
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
            gateway.run_control_cancelled,
            gateway.operator_admission_paused,
        ))
    })
    .unwrap_or_else(|error| panic!("gateway state should inspect: {error}"));
    assert_eq!(state, (true, true, None, false, Some(4), false));
    let poll = DebugGatewayFrame::v1(DebugGatewayMessageKind::RunControl, 1, Vec::new())
        .expect("build cancellation poll");
    let cancellation = dispatch_request(&process, poll).expect("poll cancelled run");
    assert_eq!(cancellation.stream_id, 4);
    assert_eq!(cancellation.payload, [0x03]);
    let completion = DebugGatewayFrame::v1(DebugGatewayMessageKind::RspData, 4, b"T02".to_vec())
        .expect("build cancellation completion");
    dispatch_request(&process, completion).expect("acknowledge cancelled run");
    let cancelled = with_gateway(&process, |gateway| Ok(gateway.run_control_cancelled))
        .expect("inspect cancellation state");
    assert_eq!(cancelled, None);
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
