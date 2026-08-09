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
