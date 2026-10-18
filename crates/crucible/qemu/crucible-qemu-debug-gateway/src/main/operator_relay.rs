//! Owner-gated operator RSP relay and backend state restoration.

use super::*;

pub(super) fn spawn_operator_listener(
    process: SharedGatewayProcess,
    listener: UnixListener,
) -> Result<(), String> {
    std::thread::Builder::new()
        .name(String::from("crucible-debug-gdb-listener"))
        .spawn(move || operator_listener_loop(&process, listener))
        .map(|_| ())
        .map_err(|error| format!("spawn operator gdb listener: {error}"))
}

fn operator_listener_loop(process: &SharedGatewayProcess, listener: UnixListener) {
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let result = serve_operator_connection(process, stream);
                let cleanup =
                    with_gateway(process, |gateway| Ok(gateway.operator_writer.is_some()))
                        .and_then(|attached| {
                            if attached {
                                restore_backend_after_operator_disconnect(process, result.is_ok())
                            } else {
                                Ok(())
                            }
                        });
                if let Err(error) = result {
                    eprintln!(
                        "crucible-debug-gateway: operator gdb connection closed: {}",
                        bounded_diagnostic(&error)
                    );
                }
                if let Err(error) = cleanup {
                    eprintln!(
                        "crucible-debug-gateway: operator cleanup failed: {}",
                        bounded_diagnostic(&error)
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "crucible-debug-gateway: accept operator gdb connection: {}",
                    bounded_diagnostic(&error.to_string())
                );
            }
        }
    }
}

pub(super) fn restore_backend_after_operator_disconnect(
    process: &SharedGatewayProcess,
    relay_closed_cleanly: bool,
) -> Result<(), String> {
    let ownership_recovered = with_gateway(process, |gateway| {
        if gateway.gdb_scheduler_run_active.is_some() {
            let cancelled = gateway.gdb_scheduler_run_active;
            let active = gateway
                .active
                .as_mut()
                .ok_or_else(|| String::from("GDB run control lost its active backend"))?;
            interrupt_scheduler_backend(&mut active.1)?;
            gateway.operator_writer = None;
            gateway.rsp_responses_pending = 0;
            gateway.run_control_requests.clear();
            gateway.run_control_inflight = None;
            gateway.run_control_cancelled = cancelled;
            gateway.run_control_completed = None;
            gateway.scheduler_response_pending = None;
            gateway.gdb_scheduler_run_active = None;
            gateway.operator_admission_paused = false;
            return Ok(true);
        }
        if gateway.scheduler_lease_active {
            gateway.operator_writer = None;
            gateway.rsp_responses_pending = 0;
            gateway.run_control_requests.clear();
            gateway.run_control_inflight = None;
            gateway.run_control_completed = None;
            gateway.scheduler_response_pending = None;
            gateway.operator_admission_paused = true;
            return Ok(true);
        }
        Ok(false)
    })?;
    if ownership_recovered {
        return Ok(());
    }

    let reconnect = with_gateway(process, |gateway| {
        // An operator disconnect cancels scheduler work owned by that connection.
        gateway.run_control_requests.clear();
        gateway.run_control_completed = None;
        gateway.scheduler_response_pending = None;
        let recovery_is_unambiguous =
            relay_closed_cleanly && gateway.replacement_boundary_is_clean();
        let active = recovery_is_unambiguous
            .then(|| gateway.model.active().cloned())
            .flatten();
        if !recovery_is_unambiguous {
            gateway.model.deactivate_backend();
        }
        gateway.active = None;
        gateway.operator_writer = None;
        gateway.rsp_responses_pending = 0;
        gateway.run_control_requests.clear();
        gateway.run_control_inflight = None;
        gateway.scheduler_response_pending = None;
        gateway.gdb_scheduler_run_active = None;
        Ok(active.map(|active| {
            (
                active.generation,
                active.endpoint,
                gateway.model.rsp_state().clone(),
                gateway.rsp_state_epoch,
            )
        }))
    })?;
    let Some((generation, endpoint, state, state_epoch)) = reconnect else {
        return Ok(());
    };

    let restored = connect_candidate(&endpoint).and_then(|mut stream| {
        validate_and_hydrate_candidate(&mut stream, &state)?;
        with_gateway(process, |gateway| {
            if gateway.active.is_some() {
                return Ok(true);
            }
            let unchanged = gateway.model.active().is_some_and(|active| {
                active.generation == generation && active.endpoint == endpoint
            }) && gateway.rsp_state_epoch == state_epoch;
            if !unchanged {
                return Ok(false);
            }
            gateway.active = Some((generation, stream));
            Ok(true)
        })
    });
    match restored {
        Ok(true) => Ok(()),
        Ok(false) => Ok(()),
        Err(error) => {
            with_gateway(process, |gateway| {
                let failed_backend_is_still_active = gateway.active.is_none()
                    && gateway.model.active().is_some_and(|active| {
                        active.generation == generation && active.endpoint == endpoint
                    });
                if failed_backend_is_still_active {
                    gateway.model.deactivate_backend();
                }
                Ok(())
            })?;
            Err(format!(
                "restore QEMU RSP backend after operator disconnect: {error}"
            ))
        }
    }
}

pub(super) fn serve_operator_connection(
    process: &SharedGatewayProcess,
    mut operator: UnixStream,
) -> Result<(), String> {
    operator
        .set_read_timeout(Some(RSP_RELAY_POLL_TIMEOUT))
        .map_err(|error| format!("set operator gdb read timeout: {error}"))?;
    let operator_writer = operator
        .try_clone()
        .map_err(|error| format!("clone operator gdb stream: {error}"))?;
    operator_writer
        .set_write_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set operator gdb write timeout: {error}"))?;
    let (mut observed_replacement_epoch, mut synthetic_stop_ack_pending) =
        with_gateway(process, |gateway| {
            if gateway.operator_writer.is_some() {
                return Err(String::from("an operator gdb connection is already active"));
            }
            if gateway.run_control_cancelled.is_some() {
                return Err(String::from(
                    "previous operator run control is awaiting scheduler cancellation",
                ));
            }
            let active = gateway.active.is_some();
            gateway.operator_epoch = gateway
                .operator_epoch
                .checked_add(1)
                .ok_or_else(|| String::from("operator connection generation exhausted"))?;
            gateway.operator_writer = Some(operator_writer);
            if active {
                let writer = gateway
                    .operator_writer
                    .as_mut()
                    .ok_or_else(|| String::from("operator gdb writer disappeared during attach"))?;
                writer
                    .write_all(&encode_rsp_packet(b"T05"))
                    .map_err(|error| format!("write initial stop to operator gdb: {error}"))?;
                gateway.replacement_epoch = gateway.replacement_epoch.saturating_add(1);
            }
            Ok((gateway.replacement_epoch, active))
        })?;
    let mut operator_decoder = RspStreamDecoder::new();
    let mut backend_decoder = RspStreamDecoder::new();
    let mut pending_state = VecDeque::<Vec<u8>>::new();
    let mut buffer = [0_u8; 4096];

    loop {
        let replacement_epoch = with_gateway(process, |gateway| Ok(gateway.replacement_epoch))?;
        if replacement_epoch != observed_replacement_epoch {
            observed_replacement_epoch = replacement_epoch;
            backend_decoder = RspStreamDecoder::new();
            // The prepare barrier drains the old backend before commit. A
            // packet waiting at that barrier is admitted only after commit and
            // must retain its request/response correlation on the new backend.
            synthetic_stop_ack_pending = false;
        }

        match operator.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                let units = operator_decoder
                    .push(&buffer[..read])
                    .map_err(|error| format!("decode operator RSP stream: {error}"))?;
                for unit in units {
                    handle_operator_rsp_unit(
                        process,
                        unit,
                        &mut pending_state,
                        &mut synthetic_stop_ack_pending,
                    )?;
                }
            }
            Err(error) if is_poll_timeout(&error) => {}
            Err(error) => return Err(format!("read operator gdb stream: {error}")),
        }

        let Some(read) = read_and_forward_active_backend(process, &mut buffer)? else {
            continue;
        };
        let units = backend_decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode QEMU RSP stream: {error}"))?;
        for unit in units {
            match unit {
                RspUnit::Nack => {
                    pending_state.pop_front();
                    resolve_pending_response(process)?;
                }
                RspUnit::Packet(response) if !is_async_console_packet(&response) => {
                    if let Some(request) = pending_state.pop_front() {
                        record_semantic_response(process, &request, &response)?;
                        resolve_pending_response(process)?;
                    }
                }
                RspUnit::Ack | RspUnit::Interrupt | RspUnit::Packet(_) => {}
            }
        }
    }
}

fn read_and_forward_active_backend(
    process: &SharedGatewayProcess,
    buffer: &mut [u8],
) -> Result<Option<usize>, String> {
    with_gateway(process, |gateway| {
        if gateway.gdb_scheduler_run_active.is_some() {
            return Ok(None);
        }
        let Some((_, stream)) = gateway.active.as_mut() else {
            return Ok(None);
        };
        stream
            .set_read_timeout(Some(RSP_RELAY_POLL_TIMEOUT))
            .map_err(|error| format!("set active QEMU RSP read timeout: {error}"))?;
        let read = match stream.read(buffer) {
            Ok(0) => Err(String::from("active QEMU RSP backend closed")),
            Ok(read) => Ok(Some(read)),
            Err(error) if is_poll_timeout(&error) => Ok(None),
            Err(error) => Err(format!("read active QEMU RSP backend: {error}")),
        }?;
        if let Some(read) = read {
            let operator = gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?;
            operator
                .write_all(&buffer[..read])
                .map_err(|error| format!("forward QEMU RSP bytes to operator gdb: {error}"))?;
        }
        Ok(read)
    })
}

pub(super) fn handle_operator_rsp_unit(
    process: &SharedGatewayProcess,
    unit: RspUnit,
    pending_state: &mut VecDeque<Vec<u8>>,
    synthetic_stop_ack_pending: &mut bool,
) -> Result<(), String> {
    match unit {
        RspUnit::Ack => {
            if acknowledge_scheduler_response(process, false)? {
                with_gateway(process, |gateway| {
                    gateway.run_control_completed = None;
                    Ok(())
                })?;
                return Ok(());
            }
            if *synthetic_stop_ack_pending {
                *synthetic_stop_ack_pending = false;
                return Ok(());
            }
            write_active_backend(process, b"+").map(|_| ())
        }
        RspUnit::Nack => {
            if acknowledge_scheduler_response(process, true)? {
                return Ok(());
            }
            if *synthetic_stop_ack_pending {
                return write_operator_bytes(process, &encode_rsp_packet(b"T05"));
            }
            write_active_backend(process, b"-").map(|_| ())
        }
        RspUnit::Interrupt => enqueue_scheduler_run_control(process, &[0x03], false),
        RspUnit::Packet(packet) => match classify_rsp_packet(&packet) {
            RspDisposition::ForwardToQemu => {
                // A canonical software-breakpoint request may use hardware only.
                // QEMU's reply still determines whether that mechanism exists.
                let packet = canonical_breakpoint_packet(&packet);
                if !pending_rsp_capacity(pending_state, packet.len()) {
                    return write_rsp_rejection(process, b"E20", true);
                }
                if !admit_operator_request(process, &packet)? {
                    return write_rsp_rejection(process, b"E20", true);
                }
                pending_state.push_back(packet);
                Ok(())
            }
            RspDisposition::SchedulerRunControl => {
                enqueue_scheduler_run_control(process, rsp_payload(&packet), true)
            }
            RspDisposition::RejectReadOnly if branch_guest_write_allowed(process, &packet)? => {
                if !pending_rsp_capacity(pending_state, packet.len()) {
                    return write_rsp_rejection(process, b"E20", true);
                }
                if !admit_operator_request(process, &packet)? {
                    return write_rsp_rejection(process, b"E20", true);
                }
                pending_state.push_back(packet);
                Ok(())
            }
            RspDisposition::RejectReadOnly => write_rsp_rejection(process, b"E22", true),
            RspDisposition::RejectUnsupported => write_rsp_rejection(process, b"E01", true),
        },
    }
}

fn pending_rsp_capacity(pending: &VecDeque<Vec<u8>>, next_len: usize) -> bool {
    pending.len() < MAX_PENDING_RSP_REQUESTS
        && pending.iter().map(Vec::len).sum::<usize>() + next_len <= MAX_PENDING_RSP_BYTES
}

fn enqueue_scheduler_run_control(
    process: &SharedGatewayProcess,
    packet: &[u8],
    acknowledge_request: bool,
) -> Result<(), String> {
    with_gateway(process, |gateway| {
        let operator = gateway
            .operator_writer
            .as_mut()
            .ok_or_else(|| String::from("operator gdb connection is not active"))?;
        let duplicate = gateway
            .run_control_requests
            .front()
            .is_some_and(|(_, epoch, queued)| *epoch == gateway.operator_epoch && queued == packet)
            || gateway
                .run_control_inflight
                .as_ref()
                .is_some_and(|(_, epoch, inflight)| {
                    *epoch == gateway.operator_epoch && inflight == packet
                })
            || gateway
                .run_control_completed
                .as_ref()
                .is_some_and(|(_, completed, _)| completed == packet);
        if duplicate {
            if acknowledge_request {
                operator
                    .write_all(b"+")
                    .map_err(|error| format!("acknowledge duplicate GDB run control: {error}"))?;
            }
            if let Some(response) = gateway.scheduler_response_pending.as_ref() {
                operator
                    .write_all(response)
                    .map_err(|error| format!("replay scheduler RSP response: {error}"))?;
            }
            return Ok(());
        }

        let interrupt = packet == [0x03];
        let queued = gateway.run_control_requests.front().is_some();
        let inflight = gateway.run_control_inflight.is_some();
        let busy = gateway.scheduler_response_pending.is_some()
            || gateway.run_control_cancelled.is_some()
            || gateway.prepared.is_some()
            || gateway.active.is_none();
        if busy || ((queued || inflight) && !interrupt) {
            if acknowledge_request {
                operator
                    .write_all(b"+")
                    .map_err(|error| format!("acknowledge rejected GDB run control: {error}"))?;
            }
            return operator
                .write_all(&encode_rsp_packet(b"E22"))
                .map_err(|error| format!("reject GDB run control: {error}"));
        }
        let request_id = gateway
            .next_run_control_id
            .checked_add(1)
            .ok_or_else(|| String::from("scheduler run-control request ID exhausted"))?;
        if acknowledge_request {
            operator
                .write_all(b"+")
                .map_err(|error| format!("acknowledge GDB run control: {error}"))?;
        }
        // The operator acknowledgement precedes visibility to scheduler polls.
        gateway.next_run_control_id = request_id;
        if interrupt && queued {
            gateway.run_control_requests.clear();
        }
        gateway.run_control_requests.push_back((
            request_id,
            gateway.operator_epoch,
            packet.to_vec(),
        ));
        Ok(())
    })
}

fn canonical_breakpoint_packet(packet: &[u8]) -> Vec<u8> {
    let payload = rsp_payload(packet);
    let hardware = if let Some(address) = payload.strip_prefix(b"Z0,") {
        Some((b"Z1,".as_slice(), address))
    } else {
        payload
            .strip_prefix(b"z0,")
            .map(|address| (b"z1,".as_slice(), address))
    };

    if let Some((prefix, address)) = hardware {
        let mut payload = Vec::with_capacity(prefix.len() + address.len());
        payload.extend_from_slice(prefix);
        payload.extend_from_slice(address);
        encode_rsp_packet(&payload)
    } else {
        packet.to_vec()
    }
}

fn branch_guest_write_allowed(
    process: &SharedGatewayProcess,
    packet: &[u8],
) -> Result<bool, String> {
    let payload = rsp_payload(packet);
    let guest_write = matches!(payload.first(), Some(b'G' | b'P' | b'M' | b'X'));
    with_gateway(process, |gateway| {
        Ok(guest_write && gateway.branch_guest_write_enabled)
    })
}

fn admit_operator_request(process: &SharedGatewayProcess, packet: &[u8]) -> Result<bool, String> {
    loop {
        let admitted = with_gateway(process, |gateway| {
            if !gateway.run_control_requests.is_empty()
                || gateway.run_control_inflight.is_some()
                || gateway.run_control_cancelled.is_some()
                || gateway.scheduler_response_pending.is_some()
            {
                return Ok(Some(false));
            }
            if gateway.operator_admission_paused {
                return Ok(None);
            }
            let Some((_, backend)) = gateway.active.as_mut() else {
                return Ok(Some(false));
            };
            backend
                .write_all(packet)
                .map_err(|error| format!("forward operator RSP packet to QEMU: {error}"))?;
            gateway.rsp_responses_pending = gateway.rsp_responses_pending.saturating_add(1);
            Ok(Some(true))
        })?;
        if let Some(admitted) = admitted {
            return Ok(admitted);
        }
        std::thread::yield_now();
    }
}

pub(super) fn write_active_backend(
    process: &SharedGatewayProcess,
    bytes: &[u8],
) -> Result<bool, String> {
    with_gateway(process, |gateway| {
        let Some((_, backend)) = gateway.active.as_mut() else {
            return Ok(false);
        };
        backend
            .write_all(bytes)
            .map_err(|error| format!("forward operator RSP bytes to QEMU: {error}"))?;
        Ok(true)
    })
}

fn write_rsp_rejection(
    process: &SharedGatewayProcess,
    payload: &[u8],
    acknowledge_request: bool,
) -> Result<(), String> {
    if acknowledge_request {
        write_operator_bytes(process, b"+")?;
    }
    write_operator_bytes(process, &encode_rsp_packet(payload))
}

fn write_operator_bytes(process: &SharedGatewayProcess, bytes: &[u8]) -> Result<(), String> {
    with_gateway(process, |gateway| {
        let operator = gateway
            .operator_writer
            .as_mut()
            .ok_or_else(|| String::from("operator gdb connection is not active"))?;
        operator
            .write_all(bytes)
            .map_err(|error| format!("write operator gdb bytes: {error}"))
    })
}

fn resolve_pending_response(process: &SharedGatewayProcess) -> Result<(), String> {
    with_gateway(process, |gateway| {
        gateway.rsp_responses_pending = gateway.rsp_responses_pending.saturating_sub(1);
        Ok(())
    })
}

pub(super) fn record_semantic_response(
    process: &SharedGatewayProcess,
    request: &[u8],
    response: &[u8],
) -> Result<(), String> {
    if rsp_payload(response) != b"OK" {
        return Ok(());
    }
    with_gateway(process, |gateway| {
        let before = gateway.model.rsp_state().clone();
        gateway.model.observe_acknowledged_rsp(request);
        if gateway.model.rsp_state() != &before {
            gateway.rsp_state_epoch = gateway.rsp_state_epoch.saturating_add(1);
        }
        Ok(())
    })
}

fn is_async_console_packet(packet: &[u8]) -> bool {
    let payload = rsp_payload(packet);
    payload.starts_with(b"O") && payload != b"OK"
}

pub(super) fn rsp_payload(packet: &[u8]) -> &[u8] {
    &packet[1..packet.len() - 3]
}

fn is_poll_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
