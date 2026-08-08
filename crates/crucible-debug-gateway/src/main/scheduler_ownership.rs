//! Scheduler ownership and mediated GDB run-control state transitions.

use super::*;

pub(super) fn poll_scheduler_run_control(
    process: &SharedGatewayProcess,
    frame: DebugGatewayFrame,
) -> Result<DebugGatewayFrame, String> {
    if !frame.payload.is_empty() {
        return Err(String::from("run-control poll payload must be empty"));
    }
    with_gateway(process, |gateway| {
        if let Some((stream_id, operator_epoch, packet)) =
            gateway.run_control_requests.front().cloned()
        {
            if gateway.scheduler_lease_active {
                return response(
                    DebugGatewayMessageKind::RunControl,
                    frame.stream_id,
                    Vec::new(),
                );
            }
            if packet != [0x03] && gateway.gdb_scheduler_run_active.is_none() {
                if gateway.prepared.is_some() {
                    return Err(String::from(
                        "cannot begin GDB run control during replacement work",
                    ));
                }
                gateway.operator_admission_paused = true;
                let active = gateway
                    .active
                    .as_mut()
                    .ok_or_else(|| String::from("GDB run control requires an active backend"))?;
                if let Err(error) = resume_scheduler_backend(&mut active.1) {
                    gateway.operator_admission_paused = false;
                    return Err(error);
                }
            }
            let _queued = gateway.run_control_requests.pop_front();
            gateway.run_control_inflight = Some((stream_id, operator_epoch, packet.clone()));
            gateway.gdb_scheduler_run_active = Some(stream_id);
            return response(DebugGatewayMessageKind::RunControl, stream_id, packet);
        }
        if let Some((stream_id, _operator_epoch, packet)) =
            gateway.run_control_inflight.as_ref().cloned()
        {
            return response(DebugGatewayMessageKind::RunControl, stream_id, packet);
        }
        response(
            DebugGatewayMessageKind::RunControl,
            frame.stream_id,
            Vec::new(),
        )
    })
}

pub(super) fn finish_gdb_scheduler_run(
    gateway: &mut GatewayProcess,
    stream_id: u32,
) -> Result<(), String> {
    let Some(active_stream) = gateway.gdb_scheduler_run_active else {
        return Ok(());
    };
    if active_stream != stream_id {
        return Err(String::from(
            "scheduler response does not match active GDB run-control stream",
        ));
    }
    let active = gateway
        .active
        .as_mut()
        .ok_or_else(|| String::from("GDB run control lost its active backend"))?;
    interrupt_scheduler_backend(&mut active.1)?;
    gateway.gdb_scheduler_run_active = None;
    gateway.operator_admission_paused = false;
    Ok(())
}

pub(super) fn scheduler_lease(
    process: &SharedGatewayProcess,
    payload: &[u8],
) -> Result<DebugGatewayFrame, String> {
    let acquire = match payload {
        [1] => true,
        [2] => false,
        _ => {
            return Err(String::from(
                "scheduler lease payload must be acquire=1 or release=2",
            ));
        }
    };
    if acquire {
        let deadline = Instant::now() + QEMU_RSP_TIMEOUT;
        loop {
            let acquired = with_gateway(process, |gateway| {
                if gateway.scheduler_lease_active {
                    return Ok(true);
                }
                if !gateway.run_control_requests.is_empty()
                    || gateway.run_control_inflight.is_some()
                    || gateway.scheduler_response_pending.is_some()
                    || gateway.prepared.is_some()
                {
                    return Err(String::from(
                        "cannot acquire scheduler ownership with pending run-control or replacement work",
                    ));
                }
                let breakpoints = gateway
                    .model
                    .rsp_state()
                    .hardware_breakpoints
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>();
                if breakpoints
                    .iter()
                    .any(|breakpoint| breakpoint.first() != Some(&b'Z'))
                {
                    return Err(String::from("stored hardware breakpoint is malformed"));
                }
                if gateway.active.is_none() {
                    return Err(String::from(
                        "scheduler ownership requires an active backend",
                    ));
                }
                gateway.operator_admission_paused = true;
                if gateway.rsp_responses_pending != 0 {
                    return Ok(false);
                }
                let active = gateway.active.as_mut().ok_or_else(|| {
                    String::from("scheduler ownership requires an active backend")
                })?;
                let mut removed = Vec::new();
                for breakpoint in breakpoints {
                    let mut remove = breakpoint.clone();
                    remove[0] = b'z';
                    match exchange_rsp_packet(&mut active.1, &remove) {
                        Ok(reply) if reply == b"OK" => removed.push(breakpoint),
                        Ok(reply) => {
                            let rollback = restore_scheduler_breakpoints(&mut active.1, &removed);
                            gateway.operator_admission_paused = false;
                            rollback?;
                            return Err(format!(
                                "QEMU rejected scheduler breakpoint suspension with {}",
                                String::from_utf8_lossy(&reply)
                            ));
                        }
                        Err(error) => {
                            let rollback = restore_scheduler_breakpoints(&mut active.1, &removed);
                            gateway.operator_admission_paused = false;
                            rollback?;
                            return Err(error);
                        }
                    }
                }
                if let Err(error) = resume_scheduler_backend(&mut active.1) {
                    let rollback = restore_scheduler_breakpoints(&mut active.1, &removed);
                    gateway.operator_admission_paused = false;
                    rollback?;
                    return Err(error);
                }
                gateway.scheduler_lease_active = true;
                Ok(true)
            })?;
            if acquired {
                break;
            }
            if Instant::now() >= deadline {
                with_gateway(process, |gateway| {
                    gateway.operator_admission_paused = false;
                    Ok(())
                })?;
                return Err(String::from(
                    "timed out waiting for the scheduler ownership packet boundary",
                ));
            }
            std::thread::yield_now();
        }
    } else {
        with_gateway(process, |gateway| {
            if !gateway.scheduler_lease_active {
                return Ok(());
            }
            let breakpoints = gateway
                .model
                .rsp_state()
                .hardware_breakpoints
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            let active = gateway
                .active
                .as_mut()
                .ok_or_else(|| String::from("scheduler ownership lost its active backend"))?;
            interrupt_scheduler_backend(&mut active.1)?;
            restore_scheduler_breakpoints(&mut active.1, &breakpoints)?;
            gateway.scheduler_lease_active = false;
            gateway.operator_admission_paused = false;
            Ok(())
        })?;
    }
    response(DebugGatewayMessageKind::Ack, 0, Vec::new())
}

fn resume_scheduler_backend(stream: &mut UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set QEMU scheduler-resume timeout: {error}"))?;
    stream
        .write_all(&encode_rsp_packet(b"c"))
        .map_err(|error| format!("resume QEMU for scheduler ownership: {error}"))?;
    let mut decoder = RspStreamDecoder::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read QEMU scheduler-resume acknowledgement: {error}"))?;
        if read == 0 {
            return Err(String::from(
                "QEMU RSP backend closed before scheduler resume was acknowledged",
            ));
        }
        let mut acknowledged = false;
        for unit in decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode QEMU scheduler-resume acknowledgement: {error}"))?
        {
            match unit {
                RspUnit::Ack => acknowledged = true,
                RspUnit::Nack => {
                    return Err(String::from("QEMU rejected scheduler resume"));
                }
                RspUnit::Packet(_) | RspUnit::Interrupt => {
                    return Err(String::from(
                        "QEMU stopped unexpectedly while scheduler ownership was acquired",
                    ));
                }
            }
        }
        if acknowledged {
            return Ok(());
        }
    }
}

pub(super) fn interrupt_scheduler_backend(stream: &mut UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set QEMU scheduler-stop timeout: {error}"))?;
    stream
        .write_all(&[0x03])
        .map_err(|error| format!("interrupt QEMU after scheduler ownership: {error}"))?;
    let mut decoder = RspStreamDecoder::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read QEMU scheduler-stop response: {error}"))?;
        if read == 0 {
            return Err(String::from(
                "QEMU RSP backend closed before scheduler stop was reported",
            ));
        }
        for unit in decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode QEMU scheduler-stop response: {error}"))?
        {
            match unit {
                RspUnit::Packet(packet)
                    if matches!(rsp_payload(&packet).first(), Some(b'S' | b'T')) =>
                {
                    stream
                        .write_all(b"+")
                        .map_err(|error| format!("acknowledge QEMU scheduler stop: {error}"))?;
                    return Ok(());
                }
                RspUnit::Ack => {}
                RspUnit::Nack | RspUnit::Interrupt | RspUnit::Packet(_) => {
                    return Err(String::from(
                        "QEMU returned an invalid scheduler-stop response",
                    ));
                }
            }
        }
    }
}

fn restore_scheduler_breakpoints(
    stream: &mut UnixStream,
    breakpoints: &[Vec<u8>],
) -> Result<(), String> {
    for breakpoint in breakpoints {
        let reply = exchange_rsp_packet(stream, breakpoint)?;
        if reply != b"OK" {
            return Err(format!(
                "QEMU rejected scheduler breakpoint restoration with {}",
                String::from_utf8_lossy(&reply)
            ));
        }
    }
    Ok(())
}

pub(super) fn acknowledge_scheduler_response(
    process: &SharedGatewayProcess,
    retransmit: bool,
) -> Result<bool, String> {
    with_gateway(process, |gateway| {
        let Some(response) = gateway.scheduler_response_pending.as_ref() else {
            return Ok(false);
        };
        if retransmit {
            gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?
                .write_all(response)
                .map_err(|error| format!("retransmit scheduler RSP response: {error}"))?;
        } else {
            gateway.scheduler_response_pending = None;
        }
        Ok(true)
    })
}

pub(super) fn queue_scheduler_run_control(
    process: &SharedGatewayProcess,
    packet: Vec<u8>,
    acknowledge: bool,
) -> Result<(), String> {
    with_gateway(process, |gateway| {
        let is_interrupt = packet == [0x03];
        let duplicate = gateway
            .run_control_requests
            .front()
            .or(gateway.run_control_inflight.as_ref())
            .is_some_and(|(_, epoch, pending)| {
                *epoch == gateway.operator_epoch && pending == &packet
            });
        let completed_duplicate = gateway.scheduler_response_pending.is_some()
            && gateway
                .run_control_completed
                .as_ref()
                .is_some_and(|(_, completed, _)| completed == &packet);
        // A stop response already awaiting the operator's acknowledgement
        // satisfies a racing interrupt. Queueing another interrupt would make
        // the scheduler stop an already-paused backend after that response.
        if is_interrupt && gateway.scheduler_response_pending.is_some() {
            return Ok(());
        }
        let request_pending = !gateway.run_control_requests.is_empty()
            || gateway.run_control_inflight.is_some()
            || gateway.scheduler_response_pending.is_some();
        let interrupt_can_supersede = is_interrupt && gateway.scheduler_response_pending.is_none();
        let admission_conflict =
            request_pending && !(duplicate || completed_duplicate || interrupt_can_supersede);
        if admission_conflict {
            return Err(String::from(
                "operator issued run control while a scheduler request is pending",
            ));
        }
        if acknowledge {
            gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?
                .write_all(b"+")
                .map_err(|error| format!("acknowledge scheduler RSP request: {error}"))?;
        }
        if !duplicate && !completed_duplicate {
            if is_interrupt {
                gateway.run_control_requests.clear();
            }
            gateway.next_run_control_stream = gateway
                .next_run_control_stream
                .checked_add(1)
                .ok_or_else(|| String::from("run-control stream generation exhausted"))?;
            gateway.run_control_requests.push_back((
                gateway.next_run_control_stream,
                gateway.operator_epoch,
                packet,
            ));
        }
        Ok(())
    })
}
