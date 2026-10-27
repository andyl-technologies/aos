//! Consumes complete native receipt banks before any decoded controller effect.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crucible_qemu_protocol::ram_control::*;

const NATIVE_FRAME_BYTES: usize = 1024;

pub(super) fn run(
    owner: &Arc<LivePagerController>,
    id: u64,
    actor: *mut Actor,
    fd: i32,
    api: native::Api,
) -> i32 {
    loop {
        let mut record = native::Borrow::default();
        let status = (api.begin)(id, actor, &mut record);
        if status == -libc::EAGAIN || status == -libc::EBUSY {
            let end = (api.dispatch_end)(id, actor);
            if end == 0 {
                return 0;
            }
            if end != -libc::EAGAIN {
                return end;
            }
            let wait = (api.wait)(id, actor, native::WAIT_READ);
            if wait != 0 && wait != -libc::EAGAIN {
                return wait;
            }
            continue;
        }
        if status != 0 {
            return status;
        }
        if record.schema_version != 1
            || record.struct_size as usize != size_of::<native::Borrow>()
            || record.loan.is_null()
            || record.frame.is_null()
            || record.frame_capacity != NATIVE_FRAME_BYTES
        {
            return -libc::EPROTO;
        }
        let result = receive_frame(id, actor, api, &record)
            .and_then(|length| decode_record(&record, length))
            .and_then(|frame| dispatch(owner, id, actor, fd, api, &record, frame));
        let disposition = match result {
            Ok(disposition) => disposition,
            Err(status) => {
                // This is the first and only attempted bank disposition. It
                // cannot infer movement, close an ambiguous alias or retry end.
                let _retained = (api.dispose)(id, actor, record.loan, status);
                return status;
            }
        };
        let status = if disposition.moved {
            (api.record_return)(id, actor, record.loan, disposition.status)
        } else {
            (api.dispose)(id, actor, record.loan, disposition.status)
        };
        // Native may have returned the actual bank before reporting its cause.
        // Never touch that loan again or repeat completion after this call.
        if status != 0 {
            return status;
        }
    }
}

fn receive_frame(
    id: u64,
    actor: *mut Actor,
    api: native::Api,
    record: &native::Borrow,
) -> Result<usize, i32> {
    let mut received = 0;
    let mut extent = 4;
    while received < extent {
        let maximum = if received == 0 { 1 } else { extent - received };
        let mut chunk = 0;
        let status = (api.read)(id, actor, record.loan, maximum, &mut chunk);
        if status == -libc::EAGAIN || status == -libc::EWOULDBLOCK {
            let wait = (api.wait)(id, actor, native::WAIT_READ);
            if wait != 0 && wait != -libc::EAGAIN {
                return Err(wait);
            }
            continue;
        }
        if status != 0 {
            return Err(status);
        }
        if chunk == 0 || chunk > maximum {
            return Err(-libc::EPROTO);
        }
        received = received.checked_add(chunk).ok_or(-libc::EOVERFLOW)?;
        if received == 4 {
            // SAFETY: same native loan physically initialized this exact prefix.
            // No native read runs while this immutable borrowed view is active.
            let prefix = unsafe { *record.frame.cast::<[u8; 4]>() };
            let length = u32::from_be_bytes(prefix) as usize;
            extent = length
                .checked_add(4)
                .filter(|extent| *extent <= record.frame_capacity)
                .ok_or(-libc::EMSGSIZE)?;
            if length == 0 {
                return Err(-libc::EPROTO);
            }
        }
    }
    Ok(extent)
}

fn decode_record(record: &native::Borrow, extent: usize) -> Result<RamControlFrame, i32> {
    if extent < 4 || extent > record.frame_capacity {
        return Err(-libc::EPROTO);
    }
    // SAFETY: the actual native bank retains its fixed allocation and has
    // initialized this complete extent. No read, bank return or concurrent
    // native mutation occurs during canonical decoding of the borrowed body.
    let frame = unsafe { std::slice::from_raw_parts(record.frame.add(4), extent - 4) };
    decode_ram_control(frame).map_err(|_| -libc::EPROTO)
}

struct Disposition {
    moved: bool,
    status: i32,
}

fn dispatch(
    owner: &Arc<LivePagerController>,
    id: u64,
    actor: *mut Actor,
    fd: i32,
    api: native::Api,
    record: &native::Borrow,
    frame: RamControlFrame,
) -> Result<Disposition, i32> {
    let sequence = owner.actor.lock().map_err(|_| -libc::EOWNERDEAD)?.sequence;
    let request = validate_ram_control_request(&frame, owner.session, owner.identity(), sequence)
        .map_err(|_| -libc::EPROTO)?;
    let digest = ram_control_request_digest(&frame).map_err(|_| -libc::EPROTO)?;
    let mut disposition = Disposition {
        moved: false,
        status: 0,
    };
    let message = match request {
        RamControlRequest::CheckpointArm { original } => {
            let mut generation = 0;
            let status = (api.pending)(
                id,
                actor,
                record.loan,
                original.as_ptr(),
                digest.as_ptr(),
                &mut generation,
            );
            if status > 0 {
                return Err(-libc::EPROTO);
            }
            if status == 0 && generation == 0 {
                return Err(-libc::EPROTO);
            }
            // This native constructor journals generation immediately after
            // its actual alias movement, including negatives. It selects the
            // disposition path and supplies no stopped/root authority.
            disposition.moved = generation != 0;
            if generation == 0 {
                disposition.status = status;
            }
            let post = if status == 0 {
                0
            } else {
                let binding = RamControlCheckpointBinding {
                    arm_request_digest: digest,
                    request_generation: generation,
                    connection_epoch: 0,
                };
                if generation == 0 {
                    -libc::EINPROGRESS
                } else {
                    observe_disposition(api, id, actor, binding)
                        .map_or(-libc::EINPROGRESS, |receipt| receipt.post_status)
                }
            };
            RamControlMessage::CheckpointArmReply {
                request_digest: digest,
                receipt: RamControlCheckpointArmReceipt {
                    disposition: if status == 0 {
                        RamControlDisposition::Accepted
                    } else {
                        RamControlDisposition::AdmissionRefused
                    },
                    request_generation: generation,
                    first_status: status,
                    post_status: post,
                },
            }
        }
        RamControlRequest::CheckpointDisposition { binding } => {
            descriptor_free(api, id, actor, record.loan)?;
            RamControlMessage::CheckpointDispositionReply {
                binding,
                receipt: observe_disposition(api, id, actor, binding)?,
            }
        }
        request => {
            // Only this actual native check establishes zero ancillary aliases.
            // Canonical syntax or later successful close cannot grant effects.
            descriptor_free(api, id, actor, record.loan)?;
            RamControlMessage::Reply {
                request_digest: digest,
                state: ordinary(owner, request)?,
            }
        }
    };
    let response = RamControlFrame {
        session: owner.session,
        target: owner.identity(),
        sequence: frame.sequence,
        message,
    };
    let mut reply = [0; RAM_CONTROL_MAX_BYTES + 4];
    let length = encode_ram_control_into(&response, &mut reply[4..]).map_err(|_| -libc::EPROTO)?;
    reply[..4].copy_from_slice(&(length as u32).to_be_bytes());
    send_reply(owner, id, actor, record.loan, fd, api, &reply[..length + 4])?;
    owner.actor.lock().map_err(|_| -libc::EOWNERDEAD)?.sequence = frame.sequence;
    // No native bank mutation occurs here. The outer loop performs exactly one
    // bank return after successful reply/cursor disposition, then stops touching
    // that loan even if the returned signed cause is negative.
    Ok(disposition)
}

fn descriptor_free(
    api: native::Api,
    id: u64,
    actor: *mut Actor,
    loan: *mut Receive,
) -> Result<(), i32> {
    let status = (api.descriptor_free)(id, actor, loan);
    if status == 0 { Ok(()) } else { Err(status) }
}

fn ordinary(
    owner: &LivePagerController,
    request: RamControlRequest,
) -> Result<RamControlReply, i32> {
    Ok(match request {
        RamControlRequest::Hello | RamControlRequest::Status => owner.status(),
        RamControlRequest::Performance { action } => owner.performance(action),
        RamControlRequest::TestFaultActor {
            entitlement,
            worker_generation,
            action,
        } => owner.test_fault_actor(entitlement, worker_generation, action),
        RamControlRequest::Apply {
            expected_revision,
            policy_revision,
            reservation_revision,
            resources,
            policy,
        } => owner.apply(
            expected_revision,
            policy_revision,
            reservation_revision,
            policy,
            resources,
        ),
        RamControlRequest::InventoryRegion {
            topology_generation,
            ordinal,
        } => owner.inventory_region(topology_generation, ordinal),
        RamControlRequest::GrantInventory {
            topology_generation,
            resources,
            spill_quota_bytes,
        } => owner.grant_inventory(topology_generation, resources, spill_quota_bytes),
        RamControlRequest::SyncOuterCap { cap } => owner.sync_outer_cap(cap),
        RamControlRequest::Cancel {
            operation_generation,
        } => owner.cancel(operation_generation),
        RamControlRequest::CheckpointArm { .. }
        | RamControlRequest::CheckpointDisposition { .. } => return Err(-libc::EPROTO),
    })
}

fn observe_disposition(
    api: native::Api,
    id: u64,
    actor: *mut Actor,
    binding: RamControlCheckpointBinding,
) -> Result<RamControlCheckpointDispositionReceipt, i32> {
    let mut output = native::TerminalStatus::default();
    let status = (api.terminal)(
        id,
        actor,
        binding.arm_request_digest.as_ptr(),
        binding.request_generation,
        binding.connection_epoch,
        &mut output,
    );
    if status != 0 {
        return Err(status);
    }
    if output.schema_version != 1
        || output.struct_size as usize != size_of::<native::TerminalStatus>()
        || output.reserved != 0
        || output.arm_request_digest != binding.arm_request_digest
        || output.request_generation != binding.request_generation
        || output.connection_epoch != binding.connection_epoch
    {
        return Err(-libc::EPROTO);
    }
    let physical_state = match output.physical_state {
        0 => RamControlCheckpointPhysicalState::Pending,
        1 => RamControlCheckpointPhysicalState::Retired,
        2 => RamControlCheckpointPhysicalState::NoRootAbandoned,
        3 => RamControlCheckpointPhysicalState::Uncertain,
        _ => return Err(-libc::EPROTO),
    };
    let receipt = RamControlCheckpointDispositionReceipt {
        physical_state,
        first_status: output.first_status,
        post_status: output.post_status,
    };
    receipt
        .validate(binding.connection_epoch)
        .map_err(|_| -libc::EPROTO)?;
    Ok(receipt)
}

fn reply_slice(
    owner: &LivePagerController,
    actor: *mut Actor,
    loan: *mut Receive,
) -> Result<Duration, i32> {
    let mut state = owner.actor.lock().map_err(|_| -libc::EOWNERDEAD)?;
    if state.address != actor as usize
        || state.record.actor != actor as usize
        || state.record.loan != loan as usize
        || state.record.end_attempted
    {
        return Err(-libc::ESTALE);
    }
    let result = state
        .record
        .operation
        .as_ref()
        .ok_or(-libc::ENOKEY)?
        .wait_slice_for_observation();
    result.map_err(|error| {
        let status = observation_status(&error);
        state.record.failure = Some(error);
        status
    })
}

fn send_reply(
    owner: &LivePagerController,
    id: u64,
    actor: *mut Actor,
    loan: *mut Receive,
    fd: i32,
    api: native::Api,
    bytes: &[u8],
) -> Result<(), i32> {
    let mut sent = 0;
    while sent < bytes.len() {
        reply_slice(owner, actor, loan)?;
        // SAFETY: actual actor entry lends this retained endpoint for its whole
        // invocation. This syscall changes no ownership or shared OFD options;
        // the bounded caller-owned body stays borrowed until send returns.
        let written = unsafe {
            libc::send(
                fd,
                bytes[sent..].as_ptr().cast(),
                bytes.len() - sent,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        let errno = if written < 0 {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        } else {
            0
        };
        reply_slice(owner, actor, loan)?;
        if written < 0 {
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                let status = (api.wait)(id, actor, native::WAIT_WRITE);
                if status != 0 && status != -libc::EAGAIN {
                    return Err(status);
                }
                continue;
            }
            return Err(-errno);
        }
        if written == 0 {
            return Err(-libc::EPIPE);
        }
        sent = sent
            .checked_add(written as usize)
            .filter(|sent| *sent <= bytes.len())
            .ok_or(-libc::EPROTO)?;
    }
    Ok(())
}
