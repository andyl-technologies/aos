//! Canonical fixed-width pager frames, decoded without attacker-sized allocation.

use super::*;

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], RamControlError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(RamControlError::InvalidFrame)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RamControlError::InvalidFrame)?;
        let result = bytes
            .try_into()
            .map_err(|_| RamControlError::InvalidFrame)?;
        self.offset = end;
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, RamControlError> {
        Ok(self.take::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, RamControlError> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, RamControlError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn boolean(&mut self) -> Result<bool, RamControlError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RamControlError::InvalidFrame),
        }
    }

    fn duration(&mut self) -> Result<Option<u64>, RamControlError> {
        match self.byte()? {
            0 => Ok(None),
            1 => {
                let value = self.u64()?;
                if value == 0 || value > i64::MAX as u64 / 1_000_000 {
                    return Err(RamControlError::InvalidFrame);
                }
                Ok(Some(value))
            }
            _ => Err(RamControlError::InvalidFrame),
        }
    }
}

fn duration(out: &mut Vec<u8>, value: Option<u64>) -> Result<(), RamControlError> {
    match value {
        None => out.push(0),
        Some(value) if value > 0 && value <= i64::MAX as u64 / 1_000_000 => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
        _ => return Err(RamControlError::InvalidFrame),
    }
    Ok(())
}

fn encode_inventory(
    out: &mut Vec<u8>,
    report: Option<RamControlInventoryReport>,
    region: Option<RamControlInventoryRegion>,
) -> Result<(), RamControlError> {
    let Some(report) = report else {
        if region.is_some() {
            return Err(RamControlError::InvalidFrame);
        }
        out.push(0);
        return Ok(());
    };
    if report.topology_generation == 0
        || report.logical_bytes == 0
        || report.region_count == 0
        || report.region_count > 4096
        || report.native_metadata_bytes == 0
        || report.native_scratch_bytes == 0
    {
        return Err(RamControlError::InvalidFrame);
    }
    out.push(if region.is_some() { 2 } else { 1 });
    for value in [
        report.topology_generation,
        report.logical_bytes,
        report.native_metadata_bytes,
        report.native_scratch_bytes,
    ] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&report.region_count.to_be_bytes());
    out.push(u8::from(report.granted));
    if let Some(region) = region {
        region.identity()?;
        if region.ordinal >= report.region_count || region.logical_length > report.logical_bytes {
            return Err(RamControlError::InvalidFrame);
        }
        out.extend_from_slice(&region.ordinal.to_be_bytes());
        out.extend_from_slice(&region.logical_length.to_be_bytes());
        out.push(region.class);
        out.push(region.identity_length);
        out.extend_from_slice(&region.identity);
    }
    Ok(())
}

fn decode_inventory(
    input: &mut Decoder<'_>,
) -> Result<
    (
        Option<RamControlInventoryReport>,
        Option<RamControlInventoryRegion>,
    ),
    RamControlError,
> {
    let tag = input.byte()?;
    if tag == 0 {
        return Ok((None, None));
    }
    if tag != 1 && tag != 2 {
        return Err(RamControlError::InvalidFrame);
    }
    let report = RamControlInventoryReport {
        topology_generation: input.u64()?,
        logical_bytes: input.u64()?,
        native_metadata_bytes: input.u64()?,
        native_scratch_bytes: input.u64()?,
        region_count: input.u32()?,
        granted: input.boolean()?,
    };
    let region = if tag == 2 {
        Some(RamControlInventoryRegion {
            ordinal: input.u32()?,
            logical_length: input.u64()?,
            class: input.byte()?,
            identity_length: input.byte()?,
            identity: input.take()?,
        })
    } else {
        None
    };
    Ok((Some(report), region))
}

fn encode_budgets(
    out: &mut Vec<u8>,
    budgets: &[RamControlBudget; RAM_CONTROL_BUDGET_COUNT],
) -> Result<(), RamControlError> {
    for budget in budgets {
        if budget.poll_ms == 0 || budget.poll_ms > i64::MAX as u64 / 1_000_000 {
            return Err(RamControlError::InvalidFrame);
        }
        out.extend_from_slice(&budget.poll_ms.to_be_bytes());
        duration(out, budget.progress_ms)?;
        duration(out, budget.total_ms)?;
    }
    Ok(())
}

fn decode_budgets(
    input: &mut Decoder<'_>,
) -> Result<[RamControlBudget; RAM_CONTROL_BUDGET_COUNT], RamControlError> {
    let mut budgets = [RamControlBudget {
        poll_ms: 1,
        progress_ms: None,
        total_ms: None,
    }; RAM_CONTROL_BUDGET_COUNT];
    for budget in &mut budgets {
        budget.poll_ms = input.u64()?;
        if budget.poll_ms == 0 || budget.poll_ms > i64::MAX as u64 / 1_000_000 {
            return Err(RamControlError::InvalidFrame);
        }
        budget.progress_ms = input.duration()?;
        budget.total_ms = input.duration()?;
    }
    Ok(budgets)
}

/// Encodes the versioned initial live budget roster for authenticated launch.
///
/// The schema is a big-endian u32 followed by the fourteen canonical budget
/// records also used by Apply; no placement policy is accepted by this projection.
///
/// # Errors
/// Refuses zero/overflowing durations or invalid optional allowance encodings.
pub fn encode_ram_control_budgets(
    budgets: &[RamControlBudget; RAM_CONTROL_BUDGET_COUNT],
) -> Result<Vec<u8>, RamControlError> {
    let mut out = Vec::with_capacity(RAM_CONTROL_BUDGET_ROSTER_MAX_BYTES);
    out.extend_from_slice(&RAM_CONTROL_VERSION.to_be_bytes());
    encode_budgets(&mut out, budgets)?;
    Ok(out)
}

/// Decodes a bounded canonical initial budget roster without proportional allocation.
///
/// # Errors
/// Refuses oversized/truncated input, unsupported schema, invalid budgets, or
/// trailing bytes. Placement acceptance remains a separate live Apply operation.
pub fn decode_ram_control_budgets(
    bytes: &[u8],
) -> Result<[RamControlBudget; RAM_CONTROL_BUDGET_COUNT], RamControlError> {
    if bytes.len() > RAM_CONTROL_BUDGET_ROSTER_MAX_BYTES {
        return Err(RamControlError::TooLarge);
    }
    let mut input = Decoder { bytes, offset: 0 };
    let version = input.u32()?;
    if version != RAM_CONTROL_VERSION {
        return Err(RamControlError::UnsupportedVersion(version));
    }
    let budgets = decode_budgets(&mut input)?;
    if input.offset != bytes.len() {
        return Err(RamControlError::InvalidFrame);
    }
    Ok(budgets)
}

fn encode_policy(out: &mut Vec<u8>, policy: RamControlPolicy) -> Result<(), RamControlError> {
    if policy.eviction_preference > 100
        || policy.writeback_bytes_per_second == 0
        || policy.maximum_paging_io_in_flight == 0
    {
        return Err(RamControlError::InvalidFrame);
    }
    out.push(policy.mode as u8);
    out.extend_from_slice(&policy.resident_target_bytes.to_be_bytes());
    out.push(policy.eviction_preference);
    out.extend_from_slice(&policy.writeback_bytes_per_second.to_be_bytes());
    out.extend_from_slice(&policy.maximum_paging_io_in_flight.to_be_bytes());
    out.push(u8::from(policy.prefetch_on_increase));
    encode_budgets(out, &policy.budgets)
}

fn decode_policy(input: &mut Decoder<'_>) -> Result<RamControlPolicy, RamControlError> {
    let mode = match input.byte()? {
        0 => RamControlMode::Managed,
        1 => RamControlMode::DiskOriented,
        2 => RamControlMode::ResidentRequired,
        _ => return Err(RamControlError::InvalidFrame),
    };
    let resident_target_bytes = input.u64()?;
    let eviction_preference = input.byte()?;
    let writeback_bytes_per_second = input.u64()?;
    let maximum_paging_io_in_flight = input.u32()?;
    let prefetch_on_increase = input.boolean()?;
    if eviction_preference > 100
        || writeback_bytes_per_second == 0
        || maximum_paging_io_in_flight == 0
    {
        return Err(RamControlError::InvalidFrame);
    }
    let budgets = decode_budgets(input)?;
    Ok(RamControlPolicy {
        mode,
        resident_target_bytes,
        eviction_preference,
        writeback_bytes_per_second,
        maximum_paging_io_in_flight,
        prefetch_on_increase,
        budgets,
    })
}

/// Encodes a canonical message body, excluding the four-byte stream length.
///
/// # Errors
/// Rejects zero authority/session/sequence fields, invalid policy bounds,
/// exhausted or non-advancing application revisions, and oversized bodies.
pub fn encode_ram_control(frame: &RamControlFrame) -> Result<Vec<u8>, RamControlError> {
    if frame.session == [0; 32]
        || frame.sequence == 0
        || frame.target.owner_generation == 0
        || frame.target.arena_generation == 0
        || frame.target.daemon_epoch == [0; 32]
        || frame.target.owner_id == [0; 32]
        || frame.target.node_id == [0; 32]
    {
        return Err(RamControlError::InvalidFrame);
    }
    let tag = match frame.message {
        RamControlMessage::Request(RamControlRequest::Hello) => 0,
        RamControlMessage::Request(RamControlRequest::Apply { .. }) => 1,
        RamControlMessage::Request(RamControlRequest::Status) => 2,
        RamControlMessage::Request(RamControlRequest::Cancel { .. }) => 3,
        RamControlMessage::Request(RamControlRequest::InventoryRegion { .. }) => 4,
        RamControlMessage::Request(RamControlRequest::GrantInventory { .. }) => 5,
        RamControlMessage::Reply { .. } => 128,
    };
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(&RAM_CONTROL_VERSION.to_be_bytes());
    out.push(tag);
    out.extend_from_slice(&frame.session);
    out.extend_from_slice(&frame.sequence.to_be_bytes());
    out.extend_from_slice(&frame.target.daemon_epoch);
    out.extend_from_slice(&frame.target.owner_id);
    out.extend_from_slice(&frame.target.node_id);
    out.extend_from_slice(&frame.target.owner_generation.to_be_bytes());
    out.extend_from_slice(&frame.target.arena_generation.to_be_bytes());
    out.push(u8::from(frame.target.retained_template));
    match frame.message {
        RamControlMessage::Request(RamControlRequest::Apply {
            expected_revision,
            policy_revision,
            reservation_revision,
            policy,
        }) => {
            if expected_revision.checked_add(1) != Some(policy_revision) {
                return Err(RamControlError::InvalidFrame);
            }
            for value in [expected_revision, policy_revision, reservation_revision] {
                out.extend_from_slice(&value.to_be_bytes());
            }
            encode_policy(&mut out, policy)?;
        }
        RamControlMessage::Request(RamControlRequest::Cancel {
            operation_generation,
        }) => {
            if operation_generation == 0 {
                return Err(RamControlError::InvalidFrame);
            }
            out.extend_from_slice(&operation_generation.to_be_bytes());
        }
        RamControlMessage::Request(RamControlRequest::InventoryRegion {
            topology_generation,
            ordinal,
        }) => {
            if topology_generation == 0 || ordinal >= 4096 {
                return Err(RamControlError::InvalidFrame);
            }
            out.extend_from_slice(&topology_generation.to_be_bytes());
            out.extend_from_slice(&ordinal.to_be_bytes());
        }
        RamControlMessage::Request(RamControlRequest::GrantInventory {
            topology_generation,
            resources,
        }) => {
            if topology_generation == 0 {
                return Err(RamControlError::InvalidFrame);
            }
            out.extend_from_slice(&topology_generation.to_be_bytes());
            for value in resources.components() {
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        RamControlMessage::Reply {
            request_digest,
            state,
        } => {
            if state.applied_policy_revision > state.requested_policy_revision {
                return Err(RamControlError::InvalidFrame);
            }
            if state.limitation_reasons & !RAM_LIMIT_KNOWN_MASK != 0
                || (!state.measurements_available
                    && [
                        state.private_resident_bytes,
                        state.shared_resident_bytes_observed,
                        state.preserved_backing_bytes,
                        state.private_dirty_bytes,
                        state.writeback_pending_bytes,
                    ]
                    .into_iter()
                    .any(|value| value != 0))
            {
                return Err(RamControlError::InvalidFrame);
            }
            out.extend_from_slice(&request_digest);
            out.push(state.disposition as u8);
            out.extend_from_slice(&state.limitation_reasons.to_be_bytes());
            out.push(u8::from(state.measurements_available));
            for value in [
                state.logical_ram_bytes,
                state.requested_policy_revision,
                state.applied_policy_revision,
                state.reservation_revision,
                state.observation_sequence,
                state.effective_resident_target_bytes,
                state.effective_floor_bytes,
                state.private_resident_bytes,
                state.shared_resident_bytes_observed,
                state.preserved_backing_bytes,
                state.private_dirty_bytes,
                state.writeback_pending_bytes,
            ] {
                out.extend_from_slice(&value.to_be_bytes());
            }
            out.push(state.convergence as u8);
            encode_inventory(&mut out, state.inventory, state.inventory_region)?;
        }
        _ => {}
    }
    if out.len() > RAM_CONTROL_MAX_BYTES {
        return Err(RamControlError::TooLarge);
    }
    Ok(out)
}

/// Decodes one complete bounded body and rejects trailing or noncanonical bytes.
///
/// # Errors
/// Returns errors for unsupported schema, unknown tags, incomplete fields,
/// invalid bounds/authority, excessive size, and any trailing bytes.
pub fn decode_ram_control(bytes: &[u8]) -> Result<RamControlFrame, RamControlError> {
    if bytes.len() > RAM_CONTROL_MAX_BYTES {
        return Err(RamControlError::TooLarge);
    }
    let mut input = Decoder { bytes, offset: 0 };
    let version = input.u32()?;
    if version != RAM_CONTROL_VERSION {
        return Err(RamControlError::UnsupportedVersion(version));
    }
    let tag = input.byte()?;
    let session = input.take()?;
    let sequence = input.u64()?;
    let target = RamControlTarget {
        daemon_epoch: input.take()?,
        owner_id: input.take()?,
        node_id: input.take()?,
        owner_generation: input.u64()?,
        arena_generation: input.u64()?,
        retained_template: input.boolean()?,
    };
    let message = match tag {
        0 => RamControlMessage::Request(RamControlRequest::Hello),
        1 => RamControlMessage::Request(RamControlRequest::Apply {
            expected_revision: input.u64()?,
            policy_revision: input.u64()?,
            reservation_revision: input.u64()?,
            policy: decode_policy(&mut input)?,
        }),
        2 => RamControlMessage::Request(RamControlRequest::Status),
        3 => RamControlMessage::Request(RamControlRequest::Cancel {
            operation_generation: input.u64()?,
        }),
        4 => RamControlMessage::Request(RamControlRequest::InventoryRegion {
            topology_generation: input.u64()?,
            ordinal: input.u32()?,
        }),
        5 => {
            let topology_generation = input.u64()?;
            let mut values = [0; 8];
            for value in &mut values {
                *value = input.u64()?;
            }
            RamControlMessage::Request(RamControlRequest::GrantInventory {
                topology_generation,
                resources: RamControlResources::from_components(values),
            })
        }
        128 => {
            let request_digest = input.take()?;
            let disposition = match input.byte()? {
                0 => RamControlDisposition::Accepted,
                1 => RamControlDisposition::RevisionConflict,
                2 => RamControlDisposition::NotCurrent,
                3 => RamControlDisposition::Unsupported,
                4 => RamControlDisposition::AdmissionRefused,
                5 => RamControlDisposition::Unavailable,
                6 => RamControlDisposition::Canceled,
                _ => return Err(RamControlError::InvalidFrame),
            };
            let limitation_reasons = input.u32()?;
            let measurements_available = input.boolean()?;
            let mut state = RamControlReply {
                inventory: None,
                inventory_region: None,
                logical_ram_bytes: input.u64()?,
                disposition,
                limitation_reasons,
                measurements_available,
                requested_policy_revision: input.u64()?,
                applied_policy_revision: input.u64()?,
                reservation_revision: input.u64()?,
                observation_sequence: input.u64()?,
                effective_resident_target_bytes: input.u64()?,
                effective_floor_bytes: input.u64()?,
                private_resident_bytes: input.u64()?,
                shared_resident_bytes_observed: input.u64()?,
                preserved_backing_bytes: input.u64()?,
                private_dirty_bytes: input.u64()?,
                writeback_pending_bytes: input.u64()?,
                convergence: RamControlConvergence::Stable,
            };
            state.convergence = match input.byte()? {
                0 => RamControlConvergence::Stable,
                1 => RamControlConvergence::Applying,
                2 => RamControlConvergence::Evicting,
                3 => RamControlConvergence::Prefetching,
                4 => RamControlConvergence::Blocked,
                5 => RamControlConvergence::Failed,
                6 => RamControlConvergence::Quarantined,
                _ => return Err(RamControlError::InvalidFrame),
            };
            (state.inventory, state.inventory_region) = decode_inventory(&mut input)?;
            RamControlMessage::Reply {
                request_digest,
                state,
            }
        }
        _ => return Err(RamControlError::InvalidFrame),
    };
    if input.offset != bytes.len() {
        return Err(RamControlError::InvalidFrame);
    }
    let frame = RamControlFrame {
        session,
        sequence,
        target,
        message,
    };
    // One encoder owns all cross-field invariants. The decoder never allocates
    // according to a wire length and requires byte-for-byte canonical identity.
    if encode_ram_control(&frame)?.as_slice() != bytes {
        return Err(RamControlError::InvalidFrame);
    }
    Ok(frame)
}

/// Computes the domain-separated digest bound into the corresponding reply.
///
/// # Errors
/// Rejects responses and any request that cannot be canonically encoded.
pub fn ram_control_request_digest(frame: &RamControlFrame) -> Result<[u8; 32], RamControlError> {
    if !matches!(frame.message, RamControlMessage::Request(_)) {
        return Err(RamControlError::InvalidFrame);
    }
    let bytes = encode_ram_control(frame)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.ram.control.request.v1\0");
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// Reads a bounded message, returning `None` only for clean EOF before a header.
///
/// # Errors
/// Rejects oversized lengths before reading a body, incomplete headers/bodies,
/// malformed codec input, and underlying transport failures.
pub fn read_ram_control(
    reader: &mut impl Read,
) -> Result<Option<RamControlFrame>, RamControlError> {
    let mut length = [0; 4];
    loop {
        match reader.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    reader.read_exact(&mut length[1..])?;
    let size = u32::from_be_bytes(length) as usize;
    if size > RAM_CONTROL_MAX_BYTES {
        return Err(RamControlError::TooLarge);
    }
    let mut body = [0; RAM_CONTROL_MAX_BYTES];
    reader.read_exact(&mut body[..size])?;
    decode_ram_control(&body[..size]).map(Some)
}

/// Writes a complete canonical frame with its bounded big-endian length.
///
/// # Errors
/// Returns validation failures or an underlying stream write/flush failure.
pub fn write_ram_control(
    writer: &mut impl Write,
    frame: &RamControlFrame,
) -> Result<(), RamControlError> {
    let body = encode_ram_control(frame)?;
    let length = u32::try_from(body.len()).map_err(|_| RamControlError::TooLarge)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}
