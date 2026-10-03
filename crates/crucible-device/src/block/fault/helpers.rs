//! Private directive accounting, transport responses, and exact payload geometry.

use super::*;

pub(super) fn transport_pending_response(
    identity: BlockRequestIdentity,
    policy: BlockTransportPending,
    failure: BlockErrorCode,
) -> Result<Response, DeviceError> {
    let response = match policy {
        BlockTransportPending::Fail => BlockResponse::error_for(identity, failure),
        BlockTransportPending::RetryPreserveId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryPreserveId)
        }
        BlockTransportPending::RetryNewId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryNewId)
        }
    };
    block_response_to_uniform(&response)
}

pub(super) fn transport_resolved_response(
    identity: BlockRequestIdentity,
    policy: BlockTransportResolved,
    failure: BlockErrorCode,
) -> Result<Response, DeviceError> {
    let response = match policy {
        BlockTransportResolved::Complete => {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "completed reset policy cannot replace a resolved request",
            });
        }
        BlockTransportResolved::Fail => BlockResponse::error_for(identity, failure),
        BlockTransportResolved::RetryPreserveId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryPreserveId)
        }
        BlockTransportResolved::RetryNewId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryNewId)
        }
    };
    block_response_to_uniform(&response)
}

pub(super) fn transport_undelivered_response(
    identity: BlockRequestIdentity,
    policy: BlockTransportUndelivered,
    failure: BlockErrorCode,
) -> Result<Response, DeviceError> {
    let response = match policy {
        BlockTransportUndelivered::Complete => {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "completed reset policy cannot replace an undelivered request",
            });
        }
        BlockTransportUndelivered::Fail => BlockResponse::error_for(identity, failure),
        BlockTransportUndelivered::RetryPreserveId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryPreserveId)
        }
        BlockTransportUndelivered::RetryNewId => {
            BlockResponse::reset_disposition(identity, BlockStatus::RetryNewId)
        }
        BlockTransportUndelivered::DropCompletion => {
            BlockResponse::reset_disposition(identity, BlockStatus::DropCompletion)
        }
    };
    block_response_to_uniform(&response)
}

pub(super) const fn transport_pending(policy: BlockTransitionPending) -> BlockTransportPending {
    match policy {
        BlockTransitionPending::Fail => BlockTransportPending::Fail,
        BlockTransitionPending::RetryPreserveId => BlockTransportPending::RetryPreserveId,
        BlockTransitionPending::RetryNewId => BlockTransportPending::RetryNewId,
    }
}

pub(in crate::block) fn request_in_capacity(request: &BlockRequest, capacity: u64) -> bool {
    match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => request
            .offset
            .checked_add(u64::from(request.count))
            .is_some_and(|end| end <= capacity),
        BlockOp::Flush | BlockOp::GetLength => true,
    }
}

pub(super) fn block_admission_error(
    request: &BlockRequest,
    directive: &ResolvedBlockFaultDirective,
    config: &BlockDurabilityConfig,
) -> Option<BlockErrorCode> {
    (directive.availability == BlockFaultAvailability::Offline)
        .then_some(BlockErrorCode::Offline)
        .or_else(|| {
            (directive.availability == BlockFaultAvailability::ReadOnly
                && matches!(request.op, BlockOp::Write | BlockOp::Discard))
            .then_some(BlockErrorCode::ReadOnly)
        })
        .or_else(|| {
            (!request_in_capacity(request, directive.reported_capacity_bytes)
                || u64::from(request.count) > config.maximum_request_bytes
                || (request.op == BlockOp::Read
                    && usize::try_from(request.count).unwrap_or(usize::MAX)
                        > crate::block::device::MAX_READ_BYTES))
                .then_some(BlockErrorCode::InvalidRange)
        })
}

pub(super) fn validate_state_range(
    offset: u64,
    length: usize,
    device_length: u64,
) -> Result<(), DeviceError> {
    let length =
        u64::try_from(length).map_err(|_error| DeviceError::InvalidBlockFaultDirective {
            reason: "restored block state range length overflow",
        })?;
    if offset
        .checked_add(length)
        .is_some_and(|end| end <= device_length)
    {
        Ok(())
    } else {
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored block state range exceeds the device",
        })
    }
}

pub(super) fn validate_media_entry(
    identity: BlockMediaOperationIdentity,
    fragment_sequence: u64,
    offset: u64,
    length: usize,
    device_length: u64,
) -> Result<(), DeviceError> {
    if !matches!(identity.operation, BlockOp::Write | BlockOp::Discard) {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored media entry has an invalid physical operation",
        });
    }
    let request_end = identity
        .request_offset
        .checked_add(u64::from(identity.request_count));
    let fragment_end = offset.checked_add(u64::try_from(length).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "restored media entry length overflow",
        }
    })?);
    if identity.request_count == 0
        || identity.operation_sequence > fragment_sequence
        || request_end.is_none_or(|end| end > device_length)
        || fragment_end
            .is_none_or(|end| offset < identity.request_offset || end > request_end.unwrap_or(0))
    {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored media entry differs from its original request",
        });
    }
    Ok(())
}

pub(super) fn entry_contributes_visible(
    sequence: u64,
    overlap_start: u64,
    overlap_end: u64,
    visible: &BTreeMap<u64, (u64, Vec<u8>)>,
) -> bool {
    let mut uncovered = vec![(overlap_start, overlap_end)];
    for (_newer_sequence, (offset, bytes)) in visible.range((sequence + 1)..) {
        let newer_end = offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let mut next = Vec::new();
        for (start, end) in uncovered {
            if newer_end <= start || *offset >= end {
                next.push((start, end));
                continue;
            }
            if start < *offset {
                next.push((start, (*offset).min(end)));
            }
            if newer_end < end {
                next.push((newer_end.max(start), end));
            }
        }
        uncovered = next;
        if uncovered.is_empty() {
            return false;
        }
    }
    true
}

pub(super) fn directive_owned_bytes(
    directive: &ResolvedBlockFaultDirective,
) -> Result<u64, DeviceError> {
    let mut total = 0_u64;
    for transform in &directive.read_transforms {
        let bytes = match transform {
            BlockFaultReadTransform::Xor { mask, .. } => mask.len(),
            BlockFaultReadTransform::Replace { bytes } => bytes.len(),
        };
        total = total
            .checked_add(u64::try_from(bytes).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "pending read transform length overflow",
                }
            })?)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "pending directive byte count overflow",
            })?;
    }
    for duplicate in &directive.duplicate_completions {
        if let ResolvedBlockDuplicateCompletion::ProtocolError { response, .. } = duplicate {
            total = total
                .checked_add(u64::try_from(response.data.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "pending duplicate response length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte count overflow",
                })?;
        }
    }
    for rule in &directive.media_rules {
        total = total
            .checked_add(
                u64::try_from(
                    rule.operations
                        .len()
                        .saturating_mul(std::mem::size_of::<BlockOp>()),
                )
                .map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                    reason: "pending media operation-set length overflow",
                })?,
            )
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "pending directive byte count overflow",
            })?;
    }
    for rule in &directive.service_rules {
        for class in &rule.classes {
            total = total
                .checked_add(u64::try_from(class.operations.len()).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "pending service operation-set length overflow",
                    }
                })?)
                .ok_or(DeviceError::InvalidBlockFaultDirective {
                    reason: "pending directive byte count overflow",
                })?;
        }
    }
    total = total
        .checked_add(
            u64::try_from(
                directive
                    .persistence_media_rules
                    .len()
                    .saturating_mul(std::mem::size_of::<ResolvedBlockFlashRule>()),
            )
            .map_err(|_error| DeviceError::InvalidBlockFaultDirective {
                reason: "pending flash rule byte count overflow",
            })?,
        )
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "pending directive byte count overflow",
        })?;
    if let Some(response) = &directive.retention_timeout_response {
        total = total
            .checked_add(u64::try_from(response.data.len()).map_err(|_error| {
                DeviceError::InvalidBlockFaultDirective {
                    reason: "pending timeout response length overflow",
                }
            })?)
            .ok_or(DeviceError::InvalidBlockFaultDirective {
                reason: "pending directive byte count overflow",
            })?;
    }
    Ok(total)
}

pub(super) fn service_pending_owned_bytes(
    pending: &BlockServicePendingRequest,
) -> Result<u64, DeviceError> {
    u64::try_from(pending.request.data.len())
        .map_err(|_error| DeviceError::InvalidBlockFaultDirective {
            reason: "queued service request length overflow",
        })?
        .checked_add(directive_owned_bytes(&pending.directive)?)
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "queued service request byte count overflow",
        })
}

pub(super) fn execution_pending_owned_bytes(
    pending: &BlockExecutionPendingRequest,
) -> Result<u64, DeviceError> {
    let request = u64::try_from(pending.opportunity.request.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "execution-pending request length overflow",
        }
    })?;
    let admission = directive_owned_bytes(&pending.opportunity.admission)?;
    let execution = pending
        .execution
        .as_ref()
        .map(directive_owned_bytes)
        .transpose()?
        .unwrap_or(0);
    request
        .checked_add(admission)
        .and_then(|bytes| bytes.checked_add(execution))
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "execution-pending request byte count overflow",
        })
}

pub(super) fn request_persistence_pending_owned_bytes(
    pending: &BlockRequestPersistencePending,
) -> Result<u64, DeviceError> {
    let request = u64::try_from(pending.opportunity.request.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "request-persistence payload length overflow",
        }
    })?;
    let resolved = directive_owned_bytes(&pending.opportunity.resolved)?;
    let persistence = pending
        .persistence
        .as_ref()
        .map(directive_owned_bytes)
        .transpose()?
        .unwrap_or(0);
    request
        .checked_add(resolved)
        .and_then(|bytes| bytes.checked_add(persistence))
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "request-persistence byte count overflow",
        })
}

pub(super) fn delivery_pending_owned_bytes(
    pending: &BlockDeliveryPending,
) -> Result<u64, DeviceError> {
    let request = u64::try_from(pending.opportunity.request.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "delivery-pending request length overflow",
        }
    })?;
    let response = u64::try_from(pending.opportunity.response.data.len()).map_err(|_error| {
        DeviceError::InvalidBlockFaultDirective {
            reason: "delivery-pending response length overflow",
        }
    })?;
    let resolved = directive_owned_bytes(&pending.opportunity.resolved)?;
    let delivery = pending
        .delivery
        .as_ref()
        .map(directive_owned_bytes)
        .transpose()?
        .unwrap_or(0);
    request
        .checked_add(response)
        .and_then(|bytes| bytes.checked_add(resolved))
        .and_then(|bytes| bytes.checked_add(delivery))
        .ok_or(DeviceError::InvalidBlockFaultDirective {
            reason: "delivery-pending byte count overflow",
        })
}

pub(super) fn block_response_fits_transport(response: &BlockResponse) -> bool {
    response
        .encode()
        .is_ok_and(|encoded| encoded.len() <= crucible_shmem::MAX_FRAME_DATA)
}

pub(super) fn validate_write_disposition(
    disposition: &BlockFaultWriteDisposition,
    request_offset: u64,
    request_length: u64,
    atomic_write_bytes: u64,
    allow_subatomic: bool,
) -> Result<(), DeviceError> {
    if let BlockFaultWriteDisposition::Misdirected {
        destination_offset, ..
    } = disposition
        && !allow_subatomic
        && destination_offset % atomic_write_bytes != request_offset % atomic_write_bytes
    {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "misdirected write changes atomic-fragment alignment",
        });
    }
    let spans = match disposition {
        BlockFaultWriteDisposition::Torn { spans }
        | BlockFaultWriteDisposition::ProgramFailure { spans } => spans,
        BlockFaultWriteDisposition::Apply
        | BlockFaultWriteDisposition::Lost
        | BlockFaultWriteDisposition::Misdirected { .. } => return Ok(()),
    };
    if spans.len() > HARD_BLOCK_WRITE_SPANS || spans.is_empty() {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "invalid resolved write span count",
        });
    }
    let mut prior_end = 0;
    let boundaries =
        canonical_atomic_boundaries(request_offset, request_length, atomic_write_bytes)?;
    for span in spans {
        let Some(end) = span.end() else {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "resolved write span overflow",
            });
        };
        if span.length == 0 || span.start < prior_end || end > request_length {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "resolved write spans overlap or exceed request",
            });
        }
        if !allow_subatomic
            && (boundaries.binary_search(&span.start).is_err()
                || boundaries.binary_search(&end).is_err())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "resolved write span splits an atomic-write fragment",
            });
        }
        prior_end = end;
    }
    Ok(())
}

pub(super) fn canonical_atomic_boundaries(
    request_offset: u64,
    request_length: u64,
    atomic_write_bytes: u64,
) -> Result<Vec<u64>, DeviceError> {
    if atomic_write_bytes == 0 {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "atomic-write size is zero",
        });
    }
    let mut boundaries = vec![0];
    let request_end = request_offset.checked_add(request_length).ok_or(
        DeviceError::InvalidBlockFaultDirective {
            reason: "request range overflow while splitting atomic writes",
        },
    )?;
    let mut absolute = request_offset;
    while absolute < request_end {
        let remainder = absolute % atomic_write_bytes;
        let step = if remainder == 0 {
            atomic_write_bytes
        } else {
            atomic_write_bytes - remainder
        };
        absolute = absolute.saturating_add(step).min(request_end);
        boundaries.push(absolute - request_offset);
    }
    Ok(boundaries)
}

pub(super) fn canonical_atomic_spans(
    request_offset: u64,
    request_length: u64,
    atomic_write_bytes: u64,
) -> Result<Vec<BlockFaultByteSpan>, DeviceError> {
    let boundaries =
        canonical_atomic_boundaries(request_offset, request_length, atomic_write_bytes)?;
    Ok(boundaries
        .windows(2)
        .map(|pair| BlockFaultByteSpan {
            start: pair[0],
            length: pair[1] - pair[0],
        })
        .collect())
}

pub(super) fn apply_read_transforms(
    bytes: &mut Vec<u8>,
    transforms: &[BlockFaultReadTransform],
) -> Result<(), DeviceError> {
    for transform in transforms {
        match transform {
            BlockFaultReadTransform::Xor { offset, mask } => {
                let start = usize::try_from(*offset).map_err(|_error| {
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "read transform offset does not fit memory",
                    }
                })?;
                let end = start.checked_add(mask.len()).ok_or(
                    DeviceError::InvalidBlockFaultDirective {
                        reason: "read transform range overflow",
                    },
                )?;
                let selected =
                    bytes
                        .get_mut(start..end)
                        .ok_or(DeviceError::InvalidBlockFaultDirective {
                            reason: "read transform exceeds response",
                        })?;
                if mask.is_empty() {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "read transform mask is empty",
                    });
                }
                for (byte, mask) in selected.iter_mut().zip(mask) {
                    *byte ^= *mask;
                }
            }
            BlockFaultReadTransform::Replace { bytes: replacement } => {
                if replacement.len() != bytes.len() {
                    return Err(DeviceError::InvalidBlockFaultDirective {
                        reason: "replacement read length differs",
                    });
                }
                bytes.clone_from(replacement);
            }
        }
    }
    Ok(())
}

pub(super) fn request_digest(request: &BlockRequest) -> [u8; 32] {
    match request.encode() {
        Ok(bytes) => *blake3::hash(&bytes).as_bytes(),
        Err(_) => [0; 32],
    }
}

pub(in crate::block) fn keyed_discard_bytes(
    base_hash: [u8; 32],
    request: &BlockRequest,
    count: usize,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count);
    let mut block = 0_u64;
    while bytes.len() < count {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-discard-undefined.v1\0");
        hasher.update(&base_hash);
        hasher.update(&request.request_id.to_be_bytes());
        hasher.update(&request.offset.to_be_bytes());
        hasher.update(&request.count.to_be_bytes());
        hasher.update(&block.to_be_bytes());
        let digest = hasher.finalize();
        let remaining = count - bytes.len();
        bytes.extend_from_slice(&digest.as_bytes()[..remaining.min(digest.as_bytes().len())]);
        block = block.saturating_add(1);
    }
    bytes
}

pub(super) fn block_response_to_uniform(response: &BlockResponse) -> Result<Response, DeviceError> {
    if !block_response_fits_transport(response) {
        return Err(DeviceError::InvalidBlockFaultDirective {
            reason: "block response exceeds the block transport frame",
        });
    }
    let status = if response.status == BlockStatus::Ok {
        ResponseStatus::Ok
    } else {
        ResponseStatus::Error
    };
    Ok(Response::new(
        response.request_id,
        status,
        response.encode().map_err(DeviceError::Codec)?,
    ))
}
