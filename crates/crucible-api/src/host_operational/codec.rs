//! Bounded language-neutral operational request and response codec.
//!
//! The schema is independent of Rust layouts and serde. Every integer is big
//! endian, every enum and optional discriminator is one byte, and durations are
//! exact unsigned milliseconds. Decoding rejects unknown tags and trailing data
//! before any executor controller is invoked.

use super::*;
mod records;
use records::{Reader, Writer};

const SCHEMA: u32 = 2;
type Result<T> = std::result::Result<T, HostOperationalError>;

fn invalid(message: &str) -> HostOperationalError {
    HostOperationalError::InvalidMessage {
        message: message.into(),
    }
}

/// Encodes one request with checked field values and aggregate size.
///
/// # Errors
///
/// Returns an error for zero generations, invalid policy fields, inexact or
/// overflowing durations, a message exceeding the canonical size limit, or
/// missing or exhausted original allocation authority. The returned buffer
/// retains its original credit through its final owner.
pub fn encode_request(request: &HostOperationalRequest) -> Result<crate::AdmittedOutput<Vec<u8>>> {
    crate::AdmittedOutput::try_build(
        || {
            admit_bytes(HOST_OPERATIONAL_MAX_BYTES as u64)?;
            encode_request_with_writer(request, Writer::bounded()?)
        },
        |source| HostOperationalError::Admission { source },
    )
}

fn encode_request_with_writer(
    request: &HostOperationalRequest,
    mut writer: Writer,
) -> Result<Vec<u8>> {
    let tag = match request {
        HostOperationalRequest::Capabilities { .. } => 0,
        HostOperationalRequest::Status { .. } => 1,
        HostOperationalRequest::UpdatePolicy { .. } => 2,
        HostOperationalRequest::AmendOuterCap { .. } => 3,
        HostOperationalRequest::ListTargets { .. } => 4,
    };
    writer.u8(tag);
    match request.target() {
        HostOperationalTarget::Owner(target) => {
            writer.bytes(&target.daemon_epoch);
            writer.bytes(&target.owner_id);
        }
        HostOperationalTarget::Ram(target) => writer.target(target)?,
        HostOperationalTarget::OuterCap(target) => writer.outer_cap_target(target)?,
    }
    match request {
        HostOperationalRequest::ListTargets {
            target,
            after,
            limit,
        } => {
            if *limit == 0 || usize::from(*limit) > HOST_OPERATIONAL_MAX_TARGETS {
                return Err(invalid("target discovery limit is outside 1..=32"));
            }
            writer.u8(u8::from(after.is_some()));
            if let Some(after) = after {
                if after.daemon_epoch != target.daemon_epoch || after.owner_id != target.owner_id {
                    return Err(invalid("target discovery cursor names another owner"));
                }
                writer.target(*after)?;
            }
            writer.u8(*limit);
        }
        HostOperationalRequest::Capabilities { .. } | HostOperationalRequest::Status { .. } => {}
        HostOperationalRequest::UpdatePolicy {
            expected_policy_revision,
            idempotency_key,
            policy,
            reservation_amendment,
            ..
        } => {
            writer.u64(*expected_policy_revision);
            writer.bytes(idempotency_key);
            writer.policy(**policy)?;
            writer.u8(u8::from(reservation_amendment.is_some()));
            if let Some(amendment) = reservation_amendment {
                writer.u64(amendment.expected_reservation_revision);
                writer.resources(amendment.requested);
                writer.resources(amendment.transition_peak);
            }
        }
        HostOperationalRequest::AmendOuterCap {
            expected_cap_revision,
            idempotency_key,
            allowance,
            ..
        } => {
            writer.u64(*expected_cap_revision);
            writer.bytes(idempotency_key);
            writer.optional_duration(*allowance, false)?;
        }
    }
    writer.finish()
}

/// Decodes a complete canonical request before operational mutation.
///
/// # Errors
///
/// Returns an error for unsupported schemas, oversized or truncated messages,
/// unknown tags, invalid fields, trailing bytes, or missing or exhausted
/// original allocation authority. Owned decoded fields retain their credits.
pub fn decode_request(bytes: &[u8]) -> Result<crate::AdmittedOutput<HostOperationalRequest>> {
    crate::AdmittedOutput::try_build(
        || {
            read_request(bytes, RequestPolicyStorage::Retained)?
                .ok_or_else(|| invalid("request policy was not retained"))
        },
        |source| HostOperationalError::Admission { source },
    )
}

/// Validates canonical request fields without allocating a decoded policy body.
///
/// # Errors
/// Rejects unsupported schemas, invalid fields, truncation or trailing bytes.
pub fn validate_request(bytes: &[u8]) -> Result<()> {
    read_request(bytes, RequestPolicyStorage::ValidationOnly).map(|_| ())
}

enum RequestPolicyStorage {
    Retained,
    ValidationOnly,
}

fn read_request(
    bytes: &[u8],
    policy_storage: RequestPolicyStorage,
) -> Result<Option<HostOperationalRequest>> {
    let mut reader = Reader::new(bytes)?;
    let tag = reader.u8()?;
    let request = match tag {
        0 => Some(HostOperationalRequest::Capabilities {
            target: reader.target()?,
        }),
        1 => Some(HostOperationalRequest::Status {
            target: reader.target()?,
        }),
        2 => {
            let target = reader.target()?;
            let expected_policy_revision = reader.u64()?;
            let idempotency_key = reader.fixed()?;
            let policy = reader.policy()?;
            let reservation_amendment = if reader.boolean()? {
                Some(HostReservationAmendment {
                    expected_reservation_revision: reader.u64()?,
                    requested: reader.resources()?,
                    transition_peak: reader.resources()?,
                })
            } else {
                None
            };
            match policy_storage {
                RequestPolicyStorage::Retained => {
                    admit_bytes(std::mem::size_of::<HostRamPolicy>() as u64)?;
                    Some(HostOperationalRequest::UpdatePolicy {
                        target,
                        expected_policy_revision,
                        idempotency_key,
                        policy: Box::new(policy),
                        reservation_amendment,
                    })
                }
                RequestPolicyStorage::ValidationOnly => None,
            }
        }
        3 => Some(HostOperationalRequest::AmendOuterCap {
            target: reader.outer_cap_target()?,
            expected_cap_revision: reader.u64()?,
            idempotency_key: reader.fixed()?,
            allowance: reader.optional_duration(false)?,
        }),
        4 => Some(HostOperationalRequest::ListTargets {
            target: HostRamOwnerTarget {
                daemon_epoch: reader.fixed()?,
                owner_id: reader.fixed()?,
            },
            after: if reader.boolean()? {
                Some(reader.target()?)
            } else {
                None
            },
            limit: reader.u8()?,
        }),
        _ => return Err(invalid("unknown request tag")),
    };
    reader.finish()?;
    // Every scalar reader accepts one fixed-width representation. The shared
    // validation writer checks cross-field rules without creating another body.
    if let Some(request) = &request {
        encode_request_with_writer(request, Writer::validation())?;
    }
    Ok(request)
}

/// Encodes a bounded coherent operational response.
///
/// # Errors
///
/// Returns an error for invalid targets or policies, unordered operation/cap
/// identities, oversized rosters or reasons, aggregate encoding overflow, or
/// missing or exhausted original allocation authority. The returned wire buffer
/// retains its credits through its final owner.
pub fn encode_response(
    response: &HostOperationalResponse,
) -> Result<crate::AdmittedOutput<Vec<u8>>> {
    crate::AdmittedOutput::try_build(
        || {
            admit_bytes(HOST_OPERATIONAL_MAX_BYTES as u64)?;
            encode_response_bounded(response)
        },
        |source| HostOperationalError::Admission { source },
    )
}

/// Validates canonical response fields and size without allocating a wire buffer.
///
/// # Errors
/// Rejects malformed targets, policies, ordered rosters or aggregate size.
pub fn validate_response(response: &HostOperationalResponse) -> Result<()> {
    encode_response_with_writer(response, Writer::validation()).map(|_| ())
}

/// Encodes a retained response without releasing its original wire-buffer credit.
///
/// # Errors
/// Refuses exhausted original authority or invalid canonical response fields.
pub fn encode_owned_response(
    response: &crate::AdmittedOutput<HostOperationalResponse>,
) -> Result<crate::AdmittedOutput<Vec<u8>>> {
    let _original =
        response
            .enter_original_scope()
            .ok_or_else(|| HostOperationalError::Admission {
                source: crucible::owned_decode::DecodeAdmissionError::new(std::io::Error::other(
                    "operational response has no original custody",
                )),
            })?;
    encode_response(response.value())
}

fn encode_response_bounded(response: &HostOperationalResponse) -> Result<Vec<u8>> {
    encode_response_with_writer(response, Writer::bounded()?)
}

fn encode_response_with_writer(
    response: &HostOperationalResponse,
    mut writer: Writer,
) -> Result<Vec<u8>> {
    match response {
        HostOperationalResponse::Targets {
            target,
            targets,
            next,
        } => {
            if targets.len() > HOST_OPERATIONAL_MAX_TARGETS
                || targets.windows(2).any(|pair| pair[0] >= pair[1])
                || targets.iter().any(|arena| {
                    arena.daemon_epoch != target.daemon_epoch || arena.owner_id != target.owner_id
                })
                || (next.is_some() && next.as_ref() != targets.last())
            {
                return Err(invalid(
                    "target discovery page violates owner/order/cursor bounds",
                ));
            }
            writer.u8(4);
            writer.bytes(&target.daemon_epoch);
            writer.bytes(&target.owner_id);
            writer.u8(targets.len() as u8);
            for arena in targets {
                writer.target(*arena)?;
            }
            writer.u8(u8::from(next.is_some()));
            if let Some(next) = next {
                writer.target(*next)?;
            }
        }
        HostOperationalResponse::Capabilities {
            target,
            capabilities,
            qualification,
        } => {
            if capabilities.maximum_paging_io_slots == 0
                || capabilities.minimum_execution_peak_bytes > capabilities.logical_ram_bytes
                || (!qualification.bounded_execution_peak
                    && capabilities.minimum_execution_peak_bytes != capabilities.logical_ram_bytes)
                || (capabilities.disk_oriented
                    && (!qualification.authenticated_pages
                        || !matches!(
                            qualification.backend,
                            HostRamBackend::PausedPager | HostRamBackend::StrictPager
                        )))
                || (capabilities.resident_required && qualification.evidence.is_none())
            {
                return Err(invalid(
                    "capabilities exceed independently qualified backend behavior",
                ));
            }
            writer.u8(0);
            writer.target(*target)?;
            writer.u64(capabilities.logical_ram_bytes);
            writer.u64(capabilities.compulsory_resident_bytes);
            writer.u64(capabilities.minimum_execution_peak_bytes);
            writer.u64(capabilities.maximum_paging_io_slots);
            writer.u8(u8::from(capabilities.dynamic_residency));
            writer.u8(u8::from(capabilities.disk_oriented));
            writer.u8(u8::from(capabilities.resident_required));
            writer.qualification(*qualification)?;
        }
        HostOperationalResponse::Status(status) => {
            writer.u8(1);
            writer.status(status)?;
        }
        HostOperationalResponse::PolicyUpdate {
            request_digest,
            target,
            disposition,
            policy_revision,
            reservation_revision,
            transition,
            accepted_policy,
        } => {
            let accepted = matches!(
                disposition,
                HostOperationalDisposition::Accepted | HostOperationalDisposition::Replayed
            );
            if accepted != accepted_policy.is_some()
                || (!accepted && transition.is_some())
                || *transition == Some(0)
            {
                return Err(invalid("policy acceptance fields do not bind disposition"));
            }

            writer.u8(2);
            writer.target(*target)?;
            writer.bytes(request_digest);
            writer.u8(*disposition as u8);
            writer.u64(*policy_revision);
            writer.u64(*reservation_revision);
            writer.optional_u64(*transition);
            writer.u8(u8::from(accepted_policy.is_some()));
            if let Some(policy) = accepted_policy {
                writer.policy(**policy)?;
            }
        }
        HostOperationalResponse::OuterCapAmendment {
            request_digest,
            target,
            disposition,
            accepted_cap_revision,
            accepted_allowance,
        } => {
            writer.u8(3);
            writer.outer_cap_target(*target)?;
            writer.bytes(request_digest);
            writer.u8(*disposition as u8);
            if accepted_cap_revision.is_some() != accepted_allowance.is_some()
                || (matches!(
                    disposition,
                    HostOperationalDisposition::Accepted | HostOperationalDisposition::Replayed
                ) != accepted_cap_revision.is_some())
            {
                return Err(invalid(
                    "outer cap acceptance fields do not bind disposition",
                ));
            }
            writer.optional_u64(*accepted_cap_revision);
            writer.u8(u8::from(accepted_allowance.is_some()));
            if let Some(allowance) = accepted_allowance {
                writer.optional_duration(*allowance, false)?;
            }
        }
    }
    writer.finish()
}

/// Decodes one complete bounded response under original metadata authority.
///
/// The returned owner retains every decoded field's allocation credit. Consumers
/// borrow its value while presenting or inspecting the response; moving its
/// parts requires retaining the transferred custody through the fields' drop.
///
/// # Errors
///
/// Returns an error for missing or exhausted original authority, malformed,
/// oversized, noncanonical or trailing data.
pub fn decode_response(bytes: &[u8]) -> Result<crate::AdmittedOutput<HostOperationalResponse>> {
    crate::AdmittedOutput::try_build(
        || decode_response_fields(bytes),
        |source| HostOperationalError::Admission { source },
    )
}

fn decode_response_fields(bytes: &[u8]) -> Result<HostOperationalResponse> {
    let mut reader = Reader::new(bytes)?;
    let response = match reader.u8()? {
        0 => HostOperationalResponse::Capabilities {
            target: reader.target()?,
            capabilities: HostRamCapabilities {
                logical_ram_bytes: reader.u64()?,
                compulsory_resident_bytes: reader.u64()?,
                minimum_execution_peak_bytes: reader.u64()?,
                maximum_paging_io_slots: reader.u64()?,
                dynamic_residency: reader.boolean()?,
                disk_oriented: reader.boolean()?,
                resident_required: reader.boolean()?,
            },
            qualification: reader.qualification()?,
        },
        1 => {
            admit_bytes(std::mem::size_of::<HostRamStatus>() as u64)?;
            HostOperationalResponse::Status(Box::new(reader.status()?))
        }
        2 => HostOperationalResponse::PolicyUpdate {
            target: reader.target()?,
            request_digest: reader.fixed()?,
            disposition: reader.disposition()?,
            policy_revision: reader.u64()?,
            reservation_revision: reader.u64()?,
            transition: reader.optional_u64()?,
            accepted_policy: if reader.boolean()? {
                {
                    admit_bytes(std::mem::size_of::<HostRamPolicy>() as u64)?;
                    Some(Box::new(reader.policy()?))
                }
            } else {
                None
            },
        },
        3 => HostOperationalResponse::OuterCapAmendment {
            target: reader.outer_cap_target()?,
            request_digest: reader.fixed()?,
            disposition: reader.disposition()?,
            accepted_cap_revision: reader.optional_u64()?,
            accepted_allowance: if reader.boolean()? {
                Some(reader.optional_duration(false)?)
            } else {
                None
            },
        },
        4 => {
            let target = HostRamOwnerTarget {
                daemon_epoch: reader.fixed()?,
                owner_id: reader.fixed()?,
            };
            let count = usize::from(reader.u8()?);
            if count > HOST_OPERATIONAL_MAX_TARGETS {
                return Err(invalid("target discovery page exceeds bound"));
            }
            let mut targets = admitted_vec(count)?;
            for _ in 0..count {
                targets.push(reader.target()?);
            }
            let next = if reader.boolean()? {
                Some(reader.target()?)
            } else {
                None
            };
            HostOperationalResponse::Targets {
                target,
                targets,
                next,
            }
        }
        _ => return Err(invalid("unknown response tag")),
    };
    reader.finish()?;
    // Re-encoding independently applies ordered-roster validation to received
    // status before it can be presented as a coherent authenticated observation.
    let budget = crucible::owned_decode::current_budget().ok_or_else(|| {
        HostOperationalError::Admission {
            source: crucible::owned_decode::DecodeAdmissionError::new(std::io::Error::other(
                "missing original operational response budget",
            )),
        }
    })?;
    // The writer is pre-sized to the bounded wire ceiling during this check.
    let _canonical_credit = budget
        .reserve_scratch_bytes(HOST_OPERATIONAL_MAX_BYTES as u64)
        .map_err(|source| HostOperationalError::Admission { source })?;
    if encode_response_bounded(&response)?.as_slice() != bytes {
        return Err(invalid("noncanonical response"));
    }
    Ok(response)
}

fn admit_bytes(bytes: u64) -> Result<()> {
    crucible::owned_decode::charge_bytes(bytes)
        .map_err(|source| HostOperationalError::Admission { source })
}

fn admitted_vec<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    crucible::owned_decode::reserve_vec(&mut values, count)
        .map_err(|source| HostOperationalError::Admission { source })?;
    Ok(values)
}

#[cfg(test)]
mod tests;
