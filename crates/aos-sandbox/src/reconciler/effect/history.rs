//! Canonical Effect history codecs and complete passive record relations.
//!
//! The descendant uses the original parent models and private fields directly;
//! it has no mirrored DATA representation or fresh/current authority factory.
//! Gate canonical decoding remains with its complete operation-ledger owner.
//!
//! ```text
//! Effect V2--V6 = version || domain || state || flags || lengths/method
//!                || optional authority/dispatch || request/receipt/diagnostic
//!                || optional project metadata/Q04 subgate
//! ```

use sha2::{Digest as _, Sha256};

use super::super::operation_ledger::DeleteGateHistoryV1;
// The whole codec shares its fixed private model vocabulary with this parent.
use super::*;

pub(super) fn validate_broker_method_domain(
    domain: EffectDomain,
    method: BrokerMethod,
) -> Result<(), ReconcilerError> {
    let expected = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => EffectDomain::Host,
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => EffectDomain::Storage,
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
        | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
        | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => EffectDomain::Mount,
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => EffectDomain::Network,
        _ => {
            return Err(ReconcilerError::InvalidPlan("unknown broker effect method"));
        }
    };
    if domain != expected {
        return Err(ReconcilerError::InvalidPlan(
            "broker effect method crosses its fixed domain",
        ));
    }

    Ok(())
}

const fn broker_method_from_code(value: i32) -> Option<BrokerMethod> {
    Some(match value {
        1 => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        2 => BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
        3 => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        4 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        6 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
        7 => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
        9 => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
        10 => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY,
        11 => BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
        12 => BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE,
        13 => BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE,
        14 => BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG,
        15 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
        16 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
        17 => BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
        18 => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        19 => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        20 => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
        21 => BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
        22 => BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
        23 => BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
        24 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS,
        _ => return None,
    })
}

pub(in crate::reconciler) fn encode_effect(
    record: &EffectLedgerRecord,
) -> Result<Vec<u8>, ReconcilerError> {
    encode_effect_with_q04(record, None)
}

#[cfg(target_os = "linux")]
pub(in crate::reconciler) fn encode_q04_effect(
    record: &EffectLedgerRecord,
    gate: &crate::policy_compiler::create_q04::Q04EffectSubgateV1,
) -> Result<Vec<u8>, ReconcilerError> {
    require_q04_effect_shape(record)?;
    encode_effect_with_q04(record, Some(gate.bytes()))
}

#[cfg(target_os = "linux")]
fn require_q04_effect_shape(record: &EffectLedgerRecord) -> Result<(), ReconcilerError> {
    if record.plan.domain != EffectDomain::Controller
        || record.plan.controller_method
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
        || record.plan.method.is_some()
        || record.plan.authority.is_some()
        || record.dispatch.is_some()
        || !matches!(record.state, EffectState::Applying { .. })
    {
        return Err(ReconcilerError::CorruptLedger("invalid Q04 policy-subgate Effect"));
    }
    Ok(())
}

fn encode_effect_with_q04(
    record: &EffectLedgerRecord,
    q04_gate: Option<&[u8]>,
) -> Result<Vec<u8>, ReconcilerError> {
    let (state, attempt, receipt, diagnostic) = state_parts(&record.state);
    validate_lengths(&record.plan, receipt, diagnostic)?;
    if let Some(metadata) = &record.project_admission {
        validate_project_metadata_shape(&record.plan, &record.state, metadata)?;
    }
    if record.plan.is_reserved_observe() && !matches!(record.state, EffectState::Planned) {
        return Err(ReconcilerError::InvalidPlan(
            "reserved Observe effect cannot advance",
        ));
    }
    let request_length = u32::try_from(record.plan.request.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect request exceeds bounds"))?;
    let receipt_length = u32::try_from(receipt.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect receipt exceeds bounds"))?;
    let diagnostic_length = u16::try_from(diagnostic.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect diagnostic exceeds bounds"))?;
    let dispatch_shape_valid = if record.plan.authority.is_some() {
        matches!(
            (&record.state, &record.dispatch),
            (EffectState::Planned, None)
                | (EffectState::Applying { .. }, Some(_))
                | (EffectState::Applied { .. }, Some(_))
                | (EffectState::PermanentlyBlocked { .. }, Some(_))
        )
    } else {
        record.dispatch.is_none()
    };
    if !dispatch_shape_valid {
        return Err(ReconcilerError::InvalidPlan(
            "effect dispatch does not match record variant or state",
        ));
    }
    let dispatch_body_length = record
        .dispatch
        .as_ref()
        .map_or(0, |dispatch| dispatch.attempt.body().len());
    let dispatch_packet_length = record
        .dispatch
        .as_ref()
        .map_or(0, |dispatch| dispatch.attempt.packet().len());
    if dispatch_body_length > MAXIMUM_REQUEST_BYTES
        || dispatch_packet_length > MAXIMUM_DISPATCH_PACKET_BYTES
    {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect dispatch exceeds bounds",
        ));
    }
    let authority_length = if record.plan.authority.is_some() {
        375 + dispatch_body_length + dispatch_packet_length
    } else {
        0
    };
    let version = if q04_gate.is_some() {
        CONTROLLER_Q04_EFFECT_VERSION
    } else if record.plan.is_reserved_observe() {
        RESERVED_OBSERVE_EFFECT_VERSION
    } else if record.project_admission.is_some() {
        CONTROLLER_PROJECT_EFFECT_VERSION
    } else if record.plan.controller_method.is_some() {
        CONTROLLER_EFFECT_VERSION
    } else if record.plan.method.is_some() {
        EFFECT_VERSION
    } else {
        return Err(ReconcilerError::InvalidPlan("broker effect has no method"));
    };
    let metadata_bytes = record
        .project_admission
        .as_ref()
        .map(ProjectAdmissionMetadata::encode)
        .transpose()
        .map_err(ReconcilerError::from)?;
    let header_length = if version == RESERVED_OBSERVE_EFFECT_VERSION {
        18
    } else if version == CONTROLLER_Q04_EFFECT_VERSION {
        30
    } else if version == CONTROLLER_PROJECT_EFFECT_VERSION {
        26
    } else {
        22
    };
    let mut bytes = Vec::with_capacity(
        header_length
            + authority_length
            + record.plan.request.len()
            + receipt.len()
            + diagnostic.len()
            + metadata_bytes.as_ref().map_or(0, Vec::len)
            + q04_gate.map_or(0, <[u8]>::len),
    );
    bytes.push(version);
    bytes.push(record.plan.domain as u8);
    bytes.push(state);
    bytes.push(if record.plan.authority.is_some() {
        AUTHORITY_BOUND_FLAG
    } else {
        0
    });
    bytes.extend_from_slice(&attempt.to_le_bytes());
    bytes.extend_from_slice(&request_length.to_le_bytes());
    bytes.extend_from_slice(&receipt_length.to_le_bytes());
    bytes.extend_from_slice(&diagnostic_length.to_le_bytes());
    if version == EFFECT_VERSION {
        let method = record
            .plan
            .method
            .ok_or(ReconcilerError::InvalidPlan("broker effect has no method"))?;
        bytes.extend_from_slice(&(method as i32).to_be_bytes());
    } else if matches!(
        version,
        CONTROLLER_EFFECT_VERSION | CONTROLLER_PROJECT_EFFECT_VERSION | CONTROLLER_Q04_EFFECT_VERSION
    ) {
        let method = record
            .plan
            .controller_method
            .ok_or(ReconcilerError::InvalidPlan(
                "controller effect has no method",
            ))?;
        let method_code = super::super::public_operation_method_record_code_v1(method);
        bytes.extend_from_slice(&i32::from(method_code).to_be_bytes());
    }
    if let Some(gate) = q04_gate {
        bytes.extend_from_slice(
            &u32::try_from(metadata_bytes.as_ref().map_or(0, Vec::len))
                .map_err(|_| ReconcilerError::InvalidPlan("project metadata exceeds bounds"))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(gate.len())
                .map_err(|_| ReconcilerError::InvalidPlan("Q04 gate exceeds bounds"))?
                .to_be_bytes(),
        );
    } else if let Some(metadata) = &metadata_bytes {
        bytes.extend_from_slice(
            &u32::try_from(metadata.len())
                .map_err(|_| ReconcilerError::InvalidPlan("project metadata exceeds bounds"))?
                .to_be_bytes(),
        );
    }
    if let Some(binding) = &record.plan.authority {
        bytes.extend_from_slice(binding.operation_id.as_bytes());
        bytes.extend_from_slice(&binding.step.to_be_bytes());
        bytes.extend_from_slice(binding.source_draft_digest.as_bytes());
        bytes.push(audience_code(binding.audience)?);
        bytes.extend_from_slice(&(binding.method as i32).to_be_bytes());
        bytes.extend_from_slice(binding.template_digest.as_bytes());
        bytes.extend_from_slice(binding.body_digest.as_bytes());
        bytes.extend_from_slice(binding.semantic_digest.as_bytes());
        bytes.extend_from_slice(binding.digest.as_bytes());
        bytes.push(u8::from(binding.descriptor_free));
        bytes.push(0);
        if let Some(dispatch) = &record.dispatch {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(dispatch.binding_digest.as_bytes());
            bytes.extend_from_slice(dispatch.publication_digest.as_bytes());
            bytes.extend_from_slice(dispatch.attempt.template_digest().as_bytes());
            bytes.extend_from_slice(dispatch.attempt.lease_digest().as_bytes());
            bytes.extend_from_slice(&dispatch.attempt.lease_generation().to_be_bytes());
            bytes.extend_from_slice(
                &dispatch
                    .attempt
                    .deadline_boottime_nanoseconds()
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&dispatch.preparation_wall_seconds.to_be_bytes());
            bytes.extend_from_slice(&dispatch.preparation_boottime_nanoseconds.to_be_bytes());
            let host_boot_id = dispatch.preparation_host_boot_id;
            if host_boot_id == [0; 16] {
                return Err(ReconcilerError::InvalidPlan(
                    "authority effect dispatch has a sentinel host boot",
                ));
            }
            bytes.extend_from_slice(&host_boot_id);
            bytes.extend_from_slice(
                &u32::try_from(dispatch_body_length)
                    .map_err(|_| ReconcilerError::InvalidPlan("dispatch body exceeds bounds"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(
                &u32::try_from(dispatch_packet_length)
                    .map_err(|_| ReconcilerError::InvalidPlan("dispatch packet exceeds bounds"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(dispatch.attempt.body());
            bytes.extend_from_slice(dispatch.attempt.packet());
        } else {
            bytes.extend_from_slice(&[0; 188]);
        }
    }
    bytes.extend_from_slice(&record.plan.request);
    bytes.extend_from_slice(receipt);
    bytes.extend_from_slice(diagnostic.as_bytes());
    if let Some(metadata) = metadata_bytes {
        bytes.extend_from_slice(&metadata);
    }
    if let Some(gate) = q04_gate {
        bytes.extend_from_slice(gate);
    }
    Ok(bytes)
}

pub(in crate::reconciler) fn decode_effect(
    bytes: &[u8],
) -> Result<EffectLedgerRecord, ReconcilerError> {
    decode_effect_with_extensions(bytes).map(|decoded| decoded.record)
}

struct DecodedEffectWithExtensions {
    record: EffectLedgerRecord,
    #[cfg(target_os = "linux")]
    q04: Option<crate::policy_compiler::create_q04::Q04EffectSubgateV1>,
}

#[cfg(target_os = "linux")]
pub(in crate::reconciler) fn decode_effect_with_q04(
    bytes: &[u8],
) -> Result<
    (EffectLedgerRecord, Option<crate::policy_compiler::create_q04::Q04EffectSubgateV1>),
    ReconcilerError,
> {
    let decoded = decode_effect_with_extensions(bytes)?;
    Ok((decoded.record, decoded.q04))
}

fn decode_effect_with_extensions(
    bytes: &[u8],
) -> Result<DecodedEffectWithExtensions, ReconcilerError> {
    if bytes.len() < 18
        || !matches!(
            bytes[0],
            EFFECT_VERSION
                | CONTROLLER_EFFECT_VERSION
                | RESERVED_OBSERVE_EFFECT_VERSION
                | CONTROLLER_PROJECT_EFFECT_VERSION
                | CONTROLLER_Q04_EFFECT_VERSION
        )
        || !matches!(bytes[3], 0 | AUTHORITY_BOUND_FLAG)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid effect record header",
        ));
    }
    let authority_bound = bytes[3] == AUTHORITY_BOUND_FLAG;
    let domain = EffectDomain::from_byte(bytes[1])?;
    let state_code = bytes[2];
    let attempt = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect attempt"))?,
    );
    let request_length = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid request length"))?,
    ) as usize;
    let receipt_length = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid receipt length"))?,
    ) as usize;
    let diagnostic_length = u16::from_le_bytes(
        bytes[16..18]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid diagnostic length"))?,
    ) as usize;
    let mut cursor = 18;
    let method = if bytes[0] == EFFECT_VERSION {
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        Some(
            broker_method_from_code(method_code).ok_or(ReconcilerError::CorruptLedger(
                "unknown broker effect method",
            ))?,
        )
    } else {
        None
    };
    let controller_method = if matches!(
        bytes[0],
        CONTROLLER_EFFECT_VERSION
            | CONTROLLER_PROJECT_EFFECT_VERSION
            | CONTROLLER_Q04_EFFECT_VERSION
    ) {
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let method_code = u8::try_from(method_code)
            .map_err(|_| ReconcilerError::CorruptLedger("unknown controller effect method"))?;
        Some(
            super::super::public_operation_method_from_record_code_v1(method_code).ok_or(
                ReconcilerError::CorruptLedger("unknown controller effect method"),
            )?,
        )
    } else {
        None
    };
    let metadata_length = if matches!(
        bytes[0],
        CONTROLLER_PROJECT_EFFECT_VERSION | CONTROLLER_Q04_EFFECT_VERSION
    ) {
        u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize
    } else {
        0
    };
    let q04_length = if bytes[0] == CONTROLLER_Q04_EFFECT_VERSION {
        u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize
    } else {
        0
    };
    if bytes[0] == CONTROLLER_Q04_EFFECT_VERSION {
        #[cfg(not(target_os = "linux"))]
        return Err(ReconcilerError::CorruptLedger(
            "Q04 requires original Linux custody",
        ));
        #[cfg(target_os = "linux")]
        if q04_length != crate::policy_compiler::create_q04::GATE_BYTES {
            return Err(ReconcilerError::CorruptLedger("invalid Q04 gate length"));
        }
    }
    if metadata_length > MAXIMUM_RECORD_BYTES
        || (bytes[0] == CONTROLLER_PROJECT_EFFECT_VERSION && metadata_length == 0)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid project metadata length",
        ));
    }
    let (authority, dispatch) = if authority_bound {
        let operation_bytes = take_array(bytes, &mut cursor)?;
        if operation_bytes == [0; 16] {
            return Err(ReconcilerError::CorruptLedger(
                "zero authority effect operation identity",
            ));
        }
        let operation_id = OperationId::from_bytes(operation_bytes);
        let step = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let source_draft_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let audience = audience_from_code(take_array::<1>(bytes, &mut cursor)?[0])?;
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let authority_method = match method_code {
            1 => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            4 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            7 => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            9 => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            _ => {
                return Err(ReconcilerError::CorruptLedger(
                    "unknown authority effect method",
                ));
            }
        };
        let template_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let body_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let semantic_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let descriptor_free = take_array::<1>(bytes, &mut cursor)?[0];
        let expected_domain = EffectDomain::from_audience(audience)
            .map_err(|_| ReconcilerError::CorruptLedger("invalid authority effect audience"))?;
        if take_array::<1>(bytes, &mut cursor)? != [0]
            || descriptor_free != 1
            || domain != expected_domain
            || !matches!(
                (audience, authority_method),
                (
                    BrokerAudience::Host,
                    BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                ) | (
                    BrokerAudience::Storage,
                    BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                ) | (
                    BrokerAudience::Mount,
                    BrokerMethod::BROKER_METHOD_MOUNT_APPLY
                ) | (
                    BrokerAudience::Network,
                    BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                )
            )
            || method.is_some_and(|method| method != authority_method)
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid authority effect binding",
            ));
        }
        let binding = AuthorityEffectBindingV1 {
            operation_id,
            step,
            source_draft_digest,
            audience,
            method: authority_method,
            template_digest,
            body_digest,
            semantic_digest,
            descriptor_free: descriptor_free == 1,
            digest,
        };
        let dispatch_present = take_array::<1>(bytes, &mut cursor)?[0];
        if take_array::<3>(bytes, &mut cursor)? != [0; 3] {
            return Err(ReconcilerError::CorruptLedger(
                "invalid effect dispatch reserved bytes",
            ));
        }
        let dispatch_binding_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let publication_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let dispatch_template = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let lease_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let lease_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let deadline = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_wall = i64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_boottime = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_host_boot_id = take_array(bytes, &mut cursor)?;
        let body_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        let packet_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        let dispatch = match dispatch_present {
            0 if publication_digest.as_bytes() == &[0; 32]
                && dispatch_binding_digest.as_bytes() == &[0; 32]
                && dispatch_template.as_bytes() == &[0; 32]
                && lease_digest.as_bytes() == &[0; 32]
                && lease_generation == 0
                && deadline == 0
                && clock_wall == 0
                && clock_boottime == 0
                && clock_host_boot_id == [0; 16]
                && body_length == 0
                && packet_length == 0 =>
            {
                None
            }
            1 if publication_digest.as_bytes() != &[0; 32]
                && dispatch_template == template_digest
                && lease_digest.as_bytes() != &[0; 32]
                && lease_generation != 0
                && deadline != 0
                && body_length != 0
                && body_length <= MAXIMUM_REQUEST_BYTES
                && packet_length != 0
                && packet_length <= MAXIMUM_DISPATCH_PACKET_BYTES
                && clock_host_boot_id != [0; 16] =>
            {
                let body = take_vec(bytes, &mut cursor, body_length)?;
                let packet = take_vec(bytes, &mut cursor, packet_length)?;
                Some(PreparedAuthorityEffectV1::from_durable_parts(
                    dispatch_binding_digest,
                    publication_digest,
                    clock_wall,
                    clock_boottime,
                    clock_host_boot_id,
                    BrokerDispatchAttemptV1::from_durable_parts(
                        dispatch_template,
                        lease_digest,
                        lease_generation,
                        deadline,
                        body,
                        packet,
                    ),
                ))
            }
            _ => {
                return Err(ReconcilerError::CorruptLedger(
                    "invalid authority effect dispatch",
                ));
            }
        };
        (Some(binding), dispatch)
    } else {
        (None, None)
    };
    if let Some(method) = method {
        validate_broker_method_domain(domain, method)
            .map_err(|_| ReconcilerError::CorruptLedger("broker effect method/domain mismatch"))?;
    }
    let expected = cursor
        .checked_add(request_length)
        .and_then(|n| n.checked_add(receipt_length))
        .and_then(|n| n.checked_add(diagnostic_length))
        .and_then(|n| n.checked_add(metadata_length))
        .and_then(|n| n.checked_add(q04_length))
        .ok_or(ReconcilerError::CorruptLedger("effect length overflow"))?;
    if expected != bytes.len()
        || request_length == 0
        || request_length > MAXIMUM_REQUEST_BYTES
        || receipt_length > MAXIMUM_RECEIPT_BYTES
        || diagnostic_length > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::CorruptLedger("invalid effect lengths"));
    }
    let request_end = cursor + request_length;
    let receipt_end = request_end + receipt_length;
    let request = bytes[cursor..request_end].to_vec();
    let receipt = bytes[request_end..receipt_end].to_vec();
    let diagnostic_end = receipt_end + diagnostic_length;
    let diagnostic = std::str::from_utf8(&bytes[receipt_end..diagnostic_end])
        .map_err(|_| ReconcilerError::CorruptLedger("diagnostic is not UTF-8"))?
        .to_owned();
    if let Some(binding) = &authority
        && (binding.body_digest != effect_body_digest(&request)
            || binding.digest
                != effect_binding_digest(
                    binding.operation_id,
                    binding.step,
                    binding.source_draft_digest,
                    binding.audience,
                    binding.method,
                    binding.template_digest,
                    binding.body_digest,
                    binding.semantic_digest,
                )?)
    {
        return Err(ReconcilerError::CorruptLedger(
            "authority effect binding digest mismatch",
        ));
    }
    if let Some(method) = controller_method {
        if domain != EffectDomain::Controller || authority.is_some() {
            return Err(ReconcilerError::CorruptLedger(
                "controller effect has invalid domain or authority",
            ));
        }
        EffectPlan::from_public_mutation_bytes(method, request.clone()).map_err(|_| {
            ReconcilerError::CorruptLedger("controller effect method/request mismatch")
        })?;
    }
    let state = decode_state(state_code, attempt, receipt, diagnostic)?;
    let metadata_end = diagnostic_end + metadata_length;
    let project_admission = if metadata_length != 0 {
        let metadata = ProjectAdmissionMetadata::decode(&bytes[diagnostic_end..metadata_end])
            .map_err(ReconcilerError::from)?;
        validate_project_metadata_shape(
            &EffectPlan {
                domain,
                method,
                controller_method,
                request: request.clone(),
                authority: authority.clone(),
            },
            &state,
            &metadata,
        )?;
        Some(metadata)
    } else {
        None
    };
    if bytes[0] == RESERVED_OBSERVE_EFFECT_VERSION
        && (domain != EffectDomain::Controller
            || method.is_some()
            || controller_method.is_some()
            || authority.is_some()
            || !matches!(state, EffectState::Planned)
            || !(EffectPlan {
                domain,
                method,
                controller_method,
                request: request.clone(),
                authority: None,
            })
            .is_reserved_observe())
    {
        return Err(ReconcilerError::CorruptLedger(
            "reserved Observe effect has invalid shape",
        ));
    }
    let dispatch_shape_valid = if authority.is_some() {
        matches!(
            (&state, &dispatch),
            (EffectState::Planned, None)
                | (EffectState::Applying { .. }, Some(_))
                | (EffectState::Applied { .. }, Some(_))
                | (EffectState::PermanentlyBlocked { .. }, Some(_))
        )
    } else {
        dispatch.is_none()
    };
    if !dispatch_shape_valid {
        return Err(ReconcilerError::CorruptLedger(
            "effect dispatch does not match authority state",
        ));
    }
    let record = EffectLedgerRecord {
        plan: EffectPlan {
            domain,
            method,
            controller_method,
            request,
            authority,
        },
        state,
        dispatch,
        project_admission,
    };
    #[cfg(target_os = "linux")]
    let q04 = if bytes[0] == CONTROLLER_Q04_EFFECT_VERSION {
        require_q04_effect_shape(&record)?;
        Some(
            crate::policy_compiler::create_q04::Q04EffectSubgateV1::decode(&bytes[metadata_end..])
                .map_err(|_| ReconcilerError::CorruptLedger("invalid Q04 policy-subgate record"))?,
        )
    } else {
        None
    };
    Ok(DecodedEffectWithExtensions {
        record,
        #[cfg(target_os = "linux")]
        q04,
    })
}

// The ordinary record intentionally keeps its old construction API. A caller
// needing Q04 history must read this companion from the SAME complete row;
// decoding either value is not held-owner or publication authority.
#[cfg(target_os = "linux")]
pub(in crate::reconciler) fn q04_effect_subgate(
    bytes: &[u8],
) -> Result<Option<crate::policy_compiler::create_q04::Q04EffectSubgateV1>, ReconcilerError> {
    if bytes.first() != Some(&CONTROLLER_Q04_EFFECT_VERSION) {
        return Ok(None);
    }
    Ok(decode_effect_with_extensions(bytes)?.q04)
}

fn validate_project_metadata_shape(
    plan: &EffectPlan,
    state: &EffectState,
    _metadata: &ProjectAdmissionMetadata,
) -> Result<(), ReconcilerError> {
    if plan.public_mutation_method()
        != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
        || plan.authority.is_some()
        || matches!(
            state,
            EffectState::Applied { .. } | EffectState::PermanentlyBlocked { .. }
        )
    {
        return Err(ReconcilerError::CorruptLedger(
            "project admission metadata has invalid Effect shape",
        ));
    }
    Ok(())
}

fn state_parts(state: &EffectState) -> (u8, u32, &[u8], &str) {
    match state {
        EffectState::Planned => (1, 0, &[], ""),
        EffectState::Applying {
            attempt,
            diagnostic,
        } => (2, *attempt, &[], diagnostic),
        EffectState::Applied { attempt, receipt } => (3, *attempt, receipt.as_bytes(), ""),
        EffectState::PermanentlyBlocked {
            attempt,
            diagnostic,
        } => (4, *attempt, &[], diagnostic),
    }
}

fn validate_lengths(
    plan: &EffectPlan,
    receipt: &[u8],
    diagnostic: &str,
) -> Result<(), ReconcilerError> {
    if plan.request.is_empty()
        || plan.request.len() > MAXIMUM_REQUEST_BYTES
        || receipt.len() > MAXIMUM_RECEIPT_BYTES
        || diagnostic.len() > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::InvalidPlan("effect record exceeds bounds"));
    }
    if let Some(method) = plan.method {
        validate_broker_method_domain(plan.domain, method)?;
    }
    if let Some(method) = plan.controller_method {
        if plan.domain != EffectDomain::Controller || plan.method.is_some() {
            return Err(ReconcilerError::InvalidPlan(
                "controller effect has an invalid dispatch identity",
            ));
        }
        EffectPlan::from_public_mutation_bytes(method, plan.request.clone())?;
    } else if plan.domain == EffectDomain::Controller && !plan.is_reserved_observe() {
        return Err(ReconcilerError::InvalidPlan(
            "controller effect has no dispatch method",
        ));
    }
    if plan
        .authority
        .as_ref()
        .is_some_and(|binding| plan.method != Some(binding.method))
    {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect method does not match its dispatch method",
        ));
    }
    if plan.authority.is_some() && plan.method.is_none() {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect has no dispatch method",
        ));
    }
    Ok(())
}

fn decode_state(
    state: u8,
    attempt: u32,
    receipt: Vec<u8>,
    diagnostic: String,
) -> Result<EffectState, ReconcilerError> {
    match state {
        1 if attempt == 0 && receipt.is_empty() && diagnostic.is_empty() => {
            Ok(EffectState::Planned)
        }
        2 if attempt > 0 && receipt.is_empty() => Ok(EffectState::Applying {
            attempt,
            diagnostic,
        }),
        3 if attempt > 0 && !receipt.is_empty() && diagnostic.is_empty() => {
            Ok(EffectState::Applied {
                attempt,
                receipt: EffectReceipt(receipt),
            })
        }
        4 if attempt > 0 && receipt.is_empty() && !diagnostic.is_empty() => {
            Ok(EffectState::PermanentlyBlocked {
                attempt,
                diagnostic,
            })
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "invalid effect state fields",
        )),
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ReconcilerError> {
    let end = cursor.checked_add(N).ok_or(ReconcilerError::CorruptLedger(
        "effect binding length overflow",
    ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated effect binding"))?;
    *cursor = end;
    value
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("truncated effect binding"))
}

fn take_vec(bytes: &[u8], cursor: &mut usize, length: usize) -> Result<Vec<u8>, ReconcilerError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ReconcilerError::CorruptLedger(
            "effect dispatch length overflow",
        ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated effect dispatch"))?
        .to_vec();
    *cursor = end;
    Ok(value)
}

pub(in crate::reconciler) fn effect_body_digest(body: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BODY_DIGEST_DOMAIN);
    digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(body);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn effect_binding_digest(
    operation_id: OperationId,
    step: u32,
    source: ObjectDigest,
    audience: BrokerAudience,
    method: BrokerMethod,
    template: ObjectDigest,
    body: ObjectDigest,
    semantics: ObjectDigest,
) -> Result<ObjectDigest, ReconcilerError> {
    let mut digest = Sha256::new();
    digest.update(BINDING_DIGEST_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(step.to_be_bytes());
    digest.update(source.as_bytes());
    digest.update([audience_code(audience)?]);
    digest.update((method as i32).to_be_bytes());
    digest.update(template.as_bytes());
    digest.update(body.as_bytes());
    digest.update(semantics.as_bytes());
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

pub(super) fn attempt_token_digest(attempt: &BrokerDispatchAttemptV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ATTEMPT_TOKEN_DIGEST_DOMAIN);
    digest.update(
        u64::try_from(attempt.packet().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(attempt.packet());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) const fn audience_code(audience: BrokerAudience) -> Result<u8, ReconcilerError> {
    match audience {
        BrokerAudience::Host => Ok(1),
        BrokerAudience::Mount => Ok(2),
        BrokerAudience::Storage => Ok(3),
        BrokerAudience::Network => Ok(4),
        BrokerAudience::Guardian => Err(ReconcilerError::InvalidPlan(
            "guardian authority cannot use the generic broker effect path",
        )),
        BrokerAudience::Nix => Err(ReconcilerError::InvalidPlan(
            "Nix authority cannot use the generic broker effect path",
        )),
    }
}

pub(super) fn audience_from_code(value: u8) -> Result<BrokerAudience, ReconcilerError> {
    match value {
        1 => Ok(BrokerAudience::Host),
        2 => Ok(BrokerAudience::Mount),
        3 => Ok(BrokerAudience::Storage),
        4 => Ok(BrokerAudience::Network),
        _ => Err(ReconcilerError::CorruptLedger(
            "unknown authority effect audience",
        )),
    }
}

/// Holds the original decoded prior once while Journal checks the next row.
pub(crate) struct OriginalCapacityEffectHistoryV1(EffectLedgerRecord);

/// Preserves the prior decode before the caller inspects transaction records.
///
/// # Errors
///
/// Returns ProtectedBoundary when the original Effect bytes fail decoding.
pub(crate) fn decode_capacity_effect_history(
    bytes: &[u8],
) -> Result<OriginalCapacityEffectHistoryV1, crate::journal::JournalError> {
    let prior = decode_effect(bytes).map_err(|_| crate::journal::JournalError::ProtectedBoundary)?;
    Ok(OriginalCapacityEffectHistoryV1(prior))
}

/// Compares the next row only after the caller's original row/key frontier.
///
/// # Errors
///
/// Returns ProtectedBoundary for an absent or malformed next value, differing
/// plan/state/dispatch, or absent project-admission metadata.
pub(crate) fn compare_capacity_effect_history(
    prior: OriginalCapacityEffectHistoryV1,
    next: &crate::journal::JournalRecord,
) -> Result<(ProjectAdmissionMetadata, ProjectAdmissionMetadata), crate::journal::JournalError> {
    use crate::journal::JournalError;

    let prior = prior.0;
    let next = decode_effect(next.value().ok_or(JournalError::ProtectedBoundary)?)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if next.plan != prior.plan || next.state != prior.state || next.dispatch != prior.dispatch {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok((
        prior
            .project_admission
            .ok_or(JournalError::ProtectedBoundary)?,
        next.project_admission
            .ok_or(JournalError::ProtectedBoundary)?,
    ))
}

/// Validates the complete per-row Delete Effect relation with original errors.
///
/// # Errors
///
/// Returns the original history/context error or Native publication error when
/// the complete Effect, request, Gate template, or bound-plan relation is invalid.
pub(crate) fn validate_delete_effect_record(
    row: &crate::journal::JournalRecord,
    gate: &Option<DeleteGateHistoryV1>,
    operation_id: OperationId,
    step: u32,
    batch: crate::lifecycle::delete_batch::DeleteBatchViewV1<'_>,
    root: &[u8],
    delete_effects: &mut usize,
) -> Result<(), ReconcilerError> {
    use super::super::OwnershipGateStatusV1;
    use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

    let invalid = || ReconcilerError::CorruptLedger("invalid Delete batch admission metadata");
    let effect = decode_effect(row.value().ok_or_else(invalid)?)?;
    if effect.state != EffectState::Planned
        || effect.dispatch.is_some()
        || effect.project_admission.is_some()
        || encode_effect(&effect)?.as_slice() != row.value().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    if effect.plan.public_mutation_method() == Some(PublicOperationMethodV1::DeleteSandbox) {
        let context = effect.plan.public_mutation_context()?.ok_or_else(invalid)?;
        let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Delete(request) = context.validated_request()?
        else {
            return Err(invalid());
        };
        if context.project() != batch.project()
            || request.sandbox_id.as_slice() != root
            || request.expected_plan_digest.as_slice() != batch.graph_plan().as_slice()
            || request.cascade != (batch.flags() & 1 != 0)
            || request.force != (batch.flags() & 2 != 0)
        {
            return Err(invalid());
        }
        // The original counter advances before this decoded Effect is dropped.
        // Keep it inside the relation instead of returning a deferred Boolean.
        *delete_effects += 1;
    } else {
        let binding = effect.plan.authority().ok_or_else(invalid)?;
        let Some(DeleteGateHistoryV1(OwnershipGateStatusV1::Pending(gate))) = gate.as_ref() else {
            return Err(invalid());
        };
        if crate::bind_authority_publication_effect(
            gate.publication_draft(),
            binding.template_digest,
        )?
        .into_inner(operation_id, step)?
            != effect.plan
        {
            return Err(invalid());
        }
    }
    Ok(())
}
