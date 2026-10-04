//! Closed comparison records for the original pending Storage output request.
//!
//! ```text
//! preparation-v1: nomination(original46, Storage head, exact Host48 body)
//!               | authorization(exact nomination, Controller head, Host quartet)
//! terminal: AOSEOR03[177] + AOSEOS01[184]
//! ```
//!
//! Endpoint heads are independent comparison DATA. Neither their bytes nor
//! these parsers supply a live session, writer, floor, or effect permission.

use aos_proto::aos::sandbox::local::v1::{
    StorageOutputRegistrationPreparationV1, StorageOutputRegistrationResponseV1,
};
use aos_sandbox_core::{MediaType, ObjectDigest, PortableMediaType};
use aos_sandbox_core::format::descriptor_for_bytes;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use crate::session::{AuthorizationArtifactBytes, validate_authorization_artifact_bytes};
use crate::ProtocolValidationError;

use super::StorageOutputReserveRecordsV1;

/// Maximum complete pending preparation packet, including its quartet.
pub const MAXIMUM_PREPARATION_BYTES_V1: usize = 1024 * 1024;
/// Identifies the original Storage nomination record.
pub const NOMINATION_V1: u32 = 1;
/// Identifies the Controller response carrying the distinct Host authorization.
pub const AUTHORIZATION_V1: u32 = 2;

/// Decodes one exact preparation stage before any caller currentness checks.
///
/// # Errors
///
/// Rejects excessive bytes, unknown fields, noncanonical wire, changed version,
/// malformed bindings, or a stage with missing or unexpected authorization.
pub fn decode_preparation_v1(
    bytes: &[u8],
    stage: u32,
) -> Result<StorageOutputRegistrationPreparationV1, ProtocolValidationError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_PREPARATION_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let record = StorageOutputRegistrationPreparationV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    validate_preparation(&record, stage)?;
    if record.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    Ok(record)
}

/// Encodes a bounded preparation after checking all complete-message limits.
///
/// # Errors
///
/// Rejects malformed stage bindings or a complete packet exceeding its ceiling.
pub fn encode_preparation_v1(
    record: &StorageOutputRegistrationPreparationV1,
) -> Result<Vec<u8>, ProtocolValidationError> {
    validate_preparation(record, record.stage)?;
    Ok(record.encode_to_vec())
}

fn validate_preparation(
    record: &StorageOutputRegistrationPreparationV1,
    stage: u32,
) -> Result<(), ProtocolValidationError> {
    if record.version != 1
        || record.stage != stage
        || !matches!(stage, NOMINATION_V1 | AUTHORIZATION_V1)
        || !record.__buffa_unknown_fields.is_empty()
        || !nonzero(&record.original_storage_request_id, 16)
        || !nonzero(&record.original_storage_session_binding, 32)
        || !nonzero(&record.original_signed_request_digest, 32)
        || !nonzero(&record.original_semantic_request_digest, 32)
        || !nonzero(&record.storage_pending_head, 32)
        || record.canonical_host_readback_request.is_empty()
        || record.canonical_host_readback_request.len() > 4096
    {
        return Err(invalid());
    }
    match stage {
        NOMINATION_V1 => {
            if !record.controller_pending_head.is_empty()
                || record.host_authorization.as_option().is_some()
            {
                return Err(invalid());
            }
        }
        AUTHORIZATION_V1 => {
            if !nonzero(&record.controller_pending_head, 32) {
                return Err(invalid());
            }
            let artifacts = record.host_authorization.as_option().ok_or_else(invalid)?;
            if !artifacts.__buffa_unknown_fields.is_empty() {
                return Err(invalid());
            }
            validate_authorization_artifact_bytes(AuthorizationArtifactBytes {
                broker_plan: &artifacts.broker_plan,
                broker_plan_signature: &artifacts.broker_plan_signature,
                ownership_lease: &artifacts.ownership_lease,
                ownership_lease_signature: &artifacts.ownership_lease_signature,
            })?;
        }
        _ => return Err(invalid()),
    }
    if record.encoded_len() > MAXIMUM_PREPARATION_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(())
}

/// Compares a preparation with the complete original authenticated request.
#[must_use]
pub fn matches_original_request_v1(
    record: &StorageOutputRegistrationPreparationV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> bool {
    record.original_storage_request_id == request.request_id()
        && record.original_storage_session_binding == request.session_binding()
        && record.original_signed_request_digest == request.signed_request_digest()
        && record.original_semantic_request_digest == request.semantic_commitment()
}

/// Compares an authorization with every original nomination field.
#[must_use]
pub fn matches_nomination_v1(
    authorization: &StorageOutputRegistrationPreparationV1,
    nomination: &StorageOutputRegistrationPreparationV1,
) -> bool {
    authorization.version == nomination.version
        && authorization.stage == AUTHORIZATION_V1
        && nomination.stage == NOMINATION_V1
        && authorization.original_storage_request_id == nomination.original_storage_request_id
        && authorization.original_storage_session_binding == nomination.original_storage_session_binding
        && authorization.original_signed_request_digest == nomination.original_signed_request_digest
        && authorization.original_semantic_request_digest == nomination.original_semantic_request_digest
        && authorization.storage_pending_head == nomination.storage_pending_head
        && authorization.canonical_host_readback_request == nomination.canonical_host_readback_request
}

/// Derives the canonical object identity of the exact original signed plan bytes.
///
/// # Errors
///
/// Rejects an original request without its validated authorization quartet.
pub fn original_plan_digest_v1(
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<ObjectDigest, ProtocolValidationError> {
    let authorization = request.authorization().ok_or_else(invalid)?;
    let media_type = MediaType::new(PortableMediaType::BrokerAuthorizationPlan.as_str().to_owned())
        .map_err(|_| invalid())?;
    Ok(descriptor_for_bytes(media_type, authorization.broker_plan()).digest())
}

/// Validates exact returned logical records without verifying their Storage MAC.
///
/// The authenticated terminal commits these bytes. Only Storage's local ledger
/// can verify its MAC; this comparison never permits a new effect.
///
/// # Errors
///
/// Rejects changed source, quantities, original identity, row digest, or wire.
pub fn decode_registration_response_v1(
    bytes: &[u8],
    records: &StorageOutputReserveRecordsV1,
    original_request_id: [u8; 16],
    original_plan_digest: ObjectDigest,
) -> Result<StorageOutputRegistrationResponseV1, ProtocolValidationError> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = StorageOutputRegistrationResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let row = &response.canonical_reservation;
    let marker = &response.canonical_original_marker;
    let source = &records.attempt()[8..696];
    if row.len() != 177 || marker.len() != 184 {
        return Err(invalid());
    }
    if row[..8] != *b"AOSEOR03"
        || row[8..24] != *records.host_locator().execution().as_bytes()
        || row[24..40] != *records.host_locator().create_operation().as_bytes()
        || row[40..72] != *records.assignment().digest().as_bytes()
        || row[72..104] != *records.host_locator().claim_digest().as_bytes()
        || row[104..112] != source[424..432]
        || row[112..120] != source[80..88]
        || row[120..128] != source[88..96]
        || row[128] != 1
        || row[129..145] != [0; 16]
        || marker[..8] != *b"AOSEOS01"
        || marker[8..24] != original_request_id
        || marker[24..40] != row[8..24]
        || marker[40..56] != row[24..40]
        || marker[56..88] != *original_plan_digest.as_bytes()
        || marker[88..120] == [0; 32]
        || marker[120..152] != Sha256::digest(row).as_slice()
    {
        return Err(invalid());
    }
    Ok(response)
}

fn nonzero(bytes: &[u8], width: usize) -> bool {
    bytes.len() == width && bytes.iter().any(|byte| *byte != 0)
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("original Storage output registration")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nomination() -> StorageOutputRegistrationPreparationV1 {
        StorageOutputRegistrationPreparationV1 {
            version: 1,
            stage: NOMINATION_V1,
            original_storage_request_id: vec![1; 16],
            original_storage_session_binding: vec![2; 32],
            original_signed_request_digest: vec![3; 32],
            original_semantic_request_digest: vec![4; 32],
            storage_pending_head: vec![5; 32],
            canonical_host_readback_request: vec![6; 16],
            ..Default::default()
        }
    }

    #[test]
    fn nomination_roundtrip_preserves_all_comparison_fields() {
        let original = nomination();

        let bytes = encode_preparation_v1(&original).unwrap();
        let decoded = decode_preparation_v1(&bytes, NOMINATION_V1).unwrap();

        assert_eq!(decoded, original);
        assert!(decoded.controller_pending_head.is_empty());
        assert!(decoded.host_authorization.as_option().is_none());
    }

    #[test]
    fn nomination_rejects_changed_version_stage_and_width_before_encoding() {
        let original = nomination();
        let mut changed = original.clone();
        changed.version = 2;
        assert!(encode_preparation_v1(&changed).is_err());

        changed = original.clone();
        changed.stage = 3;
        assert!(encode_preparation_v1(&changed).is_err());

        changed = original.clone();
        changed.storage_pending_head.pop();
        assert!(encode_preparation_v1(&changed).is_err());

        changed = original;
        changed.controller_pending_head = vec![7; 32];
        assert!(encode_preparation_v1(&changed).is_err());
    }

    #[test]
    fn preparation_rejects_excessive_body_and_noncanonical_wire() {
        let mut original = nomination();
        original.canonical_host_readback_request.resize(4097, 6);
        assert!(encode_preparation_v1(&original).is_err());

        let mut bytes = encode_preparation_v1(&nomination()).unwrap();
        // A repeated version field is parseable protobuf but not canonical.
        bytes.extend_from_slice(&[8, 1]);
        assert!(decode_preparation_v1(&bytes, NOMINATION_V1).is_err());
        assert!(decode_preparation_v1(&vec![0; MAXIMUM_PREPARATION_BYTES_V1 + 1], NOMINATION_V1).is_err());
    }

    #[test]
    fn nomination_crosslinks_do_not_equate_endpoint_heads() {
        let original = nomination();
        let mut authorization = original.clone();
        authorization.stage = AUTHORIZATION_V1;
        authorization.controller_pending_head = vec![7; 32];

        assert!(matches_nomination_v1(&authorization, &original));
        authorization.storage_pending_head[0] ^= 1;
        assert!(!matches_nomination_v1(&authorization, &original));
    }
}
