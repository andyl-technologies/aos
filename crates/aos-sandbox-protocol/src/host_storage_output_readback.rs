//! Closed Storage-audience Host readback of one original output reservation.
//!
//! Method 48 has a distinct Host grant and a fresh Storage-to-Host session.
//! Its body carries the exact Controller-held method-46 attempt identity, not
//! caller-selected output-claim fields. Structural parsing alone is not proof:
//! only a signed client-received terminal retained under the protected session
//! can attest Host's current AOSEOR02/AOSHOP01 readback. No production hello
//! advertises this method yet.

use aos_proto::aos::sandbox::local::v1::{
    Audience, ObserveHostStorageOutputRequestV1, ObserveHostStorageOutputResponseV1,
    ReserveStorageExecutionOutputRequestV1,
};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerGrant, BrokerGrantTarget, BrokerVerb,
    ObjectDigest, ProtocolId, ProtocolVersion,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::host_output::{
    HostOutputReservationStatusV1, ValidatedHostOutputReservationV1,
    decode_host_output_reservation_response_v1,
};
use crate::storage_output_reserve::{
    StorageOutputReserveRecordsV1, storage_output_reserve_grant_v1,
};
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_fence, validate_request_header,
};

const GRANT_DOMAIN: &[u8] = b"aos.sandbox.host.storage-output-readback-grant.v1\0";
const CONTROLLER_ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-attempt.v1\0";
const MAXIMUM_REQUEST_BODY_BYTES: usize = 4 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1_024;

/// Retains a structural request awaiting a separate Controller Host grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostStorageOutputReadbackRequestV1 {
    header: ValidatedHeader,
    original_body: Vec<u8>,
    original_storage_request_id: [u8; 16],
    original_storage_plan_digest: ObjectDigest,
    original_storage_semantic_digest: ObjectDigest,
    controller_storage_attempt_digest: ObjectDigest,
    records: StorageOutputReserveRecordsV1,
}

impl ValidatedHostStorageOutputReadbackRequestV1 {
    /// Returns the fresh authenticated Storage-to-Host request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the exact original method-46 body retained by Controller.
    #[must_use]
    pub fn original_body(&self) -> &[u8] {
        &self.original_body
    }

    /// Returns the original Storage reserve request ID.
    #[must_use]
    pub const fn original_storage_request_id(&self) -> [u8; 16] {
        self.original_storage_request_id
    }

    /// Returns the exact original Storage signed-plan digest.
    #[must_use]
    pub const fn original_storage_plan_digest(&self) -> ObjectDigest {
        self.original_storage_plan_digest
    }

    /// Returns the exact original Storage semantic commitment digest.
    #[must_use]
    pub const fn original_storage_semantic_digest(&self) -> ObjectDigest {
        self.original_storage_semantic_digest
    }

    /// Returns the deterministic AOSCST01 digest; this does not prove custody.
    #[must_use]
    pub const fn controller_storage_attempt_digest(&self) -> ObjectDigest {
        self.controller_storage_attempt_digest
    }

    /// Borrows the original Controller source and Host settlement preimages.
    #[must_use]
    pub const fn records(&self) -> &StorageOutputReserveRecordsV1 {
        &self.records
    }
}

/// Retains a structural Host response pending signed-session currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostStorageOutputReadbackV1 {
    controller_storage_attempt_digest: ObjectDigest,
    original_storage_request_id: [u8; 16],
    original_storage_plan_digest: ObjectDigest,
    original_storage_semantic_digest: ObjectDigest,
    reservation: ValidatedHostOutputReservationV1,
    current_assignment: BrokerAssignment,
    protected_head_sequence: u64,
    protected_head_digest: ObjectDigest,
}

impl ValidatedHostStorageOutputReadbackV1 {
    /// Returns the deterministic AOSCST01 digest echoed by Host.
    #[must_use]
    pub const fn controller_storage_attempt_digest(self) -> ObjectDigest {
        self.controller_storage_attempt_digest
    }

    /// Returns the original method-46 request identifier.
    #[must_use]
    pub const fn original_storage_request_id(self) -> [u8; 16] {
        self.original_storage_request_id
    }

    /// Returns the original signed Storage plan digest.
    #[must_use]
    pub const fn original_storage_plan_digest(self) -> ObjectDigest {
        self.original_storage_plan_digest
    }

    /// Returns the original Storage semantic-grant digest.
    #[must_use]
    pub const fn original_storage_semantic_digest(self) -> ObjectDigest {
        self.original_storage_semantic_digest
    }

    /// Returns the exact committed Host AOSEOR02/AOSHOP01 observation.
    #[must_use]
    pub const fn reservation(self) -> ValidatedHostOutputReservationV1 {
        self.reservation
    }

    /// Returns Host's signed current assignment observation.
    #[must_use]
    pub const fn current_assignment(self) -> BrokerAssignment {
        self.current_assignment
    }

    /// Returns the protected Host journal head sequence at readback.
    #[must_use]
    pub const fn protected_head_sequence(self) -> u64 {
        self.protected_head_sequence
    }

    /// Returns the protected Host journal head commitment at readback.
    #[must_use]
    pub const fn protected_head_digest(self) -> ObjectDigest {
        self.protected_head_digest
    }
}

/// Parses the fresh Host request and exact original Controller attempt fields.
///
/// # Errors
///
/// Rejects noncanonical wire, a stale or wrong-audience header, mismatched
/// original Storage semantics, or incomplete AOSCST01 identity.
pub fn decode_host_storage_output_readback_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostStorageOutputReadbackRequestV1, ProtocolValidationError> {
    let (request, original_id, records, plan_digest, semantic_digest, attempt_digest) =
        parse_request(body)?;
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version() != ProtocolVersion::new(1, 0)
        || header.request_id() == &original_id
        || policy.audience != Audience::AUDIENCE_STORAGE_BROKER
    {
        return Err(invalid());
    }
    Ok(ValidatedHostStorageOutputReadbackRequestV1 {
        header,
        original_body: request.canonical_original_storage_reserve_request,
        original_storage_request_id: original_id,
        original_storage_plan_digest: plan_digest,
        original_storage_semantic_digest: semantic_digest,
        controller_storage_attempt_digest: attempt_digest,
        records,
    })
}

/// Compiles a distinct Host-audience grant over the complete readback body.
///
/// The Controller must issue this from its protected original AOSCST01 attempt;
/// this structural helper does not sign or authorize a Host response.
///
/// # Errors
///
/// Rejects a foreign assignment, repeated original request ID, malformed
/// Controller source, or noncanonical fresh request.
pub fn host_storage_output_readback_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<BrokerGrant, ProtocolValidationError> {
    let (request, original_id, records, _, _, _) = parse_request(body)?;
    let header = request.header.as_option().ok_or_else(invalid)?;
    if request_id == [0; 16]
        || header.request_id != request_id
        || request_id == original_id
        || assignment != records.assignment()
    {
        return Err(invalid());
    }
    let mut statement = Vec::with_capacity(GRANT_DOMAIN.len() + 1 + 16 + body.len());
    statement.extend_from_slice(GRANT_DOMAIN);
    statement.push(1);
    statement.extend_from_slice(&request_id);
    statement.extend_from_slice(body);
    BrokerGrant::new(
        BrokerVerb::HostObserveStorageOutput,
        BrokerGrantTarget::Assignment,
        BrokerArgumentCommitment::for_canonical_bytes(&statement),
        MAXIMUM_REQUEST_BODY_BYTES as u32,
        0,
    )
    .map_err(|_| invalid())
}

/// Checks a signed Host response against the protected original Host receipt.
///
/// This parser is structural only. Callers must retain a client-received
/// authenticated terminal and its protected session-currentness borrow.
///
/// # Errors
///
/// Rejects absence, substituted Host plan/correlation/sequence, foreign
/// assignment or boot, or a noncanonical protected-head attestation.
pub fn decode_host_storage_output_readback_response_v1(
    body: &[u8],
    request: &ValidatedHostStorageOutputReadbackRequestV1,
) -> Result<ValidatedHostStorageOutputReadbackV1, ProtocolValidationError> {
    if body.is_empty() || body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = ObserveHostStorageOutputResponseV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let reservation = decode_host_output_reservation_response_v1(
        &response.canonical_host_output_reservation,
        request.records.host_locator(),
        false,
    )?;
    let assignment = validate_fence(response.current_host_assignment.as_option().ok_or(
        ProtocolValidationError::MissingField("current_host_assignment"),
    )?)?
    .broker_assignment()
    .map_err(|_| invalid())?;
    let attempt = request.records.attempt();
    let settlement = request.records.settlement();
    let original_host_sequence = read_u64(&settlement[104..112])?;
    if reservation.status() != HostOutputReservationStatusV1::Committed
        || reservation.original_plan_digest()
            != Some(ObjectDigest::from_bytes(
                attempt[712..744].try_into().map_err(|_| invalid())?,
            ))
        || reservation.original_semantic_request_digest()
            != Some(ObjectDigest::from_bytes(
                attempt[744..776].try_into().map_err(|_| invalid())?,
            ))
        || reservation.correlation_digest()
            != Some(ObjectDigest::from_bytes(
                settlement[72..104].try_into().map_err(|_| invalid())?,
            ))
        || reservation.original_host_journal_sequence() != Some(original_host_sequence)
        || response.controller_storage_attempt_digest
            != *request.controller_storage_attempt_digest.as_bytes()
        || assignment != request.records.assignment()
        || response.host_boot_id != request.records.host_locator().host_boot_id()
        || response.protected_host_journal_head_sequence < original_host_sequence
    {
        return Err(invalid());
    }
    let protected_head_digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &response.protected_host_journal_head_digest,
        "protected_host_journal_head_digest",
    )?);
    Ok(ValidatedHostStorageOutputReadbackV1 {
        controller_storage_attempt_digest: request.controller_storage_attempt_digest,
        original_storage_request_id: request.original_storage_request_id,
        original_storage_plan_digest: request.original_storage_plan_digest,
        original_storage_semantic_digest: request.original_storage_semantic_digest,
        reservation,
        current_assignment: assignment,
        protected_head_sequence: response.protected_host_journal_head_sequence,
        protected_head_digest,
    })
}

fn parse_request(
    body: &[u8],
) -> Result<
    (
        ObserveHostStorageOutputRequestV1,
        [u8; 16],
        StorageOutputReserveRecordsV1,
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
    ),
    ProtocolValidationError,
> {
    if body.is_empty() || body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(invalid());
    }
    let request = ObserveHostStorageOutputRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = request.header.as_option().ok_or_else(invalid)?;
    if !header.__buffa_unknown_fields.is_empty()
        || header.protocol_major != 1
        || header.protocol_minor != 0
        || header.audience.as_known() != Some(Audience::AUDIENCE_STORAGE_BROKER)
        || header.deadline_boottime_nanoseconds == 0
        || !(crate::MINIMUM_RESPONSE_BYTES..=crate::MAXIMUM_RESPONSE_BYTES)
            .contains(&header.maximum_response_bytes)
    {
        return Err(invalid());
    }
    let original = ReserveStorageExecutionOutputRequestV1::decode_from_slice(
        &request.canonical_original_storage_reserve_request,
    )
    .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let original_id: [u8; 16] = original
        .header
        .as_option()
        .ok_or_else(invalid)?
        .request_id
        .as_slice()
        .try_into()
        .map_err(|_| invalid())?;
    let records = StorageOutputReserveRecordsV1::from_canonical_records(
        &original.canonical_controller_attempt,
        &original.canonical_controller_settlement,
    )?;
    let original_grant = storage_output_reserve_grant_v1(
        records.assignment(),
        original_id,
        &request.canonical_original_storage_reserve_request,
    )?;
    let semantic_digest = original_grant.argument_commitment().digest();
    let plan_digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.original_storage_signed_plan_digest,
        "original_storage_signed_plan_digest",
    )?);
    let attempt_digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.controller_storage_attempt_digest,
        "controller_storage_attempt_digest",
    )?);
    let original_body = &request.canonical_original_storage_reserve_request;
    let body_length = u16::try_from(original_body.len()).map_err(|_| invalid())?;
    let locator = records.host_locator();
    let expected_attempt_digest = Sha256::new()
        .chain_update(CONTROLLER_ATTEMPT_DOMAIN)
        .chain_update(b"AOSCST01")
        .chain_update(locator.execution().as_bytes())
        .chain_update(locator.create_operation().as_bytes())
        .chain_update(original_id)
        .chain_update(plan_digest.as_bytes())
        .chain_update(semantic_digest.as_bytes())
        .chain_update(body_length.to_be_bytes())
        .chain_update(original_body)
        .finalize();
    if request.original_storage_semantic_digest != *semantic_digest.as_bytes()
        || attempt_digest.as_bytes() != expected_attempt_digest.as_slice()
    {
        return Err(invalid());
    }
    Ok((
        request,
        original_id,
        records,
        plan_digest,
        semantic_digest,
        attempt_digest,
    ))
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProtocolValidationError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| invalid())?))
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host Storage output readback")
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, HostExecutionOutputReservationStatusV1, HostExecutionOutputReservationV1,
        RequestHeader,
    };

    use super::*;

    fn fixture() -> (
        ObserveHostStorageOutputRequestV1,
        ObserveHostStorageOutputResponseV1,
        BrokerAssignment,
    ) {
        let (original, assignment) = crate::storage_output_reserve::tests::fixture();
        let records = StorageOutputReserveRecordsV1::from_canonical_records(
            &original.canonical_controller_attempt,
            &original.canonical_controller_settlement,
        )
        .unwrap();
        let locator = records.host_locator();
        let original_body = original.encode_to_vec();
        let original_grant =
            storage_output_reserve_grant_v1(assignment, [18; 16], &original_body).unwrap();
        let semantic_digest = original_grant.argument_commitment().digest();
        let attempt_digest = Sha256::new()
            .chain_update(CONTROLLER_ATTEMPT_DOMAIN)
            .chain_update(b"AOSCST01")
            .chain_update(locator.execution().as_bytes())
            .chain_update(locator.create_operation().as_bytes())
            .chain_update([18; 16])
            .chain_update([21; 32])
            .chain_update(semantic_digest.as_bytes())
            .chain_update((original_body.len() as u16).to_be_bytes())
            .chain_update(&original_body)
            .finalize();
        let request = ObserveHostStorageOutputRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![19; 16],
                audience: Audience::AUDIENCE_STORAGE_BROKER.into(),
                deadline_boottime_nanoseconds: 2_000,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            canonical_original_storage_reserve_request: original_body,
            original_storage_signed_plan_digest: vec![21; 32],
            original_storage_semantic_digest: semantic_digest.as_bytes().to_vec(),
            controller_storage_attempt_digest: attempt_digest.to_vec(),
            ..Default::default()
        };
        let host = HostExecutionOutputReservationV1 {
            status: HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_COMMITTED.into(),
            execution_id: locator.execution().as_bytes().to_vec(),
            create_operation_id: locator.create_operation().as_bytes().to_vec(),
            preissue_record_digest: locator.preissue_digest().as_bytes().to_vec(),
            output_claim_digest: locator.claim_digest().as_bytes().to_vec(),
            reserve_source_digest: locator.carrier_digest().as_bytes().to_vec(),
            original_reserve_request_id: locator.original_request_id().to_vec(),
            assignment_digest: locator.assignment_digest().as_bytes().to_vec(),
            host_boot_id: locator.host_boot_id().to_vec(),
            original_plan_digest: records.attempt()[712..744].to_vec(),
            original_semantic_request_digest: records.attempt()[744..776].to_vec(),
            host_correlation_record_digest: records.settlement()[72..104].to_vec(),
            original_host_journal_sequence: 1,
            ..Default::default()
        };
        let response = ObserveHostStorageOutputResponseV1 {
            canonical_host_output_reservation: host.encode_to_vec(),
            controller_storage_attempt_digest: attempt_digest.to_vec(),
            current_host_assignment: Some(AssignmentFence {
                sandbox_id: vec![9; 16],
                incarnation_id: vec![10; 16],
                assignment_epoch: 1,
                desired_generation: 1,
                assignment_digest: vec![7; 32],
                ..Default::default()
            })
            .into(),
            host_boot_id: locator.host_boot_id().to_vec(),
            protected_host_journal_head_sequence: 2,
            protected_host_journal_head_digest: vec![23; 32],
            ..Default::default()
        };
        (request, response, assignment)
    }

    fn decode_request(
        request: &ObserveHostStorageOutputRequestV1,
    ) -> Result<ValidatedHostStorageOutputReadbackRequestV1, ProtocolValidationError> {
        decode_host_storage_output_readback_request_v1(
            &request.encode_to_vec(),
            PeerCredentials {
                uid: 1,
                gid: 2,
                pid: None,
            },
            PeerPolicy {
                uid: 1,
                gid: Some(2),
                audience: Audience::AUDIENCE_STORAGE_BROKER,
            },
            900,
        )
    }

    #[test]
    fn exact_original_and_fresh_host_grant_are_distinct_from_storage_reserve() {
        let (mut request, response, assignment) = fixture();
        let decoded = decode_request(&request).unwrap();
        let grant =
            host_storage_output_readback_grant_v1(assignment, [19; 16], &request.encode_to_vec())
                .unwrap();
        assert_eq!(grant.verb(), BrokerVerb::HostObserveStorageOutput);
        assert_eq!(decoded.original_storage_request_id(), [18; 16]);
        assert_eq!(
            decoded
                .controller_storage_attempt_digest()
                .as_bytes()
                .as_slice(),
            request.controller_storage_attempt_digest.as_slice(),
        );
        let readback =
            decode_host_storage_output_readback_response_v1(&response.encode_to_vec(), &decoded)
                .unwrap();
        assert_eq!(readback.protected_head_sequence(), 2);
        assert_eq!(readback.original_storage_request_id(), [18; 16]);
        assert_eq!(
            readback.controller_storage_attempt_digest(),
            decoded.controller_storage_attempt_digest(),
        );

        request.controller_storage_attempt_digest[0] ^= 1;
        assert!(decode_request(&request).is_err());
        request.controller_storage_attempt_digest[0] ^= 1;
        request.header.as_option_mut().unwrap().request_id = vec![20; 16];
        let altered_grant =
            host_storage_output_readback_grant_v1(assignment, [20; 16], &request.encode_to_vec())
                .unwrap();
        assert_ne!(
            grant.argument_commitment(),
            altered_grant.argument_commitment()
        );
    }

    #[test]
    fn request_rejects_reused_id_wrong_role_and_original_replay() {
        let (mut request, _, assignment) = fixture();
        request.header.as_option_mut().unwrap().request_id = vec![18; 16];
        assert!(decode_request(&request).is_err());
        assert!(
            host_storage_output_readback_grant_v1(assignment, [18; 16], &request.encode_to_vec(),)
                .is_err()
        );

        request.header.as_option_mut().unwrap().request_id = vec![19; 16];
        request.header.as_option_mut().unwrap().audience =
            Audience::AUDIENCE_NODE_CONTROLLER.into();
        assert!(decode_request(&request).is_err());

        request.header.as_option_mut().unwrap().audience = Audience::AUDIENCE_STORAGE_BROKER.into();
        request
            .header
            .as_option_mut()
            .unwrap()
            .maximum_response_bytes = 0;
        assert!(decode_request(&request).is_err());
        assert!(
            host_storage_output_readback_grant_v1(assignment, [19; 16], &request.encode_to_vec(),)
                .is_err()
        );

        request
            .header
            .as_option_mut()
            .unwrap()
            .maximum_response_bytes = 4_096;
        request.canonical_original_storage_reserve_request[0] ^= 1;
        assert!(decode_request(&request).is_err());
    }

    #[test]
    fn response_rejects_foreign_receipt_assignment_boot_and_head() {
        let (request, response, _) = fixture();
        let decoded = decode_request(&request).unwrap();

        let mut foreign = response.clone();
        let mut host = HostExecutionOutputReservationV1::decode_from_slice(
            &foreign.canonical_host_output_reservation,
        )
        .unwrap();
        host.original_plan_digest[0] ^= 1;
        foreign.canonical_host_output_reservation = host.encode_to_vec();
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );

        let mut foreign = response.clone();
        let mut host = HostExecutionOutputReservationV1::decode_from_slice(
            &foreign.canonical_host_output_reservation,
        )
        .unwrap();
        host.host_correlation_record_digest[0] ^= 1;
        foreign.canonical_host_output_reservation = host.encode_to_vec();
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );

        let mut foreign = response.clone();
        let mut host = HostExecutionOutputReservationV1::decode_from_slice(
            &foreign.canonical_host_output_reservation,
        )
        .unwrap();
        host.original_host_journal_sequence = 2;
        foreign.canonical_host_output_reservation = host.encode_to_vec();
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );

        let mut foreign = response.clone();
        let mut host = HostExecutionOutputReservationV1::decode_from_slice(
            &foreign.canonical_host_output_reservation,
        )
        .unwrap();
        host.status =
            HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_ABSENT
                .into();
        foreign.canonical_host_output_reservation = host.encode_to_vec();
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );

        let mut foreign = response.clone();
        foreign
            .current_host_assignment
            .as_option_mut()
            .unwrap()
            .assignment_epoch = 2;
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );

        let mut foreign = response.clone();
        foreign.host_boot_id[0] ^= 1;
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );

        let mut foreign = response;
        foreign.protected_host_journal_head_sequence = 0;
        assert!(
            decode_host_storage_output_readback_response_v1(&foreign.encode_to_vec(), &decoded,)
                .is_err()
        );
    }
}
