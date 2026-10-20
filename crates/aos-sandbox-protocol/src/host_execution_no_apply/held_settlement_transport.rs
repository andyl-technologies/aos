//! Encodes the finite held-owner42 programme without adopting a native lease.
//!
//! Preliminary asks the actual Host receiver to create its own challenge.
//! FloorSeal and Acknowledge bind the independently signed Root floor and the
//! sole canonical Controller prepare/ACK. Every value here is comparison DATA.
//!
//! ```text
//! AOSHLS02 | header-length:u64be | canonical RequestHeader | command:u64be |
//! command-specific length-framed fields | checksum:32
//! ```

use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};
use aos_sandbox_core::{ObjectDigest, ProtocolId, bounded_codec::BoundedReader};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::closed_controller::{
    CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2, CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2,
    ClosedCreateFailurePrepareDataV2, ControllerCreateFailureAckDataV2,
};
use super::current_lease::{
    CurrentHostNoApplyLeaseDataV2, HostNoApplyLeaseScopeV2,
    MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
};
use super::root_attestation::{
    MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2, RootExecutionNoApplyAttestationDataV2,
};
use super::recovery_acquisition::{
    MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2,
    RootNoApplyRecoveryAcquisitionDataV2,
};
use super::{BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2, ClosedBeforeArgumentNoApplyRecordV2};
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader};

const MAGIC: &[u8; 8] = b"AOSHLS02";
const DOMAIN: &[u8] = b"aos.sandbox.host.held-no-apply-settlement.v2\0";
const MAXIMUM_HEADER_BYTES: usize = 256;
const MAXIMUM_REQUEST_BYTES: usize = 8192;

/// Names one request to an already funded native Host settlement programme.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostNoApplyHeldCommandV2 {
    /// Acquires fresh cleanup reads under a distinct current Root authorization.
    ///
    /// Historical execution bounds remain inert. The Host must independently
    /// retain a new current-control payer and native original before replying.
    RecoveryPreliminary {
        /// Exact dedicated signed cleanup-read authorization, never a floor seal.
        canonical_root_acquisition: Vec<u8>,
    },
    /// Requests a fresh Host challenge over its exact already durable39.
    Preliminary {
        /// Literal closed-before-argument terminal marker.
        marker: ClosedBeforeArgumentNoApplyRecordV2,
        /// Common terminal-group commitment of both literal signed packets.
        archive_head: ObjectDigest,
        /// SHA-256 of the exact literal signed terminal outcome packet.
        signed_terminal_outcome: ObjectDigest,
    },
    /// Seals the actual Root floor and exact Controller prepare on held cuts.
    FloorSeal {
        /// Comparison from the same actual current43 response.
        comparison: CurrentHostNoApplyLeaseDataV2,
        /// Exact canonical Root artifact; signature verification stays native.
        canonical_root_attestation: Vec<u8>,
        /// Sole canonical prepare for those exact six Controller row digests.
        controller_prepare: ClosedCreateFailurePrepareDataV2,
    },
    /// Retains an actual Controller post-CAS ACK before native retirement.
    Acknowledge {
        /// Coordinates of the same retained native lease.
        comparison: CurrentHostNoApplyLeaseDataV2,
        /// Exact closed Controller ACK comparison DATA.
        ack: ControllerCreateFailureAckDataV2,
    },
}

/// Retains one strict authenticated42 body without creating native authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostHeldNoApplySettlementRequestV2 {
    header: ValidatedHeader,
    command: HostNoApplyHeldCommandV2,
}

impl ValidatedHostHeldNoApplySettlementRequestV2 {
    /// Borrows the actual signed request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows its finite comparison-only command.
    #[must_use]
    pub const fn command_v2(&self) -> &HostNoApplyHeldCommandV2 {
        &self.command
    }
}

pub(crate) fn is_held_settlement_request_v2(body: &[u8]) -> bool {
    body.starts_with(MAGIC)
}

/// Encodes the distinct42 grammar after validating its structural joins.
///
/// # Errors
/// Rejects malformed headers, unsupported command data, foreign terminal
/// identities, inconsistent Root/Controller coordinates or excessive framing.
pub fn encode_host_held_no_apply_settlement_request_v2(
    header: &RequestHeader,
    command: &HostNoApplyHeldCommandV2,
) -> Result<Vec<u8>, ProtocolValidationError> {
    let validated = crate::validate_request_header_data_v2(
        header,
        Audience::AUDIENCE_NODE_CONTROLLER,
        ProtocolId::HostBroker,
        0,
    )?;
    validate_command(command)?;
    validate_command_header(command, &validated)?;
    let header = header.encode_to_vec();
    if header.len() > MAXIMUM_HEADER_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    append_field(&mut bytes, &header);
    match command {
        HostNoApplyHeldCommandV2::RecoveryPreliminary {
            canonical_root_acquisition,
        } => {
            bytes.extend_from_slice(&4_u64.to_be_bytes());
            append_field(&mut bytes, canonical_root_acquisition);
        }
        HostNoApplyHeldCommandV2::Preliminary {
            marker,
            archive_head,
            signed_terminal_outcome,
        } => {
            bytes.extend_from_slice(&1_u64.to_be_bytes());
            append_field(&mut bytes, &marker.encode_canonical());
            append_field(&mut bytes, archive_head.as_bytes());
            append_field(&mut bytes, signed_terminal_outcome.as_bytes());
        }
        HostNoApplyHeldCommandV2::FloorSeal {
            comparison,
            canonical_root_attestation,
            controller_prepare,
        } => {
            bytes.extend_from_slice(&2_u64.to_be_bytes());
            append_field(&mut bytes, &comparison.encode_canonical());
            append_field(&mut bytes, canonical_root_attestation);
            append_field(&mut bytes, &controller_prepare.encode_canonical());
        }
        HostNoApplyHeldCommandV2::Acknowledge { comparison, ack } => {
            bytes.extend_from_slice(&3_u64.to_be_bytes());
            append_field(&mut bytes, &comparison.encode_canonical());
            append_field(&mut bytes, &ack.encode_canonical());
        }
    }
    if bytes
        .len()
        .checked_add(32)
        .is_none_or(|length| length > MAXIMUM_REQUEST_BYTES)
    {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let checksum = checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

/// Decodes only the closed42 grammar and its independently current header.
///
/// # Errors
/// Rejects changed checksums, noncanonical framing, foreign audiences/peers,
/// expired headers or structurally inconsistent Root/Controller terminal data.
pub fn decode_host_held_no_apply_settlement_request_v2(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
) -> Result<ValidatedHostHeldNoApplySettlementRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let end = body.len().checked_sub(32).ok_or_else(invalid)?;
    if !is_held_settlement_request_v2(body)
        || body.get(end..) != Some(checksum(&body[..end]).as_slice())
    {
        return Err(invalid());
    }
    let mut reader = BoundedReader::new(&body[8..end], |_| invalid());
    let header_bytes = field(&mut reader, MAXIMUM_HEADER_BYTES)?;
    let raw_header = RequestHeader::decode_from_slice(header_bytes).map_err(|_| invalid())?;
    if !raw_header.__buffa_unknown_fields.is_empty() || raw_header.encode_to_vec() != header_bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header =
        crate::validate_request_header(&raw_header, peer, policy, ProtocolId::HostBroker, now)?;
    if header.audience() != Audience::AUDIENCE_NODE_CONTROLLER {
        return Err(invalid());
    }
    let command = match reader.u64()? {
        1 => HostNoApplyHeldCommandV2::Preliminary {
            marker: ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(field(
                &mut reader,
                BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2,
            )?)
            .map_err(|_| invalid())?,
            archive_head: decode_digest(field(&mut reader, 32)?)?,
            signed_terminal_outcome: decode_digest(field(&mut reader, 32)?)?,
        },
        2 => {
            let comparison = decode_comparison(field(
                &mut reader,
                MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
            )?)?;
            let artifact = field(&mut reader, MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2)?;
            RootExecutionNoApplyAttestationDataV2::decode_canonical(artifact)
                .map_err(|_| invalid())?;
            let key = comparison
                .fields()
                .accepted_source
                .fields()
                .create_operation;
            let controller_prepare = ClosedCreateFailurePrepareDataV2::decode_canonical(
                &key,
                field(&mut reader, CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2)?,
            )
            .map_err(|_| invalid())?;
            HostNoApplyHeldCommandV2::FloorSeal {
                comparison,
                canonical_root_attestation: artifact.to_vec(),
                controller_prepare,
            }
        }
        3 => HostNoApplyHeldCommandV2::Acknowledge {
            comparison: decode_comparison(field(
                &mut reader,
                MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
            )?)?,
            ack: ControllerCreateFailureAckDataV2::decode_canonical(field(
                &mut reader,
                CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2,
            )?)
            .map_err(|_| invalid())?,
        },
        4 => {
            let artifact = field(
                &mut reader,
                MAXIMUM_ROOT_NO_APPLY_RECOVERY_ACQUISITION_BYTES_V2,
            )?;
            RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(artifact)
                .map_err(|_| invalid())?;
            HostNoApplyHeldCommandV2::RecoveryPreliminary {
                canonical_root_acquisition: artifact.to_vec(),
            }
        }
        _ => return Err(invalid()),
    };
    if !reader.is_empty() {
        return Err(invalid());
    }
    validate_command(&command)?;
    validate_command_header(&command, &header)?;
    Ok(ValidatedHostHeldNoApplySettlementRequestV2 { header, command })
}

/// Joins a signed42 response to the exact finite request context.
///
/// # Errors
/// Rejects a changed marker/archive, native owner identity or retained cut,
/// another signed request, a regressed clock or an expired current request.
pub fn decode_host_held_no_apply_settlement_response_v2(
    body: &[u8],
    request: &ValidatedHostHeldNoApplySettlementRequestV2,
    session: [u8; 32],
    signed_request: [u8; 32],
) -> Result<CurrentHostNoApplyLeaseDataV2, ProtocolValidationError> {
    let lease = decode_comparison(body)?;
    let actual = lease.fields();
    match request.command_v2() {
        HostNoApplyHeldCommandV2::RecoveryPreliminary {
            canonical_root_acquisition,
        } => {
            let artifact = RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(
                canonical_root_acquisition,
            ).map_err(|_| invalid())?.fields_v2();
            if actual.scope != HostNoApplyLeaseScopeV2::RecoveryCleanup
                || actual.native_boot != artifact.host_boot
                || actual.native_first_clock < artifact.first_clock
                || actual.native_cutoff > artifact.cutoff
                || actual.native_cutoff != request.header.deadline_boottime_nanoseconds()
                || actual.availability != artifact.historical_availability
                || actual.accepted_source != artifact.accepted_source
                || actual.marker
                    != super::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(artifact.marker)
                || actual.terminal_archive_head != artifact.terminal_archive
                || actual.signed_terminal_outcome != artifact.signed_terminal
                || session != artifact.host_session
            {
                return Err(invalid());
            }
        }
        HostNoApplyHeldCommandV2::Preliminary {
            marker,
            archive_head,
            signed_terminal_outcome,
        } => {
            if actual.scope != HostNoApplyLeaseScopeV2::Active
                || actual.marker
                    != super::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(*marker)
                || actual.terminal_archive_head != *archive_head.as_bytes()
                || actual.signed_terminal_outcome != *signed_terminal_outcome.as_bytes()
            {
                return Err(invalid());
            }
        }
        HostNoApplyHeldCommandV2::FloorSeal { comparison, .. }
        | HostNoApplyHeldCommandV2::Acknowledge { comparison, .. } => {
            let expected = comparison.fields();
            let mut retained = actual;
            retained.current_session = expected.current_session;
            retained.signed_current_request = expected.signed_current_request;
            retained.current_request = expected.current_request;
            retained.observed_clock = expected.observed_clock;
            if retained != expected || actual.observed_clock < expected.observed_clock {
                return Err(invalid());
            }
        }
    }
    if actual.current_session != session
        || actual.signed_current_request != signed_request
        || actual.current_request != *request.header.request_id()
        || actual.observed_clock >= request.header.deadline_boottime_nanoseconds()
    {
        return Err(invalid());
    }
    Ok(lease)
}

fn validate_command(command: &HostNoApplyHeldCommandV2) -> Result<(), ProtocolValidationError> {
    match command {
        HostNoApplyHeldCommandV2::RecoveryPreliminary {
            canonical_root_acquisition,
        } => {
            RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(canonical_root_acquisition)
                .map_err(|_| invalid())?;
            Ok(())
        }
        HostNoApplyHeldCommandV2::Preliminary {
            archive_head,
            signed_terminal_outcome,
            ..
        } if archive_head.as_bytes() != &[0; 32]
            && signed_terminal_outcome.as_bytes() != &[0; 32] =>
        {
            Ok(())
        }
        HostNoApplyHeldCommandV2::FloorSeal {
            comparison,
            canonical_root_attestation,
            controller_prepare,
        } => {
            let artifact =
                RootExecutionNoApplyAttestationDataV2::decode_canonical(canonical_root_attestation)
                    .map_err(|_| invalid())?;
            if artifact.prepare_data_v2() != *controller_prepare
                || artifact.floor_data_v2().fields().host_lease != *comparison
            {
                return Err(invalid());
            }
            Ok(())
        }
        HostNoApplyHeldCommandV2::Acknowledge { comparison, ack }
            if ack.operation.as_bytes()
                == &comparison
                    .fields()
                    .accepted_source
                    .fields()
                    .create_operation =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

fn validate_command_header(
    command: &HostNoApplyHeldCommandV2,
    header: &ValidatedHeader,
) -> Result<(), ProtocolValidationError> {
    if let HostNoApplyHeldCommandV2::RecoveryPreliminary {
        canonical_root_acquisition,
    } = command {
        let artifact = RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(
            canonical_root_acquisition,
        ).map_err(|_| invalid())?.fields_v2();
        if header.deadline_boottime_nanoseconds() > artifact.cutoff
            || *header.request_id() != artifact.controller_nonce[..16]
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn decode_comparison(
    bytes: &[u8],
) -> Result<CurrentHostNoApplyLeaseDataV2, ProtocolValidationError> {
    let comparison =
        CurrentHostNoApplyLeaseDataV2::decode_canonical(bytes).map_err(|_| invalid())?;
    if !matches!(
        comparison.fields().marker,
        super::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(_)
    ) {
        return Err(invalid());
    }
    Ok(comparison)
}

fn decode_digest(bytes: &[u8]) -> Result<ObjectDigest, ProtocolValidationError> {
    bytes
        .try_into()
        .map(ObjectDigest::from_bytes)
        .map_err(|_| invalid())
}

fn field<'a>(
    reader: &mut BoundedReader<'a, ProtocolValidationError>,
    maximum: usize,
) -> Result<&'a [u8], ProtocolValidationError> {
    let length = usize::try_from(reader.u64()?).map_err(|_| invalid())?;
    if length == 0 || length > maximum {
        return Err(invalid());
    }
    reader.bytes(length)
}

fn append_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field);
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("held_no_apply_settlement")
}
