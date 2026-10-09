//! Closed zero-descriptor Git-project coverage comparison flights.
//!
//! ```text
//! Mount 2.0:  Prepare53 / Read54
//! Storage1.0: Prepare55 / Read56
//! cleared RequestHeader + canonical DATA <=3072; signed packet <=4096
//! response request_id16 + AOSGUFO1[340]; zero request/reply descriptors
//! ```
//!
//! The authenticated session owns signatures, nonce freshness and original
//! peer custody. These canonical bodies grant no reservation, allocation,
//! currentness, retirement, floor or resource-account authority.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerMethod, GitProjectCoverageRequestV1, GitProjectCoverageResponseV1,
};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBrokerRoleV1, GitCoverageFlightV1, GitCoverageOutcomeFieldsV1,
    GitCoverageOutcomeV1, GitCoverageRequestV1,
};
use buffa::Message as _;

use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    validate_request_header};

/// Maximum complete canonical cleared request, checked before wire allocation.
pub const GIT_COVERAGE_CLEARED_REQUEST_MAXIMUM_BYTES_V1: usize = 3072;
/// Maximum whole authenticated packet and negotiated response budget.
pub const GIT_COVERAGE_PACKET_MAXIMUM_BYTES_V1: usize = 4096;

/// Retains one genuine header-checked body without creating an owner permit.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedGitProjectCoverageRequestV1 {
    wire: GitProjectCoverageRequestV1,
    header: ValidatedHeader,
    method: BrokerMethod,
}

impl ValidatedGitProjectCoverageRequestV1 {
    /// Borrows the unchanged decoded canonical wire carrier.
    #[must_use]
    pub fn wire(&self) -> &GitProjectCoverageRequestV1 {
        &self.wire
    }

    /// Borrows the peer-checked current dispatch header.
    #[must_use]
    pub fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact closed signed method, not an effect grant.
    #[must_use]
    pub fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Borrows canonical inner DATA through its sole shape decoder.
    ///
    /// # Errors
    /// Reports a changed or malformed carrier; no authority is reconstructed.
    pub fn comparison(&self) -> Result<GitCoverageRequestV1<'_>, ProtocolValidationError> {
        GitCoverageRequestV1::decode(&self.wire.coverage)
            .map_err(|_| ProtocolValidationError::InvalidField("Git coverage DATA"))
    }
}

/// Decodes the bounded live body using the existing peer/header engine.
///
/// # Errors
/// Rejects oversized, foreign-method/audience, unknown or noncanonical wire,
/// invalid original peer/deadline, changed role/flight, or response budgets
/// other than the fixed4096 profile. No owner census is inferred here.
pub fn decode_git_project_coverage_request_v1(
    bytes: &[u8],
    method: BrokerMethod,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedGitProjectCoverageRequestV1, ProtocolValidationError> {
    if bytes.len() > GIT_COVERAGE_CLEARED_REQUEST_MAXIMUM_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let (protocol, role, flight) = method_coordinates(method)?;
    if policy.audience != Audience::AUDIENCE_NODE_CONTROLLER {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let wire = GitProjectCoverageRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !wire.__buffa_unknown_fields.is_empty() || wire.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        wire.header.as_option().ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        protocol,
        now_boottime_nanoseconds,
    )?;
    if header.maximum_response_bytes() != GIT_COVERAGE_PACKET_MAXIMUM_BYTES_V1 as u32 {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    let comparison = GitCoverageRequestV1::decode(&wire.coverage)
        .map_err(|_| ProtocolValidationError::InvalidField("Git coverage DATA"))?;
    if comparison.coordinates().role != role || comparison.flight() != flight {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    Ok(ValidatedGitProjectCoverageRequestV1 { wire, header, method })
}

/// Compares a complete response with the whole original current request.
///
/// # Errors
/// Rejects oversized/noncanonical wire, foreign request ID or substituted
/// inner coordinates. Authentication and native readback stay with owners.
pub fn compare_git_project_coverage_response_v1(
    bytes: &[u8],
    original: &ValidatedGitProjectCoverageRequestV1,
) -> Result<GitProjectCoverageResponseV1, ProtocolValidationError> {
    if bytes.len() > GIT_COVERAGE_PACKET_MAXIMUM_BYTES_V1 {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    let response = GitProjectCoverageResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if response.request_id.as_slice() != original.header.request_id() {
        return Err(ProtocolValidationError::InvalidField("Git coverage response request ID"));
    }
    let request = original.comparison()?;
    let outcome = GitCoverageOutcomeV1::decode(&response.coverage)
        .map_err(|_| ProtocolValidationError::InvalidField("Git coverage outcome DATA"))?;
    outcome.compare_request(&request)
        .map_err(|_| ProtocolValidationError::InvalidField("Git coverage original request"))?;
    Ok(response)
}

/// Builds the sole canonical response body from owner-supplied readback DATA.
///
/// # Errors
/// Rejects malformed readback coordinates, original-request substitution or
/// the complete response bound. This performs no signature or owner effect.
pub fn encode_git_project_coverage_response_v1(
    original: &ValidatedGitProjectCoverageRequestV1,
    readback: GitCoverageOutcomeFieldsV1,
) -> Result<Vec<u8>, ProtocolValidationError> {
    let coverage = readback.encode()
        .map_err(|_| ProtocolValidationError::InvalidField("Git coverage readback DATA"))?;
    let response = GitProjectCoverageResponseV1 {
        request_id: original.header.request_id().to_vec(),
        coverage: coverage.to_vec(),
        ..Default::default()
    };
    let bytes = response.encode_to_vec();
    compare_git_project_coverage_response_v1(&bytes, original)?;
    Ok(bytes)
}

/// Returns the exact protocol/role/flight mapping for the four new methods.
///
/// # Errors
/// Refuses every old method and sentinel instead of selecting a default role.
pub fn method_coordinates(
    method: BrokerMethod,
) -> Result<(ProtocolId, GitCoverageBrokerRoleV1, GitCoverageFlightV1), ProtocolValidationError> {
    match method {
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1 => {
            Ok((ProtocolId::MountBroker, GitCoverageBrokerRoleV1::Mount, GitCoverageFlightV1::Prepare))
        }
        BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1 => {
            Ok((ProtocolId::MountBroker, GitCoverageBrokerRoleV1::Mount, GitCoverageFlightV1::Read))
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1 => {
            Ok((ProtocolId::StorageBroker, GitCoverageBrokerRoleV1::Storage, GitCoverageFlightV1::Prepare))
        }
        BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => {
            Ok((ProtocolId::StorageBroker, GitCoverageBrokerRoleV1::Storage, GitCoverageFlightV1::Read))
        }
        _ => Err(ProtocolValidationError::MethodMismatch),
    }
}
