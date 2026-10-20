//! Binds a fresh signed43 read to the actual retained NoApply lease.
//!
//! The supplied comparison is inert DATA. The Host must already own the exact
//! native lease; decoding cannot reconstruct it. Root independently compares
//! the read nonce with its own paid opening, then reads the actual signed
//! outcome through the same protected ControllerHostClient Session history.
//!
//! ```text
//! AOSHLQ02 | header-length:u64be | canonical RequestHeader |
//! lease-length:u64be | canonical AOSHLV02 | Root-read-nonce:32 | checksum:32
//! ```

use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::current_lease::CurrentHostNoApplyLeaseDataV2;
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader};

const MAGIC: &[u8; 8] = b"AOSHLQ02";
const DOMAIN: &[u8] = b"aos.sandbox.host.current-no-apply-lease-query.v2\0";
const MAXIMUM_HEADER_BYTES: usize = 256;
const MAXIMUM_QUERY_BYTES: usize = 2048;

/// Retains the exact comparison and Root challenge from a signed current read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostNoApplyCurrentLeaseQueryV2 {
    header: ValidatedHeader,
    comparison: CurrentHostNoApplyLeaseDataV2,
    read_nonce: [u8; 32],
}

impl ValidatedHostNoApplyCurrentLeaseQueryV2 {
    /// Borrows the actual current request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns inert coordinates of the already existing native lease.
    #[must_use]
    pub const fn comparison_v2(&self) -> CurrentHostNoApplyLeaseDataV2 {
        self.comparison
    }

    /// Returns the nonce that Root must compare with its actual paid opening.
    #[must_use]
    pub const fn read_nonce_v2(&self) -> [u8; 32] {
        self.read_nonce
    }
}

pub(crate) fn is_current_lease_query_v2(body: &[u8]) -> bool {
    body.starts_with(MAGIC)
}

/// Encodes a distinct closed43 read without creating a native owner.
///
/// # Errors
/// Rejects malformed headers, zero challenges, reused request identities, or
/// a request that cannot overlap the existing native lease interval.
pub fn encode_host_no_apply_current_lease_query_v2(
    header: &RequestHeader,
    comparison: CurrentHostNoApplyLeaseDataV2,
    read_nonce: [u8; 32],
) -> Result<Vec<u8>, ProtocolValidationError> {
    let validated = crate::validate_request_header_data_v2(
        header,
        Audience::AUDIENCE_NODE_CONTROLLER,
        ProtocolId::HostBroker,
        0,
    )?;
    validate_comparison(&validated, comparison, read_nonce)?;
    let header = header.encode_to_vec();
    if header.len() > MAXIMUM_HEADER_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let lease = comparison.encode_canonical();
    let mut bytes = Vec::with_capacity(8 + 8 + header.len() + 8 + lease.len() + 64);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(header.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&(lease.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&lease);
    bytes.extend_from_slice(&read_nonce);
    let digest = checksum(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

/// Decodes the new explicit query and independently validates its live header.
///
/// # Errors
/// Rejects malformed or noncanonical framing, changed checksums, foreign peer
/// or audience, expired requests, and structurally inconsistent comparisons.
pub fn decode_host_no_apply_current_lease_query_v2(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
) -> Result<ValidatedHostNoApplyCurrentLeaseQueryV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_QUERY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if !is_current_lease_query_v2(body) {
        return Err(invalid());
    }
    let checksum_start = body.len().checked_sub(32).ok_or_else(invalid)?;
    if body.get(checksum_start..) != Some(checksum(&body[..checksum_start]).as_slice()) {
        return Err(invalid());
    }
    let mut cursor = 8;
    let header_bytes = field(body, &mut cursor, MAXIMUM_HEADER_BYTES, checksum_start)?;
    let header = RequestHeader::decode_from_slice(header_bytes).map_err(|_| invalid())?;
    if !header.__buffa_unknown_fields.is_empty() || header.encode_to_vec() != header_bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header =
        crate::validate_request_header(&header, peer, policy, ProtocolId::HostBroker, now)?;
    if header.audience() != Audience::AUDIENCE_NODE_CONTROLLER {
        return Err(invalid());
    }
    let lease = field(
        body,
        &mut cursor,
        super::current_lease::MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
        checksum_start,
    )?;
    let comparison =
        CurrentHostNoApplyLeaseDataV2::decode_canonical(lease).map_err(|_| invalid())?;
    let nonce_end = cursor.checked_add(32).ok_or_else(invalid)?;
    if nonce_end != checksum_start {
        return Err(invalid());
    }
    let read_nonce = body
        .get(cursor..nonce_end)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    validate_comparison(&header, comparison, read_nonce)?;
    if now >= comparison.fields().native_cutoff {
        return Err(ProtocolValidationError::DeadlineExpired);
    }
    Ok(ValidatedHostNoApplyCurrentLeaseQueryV2 {
        header,
        comparison,
        read_nonce,
    })
}

/// Validates an actual signed43 response against that exact request context.
///
/// The fresh Root nonce is committed by the signed current request digest.
/// Original settlement challenge, marker, archive, clocks and native cuts stay
/// unchanged. A valid result remains DATA until the genuine native reader and
/// paid Root opening independently verify the matching live owner.
///
/// # Errors
/// Rejects a different native interval, original source or terminal identity,
/// changed cuts/head/epoch, foreign signed request or expired observed clock.
pub fn decode_host_no_apply_current_lease_response_v2(
    body: &[u8],
    original: &ValidatedHostNoApplyCurrentLeaseQueryV2,
    current_session: [u8; 32],
    signed_current_request: [u8; 32],
) -> Result<CurrentHostNoApplyLeaseDataV2, ProtocolValidationError> {
    let observed = CurrentHostNoApplyLeaseDataV2::decode_canonical(body).map_err(|_| invalid())?;
    let actual = observed.fields();
    let expected = original.comparison.fields();
    // Only fresh signed-read coordinates and its actual native sample vary.
    // Equal DATA never supplies the retained owner or a new cleanup interval.
    let mut retained = actual;
    retained.current_session = expected.current_session;
    retained.signed_current_request = expected.signed_current_request;
    retained.current_request = expected.current_request;
    retained.observed_clock = expected.observed_clock;
    if retained != expected
        || actual.current_session != current_session
        || actual.signed_current_request != signed_current_request
        || actual.current_request != *original.header.request_id()
        || actual.observed_clock < expected.observed_clock
        || actual.observed_clock >= original.header.deadline_boottime_nanoseconds()
    {
        return Err(invalid());
    }
    Ok(observed)
}

fn validate_comparison(
    header: &ValidatedHeader,
    comparison: CurrentHostNoApplyLeaseDataV2,
    nonce: [u8; 32],
) -> Result<(), ProtocolValidationError> {
    let fields = comparison.fields();
    if nonce == [0; 32]
        || *header.request_id() == fields.current_request
        || header.deadline_boottime_nanoseconds() <= fields.observed_clock
    {
        return Err(invalid());
    }
    Ok(())
}

fn field<'a>(
    body: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
    end: usize,
) -> Result<&'a [u8], ProtocolValidationError> {
    let length_end = cursor.checked_add(8).ok_or_else(invalid)?;
    let encoded = body.get(*cursor..length_end).ok_or_else(invalid)?;
    let length = usize::try_from(u64::from_be_bytes(
        encoded.try_into().map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    let field_end = length_end.checked_add(length).ok_or_else(invalid)?;
    if length == 0 || length > maximum || field_end > end {
        return Err(invalid());
    }
    *cursor = field_end;
    body.get(length_end..field_end).ok_or_else(invalid)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("current_host_no_apply_lease_query_v2")
}
