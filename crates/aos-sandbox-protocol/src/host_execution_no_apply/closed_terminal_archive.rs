//! Defines common H/T DATA for the exact signed closed-before-argument39 group.
//!
//! Host and Controller durable Session heads include endpoint-local bindings,
//! so their local head hashes cannot be compared. This digest instead commits
//! the same literal source, marker and signed request/outcome packets. Actual
//! native archive retention, paid observation and currentness remain separate.
//!
//! ```text
//! SHA256(domain | source-length:u64be | AOSNAB02 |
//!        marker-length:u64be | AOSHNB02 |
//!        request-length:u64be | canonical-signed39-request |
//!        outcome-length:u64be | canonical-signed39-outcome)
//! ```

use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod;
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::ProtocolValidationError;
use crate::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1 as OutcomeDirection,
    AuthenticatedBrokerRequestDirectionV1 as RequestDirection,
};

use super::{
    ClosedBeforeArgumentNoApplyRecordV2, decode_host_before_argument_no_apply_response_v2,
    signed_host_no_apply_terminal_outcome_digest_v2,
};

const DOMAIN: &[u8] = b"aos.sandbox.host.closed-before-argument-terminal-archive.v2\0";

/// Carries matching terminal-group commitments without native archive authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedHostTerminalArchiveDataV2 {
    marker: ClosedBeforeArgumentNoApplyRecordV2,
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
}

impl ClosedHostTerminalArchiveDataV2 {
    /// Returns the exact closed marker decoded from the authenticated outcome.
    #[must_use]
    pub const fn marker(self) -> ClosedBeforeArgumentNoApplyRecordV2 {
        self.marker
    }

    /// Returns the common length-framed group digest, independent of endpoint.
    #[must_use]
    pub const fn archive_head(self) -> ObjectDigest {
        self.archive_head
    }

    /// Returns the existing canonical signed terminal packet SHA256 identity.
    #[must_use]
    pub const fn signed_terminal_outcome(self) -> ObjectDigest {
        self.signed_terminal_outcome
    }
}

/// Prices this extra bounded decode, reencoding and DATA carrier before entry.
///
/// Signed packet buffers stay borrowed from their actual retained admission.
/// Their genuine owner separately pays archive copies and native currentness.
#[must_use]
pub fn closed_host_terminal_archive_receiving_bytes_v2(
    response_body_bytes: usize,
) -> Option<usize> {
    super::before_argument_no_apply_receiving_bytes_v2(response_body_bytes)?
        .checked_add(std::mem::size_of::<ClosedHostTerminalArchiveDataV2>().checked_mul(3)?)
}

/// Joins an authenticated closed39 outcome to common terminal-group H/T DATA.
///
/// Both genuine endpoint direction pairs preserve identical literal packets.
/// The helper cannot create a native archive, current lease or floor permission.
///
/// # Errors
/// Rejects another method, direction mismatch, error outcome, legacy branch,
/// query, noncanonical response or a different source/marker/request relation.
pub fn closed_host_terminal_archive_data_v2(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ClosedHostTerminalArchiveDataV2, ProtocolValidationError> {
    let request = outcome.request();
    if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
        || request.method() != outcome.method()
        || !matches!(
            (request.direction(), outcome.direction()),
            (
                RequestDirection::ClientSend,
                OutcomeDirection::ClientReceive
            ) | (
                RequestDirection::ServerReceive,
                OutcomeDirection::ServerSend
            )
        )
    {
        return Err(invalid());
    }
    let original = request
        .host_before_argument_no_apply_data_v2()
        .ok_or_else(invalid)?;
    if original.is_query() || original.exact_body() != request.exact_body() {
        return Err(invalid());
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(invalid());
    };
    let marker = decode_host_before_argument_no_apply_response_v2(
        exact_body,
        original,
        request.session_binding(),
        request.signed_request_digest(),
    )?;
    let source = original.source().encode_canonical();
    let marker_bytes = marker.encode_canonical();
    let archive_head = terminal_group_digest_v2([
        source.as_slice(),
        marker_bytes.as_slice(),
        request.canonical_packet(),
        outcome.canonical_packet(),
    ])?;
    Ok(ClosedHostTerminalArchiveDataV2 {
        marker,
        archive_head,
        signed_terminal_outcome: signed_host_no_apply_terminal_outcome_digest_v2(outcome),
    })
}

fn terminal_group_digest_v2(fields: [&[u8]; 4]) -> Result<ObjectDigest, ProtocolValidationError> {
    let mut hash = Sha256::new().chain_update(DOMAIN);
    for field in fields {
        let width = u64::try_from(field.len()).map_err(|_| invalid())?;
        hash.update(width.to_be_bytes());
        hash.update(field);
    }
    Ok(ObjectDigest::from_bytes(hash.finalize().into()))
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("closed_host_terminal_archive_v2")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_framing_distinguishes_packet_boundaries_and_order() {
        let original = terminal_group_digest_v2([b"source", b"marker", b"ab", b"c"]).unwrap();
        let moved_boundary = terminal_group_digest_v2([b"source", b"marker", b"a", b"bc"]).unwrap();
        let reversed_packets =
            terminal_group_digest_v2([b"source", b"marker", b"c", b"ab"]).unwrap();
        assert_ne!(original, moved_boundary);
        assert_ne!(original, reversed_packets);
    }
}
