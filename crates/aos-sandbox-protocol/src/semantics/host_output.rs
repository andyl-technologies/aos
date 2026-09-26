//! Canonical signed semantics for provisional Host output reservation.
//!
//! The Controller source and Host request both use these method-separated
//! bytes. The source must be structurally decoded before a broker effect;
//! this compiler binds bytes but does not establish accepted Create authority.
//!
//! ```text
//! "aos.sandbox.host.output-reserve.v1\0" || method:u8
//! || sandbox:16 || incarnation:16 || epoch:u64be
//! || desired-generation:u64be || assignment-digest:32
//! || request-id:16 || body-bytes:u64be || SHA256(body):32
//! ```

use aos_sandbox_core::{BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb};
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.host.output-reserve.v1\0";
const MAXIMUM_BODY_BYTES: usize = 4 * 1_024;

/// Rejects a missing or unbounded signed Host output source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostOutputSemanticErrorV1 {
    /// The broker attempt identifier is unspecified.
    #[error("Host output request ID is unspecified")]
    InvalidRequestId,
    /// The canonical source or query body exceeds its profile bound.
    #[error("Host output source body is empty or oversized")]
    InvalidBody,
}

/// Carries the exact signed plan-match tuple for one Host output method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHostOutputSemanticsV1 {
    verb: BrokerVerb,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalHostOutputSemanticsV1 {
    /// Returns the distinct reserve or query grant verb.
    #[must_use]
    pub const fn verb(self) -> BrokerVerb {
        self.verb
    }

    /// Returns the current assignment target required by both methods.
    #[must_use]
    pub const fn target(self) -> BrokerGrantTarget {
        BrokerGrantTarget::Assignment
    }

    /// Returns the complete method- and attempt-separated argument commitment.
    #[must_use]
    pub const fn commitment(self) -> BrokerArgumentCommitment {
        self.commitment
    }
}

/// Compiles a reserve grant for canonical AOSCIR01 bytes and one request ID.
///
/// A structurally valid source and a signature-verified plan are separate
/// requirements. This function does not mint either authority.
///
/// # Errors
///
/// Rejects an unspecified request ID or empty/oversized source bytes.
pub fn host_output_reserve_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    source: &[u8],
) -> Result<CanonicalHostOutputSemanticsV1, HostOutputSemanticErrorV1> {
    compile(
        1,
        BrokerVerb::HostReserveExecutionOutput,
        assignment,
        request_id,
        source,
    )
}

/// Compiles a read-only query grant for one canonical query body and attempt.
///
/// # Errors
///
/// Rejects an unspecified request ID or empty/oversized query bytes.
pub fn host_output_query_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    query: &[u8],
) -> Result<CanonicalHostOutputSemanticsV1, HostOutputSemanticErrorV1> {
    compile(
        2,
        BrokerVerb::HostQueryExecutionOutput,
        assignment,
        request_id,
        query,
    )
}

fn compile(
    method: u8,
    verb: BrokerVerb,
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<CanonicalHostOutputSemanticsV1, HostOutputSemanticErrorV1> {
    if request_id == [0; 16] {
        return Err(HostOutputSemanticErrorV1::InvalidRequestId);
    }
    if body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(HostOutputSemanticErrorV1::InvalidBody);
    }

    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + 16 + 8 + 8 + 32 + 16 + 8 + 32 + 1);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(method);
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(body));

    Ok(CanonicalHostOutputSemanticsV1 {
        verb,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, IncarnationId, ObjectDigest, SandboxId,
    };

    fn assignment(epoch: u64) -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(epoch),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap()
    }

    #[test]
    fn host_output_grants_bind_method_assignment_attempt_and_exact_body() {
        let original =
            host_output_reserve_grant_v1(assignment(1), [6; 16], b"AOSCIR01 source").unwrap();
        assert_eq!(original.verb(), BrokerVerb::HostReserveExecutionOutput);
        assert_eq!(original.target(), BrokerGrantTarget::Assignment);
        assert_ne!(
            original.commitment(),
            host_output_query_grant_v1(assignment(1), [6; 16], b"AOSCIR01 source")
                .unwrap()
                .commitment()
        );
        assert_ne!(
            original.commitment(),
            host_output_reserve_grant_v1(assignment(2), [6; 16], b"AOSCIR01 source")
                .unwrap()
                .commitment()
        );
        assert_ne!(
            original.commitment(),
            host_output_reserve_grant_v1(assignment(1), [7; 16], b"AOSCIR01 source")
                .unwrap()
                .commitment()
        );
        assert_ne!(
            original.commitment(),
            host_output_reserve_grant_v1(assignment(1), [6; 16], b"AOSCIR01 source!")
                .unwrap()
                .commitment()
        );
    }

    #[test]
    fn host_output_grants_reject_unspecified_attempt_and_body() {
        assert!(host_output_reserve_grant_v1(assignment(1), [0; 16], b"source").is_err());
        assert!(host_output_reserve_grant_v1(assignment(1), [6; 16], b"").is_err());
        assert!(
            host_output_query_grant_v1(assignment(1), [6; 16], &[0; MAXIMUM_BODY_BYTES + 1])
                .is_err()
        );
    }
}
