//! Method-separated signed grants for one Controller argument attempt.
//!
//! ```text
//! commitment preimage = "aos.sandbox.host.execution-argument.v1\0"
//!   || method:u8 || assignment tuple || request-id:16
//!   || source-length:u64be || SHA256(canonical AOSCIA02):32
//! ```
//!
//! AOSCIA02 is structural and nonauthorizing. The Host must still match the
//! signed plan, current assignment, protected output record, and retained
//! Guest session before sending a challenge. Query uses a distinct verb and
//! a fresh request ID and can return historical digests only.

use aos_sandbox_core::{BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb};
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.host.execution-argument.v1\0";
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.controller-argument-attempt.v1\0";
const SOURCE_BYTES: usize = 336;

/// Reports a noncanonical or mismatched method-37/38 source and request ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostExecutionArgumentSemanticErrorV1 {
    /// The authenticated-session request ID is zero or misbound.
    #[error("Host execution argument request ID is invalid")]
    InvalidRequestId,
    /// The exact AOSCIA02 source or assignment is invalid.
    #[error("Host execution argument source is invalid")]
    InvalidSource,
}

/// Carries the exact Host-audience plan commitment for one method-37/38 attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHostExecutionArgumentSemanticsV1 {
    verb: BrokerVerb,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalHostExecutionArgumentSemanticsV1 {
    /// Returns the distinct observe or historical-query verb.
    #[must_use]
    pub const fn verb(self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment-scoped Host grant target.
    #[must_use]
    pub const fn target(self) -> BrokerGrantTarget {
        BrokerGrantTarget::Assignment
    }

    /// Returns the canonical method/request/source commitment.
    #[must_use]
    pub const fn commitment(self) -> BrokerArgumentCommitment {
        self.commitment
    }
}

/// Compiles the one-shot fresh Guest observation grant.
///
/// # Errors
///
/// Rejects a noncanonical AOSCIA02 or an attempt whose embedded request ID or
/// assignment differs from the actual authenticated-session coordinates.
pub fn host_execution_argument_observe_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    compile(
        1,
        BrokerVerb::HostObserveExecutionArgument,
        assignment,
        request_id,
        canonical_attempt,
    )
}

/// Compiles a read-only grant for the original one-shot attempt.
///
/// # Errors
///
/// Rejects a noncanonical AOSCIA02, an unspecified request ID, or reuse of the
/// original observe ID as the query's fresh session ID.
pub fn host_execution_argument_query_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    compile(
        2,
        BrokerVerb::HostQueryExecutionArgument,
        assignment,
        request_id,
        canonical_attempt,
    )
}

fn compile(
    method: u8,
    verb: BrokerVerb,
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    let original_request_id = canonical_attempt_request_id_v1(canonical_attempt)?;
    let source: &[u8; SOURCE_BYTES] = canonical_attempt
        .try_into()
        .map_err(|_| HostExecutionArgumentSemanticErrorV1::InvalidSource)?;
    if source[184..216] != *assignment.digest().as_bytes() {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidSource);
    }
    if request_id == [0; 16]
        || (method == 1 && original_request_id != request_id)
        || (method == 2 && original_request_id == request_id)
    {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidRequestId);
    }

    let mut bytes = Vec::with_capacity(DOMAIN.len() + 1 + 16 + 16 + 8 + 8 + 32 + 16 + 8 + 32);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(method);
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&(SOURCE_BYTES as u64).to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(source));
    Ok(CanonicalHostExecutionArgumentSemanticsV1 {
        verb,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

pub(crate) fn canonical_attempt_request_id_v1(
    canonical_attempt: &[u8],
) -> Result<[u8; 16], HostExecutionArgumentSemanticErrorV1> {
    let source: &[u8; SOURCE_BYTES] = canonical_attempt
        .try_into()
        .map_err(|_| HostExecutionArgumentSemanticErrorV1::InvalidSource)?;
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(SOURCE_DOMAIN)
        .chain_update(&source[..304])
        .finalize()
        .into();
    if &source[..8] != b"AOSCIA02" || source[304..] != checksum {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidSource);
    }
    let request_id: [u8; 16] = source[40..56]
        .try_into()
        .map_err(|_| HostExecutionArgumentSemanticErrorV1::InvalidSource)?;
    if request_id == [0; 16] {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidRequestId);
    }
    Ok(request_id)
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, IncarnationId, ObjectDigest, SandboxId,
    };

    use super::*;

    fn assignment() -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap()
    }

    fn attempt(assignment: BrokerAssignment) -> [u8; SOURCE_BYTES] {
        let mut bytes = [0; SOURCE_BYTES];
        bytes[..8].copy_from_slice(b"AOSCIA02");
        bytes[40..56].copy_from_slice(&[7; 16]);
        bytes[184..216].copy_from_slice(assignment.digest().as_bytes());
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(SOURCE_DOMAIN)
            .chain_update(&bytes[..304])
            .finalize()
            .into();
        bytes[304..].copy_from_slice(&checksum);
        bytes
    }

    #[test]
    fn observe_and_historical_query_have_distinct_attempt_bound_grants() {
        let assignment = assignment();
        let source = attempt(assignment);
        let observe =
            host_execution_argument_observe_grant_v1(assignment, [7; 16], &source).unwrap();
        let query = host_execution_argument_query_grant_v1(assignment, [8; 16], &source).unwrap();

        assert_eq!(observe.verb(), BrokerVerb::HostObserveExecutionArgument);
        assert_eq!(query.verb(), BrokerVerb::HostQueryExecutionArgument);
        assert_eq!(observe.target(), BrokerGrantTarget::Assignment);
        assert_ne!(observe.commitment(), query.commitment());
        assert_eq!(
            host_execution_argument_observe_grant_v1(assignment, [8; 16], &source),
            Err(HostExecutionArgumentSemanticErrorV1::InvalidRequestId)
        );
        assert_eq!(
            host_execution_argument_query_grant_v1(assignment, [7; 16], &source),
            Err(HostExecutionArgumentSemanticErrorV1::InvalidRequestId)
        );

        let mut changed = source;
        changed[120] ^= 1;
        assert_eq!(
            host_execution_argument_observe_grant_v1(assignment, [7; 16], &changed),
            Err(HostExecutionArgumentSemanticErrorV1::InvalidSource)
        );
        assert_eq!(
            host_execution_argument_observe_grant_v1(
                BrokerAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.desired_generation(),
                    ObjectDigest::from_bytes([6; 32]),
                )
                .unwrap(),
                [7; 16],
                &source,
            ),
            Err(HostExecutionArgumentSemanticErrorV1::InvalidSource)
        );
    }
}
