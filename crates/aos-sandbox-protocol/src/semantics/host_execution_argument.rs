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
const NO_APPLY_DOMAIN: &[u8] = b"aos.sandbox.host.execution-no-apply.v1\0";
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.controller-argument-attempt.v1\0";
const SOURCE_BYTES: usize = 336;
const PREIMAGE_FIELDS_BYTES: usize = 1 + 16 + 16 + 8 + 8 + 32 + 16 + 8 + 32;

/// Reports a noncanonical or mismatched method-37/38/39/40 source and request ID.
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

/// Compiles the distinct mutating Host terminal no-Apply grant.
///
/// The grant commits to the original signed method-37 identity as well as the
/// current method-39 request. A carrier alone cannot settle Controller Create.
///
/// # Errors
///
/// Rejects a malformed source, zero original signed identity, or reuse of the
/// original one-shot request ID.
pub fn host_execution_argument_no_apply_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    compile_no_apply(
        1,
        BrokerVerb::HostTerminalNoApply,
        assignment,
        request_id,
        canonical_attempt,
        original_session_binding,
        original_signed_request_digest,
    )
}

/// Compiles the distinct read-only Host no-Apply query grant.
///
/// # Errors
///
/// Rejects a malformed source, zero original signed identity, or reuse of the
/// original one-shot request ID.
pub fn host_execution_argument_query_no_apply_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    compile_no_apply(
        2,
        BrokerVerb::HostQueryNoApply,
        assignment,
        request_id,
        canonical_attempt,
        original_session_binding,
        original_signed_request_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_no_apply(
    method: u8,
    verb: BrokerVerb,
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    let (source, original_request_id) = validated_attempt_v1(canonical_attempt)?;
    if source[184..216] != *assignment.digest().as_bytes()
        || request_id == [0; 16]
        || request_id == original_request_id
        || original_session_binding == [0; 32]
        || original_signed_request_digest == [0; 32]
    {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidSource);
    }

    Ok(CanonicalHostExecutionArgumentSemanticsV1 {
        verb,
        commitment: argument_commitment(
            NO_APPLY_DOMAIN,
            method,
            assignment,
            request_id,
            source,
            Some((original_session_binding, original_signed_request_digest)),
        ),
    })
}

fn compile(
    method: u8,
    verb: BrokerVerb,
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    canonical_attempt: &[u8],
) -> Result<CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1> {
    let (source, original_request_id) = validated_attempt_v1(canonical_attempt)?;
    if source[184..216] != *assignment.digest().as_bytes() {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidSource);
    }
    if request_id == [0; 16]
        || (method == 1 && original_request_id != request_id)
        || (method == 2 && original_request_id == request_id)
    {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidRequestId);
    }

    Ok(CanonicalHostExecutionArgumentSemanticsV1 {
        verb,
        commitment: argument_commitment(DOMAIN, method, assignment, request_id, source, None),
    })
}

fn argument_commitment(
    domain: &[u8],
    method: u8,
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    source: &[u8; SOURCE_BYTES],
    original_identity: Option<([u8; 32], [u8; 32])>,
) -> BrokerArgumentCommitment {
    let mut bytes = Vec::with_capacity(
        domain.len() + PREIMAGE_FIELDS_BYTES + original_identity.map_or(0, |_| 64),
    );
    bytes.extend_from_slice(domain);
    bytes.push(method);
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&(SOURCE_BYTES as u64).to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(source));
    if let Some((session_binding, signed_request_digest)) = original_identity {
        bytes.extend_from_slice(&session_binding);
        bytes.extend_from_slice(&signed_request_digest);
    }
    BrokerArgumentCommitment::for_canonical_bytes(&bytes)
}

pub(crate) fn canonical_attempt_request_id_v1(
    canonical_attempt: &[u8],
) -> Result<[u8; 16], HostExecutionArgumentSemanticErrorV1> {
    validated_attempt_v1(canonical_attempt).map(|(_, request_id)| request_id)
}

fn validated_attempt_v1(
    canonical_attempt: &[u8],
) -> Result<(&[u8; SOURCE_BYTES], [u8; 16]), HostExecutionArgumentSemanticErrorV1> {
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

    // Historical queries may name expired attempts, but every source field
    // required by the Controller's canonical record must still be populated.
    let required_identities = [
        &source[8..24],
        &source[24..40],
        &source[56..88],
        &source[88..120],
        &source[120..152],
        &source[152..184],
        &source[184..216],
        &source[216..248],
        &source[248..264],
        &source[264..296],
        &source[296..304],
    ];
    if required_identities
        .iter()
        .any(|field| field.iter().all(|byte| *byte == 0))
    {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidSource);
    }
    let request_id: [u8; 16] = source[40..56]
        .try_into()
        .map_err(|_| HostExecutionArgumentSemanticErrorV1::InvalidSource)?;
    if request_id == [0; 16] {
        return Err(HostExecutionArgumentSemanticErrorV1::InvalidRequestId);
    }
    Ok((source, request_id))
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
        bytes[8..40].fill(1);
        bytes[40..56].copy_from_slice(&[7; 16]);
        bytes[56..184].fill(2);
        bytes[184..216].copy_from_slice(assignment.digest().as_bytes());
        bytes[216..304].fill(3);
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

    #[test]
    fn terminal_grants_bind_original_signed_identity_and_remain_method_separated() {
        let assignment = assignment();
        let source = attempt(assignment);
        let terminal = host_execution_argument_no_apply_grant_v1(
            assignment, [9; 16], &source, [10; 32], [11; 32],
        )
        .unwrap();
        let query = host_execution_argument_query_no_apply_grant_v1(
            assignment, [12; 16], &source, [10; 32], [11; 32],
        )
        .unwrap();

        assert_eq!(terminal.verb(), BrokerVerb::HostTerminalNoApply);
        assert_eq!(query.verb(), BrokerVerb::HostQueryNoApply);
        assert_eq!(terminal.target(), BrokerGrantTarget::Assignment);
        assert_ne!(terminal.commitment(), query.commitment());
        assert_ne!(
            terminal.commitment(),
            host_execution_argument_no_apply_grant_v1(
                assignment, [9; 16], &source, [10; 32], [12; 32],
            )
            .unwrap()
            .commitment(),
        );
        assert_eq!(
            host_execution_argument_no_apply_grant_v1(
                assignment, [7; 16], &source, [10; 32], [11; 32],
            ),
            Err(HostExecutionArgumentSemanticErrorV1::InvalidSource),
        );
        assert_eq!(
            host_execution_argument_query_no_apply_grant_v1(
                assignment, [12; 16], &source, [0; 32], [11; 32],
            ),
            Err(HostExecutionArgumentSemanticErrorV1::InvalidSource),
        );
    }

    #[test]
    fn every_required_source_field_stays_required_after_checksum_recalculation() {
        let assignment = assignment();
        let source = attempt(assignment);
        let required_fields = [
            8..24,
            24..40,
            40..56,
            56..88,
            88..120,
            120..152,
            152..184,
            184..216,
            216..248,
            248..264,
            264..296,
            296..304,
        ];

        for field in required_fields {
            let mut malformed = source;
            malformed[field].fill(0);
            let checksum = Sha256::new()
                .chain_update(SOURCE_DOMAIN)
                .chain_update(&malformed[..304])
                .finalize();
            malformed[304..].copy_from_slice(&checksum);

            assert!(
                host_execution_argument_observe_grant_v1(assignment, [7; 16], &malformed).is_err()
            );
            assert!(
                host_execution_argument_query_grant_v1(assignment, [8; 16], &malformed).is_err()
            );
            assert!(
                host_execution_argument_no_apply_grant_v1(
                    assignment, [9; 16], &malformed, [10; 32], [11; 32],
                )
                .is_err()
            );
            assert!(
                host_execution_argument_query_no_apply_grant_v1(
                    assignment, [12; 16], &malformed, [10; 32], [11; 32],
                )
                .is_err()
            );
        }

        let mut expired = source;
        expired[296..304].copy_from_slice(&1_u64.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(SOURCE_DOMAIN)
            .chain_update(&expired[..304])
            .finalize();
        expired[304..].copy_from_slice(&checksum);
        assert!(
            host_execution_argument_no_apply_grant_v1(
                assignment, [9; 16], &expired, [10; 32], [11; 32],
            )
            .is_ok()
        );
    }
}
