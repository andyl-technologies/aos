//! Canonical signed semantics for protected Host execution handoffs.
//!
//! The request header belongs to the individual broker attempt. These bytes
//! bind the stable controller operation and every field that can change the
//! guest action to the protected runtime assignment.
//!
//! ```text
//! domain || method:u8 || assignment
//! || operation_id:16 || execution_id:16 || source_commitment:32
//! || action:u8 || action_arguments
//! ```

use aos_sandbox_core::runtime_backend::EffectOperationV1;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb, ExecutionId,
    ExecutionSpecV1, ObjectDigest, encode_execution_spec_v1,
};

use crate::host_execution::{
    HOST_EXECUTION_CONTROL_CONTENT_V1, HostExecutionSpecContentFieldsV1,
    MAXIMUM_HOST_EXECUTION_SPEC_BYTES, ValidatedHostExecutionApplyV1,
    ValidatedHostExecutionQueryV1,
};

const DOMAIN: &[u8] = b"aos.sandbox.host.execution.v1\0";

/// Reports an inconsistent execution action shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostExecutionSemanticErrorV1 {
    /// The stable operation locator contains an unspecified identity.
    #[error("Host execution operation locator is invalid")]
    InvalidIdentity,
    /// The validated action lacks its canonical specification.
    #[error("Host execution action is inconsistent")]
    InvalidAction,
}

/// Carries the plan-match tuple for one exact Host execution handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHostExecutionSemanticsV1 {
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalHostExecutionSemanticsV1 {
    /// Returns the distinct Apply or Query grant verb.
    #[must_use]
    pub const fn verb(self) -> BrokerVerb {
        self.verb
    }

    /// Returns the exact assignment target.
    #[must_use]
    pub const fn target(self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the exact signed argument commitment.
    #[must_use]
    pub const fn commitment(self) -> BrokerArgumentCommitment {
        self.commitment
    }
}

/// Encodes the complete stable meaning of one Apply intent for a signed grant.
///
/// `assignment` must come from current protected Host state at admission. The
/// controller uses the same portable assignment to issue its grant; matching a
/// grant does not itself authorize an effect.
///
/// # Errors
///
/// Returns an error for an inconsistent action.
pub fn canonical_host_execution_apply_semantics_v1(
    request: &ValidatedHostExecutionApplyV1,
    assignment: BrokerAssignment,
) -> Result<CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1> {
    if let Some(content) = request.content_fields() {
        return host_execution_apply_content_grant_v1(
            assignment,
            request.operation_id(),
            request.execution_id(),
            request.source_commitment(),
            request.action(),
            content,
        );
    }
    host_execution_apply_grant_v1(
        assignment,
        request.operation_id(),
        request.execution_id(),
        request.source_commitment(),
        request.action(),
        request.specification(),
    )
}

/// Compiles an Apply grant before a broker header or request ID exists.
///
/// The producer supplies the protected controller operation projection and
/// current signed assignment. Host admission calls the validated-request
/// wrapper with its independently reopened protected assignment.
///
/// # Errors
///
/// Rejects unspecified identities, invalid control arguments, or a missing or
/// mismatched authorization specification.
pub fn host_execution_apply_grant_v1(
    assignment: BrokerAssignment,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    specification: Option<&ExecutionSpecV1>,
) -> Result<CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1> {
    let bytes = match (action, specification) {
        (EffectOperationV1::AuthorizeExecution, Some(specification))
            if specification.execution() == execution_id =>
        {
            encode_execution_spec_v1(specification)
        }
        (EffectOperationV1::AuthorizeExecution, _) => {
            return Err(HostExecutionSemanticErrorV1::InvalidAction);
        }
        (_, None) => HOST_EXECUTION_CONTROL_CONTENT_V1.to_vec(),
        _ => return Err(HostExecutionSemanticErrorV1::InvalidAction),
    };
    let content = HostExecutionSpecContentFieldsV1::for_grant(&bytes);
    host_execution_apply_content_grant_v1(
        assignment,
        operation_id,
        execution_id,
        source_commitment,
        action,
        content,
    )
}

/// Compiles a signed Apply grant from the exact sealed-content reference.
///
/// # Errors
///
/// Rejects unspecified identities, invalid control arguments, or an invalid
/// content size. The authenticated attempt commitment is checked by the body
/// decoder; it is deliberately absent from this stable authorization grant.
pub fn host_execution_apply_content_grant_v1(
    assignment: BrokerAssignment,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    content: HostExecutionSpecContentFieldsV1,
) -> Result<CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1> {
    validate_locator(operation_id, execution_id, source_commitment)?;
    let mut bytes = common_bytes(
        1,
        assignment,
        operation_id,
        execution_id.as_bytes(),
        source_commitment,
    );

    bytes.push(action.code());
    bytes.extend_from_slice(&action.arguments());
    match action {
        EffectOperationV1::AuthorizeExecution
            if content.bytes() > 1
                && content.bytes() <= MAXIMUM_HOST_EXECUTION_SPEC_BYTES as u64 => {}
        EffectOperationV1::ResizeTerminal { rows, columns }
            if rows != 0 && columns != 0 && content.is_control_marker() => {}
        EffectOperationV1::Signal { signal_code }
            if (1..=64).contains(&signal_code) && content.is_control_marker() => {}
        EffectOperationV1::Cancel | EffectOperationV1::Observe if content.is_control_marker() => {}
        _ => return Err(HostExecutionSemanticErrorV1::InvalidAction),
    }
    bytes.push(1);
    bytes.extend_from_slice(&content.bytes().to_be_bytes());
    bytes.extend_from_slice(&content.digest());

    Ok(CanonicalHostExecutionSemanticsV1 {
        verb: BrokerVerb::HostApplyExecution,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

/// Encodes one exact protected outcome locator for a distinct Query grant.
///
/// # Errors
///
/// Rejects an unspecified stable operation locator.
pub fn canonical_host_execution_query_semantics_v1(
    request: &ValidatedHostExecutionQueryV1,
    assignment: BrokerAssignment,
) -> Result<CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1> {
    host_execution_query_content_grant_v1(
        assignment,
        request.operation_id(),
        request.execution_id(),
        request.source_commitment(),
        request.content_fields(),
    )
}

/// Compiles a Query grant bound to the exact Apply content for this operation.
///
/// # Errors
///
/// Rejects an unspecified locator or invalid content size.
pub fn host_execution_query_content_grant_v1(
    assignment: BrokerAssignment,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    content: HostExecutionSpecContentFieldsV1,
) -> Result<CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1> {
    validate_locator(operation_id, execution_id, source_commitment)?;
    if content.bytes() == 0 || content.bytes() > MAXIMUM_HOST_EXECUTION_SPEC_BYTES as u64 {
        return Err(HostExecutionSemanticErrorV1::InvalidAction);
    }
    let mut bytes = common_bytes(
        2,
        assignment,
        operation_id,
        execution_id.as_bytes(),
        source_commitment,
    );
    bytes.push(1);
    bytes.extend_from_slice(&content.bytes().to_be_bytes());
    bytes.extend_from_slice(&content.digest());
    Ok(CanonicalHostExecutionSemanticsV1 {
        verb: BrokerVerb::HostQueryExecution,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

/// Compiles a Query grant before a broker header or request ID exists.
///
/// # Errors
///
/// Rejects an unspecified stable operation locator.
pub fn host_execution_query_grant_v1(
    assignment: BrokerAssignment,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
) -> Result<CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1> {
    validate_locator(operation_id, execution_id, source_commitment)?;
    let bytes = common_bytes(
        2,
        assignment,
        operation_id,
        execution_id.as_bytes(),
        source_commitment,
    );

    Ok(CanonicalHostExecutionSemanticsV1 {
        verb: BrokerVerb::HostQueryExecution,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

fn validate_locator(
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
) -> Result<(), HostExecutionSemanticErrorV1> {
    if operation_id == [0; 16]
        || execution_id.as_bytes() == &[0; 16]
        || source_commitment.as_bytes() == &[0; 32]
    {
        return Err(HostExecutionSemanticErrorV1::InvalidIdentity);
    }
    Ok(())
}

fn common_bytes(
    method: u8,
    assignment: BrokerAssignment,
    operation_id: [u8; 16],
    execution_id: &[u8; 16],
    source_commitment: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 160);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(method);
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes.extend_from_slice(&operation_id);
    bytes.extend_from_slice(execution_id);
    bytes.extend_from_slice(source_commitment.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};

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
    fn apply_grant_binds_action_arguments_and_assignment() {
        let operation = [7; 16];
        let execution = ExecutionId::from_bytes([8; 16]);
        let source = ObjectDigest::from_bytes([9; 32]);
        let grant = |epoch, action| {
            host_execution_apply_grant_v1(
                assignment(epoch),
                operation,
                execution,
                source,
                action,
                None,
            )
            .unwrap()
        };

        let original = grant(3, EffectOperationV1::Signal { signal_code: 15 });
        assert_eq!(original.verb(), BrokerVerb::HostApplyExecution);
        assert_eq!(original.target(), BrokerGrantTarget::Assignment);
        assert_ne!(
            original.commitment(),
            grant(3, EffectOperationV1::Signal { signal_code: 9 }).commitment()
        );
        assert_ne!(
            original.commitment(),
            grant(4, EffectOperationV1::Signal { signal_code: 15 }).commitment()
        );
        assert!(
            host_execution_apply_grant_v1(
                assignment(3),
                operation,
                execution,
                source,
                EffectOperationV1::Signal { signal_code: 0 },
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn query_grant_is_distinct_and_binds_the_exact_locator() {
        let execution = ExecutionId::from_bytes([8; 16]);
        let source = ObjectDigest::from_bytes([9; 32]);
        let query =
            host_execution_query_grant_v1(assignment(3), [7; 16], execution, source).unwrap();
        let apply = host_execution_apply_grant_v1(
            assignment(3),
            [7; 16],
            execution,
            source,
            EffectOperationV1::Observe,
            None,
        )
        .unwrap();

        assert_eq!(query.verb(), BrokerVerb::HostQueryExecution);
        assert_ne!(query.commitment(), apply.commitment());
        assert_ne!(
            query.commitment(),
            host_execution_query_grant_v1(assignment(3), [10; 16], execution, source)
                .unwrap()
                .commitment()
        );
        assert!(host_execution_query_grant_v1(assignment(3), [0; 16], execution, source).is_err());
    }
}
