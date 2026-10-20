//! Couples the sole sealed Authorize decoder to explicit SSH source-plan DATA.

use super::{AgentProtocolError, AgentSealedAuthorizeReferenceV1};
use crate::openssh_receiving::OpenSshDescendantPlanDataV1;
use crate::{AgentOperationRequestV1, AgentRuntimeBindingV1};

/// Gives the exact kind15 frame width, including its existing sealed reference.
///
/// The old reference has twelve fixed fields totaling272 bytes; the common
/// Agent prefix/kind is9 bytes and the explicit descendant DATA is144 bytes.
pub const SEALED_SSH_AUTHORIZE_FRAME_BYTES_V1: usize =
    9 + 272 + crate::openssh_receiving::OPENSSH_DESCENDANT_PLAN_BYTES_V1;

/// Carries one sealed Authorize reference with its exact descendant-plan DATA.
///
/// This wrapper grants no financial or execution authority. The real Host
/// issuer must reserve its whole source; the real Guest owner authenticates
/// and enforces the same plan before releasing its owned native child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentSealedSshAuthorizeReferenceV1 {
    pub(super) reference: AgentSealedAuthorizeReferenceV1,
    pub(super) plan: OpenSshDescendantPlanDataV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;
    use aos_sandbox_core::{AuditId, ExecutionId, ObjectDigest, PrincipalId};

    fn reference() -> AgentSealedSshAuthorizeReferenceV1 {
        let mut plan = [1_u8; 144];
        plan[..8].copy_from_slice(b"AOSSSH01");
        plan[120..128].copy_from_slice(&100_000_u64.to_be_bytes());
        plan[128..132].copy_from_slice(&4_u32.to_be_bytes());
        plan[132..136].copy_from_slice(&15_u32.to_be_bytes());
        plan[136..140].copy_from_slice(&96_u32.to_be_bytes());
        plan[140..144].copy_from_slice(&160_u32.to_be_bytes());
        AgentSealedSshAuthorizeReferenceV1 {
            reference: AgentSealedAuthorizeReferenceV1 {
                session: crate::AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(
                    [1; 32],
                ))
                .unwrap(),
                sequence: crate::AgentOperationSequenceV1::new(1).unwrap(),
                operation_id: crate::AgentOperationIdV1::new([2; 16]).unwrap(),
                backend_request_binding: ObjectDigest::from_bytes([3; 32]),
                execution: ExecutionId::from_bytes([1; 16]),
                content_bytes: 1,
                content_digest: ObjectDigest::from_bytes([4; 32]),
                specification_digest: ObjectDigest::from_bytes([5; 32]),
                admission_commitment: ObjectDigest::from_bytes([6; 32]),
                principal: PrincipalId::from_bytes([7; 16]),
                audit: AuditId::from_bytes([8; 16]),
                request_commitment: ObjectDigest::from_bytes([1; 32]),
            },
            plan: OpenSshDescendantPlanDataV1::decode_data_v1(&plan).unwrap(),
        }
    }

    #[test]
    fn explicit_frame_reuses_the_exact_old_reference_and_fixed_plan_codec() {
        let original = reference();
        let legacy = encode_frame_v1(&AgentFrameV1::SealedAuthorizeRequest(original.reference));

        let encoded = encode_frame_v1(&AgentFrameV1::SealedSshAuthorizeRequestV1(original));

        assert_eq!(encoded.len(), SEALED_SSH_AUTHORIZE_FRAME_BYTES_V1);
        assert_eq!(&encoded[..8], &legacy[..8]);
        assert_eq!(encoded[8], 15);
        assert_eq!(&encoded[9..legacy.len()], &legacy[9..]);
        assert_eq!(&encoded[legacy.len()..], &original.plan.encode_data_v1());
        assert_eq!(
            decode_frame_v1(&encoded).unwrap(),
            AgentFrameV1::SealedSshAuthorizeRequestV1(original)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_frame_v1(&trailing),
            Err(AgentProtocolError::TrailingBytes)
        );
        assert_eq!(
            decode_frame_v1(&encoded[..encoded.len() - 1]),
            Err(AgentProtocolError::Truncated)
        );
        let mut wrong_recipe = encoded;
        wrong_recipe[legacy.len() + 128..legacy.len() + 132].copy_from_slice(&5_u32.to_be_bytes());
        assert_eq!(
            decode_frame_v1(&wrong_recipe),
            Err(AgentProtocolError::DescendantPlan(
                crate::openssh_receiving::OpenSshDescendantPlanDataErrorV1::Invalid
            ))
        );
    }
}

impl AgentSealedSshAuthorizeReferenceV1 {
    /// Joins DATA to the actual complete Authorize request without allocation.
    ///
    /// # Errors
    /// Rejects a foreign plan or an invalid/empty/oversized sealed reference.
    pub fn from_request_data_v1(
        runtime: &AgentRuntimeBindingV1,
        request: &AgentOperationRequestV1,
        plan: OpenSshDescendantPlanDataV1,
    ) -> Result<Self, AgentProtocolError> {
        plan.require_request_data_v1(runtime, request)?;
        Ok(Self {
            reference: AgentSealedAuthorizeReferenceV1::from_request(request)?,
            plan,
        })
    }

    /// Returns the exact existing sealed descriptor size.
    #[must_use]
    pub const fn content_bytes(self) -> u64 {
        self.reference.content_bytes()
    }

    /// Borrows the comparison-only plan, without paying or enforcing its caps.
    #[must_use]
    pub const fn plan_data_v1(&self) -> &OpenSshDescendantPlanDataV1 {
        &self.plan
    }

    /// Uses the sole sealed-spec decoder and full request commitment check.
    ///
    /// # Errors
    /// Preserves the existing sealed-spec length/hash/canonical/model errors,
    /// then rejects different runtime/session/execution/full request DATA.
    pub fn reconstruct(
        self,
        content: &[u8],
        runtime: &AgentRuntimeBindingV1,
    ) -> Result<AgentOperationRequestV1, AgentProtocolError> {
        let request = self.reference.reconstruct(content)?;
        self.plan.require_request_data_v1(runtime, &request)?;
        Ok(request)
    }
}
