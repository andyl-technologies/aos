//! Defines the portable Guardian arm commitment shared across processes.
//!
//! The fixed encoding binds one assignment to its owning node, the current
//! host boot, and one exact ownership lease generation and digest.

use crate::{BrokerArgumentCommitment, BrokerAssignment, NodeId, ObjectDigest};

const BINDING_DOMAIN: &[u8; 8] = b"AOSGAB1\0";
const BINDING_BYTES: u32 = 160;

/// Commits one Guardian arm grant to the current boot and exact ownership lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianPlanBinding {
    assignment: BrokerAssignment,
    node: NodeId,
    host_boot_id: [u8; 16],
    lease_generation: u64,
    lease_digest: ObjectDigest,
}

impl GuardianPlanBinding {
    /// Constructs the sole semantic argument accepted by `GuardianArm`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidGuardianPlanBinding`] for a sentinel node, boot
    /// identity, lease generation, or lease digest.
    pub fn new(
        assignment: BrokerAssignment,
        node: NodeId,
        host_boot_id: [u8; 16],
        lease_generation: u64,
        lease_digest: ObjectDigest,
    ) -> Result<Self, InvalidGuardianPlanBinding> {
        if node.as_bytes() == &[0; 16]
            || host_boot_id == [0; 16]
            || lease_generation == 0
            || lease_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidGuardianPlanBinding);
        }
        Ok(Self {
            assignment,
            node,
            host_boot_id,
            lease_generation,
            lease_digest,
        })
    }

    /// Returns the domain-separated exact semantic commitment signed by the plan.
    #[must_use]
    pub fn commitment(self) -> BrokerArgumentCommitment {
        BrokerArgumentCommitment::for_canonical_bytes(&self.encode())
    }

    /// Returns the exact fixed semantic byte length charged to the grant.
    #[must_use]
    pub const fn encoded_len(self) -> u32 {
        BINDING_BYTES
    }

    fn encode(self) -> [u8; BINDING_BYTES as usize] {
        let mut bytes = [0; BINDING_BYTES as usize];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, BINDING_DOMAIN);
        append(
            &mut bytes,
            &mut cursor,
            self.assignment.sandbox().as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            self.assignment.incarnation().as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            &self.assignment.epoch().get().to_be_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            &self.assignment.desired_generation().get().to_be_bytes(),
        );
        append(&mut bytes, &mut cursor, self.assignment.digest().as_bytes());
        append(&mut bytes, &mut cursor, self.node.as_bytes());
        append(&mut bytes, &mut cursor, &self.host_boot_id);
        append(
            &mut bytes,
            &mut cursor,
            &self.lease_generation.to_be_bytes(),
        );
        append(&mut bytes, &mut cursor, self.lease_digest.as_bytes());
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }
}

/// Reports a sentinel in a Guardian arm commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("guardian plan binding contains a sentinel value")]
pub struct InvalidGuardianPlanBinding;

fn append<const N: usize>(destination: &mut [u8], cursor: &mut usize, source: &[u8; N]) {
    let end = *cursor + N;
    destination[*cursor..end].copy_from_slice(source);
    *cursor = end;
}

#[cfg(test)]
mod tests {
    use crate::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};

    use super::*;

    const BINDING_HEX: &str = "414f5347414231000101010101010101010101010101010102020202020202020202020202020202000000000000000300000000000000040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060808080808080808080808080808080800000000000000070909090909090909090909090909090909090909090909090909090909090909";

    fn assignment(digest: u8) -> BrokerAssignment {
        assignment_fields(1, 2, 3, 4, digest)
    }

    fn assignment_fields(
        sandbox: u8,
        incarnation: u8,
        epoch: u64,
        desired_generation: u64,
        digest: u8,
    ) -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([sandbox; 16]),
            IncarnationId::from_bytes([incarnation; 16]),
            AssignmentEpoch::new(epoch),
            DesiredGeneration::new(desired_generation),
            ObjectDigest::from_bytes([digest; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"))
    }

    fn binding(
        assignment: BrokerAssignment,
        node: u8,
        boot: u8,
        lease_generation: u64,
        lease_digest: u8,
    ) -> GuardianPlanBinding {
        GuardianPlanBinding::new(
            assignment,
            NodeId::from_bytes([node; 16]),
            [boot; 16],
            lease_generation,
            ObjectDigest::from_bytes([lease_digest; 32]),
        )
        .unwrap_or_else(|error| panic!("test binding failed: {error}"))
    }

    #[test]
    fn plan_binding_preserves_the_original_exact_encoding() {
        let binding = binding(assignment(5), 6, 8, 7, 9);

        assert_eq!(hex::encode(binding.encode()), BINDING_HEX);
        assert_eq!(binding.encoded_len(), 160);
    }

    #[test]
    fn every_plan_binding_field_changes_the_commitment() {
        let original = binding(assignment(5), 6, 8, 7, 9).commitment();
        let mutations = [
            binding(assignment_fields(10, 2, 3, 4, 5), 6, 8, 7, 9),
            binding(assignment_fields(1, 10, 3, 4, 5), 6, 8, 7, 9),
            binding(assignment_fields(1, 2, 10, 4, 5), 6, 8, 7, 9),
            binding(assignment_fields(1, 2, 3, 10, 5), 6, 8, 7, 9),
            binding(assignment(10), 6, 8, 7, 9),
            binding(assignment(5), 10, 8, 7, 9),
            binding(assignment(5), 6, 10, 7, 9),
            binding(assignment(5), 6, 8, 10, 9),
            binding(assignment(5), 6, 8, 7, 10),
        ];

        for mutation in mutations {
            assert_ne!(mutation.commitment(), original);
        }
    }
}
