//! Distinct signed broker-plan semantics for public OpenSSH gate installation.
//!
//! ```text
//! "aos.sandbox.host.attach-gate-grant.v1\0" || assignment || AOSAPG01[416]
//! ```
//!
//! The exact dedicated-key pending packet is part of the plan commitment.
//! This pure compiler does not verify its signature or confer authority.

use aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES;
use aos_sandbox_core::{BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb};

const DOMAIN: &[u8] = b"aos.sandbox.host.attach-gate-grant.v1\0";
const READINESS_DOMAIN: &[u8] = b"aos.sandbox.host.attach-gate-readiness.v1\0";
const ROUTE_QUERY_DOMAIN: &[u8] = b"aos.sandbox.host.attach-gate-route-query.v1\0";

/// Carries the distinct Host ATTACH verb, assignment target, and exact intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHostAttachGateSemanticsV1 {
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalHostAttachGateSemanticsV1 {
    /// Returns the only verb allowed for an OpenSSH gate installation.
    #[must_use]
    pub const fn verb(self) -> BrokerVerb {
        self.verb
    }

    /// Returns the exact assignment target.
    #[must_use]
    pub const fn target(self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the commitment to the exact signed pending-grant packet.
    #[must_use]
    pub const fn commitment(self) -> BrokerArgumentCommitment {
        self.commitment
    }
}

/// Compiles exact ATTACH plan semantics for one assignment and grant packet.
///
/// The Host must independently verify the packet's dedicated signature and
/// current pending, assignment, lease, and trust bindings before use.
///
/// # Errors
///
/// Rejects a missing or incorrectly framed grant packet.
pub fn canonical_host_attach_gate_semantics_v1(
    assignment: BrokerAssignment,
    packet: &[u8],
) -> Result<CanonicalHostAttachGateSemanticsV1, HostAttachGateSemanticErrorV1> {
    let packet: &[u8; PUBLIC_ATTACH_GRANT_BYTES] = packet
        .try_into()
        .map_err(|_| HostAttachGateSemanticErrorV1::InvalidGrant)?;
    if &packet[..8] != b"AOSAPG01" {
        return Err(HostAttachGateSemanticErrorV1::InvalidGrant);
    }

    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + 16 + 8 + 8 + 32 + packet.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes.extend_from_slice(packet);

    Ok(CanonicalHostAttachGateSemanticsV1 {
        verb: BrokerVerb::HostInstallAttachGate,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

/// Compiles a distinct read-only readiness grant for the current assignment.
#[must_use]
pub fn canonical_host_attach_readiness_semantics_v1(
    assignment: BrokerAssignment,
) -> CanonicalHostAttachGateSemanticsV1 {
    CanonicalHostAttachGateSemanticsV1 {
        verb: BrokerVerb::HostQueryAttachGateReadiness,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&assignment_bytes(
            READINESS_DOMAIN,
            assignment,
        )),
    }
}

/// Compiles a read-only accepted-route query bound to exact operation identity.
///
/// # Errors
///
/// Rejects an unspecified operation or execution selector.
pub fn canonical_host_attach_route_query_semantics_v1(
    assignment: BrokerAssignment,
    operation_id: [u8; 16],
    execution_id: [u8; 16],
) -> Result<CanonicalHostAttachGateSemanticsV1, HostAttachGateSemanticErrorV1> {
    if operation_id == [0; 16] || execution_id == [0; 16] {
        return Err(HostAttachGateSemanticErrorV1::InvalidGrant);
    }
    let mut bytes = assignment_bytes(ROUTE_QUERY_DOMAIN, assignment);
    bytes.extend_from_slice(&operation_id);
    bytes.extend_from_slice(&execution_id);
    Ok(CanonicalHostAttachGateSemanticsV1 {
        verb: BrokerVerb::HostQueryAttachGateRoute,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

fn assignment_bytes(domain: &[u8], assignment: BrokerAssignment) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + 16 + 16 + 8 + 8 + 32);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
    bytes
}

/// Reports a missing or noncanonical attach-grant packet selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostAttachGateSemanticErrorV1 {
    /// The exact 416-byte AOSAPG01 frame is absent.
    #[error("Host attach gate grant packet is invalid")]
    InvalidGrant,
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerVerb, DesiredGeneration, IncarnationId,
        ObjectDigest, SandboxId,
    };

    use super::canonical_host_attach_gate_semantics_v1;

    #[test]
    fn distinct_attach_verb_commits_exact_pending_packet_and_assignment() {
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap();
        let mut packet = [6; 416];
        packet[..8].copy_from_slice(b"AOSAPG01");

        let original = canonical_host_attach_gate_semantics_v1(assignment, &packet).unwrap();
        assert_eq!(original.verb(), BrokerVerb::HostInstallAttachGate);

        packet[184] ^= 1;
        let different = canonical_host_attach_gate_semantics_v1(assignment, &packet).unwrap();
        assert_ne!(original.commitment(), different.commitment());
    }
}
