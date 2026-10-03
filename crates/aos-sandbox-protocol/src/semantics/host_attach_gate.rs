//! Distinct signed broker-plan semantics for public OpenSSH gate installation.
//!
//! ```text
//! "aos.sandbox.host.attach-gate-grant.v1\0" || assignment || AOSAPG01[416]
//! ```
//!
//! The exact dedicated-key pending packet is part of the plan commitment.
//! This pure compiler does not verify its signature or confer authority.

use aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb, ObjectDigest,
};

const DOMAIN: &[u8] = b"aos.sandbox.host.attach-gate-grant.v1\0";
const READINESS_DOMAIN: &[u8] = b"aos.sandbox.host.attach-gate-readiness.v1\0";
const ROUTE_QUERY_DOMAIN: &[u8] = b"aos.sandbox.host.attach-gate-route-query.v1\0";
const TICKET_DOMAIN_V2: &[u8] = b"aos.sandbox.host.attach-original-ticket-binding.v2\0";
const CONSUME_DOMAIN_V3: &[u8] = b"aos.sandbox.host.attach-original-ticket-consume.v3\0";
const CONTROL_DOMAIN_V5: &[u8] = b"aos.sandbox.host.attach-original-session-control.v5\0";

/// Commits one exact original-session control under the existing ATTACH verb.
///
/// Request bytes, monitor binding and challenge are nonauthorizing data. The
/// existing owners must independently retain genuine current LifecycleControl
/// policy, original ticket/holder and actual monitor/execution custody through
/// the effect and receipt. This compiler does not create a session or grant.
///
/// # Errors
/// Rejects malformed/substituted originals, missing correlation or a control
/// outside the bounded closed signal/resize/original-PTY profile.
pub fn canonical_host_attach_control_semantics_v5(
    assignment: BrokerAssignment,
    packet: &[u8],
    ticket: &[u8],
    monitor_binding: ObjectDigest,
    observation_challenge: [u8; 32],
    request: &[u8],
) -> Result<CanonicalHostAttachGateSemanticsV1, HostAttachGateSemanticErrorV1> {
    validate_original_ticket_packet(packet, ticket)?;
    aos_sandbox_agent::openssh_control::OpenSshControlRequestV5::decode(request)
        .map_err(|_| HostAttachGateSemanticErrorV1::InvalidGrant)?;
    if monitor_binding.as_bytes() == &[0; 32] || observation_challenge == [0; 32] {
        return Err(HostAttachGateSemanticErrorV1::InvalidGrant);
    }

    let mut bytes = assignment_bytes(CONTROL_DOMAIN_V5, assignment);
    bytes.extend_from_slice(packet);
    append_bounded_bytes(&mut bytes, ticket)?;
    bytes.extend_from_slice(monitor_binding.as_bytes());
    bytes.extend_from_slice(&observation_challenge);
    append_bounded_bytes(&mut bytes, request)?;
    Ok(CanonicalHostAttachGateSemanticsV1 {
        verb: BrokerVerb::HostInstallAttachGate,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

fn append_bounded_bytes(
    bytes: &mut Vec<u8>,
    section: &[u8],
) -> Result<(), HostAttachGateSemanticErrorV1> {
    bytes.extend_from_slice(
        &u32::try_from(section.len())
            .map_err(|_| HostAttachGateSemanticErrorV1::InvalidGrant)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(section);
    Ok(())
}

/// Compiles an exact original-ticket consume under the existing ATTACH verb.
///
/// The observed binding and challenge identify one live Guest custody record;
/// neither is authorization. Controller must retain its current policy cut,
/// and Host must hold the original route, assignment and lease through consume.
///
/// # Errors
/// Rejects malformed/substituted original data or missing live correlation.
pub fn canonical_host_attach_consume_semantics_v3(
    assignment: BrokerAssignment,
    packet: &[u8],
    ticket: &[u8],
    monitor_binding: ObjectDigest,
    observation_challenge: [u8; 32],
) -> Result<CanonicalHostAttachGateSemanticsV1, HostAttachGateSemanticErrorV1> {
    validate_original_ticket_packet(packet, ticket)?;
    if monitor_binding.as_bytes() == &[0; 32] || observation_challenge == [0; 32] {
        return Err(HostAttachGateSemanticErrorV1::InvalidGrant);
    }

    let mut bytes = assignment_bytes(CONSUME_DOMAIN_V3, assignment);
    bytes.extend_from_slice(packet);
    bytes.extend_from_slice(
        &u32::try_from(ticket.len())
            .map_err(|_| HostAttachGateSemanticErrorV1::InvalidGrant)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(ticket);
    bytes.extend_from_slice(monitor_binding.as_bytes());
    bytes.extend_from_slice(&observation_challenge);
    Ok(CanonicalHostAttachGateSemanticsV1 {
        verb: BrokerVerb::HostInstallAttachGate,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

/// Compiles binding-only ATTACH semantics over the original receipt and ticket.
///
/// # Errors
/// Rejects malformed data or receipt substitution. The existing plan signer
/// authorizes installation, not new ticket issuance or I/O transfer.
pub fn canonical_host_attach_ticket_semantics_v2(
    assignment: BrokerAssignment,
    packet: &[u8],
    ticket: &[u8],
) -> Result<CanonicalHostAttachGateSemanticsV1, HostAttachGateSemanticErrorV1> {
    validate_original_ticket_packet(packet, ticket)?;
    let mut bytes = assignment_bytes(TICKET_DOMAIN_V2, assignment);
    bytes.extend_from_slice(packet);
    bytes.extend_from_slice(
        &u32::try_from(ticket.len())
            .map_err(|_| HostAttachGateSemanticErrorV1::InvalidGrant)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(ticket);
    Ok(CanonicalHostAttachGateSemanticsV1 {
        verb: BrokerVerb::HostInstallAttachGate,
        target: BrokerGrantTarget::Assignment,
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
    })
}

fn validate_original_ticket_packet(
    packet: &[u8],
    ticket: &[u8],
) -> Result<(), HostAttachGateSemanticErrorV1> {
    let decoded =
        aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(ticket)
            .map_err(|_| HostAttachGateSemanticErrorV1::InvalidGrant)?;
    if decoded.pending_grant.as_slice() != packet {
        return Err(HostAttachGateSemanticErrorV1::InvalidGrant);
    }
    Ok(())
}

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

    #[test]
    fn consume_commits_the_unchanged_original_ticket_and_exact_live_correlation() {
        use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
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
        packet[8..24].copy_from_slice(&[1; 16]);
        packet[24..40].copy_from_slice(&[2; 16]);
        let ticket = PublicAttachTicketBindingV2 {
            operation_id: [1; 16],
            execution_id: [2; 16],
            incarnation_id: [3; 16],
            principal_id: [4; 16],
            audit_id: [5; 16],
            assignment_epoch: 3,
            valid_after: 100,
            expires_at: 200,
            holder_public_key: [7; 32],
            request_digest: [8; 32],
            decision_digest: [9; 32],
            pending_grant: packet,
            base_route_digest: [10; 32],
            certificate: vec![11],
        }
        .encode()
        .unwrap();
        let binding = ObjectDigest::from_bytes([12; 32]);
        let original = super::canonical_host_attach_consume_semantics_v3(
            assignment, &packet, &ticket, binding, [13; 32],
        )
        .unwrap();
        assert_eq!(original.verb(), BrokerVerb::HostInstallAttachGate);
        assert_ne!(
            original.commitment(),
            super::canonical_host_attach_ticket_semantics_v2(assignment, &packet, &ticket)
                .unwrap()
                .commitment()
        );
        assert_ne!(
            original.commitment(),
            super::canonical_host_attach_consume_semantics_v3(
                assignment,
                &packet,
                &ticket,
                ObjectDigest::from_bytes([14; 32]),
                [13; 32]
            )
            .unwrap()
            .commitment()
        );
        assert_ne!(
            original.commitment(),
            super::canonical_host_attach_consume_semantics_v3(
                assignment, &packet, &ticket, binding, [15; 32]
            )
            .unwrap()
            .commitment()
        );
        assert!(
            super::canonical_host_attach_consume_semantics_v3(
                assignment,
                &packet,
                &ticket,
                ObjectDigest::from_bytes([0; 32]),
                [13; 32]
            )
            .is_err()
        );
        assert!(
            super::canonical_host_attach_consume_semantics_v3(
                assignment, &packet, &ticket, binding, [0; 32]
            )
            .is_err()
        );
        let control = aos_sandbox_agent::openssh_control::OpenSshControlRequestV5 {
            sequence: 1,
            action: aos_sandbox_agent::openssh_control::OpenSshControlActionV5::Signal(15),
        };
        let exact = control.encode().unwrap();
        let control_semantics = super::canonical_host_attach_control_semantics_v5(
            assignment, &packet, &ticket, binding, [13; 32], &exact,
        )
        .unwrap();
        assert_eq!(control_semantics.verb(), BrokerVerb::HostInstallAttachGate);
        assert_ne!(control_semantics.commitment(), original.commitment());
        for changed in [
            aos_sandbox_agent::openssh_control::OpenSshControlRequestV5 {
                sequence: 2,
                ..control.clone()
            },
            aos_sandbox_agent::openssh_control::OpenSshControlRequestV5 {
                action: aos_sandbox_agent::openssh_control::OpenSshControlActionV5::Signal(9),
                ..control
            },
        ] {
            let other = super::canonical_host_attach_control_semantics_v5(
                assignment,
                &packet,
                &ticket,
                binding,
                [13; 32],
                &changed.encode().unwrap(),
            )
            .unwrap();
            assert_ne!(other.commitment(), control_semantics.commitment());
        }
        assert_ne!(
            super::canonical_host_attach_control_semantics_v5(
                assignment,
                &packet,
                &ticket,
                ObjectDigest::from_bytes([14; 32]),
                [13; 32],
                &exact,
            )
            .unwrap()
            .commitment(),
            control_semantics.commitment()
        );
        assert_ne!(
            super::canonical_host_attach_control_semantics_v5(
                assignment, &packet, &ticket, binding, [14; 32], &exact,
            )
            .unwrap()
            .commitment(),
            control_semantics.commitment()
        );
        assert!(
            super::canonical_host_attach_control_semantics_v5(
                assignment, &packet, &ticket, binding, [0; 32], &exact,
            )
            .is_err()
        );
        assert!(
            super::canonical_host_attach_control_semantics_v5(
                assignment,
                &packet,
                &ticket,
                binding,
                [13; 32],
                &[],
            )
            .is_err()
        );

        packet[40] ^= 1;
        assert!(
            super::canonical_host_attach_consume_semantics_v3(
                assignment, &packet, &ticket, binding, [13; 32]
            )
            .is_err()
        );
    }
}
