//! Canonical pre-effect Network kernel plans.
//!
//! The protected preparation catalog resolves portable policy into a complete
//! namespace allocation and packet-policy program. This module compiles those
//! typed values plus one exact assignment into an architecture-neutral byte
//! artifact for a future privileged kernel worker.
//!
//! The artifact deliberately carries no file-descriptor integers, paths,
//! netlink messages, BPF commands, or loader-selected programs. It records that
//! namespace publication requires a separately retained descriptor capability;
//! the process protocol and custody mechanism for that capability remain a
//! later design decision.
//!
//! ```text
//! header = magic[8] | version:u16be | action:u8 | publication:u8 | size:u32be
//! fixed  = assignment | allocation | artifact digests | canonical counts
//! tail   = address-pairs[] | routes[] | (endpoint | flows[])[]
//! ```

use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, NetworkEndpointId,
    ObjectDigest, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::allocation::{NetworkIpAddressV1, NetworkNamespacePlanV1};
use crate::policy::{
    NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1,
    NetworkPolicyProgramV1, NetworkPortRangeV1, NetworkTransportProtocolV1,
};

const MAGIC: &[u8; 8] = b"AOSNKP01";
const VERSION: u16 = 1;
const FIXED_BYTES: usize = 392;
const ADDRESS_PAIR_BYTES: usize = 36;
const ROUTE_BYTES: usize = 36;
const ENDPOINT_BYTES: usize = 52;
const FLOW_BYTES: usize = 28;
const MAXIMUM_PLAN_BYTES: usize = 512 * 1024;
const MAXIMUM_ADDRESS_PAIRS: usize = 2;
const MAXIMUM_ROUTES: usize = 256;
const MAXIMUM_ENDPOINTS: usize = 256;
const MAXIMUM_FLOWS_PER_ENDPOINT: usize = 64;
const PLAN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.kernel-plan.v1\0";
const NAMESPACE_PLAN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.namespace-plan.v1\0";

/// Names the one closed operation represented by a V1 kernel-plan artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NetworkKernelActionV1 {
    /// Prepares one new default-deny network namespace.
    Prepare = 1,
}

impl NetworkKernelActionV1 {
    const fn decode(value: u8) -> Result<Self, NetworkKernelPlanError> {
        match value {
            1 => Ok(Self::Prepare),
            _ => Err(NetworkKernelPlanError::Invalid("unknown kernel action")),
        }
    }
}

/// Names the external capability required to publish a prepared namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NetworkNamespacePublicationRequirementV1 {
    /// Requires custody of a retained namespace-publication descriptor target.
    RetainedDescriptorTarget = 1,
}

impl NetworkNamespacePublicationRequirementV1 {
    const fn decode(value: u8) -> Result<Self, NetworkKernelPlanError> {
        match value {
            1 => Ok(Self::RetainedDescriptorTarget),
            _ => Err(NetworkKernelPlanError::Invalid(
                "unknown namespace publication requirement",
            )),
        }
    }
}

/// Reports a malformed, oversized, or inconsistent kernel-plan artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkKernelPlanError {
    /// The artifact exceeds the fixed V1 byte ceiling.
    #[error("Network kernel plan exceeds its fixed byte ceiling")]
    TooLarge,
    /// The artifact ends before a complete fixed-width field.
    #[error("Network kernel plan is truncated")]
    Truncated,
    /// The declared and received artifact lengths differ.
    #[error("Network kernel plan length is not exact")]
    LengthMismatch,
    /// A closed enum, reserved field, count, or semantic cross-link is invalid.
    #[error("Network kernel plan is invalid: {0}")]
    Invalid(&'static str),
}

/// Owns one validated canonical Network preparation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkKernelPlanV1 {
    assignment: BrokerAssignment,
    network_handle: [u8; 32],
    allocation_generation: u64,
    namespace_plan_digest: ObjectDigest,
    policy_program_digest: ObjectDigest,
    expectation: crate::kernel_observation::NetworkKernelExpectationV1,
    digest: ObjectDigest,
    bytes: Vec<u8>,
}

impl NetworkKernelPlanV1 {
    /// Compiles one exact assignment, allocation, and packet policy.
    ///
    /// The namespace and policy objects must reproduce the same exposure kind
    /// and fixed artifact commitments. Veth-backed plans must carry the fixed
    /// lease gate; isolated plans must not carry one.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelPlanError`] when the typed inputs disagree, an
    /// input violates the fixed kernel-plan bounds, or the emitted bytes do not
    /// pass the independent decoder.
    pub fn compile(
        assignment: BrokerAssignment,
        namespace: &NetworkNamespacePlanV1,
        policy: &NetworkPolicyProgramV1,
    ) -> Result<Self, NetworkKernelPlanError> {
        validate_typed_cross_links(namespace, policy)?;
        let bytes = encode_plan(assignment, namespace, policy)?;
        let decoded = Self::decode(&bytes)?;

        if decoded.assignment != assignment
            || decoded.network_handle != *namespace.network_handle()
            || decoded.allocation_generation != namespace.allocation_generation()
            || decoded.namespace_plan_digest != namespace.digest()
            || decoded.policy_program_digest != policy.digest()
        {
            return Err(NetworkKernelPlanError::Invalid(
                "compiled plan did not round-trip",
            ));
        }

        Ok(decoded)
    }

    /// Decodes and independently validates one canonical plan artifact.
    ///
    /// The byte ceiling and fixed header are checked before any tail
    /// allocation. Counts are admitted before their collections are reserved,
    /// every closed enum and reserved byte is checked, typed policy objects are
    /// reconstructed, and the complete input must re-encode byte-for-byte.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelPlanError`] for oversized, truncated, trailing,
    /// noncanonical, or semantically inconsistent input.
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkKernelPlanError> {
        if bytes.len() > MAXIMUM_PLAN_BYTES {
            return Err(NetworkKernelPlanError::TooLarge);
        }
        if bytes.len() < FIXED_BYTES {
            return Err(NetworkKernelPlanError::Truncated);
        }

        let mut decoder = Decoder::new(bytes);
        if decoder.take::<8>()? != *MAGIC {
            return Err(NetworkKernelPlanError::Invalid("invalid magic"));
        }
        if decoder.u16()? != VERSION {
            return Err(NetworkKernelPlanError::Invalid("unsupported version"));
        }
        let action = NetworkKernelActionV1::decode(decoder.byte()?)?;
        let publication = NetworkNamespacePublicationRequirementV1::decode(decoder.byte()?)?;
        let declared_length =
            usize::try_from(decoder.u32()?).map_err(|_| NetworkKernelPlanError::TooLarge)?;
        if declared_length != bytes.len() {
            return Err(NetworkKernelPlanError::LengthMismatch);
        }

        let assignment = decode_assignment(&mut decoder)?;
        let network_handle = decoder.take()?;
        let allocation_generation = decoder.u64()?;
        let kind = decode_network_kind(decoder.byte()?)?;
        let veth_present = decode_flag(decoder.byte()?, "invalid veth presence")?;
        let gate_present = decode_flag(decoder.byte()?, "invalid gate presence")?;
        decoder.zeroes(1)?;
        let mtu = decoder.u32()?;
        let host_name = decoder.take()?;
        let sandbox_name = decoder.take()?;
        let host_mac = decoder.take()?;
        let sandbox_mac = decoder.take()?;
        decoder.zeroes(4)?;
        let profile_digest = decode_digest(&mut decoder, "missing profile digest")?;
        let packet_program_digest = decode_digest(&mut decoder, "missing packet-program digest")?;
        let enforcement_program_digest =
            decode_digest(&mut decoder, "missing enforcement-program digest")?;
        let gate_digest_bytes = decoder.take::<32>()?;
        let lease_gate_program_digest = match gate_present {
            true => Some(nonzero_digest(
                gate_digest_bytes,
                "missing lease-gate digest",
            )?),
            false => {
                if gate_digest_bytes != [0; 32] {
                    return Err(NetworkKernelPlanError::Invalid(
                        "absent lease gate has nonzero digest",
                    ));
                }
                None
            }
        };
        let namespace_plan_digest = decode_digest(&mut decoder, "missing namespace-plan digest")?;
        let policy_program_digest = decode_digest(&mut decoder, "missing policy-program digest")?;

        let address_pair_count = usize::from(decoder.u16()?);
        let route_count = usize::from(decoder.u16()?);
        let endpoint_count = usize::from(decoder.u16()?);
        decoder.zeroes(2)?;
        validate_counts(address_pair_count, route_count, endpoint_count)?;
        validate_minimum_tail(
            decoder.remaining(),
            address_pair_count,
            route_count,
            endpoint_count,
        )?;

        let mut address_pairs = Vec::with_capacity(address_pair_count);
        for _ in 0..address_pair_count {
            address_pairs.push(decode_address_pair(&mut decoder)?);
        }
        let mut routes = Vec::with_capacity(route_count);
        for _ in 0..route_count {
            routes.push(decode_route(&mut decoder)?);
        }
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
            endpoints.push(decode_endpoint(&mut decoder)?);
        }
        if !decoder.finished() {
            return Err(NetworkKernelPlanError::LengthMismatch);
        }

        let policy = NetworkPolicyProgramV1::new(
            kind,
            enforcement_program_digest,
            lease_gate_program_digest,
            endpoints,
        )
        .map_err(|_| NetworkKernelPlanError::Invalid("invalid packet-policy program"))?;
        if policy.digest() != packet_program_digest || policy.digest() != policy_program_digest {
            return Err(NetworkKernelPlanError::Invalid(
                "packet-policy digest mismatch",
            ));
        }

        let namespace = DecodedNamespace {
            network_handle,
            allocation_generation,
            kind,
            profile_digest,
            packet_program_digest,
            enforcement_program_digest,
            lease_gate_program_digest,
            veth_present,
            mtu,
            host_name,
            sandbox_name,
            host_mac,
            sandbox_mac,
            address_pairs,
            routes,
            digest: namespace_plan_digest,
        };
        validate_decoded_namespace(&namespace)?;

        let canonical = encode_decoded_plan(action, publication, assignment, &namespace, &policy)?;
        if canonical != bytes {
            return Err(NetworkKernelPlanError::Invalid(
                "plan is not byte-canonical",
            ));
        }

        let digest = kernel_plan_digest(bytes);
        let expected_veth = if namespace.veth_present {
            Some(crate::kernel_observation::ExpectedVethV1 {
                mtu: namespace.mtu,
                host_name: wire::decode_name_bytes(namespace.host_name)?,
                sandbox_name: wire::decode_name_bytes(namespace.sandbox_name)?,
                host_mac: namespace.host_mac,
                sandbox_mac: namespace.sandbox_mac,
            })
        } else {
            None
        };
        let expectation = crate::kernel_observation::NetworkKernelExpectationV1::new(
            assignment,
            network_handle,
            allocation_generation,
            kind,
            profile_digest,
            enforcement_program_digest,
            lease_gate_program_digest,
            expected_veth,
            namespace
                .address_pairs
                .iter()
                .copied()
                .map(expected_address_pair)
                .collect(),
            namespace
                .routes
                .iter()
                .copied()
                .map(expected_route)
                .collect(),
            policy,
        );
        Ok(Self {
            assignment,
            network_handle,
            allocation_generation,
            namespace_plan_digest,
            policy_program_digest,
            expectation,
            digest,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the assignment cryptographically bound into this plan.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the opaque reserved namespace handle.
    #[must_use]
    pub const fn network_handle(&self) -> &[u8; 32] {
        &self.network_handle
    }

    /// Returns the never-reused protected allocation generation.
    #[must_use]
    pub const fn allocation_generation(&self) -> u64 {
        self.allocation_generation
    }

    /// Returns the exact source namespace-plan commitment.
    #[must_use]
    pub const fn namespace_plan_digest(&self) -> ObjectDigest {
        self.namespace_plan_digest
    }

    /// Returns the exact source packet-policy commitment.
    #[must_use]
    pub const fn policy_program_digest(&self) -> ObjectDigest {
        self.policy_program_digest
    }

    /// Returns the complete semantic contract used for kernel observation.
    #[must_use]
    pub const fn observation_expectation(
        &self,
    ) -> &crate::kernel_observation::NetworkKernelExpectationV1 {
        &self.expectation
    }

    /// Returns the domain-separated digest of the complete canonical artifact.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the complete canonical bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn expected_address_pair(pair: wire::KernelAddressPair) -> crate::ExpectedAddressPairV1 {
    crate::ExpectedAddressPairV1 {
        host: expected_address(pair.host),
        sandbox: expected_address(pair.sandbox),
        prefix_length: pair.prefix_length,
    }
}

fn expected_route(route: wire::KernelRoute) -> crate::ExpectedRouteV1 {
    crate::ExpectedRouteV1 {
        destination: crate::ObservedIpPrefixV1 {
            address: expected_address(route.destination.address),
            prefix_length: route.destination.prefix_length,
        },
        gateway: expected_address(route.gateway),
    }
}

fn expected_address(address: wire::KernelAddress) -> crate::ObservedIpAddressV1 {
    match address.family {
        wire::AddressFamily::Ipv4 => {
            let mut octets = [0; 4];
            octets.copy_from_slice(&address.octets[..4]);
            crate::ObservedIpAddressV1::Ipv4(octets)
        }
        wire::AddressFamily::Ipv6 => crate::ObservedIpAddressV1::Ipv6(address.octets),
    }
}

mod wire;

use wire::*;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::model::NetworkKind;
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, NetworkEndpointId,
        ObjectDigest, SandboxId,
    };

    use super::wire::{
        AddressFamily, DecodedNamespace, KernelAddress, decoded_namespace_digest,
        encode_decoded_plan, encode_veth_fields, kernel_address_pair, kernel_route,
    };
    use super::{
        ADDRESS_PAIR_BYTES, ENDPOINT_BYTES, FIXED_BYTES, FLOW_BYTES, NetworkKernelActionV1,
        NetworkKernelPlanError, NetworkKernelPlanV1, NetworkNamespacePublicationRequirementV1,
        ROUTE_BYTES,
    };
    use crate::allocation::{
        NetworkAddressPoolV1, NetworkAllocationPolicyV1, NetworkNamespacePlanV1,
    };
    use crate::policy::{
        NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1,
        NetworkPolicyProgramV1, NetworkPortRangeV1, NetworkTransportProtocolV1,
    };

    fn assignment() -> BrokerAssignment {
        BrokerAssignment::new(
            SandboxId::from_bytes([0x11; 16]),
            IncarnationId::from_bytes([0x22; 16]),
            AssignmentEpoch::new(41),
            DesiredGeneration::new(7),
            ObjectDigest::from_bytes([0x33; 32]),
        )
        .unwrap()
    }

    fn fixture() -> (
        BrokerAssignment,
        NetworkNamespacePlanV1,
        NetworkPolicyProgramV1,
    ) {
        let assignment = assignment();
        let flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Ingress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([198, 51, 100, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let endpoint =
            NetworkEndpointPolicyV1::new(NetworkEndpointId::from_bytes([0x44; 16]), vec![flow])
                .unwrap();
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Published,
            ObjectDigest::from_bytes([0x55; 32]),
            Some(ObjectDigest::from_bytes([0x66; 32])),
            vec![endpoint],
        )
        .unwrap();
        let allocation = NetworkAllocationPolicyV1::veth(
            1_500,
            [0x02, 0xaa, 0xbb],
            vec![
                NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([192, 0, 0, 0], 17).unwrap())
                    .unwrap(),
            ],
            vec![NetworkIpPrefixV1::ipv4([203, 0, 113, 0], 24).unwrap()],
        )
        .unwrap();
        let namespace = NetworkNamespacePlanV1::derive(
            [0x77; 32],
            1,
            ObjectDigest::from_bytes([0x88; 32]),
            &policy,
            &allocation,
        )
        .unwrap();
        (assignment, namespace, policy)
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        let compact = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<String>();
        assert_eq!(compact.len() % 2, 0);
        (0..compact.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&compact[offset..offset + 2], 16).unwrap())
            .collect()
    }

    fn mutation_corpus() -> Vec<(&'static str, &'static str, usize, Vec<u8>)> {
        include_str!("../../../tests/sandbox/network-kernel-plan-v1.cases")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let mut fields = line.split_whitespace();
                let label = fields.next().unwrap();
                let operation = fields.next().unwrap();
                let third = fields.next().unwrap();
                let (offset, value) = if operation == "append" {
                    (usize::MAX, decode_hex(third))
                } else {
                    (
                        third.parse::<usize>().unwrap(),
                        decode_hex(fields.next().unwrap()),
                    )
                };
                assert!(fields.next().is_none());
                (label, operation, offset, value)
            })
            .collect()
    }

    fn decoded_namespace(namespace: &NetworkNamespacePlanV1) -> DecodedNamespace {
        let veth = encode_veth_fields(namespace).unwrap();
        DecodedNamespace {
            network_handle: *namespace.network_handle(),
            allocation_generation: namespace.allocation_generation(),
            kind: namespace.kind(),
            profile_digest: namespace.profile_digest(),
            packet_program_digest: namespace.packet_program_digest(),
            enforcement_program_digest: namespace.enforcement_program_digest(),
            lease_gate_program_digest: namespace.lease_gate_program_digest(),
            veth_present: veth.present,
            mtu: veth.mtu,
            host_name: veth.host_name,
            sandbox_name: veth.sandbox_name,
            host_mac: veth.host_mac,
            sandbox_mac: veth.sandbox_mac,
            address_pairs: namespace
                .address_pairs()
                .iter()
                .copied()
                .map(kernel_address_pair)
                .collect(),
            routes: namespace
                .routes()
                .iter()
                .copied()
                .map(kernel_route)
                .collect(),
            digest: namespace.digest(),
        }
    }

    #[test]
    fn canonical_plan_matches_shared_golden_vector() {
        let (assignment, namespace, policy) = fixture();
        let plan = NetworkKernelPlanV1::compile(assignment, &namespace, &policy).unwrap();
        let golden = decode_hex(include_str!(
            "../../../tests/sandbox/network-kernel-plan-v1.hex"
        ));

        assert_eq!(plan.as_bytes(), golden);
        assert_eq!(NetworkKernelPlanV1::decode(&golden).unwrap(), plan);
    }

    #[test]
    fn isolated_loopback_plan_round_trips_without_a_tail() {
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Isolated,
            ObjectDigest::from_bytes([0x55; 32]),
            None,
            Vec::new(),
        )
        .unwrap();
        let namespace = NetworkNamespacePlanV1::derive(
            [0x70; 32],
            2,
            ObjectDigest::from_bytes([0x80; 32]),
            &policy,
            &NetworkAllocationPolicyV1::isolated(),
        )
        .unwrap();

        let plan = NetworkKernelPlanV1::compile(assignment(), &namespace, &policy).unwrap();

        assert_eq!(plan.as_bytes().len(), FIXED_BYTES);
        assert_eq!(NetworkKernelPlanV1::decode(plan.as_bytes()).unwrap(), plan);
    }

    #[test]
    fn dual_stack_plan_round_trips_ipv6_routes_and_flows() {
        let ipv6_flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Egress,
            NetworkTransportProtocolV1::Udp,
            NetworkIpPrefixV1::ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            )
            .unwrap(),
            Some(NetworkPortRangeV1::new(53, 53).unwrap()),
        )
        .unwrap();
        let endpoint = NetworkEndpointPolicyV1::new(
            NetworkEndpointId::from_bytes([0x45; 16]),
            vec![ipv6_flow],
        )
        .unwrap();
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Outbound,
            ObjectDigest::from_bytes([0x56; 32]),
            Some(ObjectDigest::from_bytes([0x67; 32])),
            vec![endpoint],
        )
        .unwrap();
        let allocation = NetworkAllocationPolicyV1::veth(
            1_500,
            [0x02, 0xaa, 0xbb],
            vec![
                NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 40, 0, 0], 17).unwrap())
                    .unwrap(),
                NetworkAddressPoolV1::new(
                    NetworkIpPrefixV1::ipv6(
                        [0xfd, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        64,
                    )
                    .unwrap(),
                )
                .unwrap(),
            ],
            vec![
                NetworkIpPrefixV1::ipv4([0; 4], 0).unwrap(),
                NetworkIpPrefixV1::ipv6([0; 16], 0).unwrap(),
            ],
        )
        .unwrap();
        let namespace = NetworkNamespacePlanV1::derive(
            [0x71; 32],
            3,
            ObjectDigest::from_bytes([0x81; 32]),
            &policy,
            &allocation,
        )
        .unwrap();

        let plan = NetworkKernelPlanV1::compile(assignment(), &namespace, &policy).unwrap();

        assert_eq!(
            plan.as_bytes().len(),
            FIXED_BYTES + 2 * ADDRESS_PAIR_BYTES + 2 * ROUTE_BYTES + ENDPOINT_BYTES + FLOW_BYTES
        );
        assert_eq!(NetworkKernelPlanV1::decode(plan.as_bytes()).unwrap(), plan);
    }

    #[test]
    fn malformed_trailing_and_count_overflow_corpus_fails_closed() {
        let (assignment, namespace, policy) = fixture();
        let valid = NetworkKernelPlanV1::compile(assignment, &namespace, &policy)
            .unwrap()
            .as_bytes()
            .to_vec();

        for (label, operation, offset, value) in mutation_corpus() {
            let mut mutated = valid.clone();
            if operation == "append" {
                mutated.extend_from_slice(&value);
            } else {
                mutated[offset..offset + value.len()].copy_from_slice(&value);
            }
            assert!(NetworkKernelPlanV1::decode(&mutated).is_err(), "{label}");
        }
    }

    #[test]
    fn length_and_reserved_fields_are_exact() {
        let (assignment, namespace, policy) = fixture();
        let valid = NetworkKernelPlanV1::compile(assignment, &namespace, &policy)
            .unwrap()
            .as_bytes()
            .to_vec();

        assert_eq!(
            u32::from_be_bytes(valid[12..16].try_into().unwrap()) as usize,
            valid.len()
        );
        assert!(valid.len() > FIXED_BYTES);

        let mut reserved = valid.clone();
        reserved[139] = 1;
        assert!(matches!(
            NetworkKernelPlanV1::decode(&reserved),
            Err(NetworkKernelPlanError::Invalid(_))
        ));

        let mut short = valid;
        short.truncate(FIXED_BYTES - 1);
        assert_eq!(
            NetworkKernelPlanV1::decode(&short),
            Err(NetworkKernelPlanError::Truncated)
        );
    }

    #[test]
    fn recomputed_digest_cannot_admit_two_pairs_for_one_family() {
        let (assignment, namespace, policy) = fixture();
        let mut decoded = decoded_namespace(&namespace);
        let mut duplicate = decoded.address_pairs[0];
        duplicate.host = KernelAddress {
            family: AddressFamily::Ipv4,
            octets: [192, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        duplicate.sandbox = KernelAddress {
            family: AddressFamily::Ipv4,
            octets: [192, 0, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        decoded.address_pairs.push(duplicate);
        decoded.digest = decoded_namespace_digest(&decoded);
        let attack = encode_decoded_plan(
            NetworkKernelActionV1::Prepare,
            NetworkNamespacePublicationRequirementV1::RetainedDescriptorTarget,
            assignment,
            &decoded,
            &policy,
        )
        .unwrap();

        assert_eq!(
            NetworkKernelPlanV1::decode(&attack),
            Err(NetworkKernelPlanError::Invalid(
                "multiple address pairs use one family"
            ))
        );
    }
}
