//! Root-owned Network policy publication for production broker startup.
//!
//! The controller publishes one canonical JSON document named
//! `network-policy.catalog` in a protected directory. The loader rejects
//! redirects, writable or non-root-owned objects, noncanonical bytes, unknown
//! fields, policy rollback, and every invalid typed policy relationship.

use std::io::Read as _;
use std::path::Path;

use aos_sandbox_core::model::{NetworkKind, NetworkProfile};
use aos_sandbox_core::{NetworkEndpointId, NodeId, ObjectDigest};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use serde::{Deserialize, Serialize};

use crate::{
    NetworkAddressPoolV1, NetworkAllocationPolicyV1, NetworkEndpointPolicyV1,
    NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1, NetworkPolicyCatalogV1,
    NetworkPolicyProfileV1, NetworkPolicyProgramV1, NetworkPortRangeV1, NetworkTransportProtocolV1,
};

/// Names the sole protected Network policy publication.
pub const NETWORK_POLICY_CATALOG_FILE_NAME: &str = "network-policy.catalog";

const FORMAT_VERSION: u16 = 1;
const MAXIMUM_CATALOG_BYTES: usize = 1024 * 1024;

/// Reports an unavailable, insecure, malformed, or stale policy publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedNetworkPolicyErrorV1 {
    /// The protected directory or fixed catalog file is unavailable or unsafe.
    #[error("Network policy publication is unavailable or insecure")]
    ProtectedPath,
    /// The document is noncanonical or violates the typed policy schema.
    #[error("Network policy publication is malformed")]
    Malformed,
    /// The document generation is below the required rollback floor.
    #[error("Network policy publication rolled back")]
    Rollback,
}

impl NetworkPolicyCatalogV1 {
    /// Encodes the exact canonical protected policy publication.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedNetworkPolicyErrorV1::Malformed`] if serialization
    /// fails or exceeds the fixed publication ceiling.
    pub fn encode_protected_publication(&self) -> Result<Vec<u8>, ProtectedNetworkPolicyErrorV1> {
        let bytes = serde_json::to_vec(&PolicyCatalogWireV1::from_catalog(self))
            .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_CATALOG_BYTES {
            return Err(ProtectedNetworkPolicyErrorV1::Malformed);
        }

        Ok(bytes)
    }

    /// Loads one canonical policy from an exact root-owned directory.
    ///
    /// The directory must be root-owned mode 0500 or 0700. Its fixed policy
    /// file must be root-owned, single-link, regular, and mode 0400 or 0600.
    /// The descriptor identity and metadata are rechecked after the bounded
    /// read before any decoded policy becomes available.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedNetworkPolicyErrorV1`] for unsafe filesystem state,
    /// malformed or noncanonical bytes, invalid typed policy, or rollback.
    pub fn load_protected_publication(
        directory: &Path,
        minimum_generation: u64,
    ) -> Result<Self, ProtectedNetworkPolicyErrorV1> {
        let directory = open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        let directory_metadata =
            fstat(&directory).map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        if FileType::from_raw_mode(directory_metadata.st_mode) != FileType::Directory
            || directory_metadata.st_uid != 0
            || !matches!(directory_metadata.st_mode & 0o7777, 0o500 | 0o700)
        {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }

        let descriptor = openat(
            &directory,
            NETWORK_POLICY_CATALOG_FILE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        let metadata =
            fstat(&descriptor).map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        let declared_size = usize::try_from(metadata.st_size)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != 0
            || metadata.st_nlink != 1
            || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600)
            || !(1..=MAXIMUM_CATALOG_BYTES).contains(&declared_size)
        {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }

        let mut bytes = Vec::with_capacity(declared_size);
        let mut file = std::fs::File::from(descriptor);
        (&mut file)
            .take((MAXIMUM_CATALOG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        let current = fstat(&file).map_err(|_| ProtectedNetworkPolicyErrorV1::ProtectedPath)?;
        if bytes.len() != declared_size
            || current.st_dev != metadata.st_dev
            || current.st_ino != metadata.st_ino
            || current.st_size != metadata.st_size
            || current.st_mode != metadata.st_mode
            || current.st_uid != metadata.st_uid
            || current.st_gid != metadata.st_gid
            || current.st_nlink != metadata.st_nlink
            || current.st_mtime != metadata.st_mtime
            || current.st_mtime_nsec != metadata.st_mtime_nsec
            || current.st_ctime != metadata.st_ctime
            || current.st_ctime_nsec != metadata.st_ctime_nsec
        {
            return Err(ProtectedNetworkPolicyErrorV1::ProtectedPath);
        }

        let document: PolicyCatalogWireV1 =
            serde_json::from_slice(&bytes).map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)?;
        if document.version != FORMAT_VERSION || document.generation < minimum_generation {
            return Err(if document.generation < minimum_generation {
                ProtectedNetworkPolicyErrorV1::Rollback
            } else {
                ProtectedNetworkPolicyErrorV1::Malformed
            });
        }
        let catalog = document.into_catalog()?;
        let canonical = catalog.encode_protected_publication()?;
        if canonical != bytes {
            return Err(ProtectedNetworkPolicyErrorV1::Malformed);
        }

        Ok(catalog)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyCatalogWireV1 {
    version: u16,
    node: NodeId,
    generation: u64,
    profiles: Vec<PolicyProfileWireV1>,
}

impl PolicyCatalogWireV1 {
    fn from_catalog(catalog: &NetworkPolicyCatalogV1) -> Self {
        Self {
            version: FORMAT_VERSION,
            node: catalog.node(),
            generation: catalog.generation(),
            profiles: catalog
                .profiles()
                .iter()
                .map(PolicyProfileWireV1::from_profile)
                .collect(),
        }
    }

    fn into_catalog(self) -> Result<NetworkPolicyCatalogV1, ProtectedNetworkPolicyErrorV1> {
        let profiles = self
            .profiles
            .into_iter()
            .map(PolicyProfileWireV1::into_profile)
            .collect::<Result<Vec<_>, _>>()?;
        NetworkPolicyCatalogV1::new(self.node, self.generation, profiles)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyProfileWireV1 {
    portable_profile: NetworkProfile,
    program: PolicyProgramWireV1,
    allocation: AllocationPolicyWireV1,
}

impl PolicyProfileWireV1 {
    fn from_profile(profile: &NetworkPolicyProfileV1) -> Self {
        Self {
            portable_profile: profile.portable_profile().clone(),
            program: PolicyProgramWireV1::from_program(profile.program()),
            allocation: AllocationPolicyWireV1::from_policy(profile.allocation_policy()),
        }
    }

    fn into_profile(self) -> Result<NetworkPolicyProfileV1, ProtectedNetworkPolicyErrorV1> {
        let program = self.program.into_program()?;
        let allocation = self.allocation.into_policy()?;
        NetworkPolicyProfileV1::new(self.portable_profile, program, allocation)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyProgramWireV1 {
    kind: NetworkKind,
    enforcement_program_digest: ObjectDigest,
    lease_gate_program_digest: Option<ObjectDigest>,
    endpoints: Vec<EndpointPolicyWireV1>,
}

impl PolicyProgramWireV1 {
    fn from_program(program: &NetworkPolicyProgramV1) -> Self {
        Self {
            kind: program.kind(),
            enforcement_program_digest: program.enforcement_program_digest(),
            lease_gate_program_digest: program.lease_gate_program_digest(),
            endpoints: program
                .endpoints()
                .iter()
                .map(EndpointPolicyWireV1::from_endpoint)
                .collect(),
        }
    }

    fn into_program(self) -> Result<NetworkPolicyProgramV1, ProtectedNetworkPolicyErrorV1> {
        let endpoints = self
            .endpoints
            .into_iter()
            .map(EndpointPolicyWireV1::into_endpoint)
            .collect::<Result<Vec<_>, _>>()?;
        NetworkPolicyProgramV1::new(
            self.kind,
            self.enforcement_program_digest,
            self.lease_gate_program_digest,
            endpoints,
        )
        .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointPolicyWireV1 {
    endpoint_id: NetworkEndpointId,
    flows: Vec<FlowPolicyWireV1>,
}

impl EndpointPolicyWireV1 {
    fn from_endpoint(endpoint: &NetworkEndpointPolicyV1) -> Self {
        Self {
            endpoint_id: endpoint.endpoint_id(),
            flows: endpoint
                .flows()
                .iter()
                .copied()
                .map(FlowPolicyWireV1::from_flow)
                .collect(),
        }
    }

    fn into_endpoint(self) -> Result<NetworkEndpointPolicyV1, ProtectedNetworkPolicyErrorV1> {
        let flows = self
            .flows
            .into_iter()
            .map(FlowPolicyWireV1::into_flow)
            .collect::<Result<Vec<_>, _>>()?;
        NetworkEndpointPolicyV1::new(self.endpoint_id, flows)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FlowPolicyWireV1 {
    direction: FlowDirectionWireV1,
    protocol: TransportProtocolWireV1,
    remote_prefix: IpPrefixWireV1,
    ports: Option<PortRangeWireV1>,
}

impl FlowPolicyWireV1 {
    fn from_flow(flow: NetworkFlowPolicyV1) -> Self {
        Self {
            direction: FlowDirectionWireV1::from_domain(flow.direction()),
            protocol: TransportProtocolWireV1::from_domain(flow.protocol()),
            remote_prefix: IpPrefixWireV1::from_domain(flow.remote_prefix()),
            ports: flow.ports().map(PortRangeWireV1::from_domain),
        }
    }

    fn into_flow(self) -> Result<NetworkFlowPolicyV1, ProtectedNetworkPolicyErrorV1> {
        let ports = self.ports.map(PortRangeWireV1::into_domain).transpose()?;
        NetworkFlowPolicyV1::new(
            self.direction.into_domain(),
            self.protocol.into_domain(),
            self.remote_prefix.into_domain()?,
            ports,
        )
        .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FlowDirectionWireV1 {
    Ingress,
    Egress,
}

impl FlowDirectionWireV1 {
    const fn from_domain(value: NetworkFlowDirectionV1) -> Self {
        match value {
            NetworkFlowDirectionV1::Ingress => Self::Ingress,
            NetworkFlowDirectionV1::Egress => Self::Egress,
        }
    }

    const fn into_domain(self) -> NetworkFlowDirectionV1 {
        match self {
            Self::Ingress => NetworkFlowDirectionV1::Ingress,
            Self::Egress => NetworkFlowDirectionV1::Egress,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TransportProtocolWireV1 {
    Tcp,
    Udp,
    IcmpV4,
    IcmpV6,
}

impl TransportProtocolWireV1 {
    const fn from_domain(value: NetworkTransportProtocolV1) -> Self {
        match value {
            NetworkTransportProtocolV1::Tcp => Self::Tcp,
            NetworkTransportProtocolV1::Udp => Self::Udp,
            NetworkTransportProtocolV1::IcmpV4 => Self::IcmpV4,
            NetworkTransportProtocolV1::IcmpV6 => Self::IcmpV6,
        }
    }

    const fn into_domain(self) -> NetworkTransportProtocolV1 {
        match self {
            Self::Tcp => NetworkTransportProtocolV1::Tcp,
            Self::Udp => NetworkTransportProtocolV1::Udp,
            Self::IcmpV4 => NetworkTransportProtocolV1::IcmpV4,
            Self::IcmpV6 => NetworkTransportProtocolV1::IcmpV6,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "family")]
enum IpPrefixWireV1 {
    Ipv4 {
        network: [u8; 4],
        prefix_length: u8,
    },
    Ipv6 {
        network: [u8; 16],
        prefix_length: u8,
    },
}

impl IpPrefixWireV1 {
    const fn from_domain(value: NetworkIpPrefixV1) -> Self {
        match value {
            NetworkIpPrefixV1::Ipv4 {
                network,
                prefix_length,
            } => Self::Ipv4 {
                network,
                prefix_length,
            },
            NetworkIpPrefixV1::Ipv6 {
                network,
                prefix_length,
            } => Self::Ipv6 {
                network,
                prefix_length,
            },
        }
    }

    fn into_domain(self) -> Result<NetworkIpPrefixV1, ProtectedNetworkPolicyErrorV1> {
        match self {
            Self::Ipv4 {
                network,
                prefix_length,
            } => NetworkIpPrefixV1::ipv4(network, prefix_length),
            Self::Ipv6 {
                network,
                prefix_length,
            } => NetworkIpPrefixV1::ipv6(network, prefix_length),
        }
        .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortRangeWireV1 {
    first: u16,
    last: u16,
}

impl PortRangeWireV1 {
    const fn from_domain(value: NetworkPortRangeV1) -> Self {
        Self {
            first: value.first(),
            last: value.last(),
        }
    }

    fn into_domain(self) -> Result<NetworkPortRangeV1, ProtectedNetworkPolicyErrorV1> {
        NetworkPortRangeV1::new(self.first, self.last)
            .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
enum AllocationPolicyWireV1 {
    Isolated,
    Veth {
        mtu: u32,
        mac_prefix: [u8; 3],
        address_pools: Vec<IpPrefixWireV1>,
        route_prefixes: Vec<IpPrefixWireV1>,
    },
}

impl AllocationPolicyWireV1 {
    fn from_policy(policy: &NetworkAllocationPolicyV1) -> Self {
        match (policy.mtu(), policy.mac_prefix()) {
            (Some(mtu), Some(mac_prefix)) => Self::Veth {
                mtu,
                mac_prefix,
                address_pools: policy
                    .address_pools()
                    .iter()
                    .map(|pool| IpPrefixWireV1::from_domain(pool.prefix()))
                    .collect(),
                route_prefixes: policy
                    .route_prefixes()
                    .iter()
                    .copied()
                    .map(IpPrefixWireV1::from_domain)
                    .collect(),
            },
            _ => Self::Isolated,
        }
    }

    fn into_policy(self) -> Result<NetworkAllocationPolicyV1, ProtectedNetworkPolicyErrorV1> {
        match self {
            Self::Isolated => Ok(NetworkAllocationPolicyV1::isolated()),
            Self::Veth {
                mtu,
                mac_prefix,
                address_pools,
                route_prefixes,
            } => {
                let address_pools = address_pools
                    .into_iter()
                    .map(|prefix| {
                        NetworkAddressPoolV1::new(prefix.into_domain()?)
                            .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let route_prefixes = route_prefixes
                    .into_iter()
                    .map(IpPrefixWireV1::into_domain)
                    .collect::<Result<Vec<_>, _>>()?;
                NetworkAllocationPolicyV1::veth(mtu, mac_prefix, address_pools, route_prefixes)
                    .map_err(|_| ProtectedNetworkPolicyErrorV1::Malformed)
            }
        }
    }
}
