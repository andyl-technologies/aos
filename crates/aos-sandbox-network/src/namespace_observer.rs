//! Retained-descriptor Network namespace observation workers.
//!
//! The worker starts in a retained initial-host Network namespace, selects one
//! sandbox descriptor solely from the expectation's handle and the adopted
//! systemd store, and binds it to a current-boot lifecycle identity. It proves
//! both veth directions with `RTM_GETNSID(NETNSA_FD)` before accepting the
//! decoded link inventories. Namespace names, PIDs, caller-provided interface
//! indexes, and caller-provided namespace IDs never participate in authority.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::netlink::network_namespace_id;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, SingleThreadedProcess};

use crate::kernel_observation::{
    NetworkKernelExpectationV1, NetworkKernelObservationError, NetworkKernelObservationV1,
    ObservedLeaseDirectionV1, ObservedLeaseStateV1, ObservedLinkV1, valid_loopback,
};
use crate::kernel_reader::{FixedBpfObservationReader, NetworkKernelReaderError};
use crate::namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1, NetworkNamespaceObservedStateKindV1,
    NetworkNamespaceObservedStateV1,
};
use crate::namespace_store::ActivatedNetworkDescriptors;
use crate::nftables_reader::FixedNftablesObservationReader;
use crate::rtnetlink_reader::{
    FixedRtnetlinkObservationReader, RtnetlinkLinkInventoryV1, RtnetlinkNamespaceInventoryV1,
};

/// Reports missing authority, descriptor drift, peer mismatch, or unstable state.
#[derive(Debug, thiserror::Error)]
pub enum NetworkNamespaceObserverError {
    /// The retained descriptors do not match the authorized lifecycle identity.
    #[error("retained Network namespace authority does not match the lifecycle identity")]
    AuthorityMismatch,
    /// A namespace transition or descriptor-backed netlink query failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The fixed rtnetlink inventory could not be read exactly.
    #[error(transparent)]
    Reader(#[from] NetworkKernelReaderError),
    /// The protected lifecycle catalog could not authorize a current namespace.
    #[error(transparent)]
    Catalog(#[from] NetworkNamespaceCatalogError),
    /// A decoded veth does not name the descriptor-proven peer namespace.
    #[error("veth peer identity does not match reciprocal retained-descriptor proof")]
    PeerMismatch,
    /// Two complete descriptor-proven rtnetlink snapshots differed.
    #[error("descriptor-proven rtnetlink inventory changed during validation")]
    Changed,
    /// A complete snapshot differed from the authenticated kernel plan.
    #[error(transparent)]
    Postcondition(#[from] NetworkKernelObservationError),
    /// The plan's Network mode does not have a supported namespace shape.
    #[error("Network plan does not describe an isolated or veth-backed namespace")]
    UnsupportedPlan,
}

/// Binds one reciprocal peer relation to current-boot physical namespaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespacePeerProofV1 {
    boot_id: [u8; 16],
    host_namespace: NamespaceIdentity,
    sandbox_namespace: NamespaceIdentity,
    host_peer_namespace_id: u32,
    sandbox_peer_namespace_id: u32,
}

impl NetworkNamespacePeerProofV1 {
    /// Returns the kernel boot in which both mappings were observed.
    #[must_use]
    pub const fn boot_id(self) -> [u8; 16] {
        self.boot_id
    }

    /// Returns the retained initial-host namespace identity.
    #[must_use]
    pub const fn host_namespace(self) -> NamespaceIdentity {
        self.host_namespace
    }

    /// Returns the retained sandbox namespace identity.
    #[must_use]
    pub const fn sandbox_namespace(self) -> NamespaceIdentity {
        self.sandbox_namespace
    }

    /// Returns the sandbox ID observed from the retained host namespace.
    #[must_use]
    pub const fn host_peer_namespace_id(self) -> u32 {
        self.host_peer_namespace_id
    }

    /// Returns the host ID observed from the retained sandbox namespace.
    #[must_use]
    pub const fn sandbox_peer_namespace_id(self) -> u32 {
        self.sandbox_peer_namespace_id
    }
}

/// Carries one complete descriptor-proven host and sandbox rtnetlink snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtnetlinkNamespacePairInventoryV1 {
    /// Physical namespaces and their reciprocal local ID mappings.
    pub peer_proof: NetworkNamespacePeerProofV1,
    /// Exact plan-derived host-veth inventory.
    pub host: RtnetlinkLinkInventoryV1,
    /// Complete unfiltered sandbox inventory.
    pub sandbox: RtnetlinkNamespaceInventoryV1,
}

/// Carries one stable loopback-only retained namespace snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtnetlinkIsolatedNamespaceInventoryV1 {
    /// Kernel boot in which the retained identities were observed.
    pub boot_id: [u8; 16],
    /// Retained initial-host Network namespace identity.
    pub host_namespace: NamespaceIdentity,
    /// Catalog-authorized retained sandbox Network namespace identity.
    pub sandbox_namespace: NamespaceIdentity,
    /// Complete loopback-only sandbox inventory.
    pub sandbox: RtnetlinkNamespaceInventoryV1,
}

/// Carries the stable rtnetlink shape selected by the authenticated plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StableRtnetlinkNamespaceInventoryV1 {
    /// A private namespace containing only loopback networking.
    Isolated(RtnetlinkIsolatedNamespaceInventoryV1),
    /// A namespace connected through one reciprocally proven veth pair.
    Managed(RtnetlinkNamespacePairInventoryV1),
}

/// Carries one twice-observed, plan-validated complete Network kernel state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableNetworkKernelObservationV1 {
    observation: NetworkKernelObservationV1,
    digest: ObjectDigest,
}

impl StableNetworkKernelObservationV1 {
    /// Returns the normalized complete kernel snapshot.
    #[must_use]
    pub const fn observation(&self) -> &NetworkKernelObservationV1 {
        &self.observation
    }

    /// Returns the V3 digest of every normalized fact in the snapshot.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Borrows the fixed readers needed for one complete Network observation.
#[derive(Clone, Copy)]
pub struct NetworkKernelObservationReaders<'a> {
    rtnetlink: &'a FixedRtnetlinkObservationReader,
    nftables: &'a FixedNftablesObservationReader,
    bpf: Option<&'a FixedBpfObservationReader>,
}

impl<'a> NetworkKernelObservationReaders<'a> {
    /// Groups the fixed rtnetlink, nftables, and optional BPF readers.
    #[must_use]
    pub const fn new(
        rtnetlink: &'a FixedRtnetlinkObservationReader,
        nftables: &'a FixedNftablesObservationReader,
        bpf: Option<&'a FixedBpfObservationReader>,
    ) -> Self {
        Self {
            rtnetlink,
            nftables,
            bpf,
        }
    }
}

/// Observes the exact stable rtnetlink shape selected by the plan.
///
/// Isolated plans enter the catalog-authorized retained sandbox descriptor and
/// accept only one exact loopback link. They do not query or fabricate peer
/// namespace IDs. Project, outbound, and published plans use reciprocal
/// descriptor-backed namespace-ID proof for their single veth pair.
///
/// # Errors
///
/// Returns [`NetworkNamespaceObserverError`] for unsupported or inconsistent
/// plan shapes, invalid retained authority, namespace transition failure,
/// unstable inventory, or a mode-specific exactness violation. A failure to
/// restore the retained initial-host namespace terminates the worker process.
pub fn observe_stable_rtnetlink_namespace(
    reader: &FixedRtnetlinkObservationReader,
    expectation: &NetworkKernelExpectationV1,
    activation: &ActivatedNetworkDescriptors,
    catalog: &NetworkNamespaceCatalogV1,
    initial_host_namespace: &NamespaceFd,
    worker: &SingleThreadedProcess,
) -> Result<StableRtnetlinkNamespaceInventoryV1, NetworkNamespaceObserverError> {
    worker.disable_core_dumps()?;
    let authority =
        ObservationAuthority::validate(expectation, activation, catalog, initial_host_namespace)?;

    match (expectation.kind(), expectation.veth()) {
        (NetworkKind::Isolated, None) => observe_stable_isolated(reader, authority, worker)
            .map(StableRtnetlinkNamespaceInventoryV1::Isolated),
        (NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published, Some(_)) => {
            observe_stable_pair(reader, expectation, authority, worker)
                .map(StableRtnetlinkNamespaceInventoryV1::Managed)
        }
        _ => Err(NetworkNamespaceObserverError::UnsupportedPlan),
    }
}

/// Observes and validates two complete plan-selected kernel snapshots.
///
/// Each snapshot includes the descriptor-proven host and sandbox rtnetlink
/// inventories, the fixed nftables table read inside the retained sandbox
/// namespace, and the fixed BPF graph for veth-backed plans. The expected lease
/// shape is derived from the protected namespace catalog. Isolated plans must
/// not supply a BPF reader; every veth-backed plan must supply one.
///
/// The process returns to the retained initial-host namespace after every
/// sandbox read. Failure to restore it terminates the short-lived worker.
///
/// # Errors
///
/// Returns [`NetworkNamespaceObserverError`] for missing or inconsistent
/// authority, a reader failure, reciprocal-peer mismatch, catalog/kernel
/// lifecycle disagreement, any plan postcondition mismatch, or unequal
/// snapshots.
pub fn observe_stable_network_kernel(
    readers: NetworkKernelObservationReaders<'_>,
    expectation: &NetworkKernelExpectationV1,
    activation: &ActivatedNetworkDescriptors,
    catalog: &NetworkNamespaceCatalogV1,
    initial_host_namespace: &NamespaceFd,
    worker: &SingleThreadedProcess,
) -> Result<StableNetworkKernelObservationV1, NetworkNamespaceObserverError> {
    worker.disable_core_dumps()?;
    let authority =
        ObservationAuthority::validate(expectation, activation, catalog, initial_host_namespace)?;
    let expected_lifecycle = expected_lifecycle(expectation, authority.lifecycle)?;

    let valid_reader_shape = matches!(
        (expectation.kind(), expectation.veth(), readers.bpf),
        (NetworkKind::Isolated, None, None)
            | (
                NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published,
                Some(_),
                Some(_),
            )
    );
    if !valid_reader_shape {
        return Err(NetworkNamespaceObserverError::UnsupportedPlan);
    }

    let first = observe_complete_once(
        readers.rtnetlink,
        readers.nftables,
        readers.bpf,
        expectation,
        &expected_lifecycle,
        authority,
        worker,
    )?;
    let second = observe_complete_once(
        readers.rtnetlink,
        readers.nftables,
        readers.bpf,
        expectation,
        &expected_lifecycle,
        authority,
        worker,
    )?;
    let digest = expectation.validate_stable(
        authority.boot_id,
        (
            authority.sandbox.identity().device,
            authority.sandbox.identity().inode,
        ),
        &expected_lifecycle,
        &first,
        &second,
    )?;

    Ok(StableNetworkKernelObservationV1 {
        observation: first,
        digest,
    })
}

/// Observes two equal reciprocal retained-descriptor rtnetlink snapshots.
///
/// `activation` is the already validated systemd descriptor-store custody set.
/// The sandbox descriptor is selected only by `expectation.network_handle()`.
/// `catalog` must authorize that handle and reproduce the current boot and the
/// descriptor's device/inode identity. `initial_host_namespace` must match both
/// activation's protected host identity and the worker's current Network
/// namespace before either snapshot begins.
///
/// The process remains in the initial host namespace after every successful
/// snapshot. Failure to restore the initial host namespace terminates the
/// short-lived worker process immediately, so no caller can continue in a
/// partially transitioned namespace.
///
/// # Errors
///
/// Returns [`NetworkNamespaceObserverError`] for absent or mismatched retained
/// authority, a non-single-threaded or misplaced worker, failed namespace
/// entry/restoration, failed or unassigned `RTM_GETNSID`, peer-link mismatch,
/// rejected fixed-ip output, current-boot drift, or unequal snapshots.
pub fn observe_stable_rtnetlink_pair(
    reader: &FixedRtnetlinkObservationReader,
    expectation: &NetworkKernelExpectationV1,
    activation: &ActivatedNetworkDescriptors,
    catalog: &NetworkNamespaceCatalogV1,
    initial_host_namespace: &NamespaceFd,
    worker: &SingleThreadedProcess,
) -> Result<RtnetlinkNamespacePairInventoryV1, NetworkNamespaceObserverError> {
    worker.disable_core_dumps()?;
    let authority =
        ObservationAuthority::validate(expectation, activation, catalog, initial_host_namespace)?;

    if expectation.veth().is_none()
        || !matches!(
            expectation.kind(),
            NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published
        )
    {
        return Err(NetworkNamespaceObserverError::UnsupportedPlan);
    }

    observe_stable_pair(reader, expectation, authority, worker)
}

fn observe_stable_pair(
    reader: &FixedRtnetlinkObservationReader,
    expectation: &NetworkKernelExpectationV1,
    authority: ObservationAuthority<'_>,
    worker: &SingleThreadedProcess,
) -> Result<RtnetlinkNamespacePairInventoryV1, NetworkNamespaceObserverError> {
    let first = observe_once(reader, expectation, authority, worker)?;
    let second = observe_once(reader, expectation, authority, worker)?;
    if first != second {
        return Err(NetworkNamespaceObserverError::Changed);
    }
    Ok(first)
}

fn observe_stable_isolated(
    reader: &FixedRtnetlinkObservationReader,
    authority: ObservationAuthority<'_>,
    worker: &SingleThreadedProcess,
) -> Result<RtnetlinkIsolatedNamespaceInventoryV1, NetworkNamespaceObserverError> {
    let first = observe_isolated_once(reader, authority, worker)?;
    let second = observe_isolated_once(reader, authority, worker)?;
    if first != second {
        return Err(NetworkNamespaceObserverError::Changed);
    }
    Ok(first)
}

#[derive(Clone, Copy)]
struct ObservationAuthority<'a> {
    boot_id: [u8; 16],
    host: &'a NamespaceFd,
    sandbox: &'a NamespaceFd,
    lifecycle: NetworkNamespaceObservedStateV1,
}

impl<'a> ObservationAuthority<'a> {
    fn validate(
        expectation: &NetworkKernelExpectationV1,
        activation: &'a ActivatedNetworkDescriptors,
        catalog: &NetworkNamespaceCatalogV1,
        host: &'a NamespaceFd,
    ) -> Result<Self, NetworkNamespaceObserverError> {
        let boot_id = KernelBootId::current()?.into_bytes();
        let handle = *expectation.network_handle();
        let (authorized, lifecycle) =
            catalog.authorize_current_observation(handle, expectation.assignment())?;
        let Some(retained) = activation.namespace_for_handle(handle) else {
            return Err(NetworkNamespaceObserverError::AuthorityMismatch);
        };
        let sandbox = retained.namespace();
        if authorized.network_handle() != handle
            || authorized.kernel_boot_id() != boot_id
            || (authorized.namespace_device(), authorized.namespace_inode())
                != (sandbox.identity().device, sandbox.identity().inode)
            || host.identity() != activation.host_network_identity()
            || host.identity() == sandbox.identity()
        {
            return Err(NetworkNamespaceObserverError::AuthorityMismatch);
        }
        host.validate_current_network()?;

        Ok(Self {
            boot_id,
            host,
            sandbox,
            lifecycle,
        })
    }

    fn validate_unchanged(self) -> Result<(), NetworkNamespaceObserverError> {
        if KernelBootId::current()?.into_bytes() != self.boot_id {
            return Err(NetworkNamespaceObserverError::AuthorityMismatch);
        }
        self.host.validate_current_network()?;
        if self.host.identity() == self.sandbox.identity() {
            return Err(NetworkNamespaceObserverError::AuthorityMismatch);
        }
        Ok(())
    }
}

fn expected_lifecycle(
    expectation: &NetworkKernelExpectationV1,
    observed: NetworkNamespaceObservedStateV1,
) -> Result<ObservedLeaseStateV1, NetworkNamespaceObserverError> {
    let (armed, lease_generation, lease_digest, deadline_boottime_nanoseconds) =
        match (expectation.kind(), observed.kind(), observed.lease()) {
            (NetworkKind::Isolated, NetworkNamespaceObservedStateKindV1::DefaultDrop, None)
            | (
                NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published,
                NetworkNamespaceObservedStateKindV1::DefaultDrop,
                None,
            ) => (false, 0, ObjectDigest::from_bytes([0; 32]), 0),
            (
                NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published,
                NetworkNamespaceObservedStateKindV1::Armed,
                Some((digest, generation, deadline)),
            ) => (true, generation, digest, deadline),
            (
                NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published,
                NetworkNamespaceObservedStateKindV1::Fenced,
                Some((digest, generation, deadline)),
            ) => (false, generation, digest, deadline),
            _ => return Err(NetworkNamespaceObserverError::AuthorityMismatch),
        };
    let direction = ObservedLeaseDirectionV1 {
        format_version: 2,
        armed,
        assignment_epoch: expectation.assignment().epoch().get(),
        assignment_digest: expectation.assignment().digest(),
        lease_generation,
        lease_digest,
        deadline_boottime_nanoseconds,
    };

    Ok(ObservedLeaseStateV1 {
        format_version: 2,
        ingress: direction.clone(),
        egress: direction,
    })
}

fn observe_complete_once(
    rtnetlink: &FixedRtnetlinkObservationReader,
    nftables: &FixedNftablesObservationReader,
    bpf: Option<&FixedBpfObservationReader>,
    expectation: &NetworkKernelExpectationV1,
    expected_lifecycle: &ObservedLeaseStateV1,
    authority: ObservationAuthority<'_>,
    worker: &SingleThreadedProcess,
) -> Result<NetworkKernelObservationV1, NetworkNamespaceObserverError> {
    authority.validate_unchanged()?;

    let (host_peer_namespace_id, host, lease_gate) = match bpf {
        Some(reader) => (
            Some(network_namespace_id(authority.sandbox)?),
            Some(rtnetlink.observe_host_veth(expectation)?),
            Some(reader.observe(*expectation.network_handle())?),
        ),
        None => (None, None, None),
    };

    authority.sandbox.enter(worker)?;
    let sandbox_result = (|| {
        authority.sandbox.validate_current_network()?;
        let sandbox_peer_namespace_id = match host.as_ref() {
            Some(_) => Some(network_namespace_id(authority.host)?),
            None => None,
        };
        let sandbox = rtnetlink.observe_sandbox()?;
        let policy = nftables.observe(&sandbox.links)?;
        Ok::<_, NetworkNamespaceObserverError>((sandbox_peer_namespace_id, sandbox, policy))
    })();
    let restored = authority
        .host
        .enter(worker)
        .and_then(|()| authority.host.validate_current_network());
    require_restored_host(restored.is_ok());
    authority.validate_unchanged()?;

    let (sandbox_peer_namespace_id, sandbox, nftables) = sandbox_result?;
    let loopback = sandbox
        .links
        .iter()
        .find(|link| link.name == "lo")
        .cloned()
        .ok_or(NetworkNamespaceObserverError::PeerMismatch)?;
    let sandbox_veth = match host.as_ref() {
        Some(host) => {
            let expected = expectation
                .veth()
                .ok_or(NetworkNamespaceObserverError::UnsupportedPlan)?;
            let sandbox_veth = sandbox
                .links
                .iter()
                .find(|link| link.name == expected.sandbox_name)
                .cloned()
                .ok_or(NetworkNamespaceObserverError::PeerMismatch)?;
            validate_reciprocal_links(
                &host.link,
                &sandbox_veth,
                host_peer_namespace_id.ok_or(NetworkNamespaceObserverError::PeerMismatch)?,
                sandbox_peer_namespace_id.ok_or(NetworkNamespaceObserverError::PeerMismatch)?,
            )?;
            Some(sandbox_veth)
        }
        None => None,
    };

    let mut addresses = host
        .as_ref()
        .map_or_else(Vec::new, |inventory| inventory.addresses.clone());
    addresses.extend(sandbox.addresses);
    addresses.sort_unstable();
    let lifecycle = lease_gate.as_ref().map_or_else(
        // Isolated namespaces have no lease map. Their disarmed lifecycle is
        // the protected catalog projection corroborated by default-drop nft.
        || expected_lifecycle.clone(),
        |gate| gate.lease_state.clone(),
    );

    Ok(NetworkKernelObservationV1 {
        boot_id: authority.boot_id,
        namespace_device: authority.sandbox.identity().device,
        namespace_inode: authority.sandbox.identity().inode,
        loopback,
        host_veth: host.map(|inventory| inventory.link),
        sandbox_veth,
        sandbox_link_count: u32::try_from(sandbox.links.len()).map_err(|_| {
            NetworkKernelReaderError::InvalidRtnetlink("sandbox link count exceeds u32")
        })?,
        addresses,
        routes: sandbox.routes,
        policy_rules: sandbox.policy_rules,
        nftables,
        lease_gate,
        lifecycle,
    })
}

fn observe_once(
    reader: &FixedRtnetlinkObservationReader,
    expectation: &NetworkKernelExpectationV1,
    authority: ObservationAuthority<'_>,
    worker: &SingleThreadedProcess,
) -> Result<RtnetlinkNamespacePairInventoryV1, NetworkNamespaceObserverError> {
    authority.validate_unchanged()?;
    let host_peer_namespace_id = network_namespace_id(authority.sandbox)?;
    let host = reader.observe_host_veth(expectation)?;

    authority.sandbox.enter(worker)?;
    let sandbox_result = observe_sandbox_side(
        reader,
        expectation,
        authority,
        &host.link,
        host_peer_namespace_id,
    );
    let restored = authority
        .host
        .enter(worker)
        .and_then(|()| authority.host.validate_current_network());
    require_restored_host(restored.is_ok());
    authority.validate_unchanged()?;

    let (sandbox_peer_namespace_id, sandbox) = sandbox_result?;
    Ok(RtnetlinkNamespacePairInventoryV1 {
        peer_proof: NetworkNamespacePeerProofV1 {
            boot_id: authority.boot_id,
            host_namespace: authority.host.identity(),
            sandbox_namespace: authority.sandbox.identity(),
            host_peer_namespace_id,
            sandbox_peer_namespace_id,
        },
        host,
        sandbox,
    })
}

fn observe_isolated_once(
    reader: &FixedRtnetlinkObservationReader,
    authority: ObservationAuthority<'_>,
    worker: &SingleThreadedProcess,
) -> Result<RtnetlinkIsolatedNamespaceInventoryV1, NetworkNamespaceObserverError> {
    authority.validate_unchanged()?;
    authority.sandbox.enter(worker)?;
    let sandbox_result = observe_isolated_sandbox(reader, authority);
    let restored = authority
        .host
        .enter(worker)
        .and_then(|()| authority.host.validate_current_network());
    require_restored_host(restored.is_ok());
    authority.validate_unchanged()?;

    Ok(RtnetlinkIsolatedNamespaceInventoryV1 {
        boot_id: authority.boot_id,
        host_namespace: authority.host.identity(),
        sandbox_namespace: authority.sandbox.identity(),
        sandbox: sandbox_result?,
    })
}

fn require_restored_host(restored: bool) {
    if !restored {
        std::process::abort();
    }
}

fn observe_sandbox_side(
    reader: &FixedRtnetlinkObservationReader,
    expectation: &NetworkKernelExpectationV1,
    authority: ObservationAuthority<'_>,
    host_veth: &ObservedLinkV1,
    host_peer_namespace_id: u32,
) -> Result<(u32, RtnetlinkNamespaceInventoryV1), NetworkNamespaceObserverError> {
    authority.sandbox.validate_current_network()?;
    let sandbox_peer_namespace_id = network_namespace_id(authority.host)?;
    let sandbox = reader.observe_sandbox()?;
    let expected_veth = expectation
        .veth()
        .ok_or(NetworkNamespaceObserverError::PeerMismatch)?;
    let sandbox_veth = sandbox
        .links
        .iter()
        .find(|link| link.name == expected_veth.sandbox_name)
        .ok_or(NetworkNamespaceObserverError::PeerMismatch)?;
    validate_reciprocal_links(
        host_veth,
        sandbox_veth,
        host_peer_namespace_id,
        sandbox_peer_namespace_id,
    )?;
    Ok((sandbox_peer_namespace_id, sandbox))
}

fn observe_isolated_sandbox(
    reader: &FixedRtnetlinkObservationReader,
    authority: ObservationAuthority<'_>,
) -> Result<RtnetlinkNamespaceInventoryV1, NetworkNamespaceObserverError> {
    authority.sandbox.validate_current_network()?;
    let sandbox = reader.observe_sandbox()?;
    if sandbox.links.len() != 1 || !valid_loopback(&sandbox.links[0]) {
        return Err(NetworkNamespaceObserverError::PeerMismatch);
    }
    Ok(sandbox)
}

fn validate_reciprocal_links(
    host: &ObservedLinkV1,
    sandbox: &ObservedLinkV1,
    host_peer_namespace_id: u32,
    sandbox_peer_namespace_id: u32,
) -> Result<(), NetworkNamespaceObserverError> {
    if host.peer_ifindex != sandbox.ifindex
        || sandbox.peer_ifindex != host.ifindex
        || host.peer_namespace_id != Some(host_peer_namespace_id)
        || sandbox.peer_namespace_id != Some(sandbox_peer_namespace_id)
    {
        return Err(NetworkNamespaceObserverError::PeerMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Command;

    use crate::{ObservedIpv6AddressGenerationV1, ObservedLinkV1};

    use super::*;

    const RESTORATION_FAILURE_CHILD: &str = "AOS_NETWORK_RESTORATION_FAILURE_CHILD_V1";

    fn link(ifindex: u32, peer_ifindex: u32, peer_namespace_id: Option<u32>) -> ObservedLinkV1 {
        ObservedLinkV1 {
            ifindex,
            peer_ifindex,
            peer_namespace_id,
            name: format!("veth{ifindex}"),
            kind: "veth".to_owned(),
            mtu: 1_500,
            mac: [2, 0, 0, 0, 0, ifindex as u8],
            up: true,
            ipv6_address_generation: ObservedIpv6AddressGenerationV1::None,
        }
    }

    #[test]
    fn reciprocal_descriptor_mappings_accept_matching_links() {
        assert!(
            validate_reciprocal_links(&link(7, 9, Some(3)), &link(9, 7, Some(4)), 3, 4).is_ok()
        );
    }

    #[test]
    fn same_indices_in_a_third_namespace_do_not_substitute_for_fd_proof() {
        let host = link(7, 9, Some(3));
        let sandbox = link(9, 7, Some(4));

        assert!(validate_reciprocal_links(&host, &sandbox, 8, 11).is_err());
        assert!(validate_reciprocal_links(&host, &sandbox, 3, 11).is_err());
        assert!(validate_reciprocal_links(&host, &sandbox, 8, 4).is_err());
    }

    #[test]
    fn absent_link_namespace_mapping_fails_closed() {
        assert!(validate_reciprocal_links(&link(7, 9, None), &link(9, 7, Some(4)), 3, 4).is_err());
        assert!(validate_reciprocal_links(&link(7, 9, Some(3)), &link(9, 7, None), 3, 4).is_err());
    }

    #[test]
    fn isolated_link_inventory_accepts_only_exact_loopback() {
        let loopback = ObservedLinkV1 {
            ifindex: 1,
            peer_ifindex: 0,
            peer_namespace_id: None,
            name: "lo".to_owned(),
            kind: "loopback".to_owned(),
            mtu: 65_536,
            mac: [0; 6],
            up: true,
            ipv6_address_generation: ObservedIpv6AddressGenerationV1::Eui64,
        };

        assert!(valid_loopback(&loopback));
        assert!(!valid_loopback(&link(2, 0, None)));
    }

    #[test]
    fn restoration_failure_terminates_the_worker_process() {
        if std::env::var_os(RESTORATION_FAILURE_CHILD).is_some() {
            aos_sandbox_linux::process::disable_core_dumps().unwrap();
            require_restored_host(false);
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "namespace_observer::tests::restoration_failure_terminates_the_worker_process",
            ])
            .env(RESTORATION_FAILURE_CHILD, "1")
            .output()
            .unwrap();

        assert_eq!(
            output.status.signal(),
            Some(rustix::process::Signal::ABORT.as_raw())
        );
    }
}
