//! Qualifies the catalog-bearing namespace observer through public APIs.
//!
//! This fixture-only path builds real signed controller authority, protected
//! preparation and operation journals, a current namespace publication, and
//! retained activation custody before invoking the single-threaded observer.

use std::ffi::OsString;
use std::fs::{self, File};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_proto::aos::sandbox::local::v1::{
    ApplyNetworkRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerMethod,
    BrokerRequestEnvelope, NetworkAction,
};
use aos_sandbox_core::format::{
    encode_broker_authorization_plan, encode_ownership_lease, encode_sandbox_spec,
    encode_signature, encode_trust_policy,
};
use aos_sandbox_core::model::{
    AssignmentManifestV1, IdentityProfile, KeyReference, KeyUsage, NetworkKind, NetworkProfile,
    ResourceProfile, SandboxAncestry, SandboxSpec, SignaturePurpose, SignatureStatement,
    StableKeyId, TrustPolicy, UnmappableIdentityPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerPlanTrustAnchor,
    CanonicalAssignmentManifestV1, DecodeLimits, DesiredGeneration, FeatureRef, IncarnationId,
    LeaseAssignment, MediaType, NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest,
    OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, ProjectId, ProtocolId,
    ProtocolVersion, RawClockProvenance, RawPairedClockSample, ResourceVector, RevocationScopeId,
    SandboxId, TrustScopeId, descriptor_for_bytes, sign_statement,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, SingleThreadedProcess};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_network::{
    FixedBpfObservationReader, FixedNftablesObservationReader, FixedRtnetlinkObservationReader,
    NetworkAddressPoolV1, NetworkAdmissionCoordinator, NetworkAdmissionOutcome,
    NetworkAllocationPolicyV1, NetworkIpAddressV1, NetworkIpPrefixV1,
    NetworkKernelObservationReaders, NetworkKernelPlanV1, NetworkNamespaceCatalogOutcomeV1,
    NetworkNamespaceCatalogV1, NetworkNamespaceStoreName, NetworkPolicyCatalogV1,
    NetworkPolicyProfileV1, NetworkPolicyProgramV1, NetworkPreparationCatalogOutcomeV1,
    NetworkPreparationCatalogV1, NetworkPreparationReservationV1, NetworkStateStore,
    StableRtnetlinkNamespaceInventoryV1, VerifiedNetworkResultV1, adopt_systemd_activation,
    observe_stable_network_kernel, observe_stable_rtnetlink_namespace,
};
use aos_sandbox_protocol::semantics::network::CanonicalNetworkSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_request_envelope};
use buffa::Message as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

const NODE: NodeId = NodeId::from_bytes([31; 16]);
const REQUEST_ID: [u8; 16] = [7; 16];
const PREPARATION_DIRECTORY: &str = "preparation";
const OPERATION_DIRECTORY: &str = "operations";
const NAMESPACE_DIRECTORY: &str = "namespaces";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Isolated,
    Managed,
}

pub(crate) fn managed_policy_digest(gate_object: &Path) -> Result<ObjectDigest> {
    let profile = network_profile(Mode::Managed)?;
    let gate_digest = Some(artifact_digest(gate_object)?);

    Ok(policy_program(Mode::Managed, &profile, gate_digest)?.digest())
}

impl Mode {
    fn parse(value: OsString) -> Result<Self> {
        match value.to_str() {
            Some("isolated") => Ok(Self::Isolated),
            Some("managed") => Ok(Self::Managed),
            _ => bail!("observer mode must be isolated or managed"),
        }
    }

    const fn network_kind(self) -> NetworkKind {
        match self {
            Self::Isolated => NetworkKind::Isolated,
            Self::Managed => NetworkKind::Project,
        }
    }

    const fn marker(self) -> u8 {
        match self {
            Self::Isolated => 2,
            Self::Managed => 12,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Managed => "managed",
        }
    }
}

pub(crate) fn plan(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mode = Mode::parse(arguments.next().context("observer-plan requires MODE")?)?;
    let state_root = PathBuf::from(
        arguments
            .next()
            .context("observer-plan requires STATE_ROOT")?,
    );
    let gate_object = PathBuf::from(
        arguments
            .next()
            .context("observer-plan requires GATE_OBJECT")?,
    );
    if arguments.next().is_some() {
        bail!("observer-plan accepts exactly three arguments");
    }

    let gate_digest = gate_digest(mode, &gate_object)?;
    let authority_fixture = AuthorityFixture::new()?;
    let authority = authority_fixture.authority()?;
    let mut preparations = open_preparations(mode, &state_root, gate_digest)?;
    let prepared = reserve_preparation(mode, &mut preparations, &authority)?;
    let assignment = prepared.preparation().assignment();
    let resolution = prepared.preparation().resolution();
    let namespace_plan = preparations
        .plan_for_resolution(*resolution.reserved_network_handle(), resolution)
        .context("recover durable namespace plan")?;
    let program = preparations
        .program_for_resolution(*resolution.reserved_network_handle(), resolution)
        .context("recover durable Network policy")?;
    let name =
        NetworkNamespaceStoreName::from_network_handle(*resolution.reserved_network_handle())
            .context("derive namespace store name")?;

    match mode {
        Mode::Isolated => println!(
            "OBSERVER_PLAN {} - - - - - - - - - - {} {} {} {} {}",
            name.as_str(),
            format_digest(namespace_plan.enforcement_program_digest()),
            format_digest(program.digest()),
            assignment.epoch().get(),
            format_digest(assignment.digest()),
            namespace_plan.allocation_generation(),
        ),
        Mode::Managed => {
            let host_name = namespace_plan
                .host_interface_name()
                .context("managed plan omitted host interface")?;
            let sandbox_name = namespace_plan
                .sandbox_interface_name()
                .context("managed plan omitted sandbox interface")?;
            let host_mac = namespace_plan
                .host_mac()
                .context("managed plan omitted host MAC")?;
            let sandbox_mac = namespace_plan
                .sandbox_mac()
                .context("managed plan omitted sandbox MAC")?;
            ensure!(
                namespace_plan.address_pairs().len() == 2,
                "managed plan did not resolve both IPv4 address pairs"
            );
            let first_pair = namespace_plan.address_pairs()[0];
            let second_pair = namespace_plan.address_pairs()[1];
            println!(
                "OBSERVER_PLAN {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
                name.as_str(),
                host_name.as_str(),
                sandbox_name.as_str(),
                format_mac(host_mac.octets()),
                format_mac(sandbox_mac.octets()),
                format_ip(first_pair.host()),
                format_ip(first_pair.sandbox()),
                first_pair.prefix_length(),
                format_ip(second_pair.host()),
                format_ip(second_pair.sandbox()),
                second_pair.prefix_length(),
                format_digest(namespace_plan.enforcement_program_digest()),
                format_digest(program.digest()),
                assignment.epoch().get(),
                format_digest(assignment.digest()),
                namespace_plan.allocation_generation(),
            );
        }
    }
    Ok(())
}

pub(crate) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mode = Mode::parse(arguments.next().context("observer-run requires MODE")?)?;
    let state_root = PathBuf::from(
        arguments
            .next()
            .context("observer-run requires STATE_ROOT")?,
    );
    let namespace_path = PathBuf::from(
        arguments
            .next()
            .context("observer-run requires NAMESPACE")?,
    );
    let ip_path = PathBuf::from(arguments.next().context("observer-run requires IP")?);
    let gate_object = PathBuf::from(
        arguments
            .next()
            .context("observer-run requires GATE_OBJECT")?,
    );
    if arguments.next().is_some() {
        bail!("observer-run accepts exactly five arguments");
    }

    run_observation(
        mode,
        &state_root,
        &namespace_path,
        &gate_object,
        ObservationCommand::Rtnetlink { ip_path },
    )
}

pub(crate) fn run_kernel(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mode = Mode::parse(
        arguments
            .next()
            .context("observer-kernel-run requires MODE")?,
    )?;
    let state_root = PathBuf::from(
        arguments
            .next()
            .context("observer-kernel-run requires STATE_ROOT")?,
    );
    let namespace_path = PathBuf::from(
        arguments
            .next()
            .context("observer-kernel-run requires NAMESPACE")?,
    );
    let command = ObservationCommand::Kernel {
        ip_path: PathBuf::from(
            arguments
                .next()
                .context("observer-kernel-run requires IP")?,
        ),
        nft_path: PathBuf::from(
            arguments
                .next()
                .context("observer-kernel-run requires NFT")?,
        ),
        enforcement_loader: PathBuf::from(
            arguments
                .next()
                .context("observer-kernel-run requires ENFORCEMENT_LOADER")?,
        ),
        bpf_observer: PathBuf::from(
            arguments
                .next()
                .context("observer-kernel-run requires BPF_OBSERVER")?,
        ),
    };
    let gate_object = PathBuf::from(
        arguments
            .next()
            .context("observer-kernel-run requires GATE_OBJECT")?,
    );
    if arguments.next().is_some() {
        bail!("observer-kernel-run accepts exactly eight arguments");
    }

    run_observation(mode, &state_root, &namespace_path, &gate_object, command)
}

enum ObservationCommand {
    Rtnetlink {
        ip_path: PathBuf,
    },
    Kernel {
        ip_path: PathBuf,
        nft_path: PathBuf,
        enforcement_loader: PathBuf,
        bpf_observer: PathBuf,
    },
}

fn run_observation(
    mode: Mode,
    state_root: &Path,
    namespace_path: &Path,
    gate_object: &Path,
    command: ObservationCommand,
) -> Result<()> {
    let gate_digest = gate_digest(mode, gate_object)?;
    let authority_fixture = AuthorityFixture::new()?;
    let authority = authority_fixture.authority()?;
    let mut preparations = open_preparations(mode, state_root, gate_digest)?;
    let prepared = reserve_preparation(mode, &mut preparations, &authority)?;
    let resolution = prepared.preparation().resolution().clone();
    let assignment = prepared.preparation().assignment();
    let namespace_plan = preparations
        .plan_for_resolution(*resolution.reserved_network_handle(), &resolution)
        .context("recover durable namespace plan")?;
    let program = preparations
        .program_for_resolution(*resolution.reserved_network_handle(), &resolution)
        .context("recover durable Network policy")?;
    let kernel_plan = NetworkKernelPlanV1::compile(assignment, namespace_plan, program)
        .context("compile durable kernel plan")?;

    let request = apply_request(assignment)?;
    let artifacts = authority_fixture.artifacts(&request, assignment)?;
    let operation_store =
        NetworkStateStore::open_root_owned(&state_root.join(OPERATION_DIRECTORY), &authority, 0)
            .context("open protected operation state")?;
    let mut coordinator = NetworkAdmissionCoordinator::new(authority, operation_store);
    let result = commit_or_recover(
        &mut coordinator,
        &request,
        &artifacts,
        prepared.preparation(),
        &resolution,
        namespace_path,
    )?;
    let publication = coordinator
        .namespace_publication(result, &preparations)
        .context("reconstruct namespace publication")?;
    let mut namespaces =
        NetworkNamespaceCatalogV1::open_root_owned(&state_root.join(NAMESPACE_DIRECTORY))
            .context("open protected namespace catalog")?;
    ensure!(
        matches!(
            namespaces.publish(publication)?,
            NetworkNamespaceCatalogOutcomeV1::Published | NetworkNamespaceCatalogOutcomeV1::Replay
        ),
        "namespace publication returned an unknown outcome"
    );

    let store_name =
        NetworkNamespaceStoreName::from_network_handle(*resolution.reserved_network_handle())?;
    let listener_path = state_root.join(format!("observer-listener-{}.sock", std::process::id()));
    let listener =
        RecordSubjectListener::bind(&listener_path, 1).context("create typed observer listener")?;
    let namespace_file = File::open(namespace_path).context("open retained namespace")?;
    let host = NamespaceFd::current_network().context("retain initial host namespace")?;
    let activation = adopt_systemd_activation(
        listener,
        &format!("aos-netd:{}", store_name.as_str()),
        vec![namespace_file.into()],
        1,
        host.identity(),
    )
    .context("adopt observer descriptor custody")?;
    let worker = SingleThreadedProcess::verify().context("verify single-threaded worker")?;
    let observation = match command {
        ObservationCommand::Rtnetlink { ip_path } => {
            let reader = FixedRtnetlinkObservationReader::new(ip_path)
                .context("retain fixed rtnetlink reader")?;
            let observed = observe_stable_rtnetlink_namespace(
                &reader,
                kernel_plan.observation_expectation(),
                &activation,
                &namespaces,
                &host,
                &worker,
            )
            .map_err(anyhow::Error::from)
            .and_then(|observed| match (mode, observed) {
                (Mode::Isolated, StableRtnetlinkNamespaceInventoryV1::Isolated(_))
                | (Mode::Managed, StableRtnetlinkNamespaceInventoryV1::Managed(_)) => Ok(()),
                _ => bail!("observer returned the wrong plan-selected mode"),
            });
            observed.map(|()| "OBSERVER_OK")
        }
        ObservationCommand::Kernel {
            ip_path,
            nft_path,
            enforcement_loader,
            bpf_observer,
        } => {
            let rtnetlink = FixedRtnetlinkObservationReader::new(ip_path)
                .context("retain fixed rtnetlink reader")?;
            let nftables = FixedNftablesObservationReader::new(nft_path, enforcement_loader)
                .context("retain fixed nftables reader")?;
            let bpf = match mode {
                Mode::Isolated => None,
                Mode::Managed => Some(
                    FixedBpfObservationReader::new(bpf_observer, gate_object.to_path_buf())
                        .context("retain fixed BPF reader")?,
                ),
            };
            let readers = NetworkKernelObservationReaders::new(&rtnetlink, &nftables, bpf.as_ref());
            observe_stable_network_kernel(
                readers,
                kernel_plan.observation_expectation(),
                &activation,
                &namespaces,
                &host,
                &worker,
            )
            .map(|_| "KERNEL_OBSERVER_OK")
            .map_err(anyhow::Error::from)
        }
    };
    host.validate_current_network()
        .context("observer did not leave worker in initial host namespace")?;
    fs::remove_file(&listener_path).context("remove fixture-owned observer listener")?;
    let message = match observation {
        Ok(message) => message,
        Err(error) => {
            bail!("observer rejected after restoring initial host namespace: {error}");
        }
    };
    println!("{message} {}", mode.as_str());
    Ok(())
}

fn open_preparations(
    mode: Mode,
    state_root: &Path,
    gate_digest: Option<ObjectDigest>,
) -> Result<NetworkPreparationCatalogV1> {
    let policy = policy_catalog(mode, gate_digest)?;

    NetworkPreparationCatalogV1::open_root_owned(&state_root.join(PREPARATION_DIRECTORY), policy, 1)
        .context("open protected preparation catalog")
}

fn policy_catalog(mode: Mode, gate_digest: Option<ObjectDigest>) -> Result<NetworkPolicyCatalogV1> {
    let profile = network_profile(mode)?;
    let program = policy_program(mode, &profile, gate_digest)?;
    let allocation = match mode {
        Mode::Isolated => NetworkAllocationPolicyV1::isolated(),
        Mode::Managed => NetworkAllocationPolicyV1::veth(
            1_500,
            [0x02, 0xaa, 0xbb],
            vec![
                NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv4([10, 80, 0, 0], 17)?)?,
                NetworkAddressPoolV1::new(NetworkIpPrefixV1::ipv6(
                    [
                        0x20, 0x01, 0x0d, 0xb8, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                    113,
                )?)?,
            ],
            Vec::new(),
        )?,
    };
    let policy_profile = NetworkPolicyProfileV1::new(profile, program, allocation)?;
    NetworkPolicyCatalogV1::new(NODE, 1, vec![policy_profile])
        .context("construct qualification Network policy catalog")
}

fn reserve_preparation(
    mode: Mode,
    preparations: &mut NetworkPreparationCatalogV1,
    authority: &aos_sandbox_network::NetworkAuthorityV1,
) -> Result<NetworkPreparationCatalogOutcomeV1> {
    let profile = network_profile(mode)?;
    let spec = sandbox_spec(profile)?;
    let manifest = assignment_manifest(&spec, mode)?;
    let reservation = NetworkPreparationReservationV1::new(&manifest, &spec)?;

    preparations
        .reserve(reservation, authority)
        .context("reserve authenticated Network preparation")
}

fn network_profile(mode: Mode) -> Result<NetworkProfile> {
    let endpoints = match mode {
        Mode::Isolated => Vec::new(),
        Mode::Managed => vec![aos_sandbox_core::NetworkEndpointId::from_bytes([81; 16])],
    };
    NetworkProfile::new(mode.network_kind(), endpoints, Vec::new())
        .context("construct portable Network profile")
}

fn policy_program(
    mode: Mode,
    profile: &NetworkProfile,
    gate_digest: Option<ObjectDigest>,
) -> Result<NetworkPolicyProgramV1> {
    let endpoints = match mode {
        Mode::Isolated => Vec::new(),
        Mode::Managed => vec![aos_sandbox_network::NetworkEndpointPolicyV1::new(
            profile.endpoint_ids()[0],
            vec![
                aos_sandbox_network::NetworkFlowPolicyV1::new(
                    aos_sandbox_network::NetworkFlowDirectionV1::Ingress,
                    aos_sandbox_network::NetworkTransportProtocolV1::Tcp,
                    aos_sandbox_network::NetworkIpPrefixV1::ipv6(
                        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        128,
                    )?,
                    Some(aos_sandbox_network::NetworkPortRangeV1::new(8443, 8443)?),
                )?,
                aos_sandbox_network::NetworkFlowPolicyV1::new(
                    aos_sandbox_network::NetworkFlowDirectionV1::Ingress,
                    aos_sandbox_network::NetworkTransportProtocolV1::Udp,
                    aos_sandbox_network::NetworkIpPrefixV1::ipv4([198, 51, 100, 7], 32)?,
                    Some(aos_sandbox_network::NetworkPortRangeV1::new(53, 54)?),
                )?,
                aos_sandbox_network::NetworkFlowPolicyV1::new(
                    aos_sandbox_network::NetworkFlowDirectionV1::Ingress,
                    aos_sandbox_network::NetworkTransportProtocolV1::IcmpV6,
                    aos_sandbox_network::NetworkIpPrefixV1::ipv6(
                        [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        64,
                    )?,
                    None,
                )?,
                aos_sandbox_network::NetworkFlowPolicyV1::new(
                    aos_sandbox_network::NetworkFlowDirectionV1::Egress,
                    aos_sandbox_network::NetworkTransportProtocolV1::Tcp,
                    aos_sandbox_network::NetworkIpPrefixV1::ipv4([10, 80, 0, 0], 16)?,
                    Some(aos_sandbox_network::NetworkPortRangeV1::new(443, 443)?),
                )?,
                aos_sandbox_network::NetworkFlowPolicyV1::new(
                    aos_sandbox_network::NetworkFlowDirectionV1::Egress,
                    aos_sandbox_network::NetworkTransportProtocolV1::Udp,
                    aos_sandbox_network::NetworkIpPrefixV1::ipv6(
                        [0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        64,
                    )?,
                    Some(aos_sandbox_network::NetworkPortRangeV1::new(1000, 1005)?),
                )?,
                aos_sandbox_network::NetworkFlowPolicyV1::new(
                    aos_sandbox_network::NetworkFlowDirectionV1::Egress,
                    aos_sandbox_network::NetworkTransportProtocolV1::IcmpV4,
                    aos_sandbox_network::NetworkIpPrefixV1::ipv4([203, 0, 113, 0], 24)?,
                    None,
                )?,
            ],
        )?],
    };
    NetworkPolicyProgramV1::new(
        mode.network_kind(),
        fixture_artifact_digest()?,
        gate_digest,
        endpoints,
    )
    .context("construct typed Network policy")
}

fn sandbox_spec(profile: NetworkProfile) -> Result<SandboxSpec> {
    SandboxSpec::new(
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)?,
        IdentityProfile::PrivateUserns {
            id_range_size: NonZeroU32::new(65_536).context("nonzero identity range")?,
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        },
        ResourceProfile::new(Vec::new())?,
        marker_descriptor(PortableMediaType::Environment, 71)?,
        marker_descriptor(PortableMediaType::View, 72)?,
        Vec::new(),
        profile,
        Vec::new(),
    )
    .context("construct Sandbox specification")
}

fn assignment_manifest(spec: &SandboxSpec, mode: Mode) -> Result<CanonicalAssignmentManifestV1> {
    let marker = mode.marker();
    let spec_bytes = encode_sandbox_spec(spec);
    let spec_descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned())?,
        &spec_bytes,
    );
    let manifest = AssignmentManifestV1::new(
        SandboxId::from_bytes([marker; 16]),
        ProjectId::from_bytes([4; 16]),
        SandboxAncestry::new(SandboxId::from_bytes([marker; 16]), Vec::new())?,
        IncarnationId::from_bytes([marker.wrapping_add(1); 16]),
        NODE,
        AssignmentEpoch::new(4),
        DesiredGeneration::new(5),
        NamespaceGeneration::new(6),
        spec_descriptor,
        marker_descriptor(PortableMediaType::Policy, 70)?,
        spec.environment().clone(),
        spec.root_view().clone(),
        Vec::new(),
        ObjectDigest::from_bytes([73; 32]),
        ResourceVector::ZERO,
        Vec::new(),
    )?;
    Ok(CanonicalAssignmentManifestV1::new(manifest))
}

fn marker_descriptor(kind: PortableMediaType, marker: u8) -> Result<ObjectDescriptor> {
    Ok(ObjectDescriptor::new(
        MediaType::new(kind.as_str().to_owned())?,
        ObjectDigest::from_bytes([marker; 32]),
        u64::from(marker) + 1,
    ))
}

fn apply_request(assignment: aos_sandbox_core::BrokerAssignment) -> Result<Vec<u8>> {
    let mut request = ApplyNetworkRequest::default();
    let header = request.header.get_or_insert_default();
    header.protocol_major = 1;
    header.protocol_minor = 1;
    header.request_id = REQUEST_ID.to_vec();
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.deadline_boottime_nanoseconds = 180;
    header.maximum_response_bytes = 4096;
    let fence = request.fence.get_or_insert_default();
    fence.sandbox_id = assignment.sandbox().as_bytes().to_vec();
    fence.incarnation_id = assignment.incarnation().as_bytes().to_vec();
    fence.assignment_epoch = assignment.epoch().get();
    fence.desired_generation = assignment.desired_generation().get();
    fence.assignment_digest = assignment.digest().as_bytes().to_vec();
    request.action = NetworkAction::NETWORK_ACTION_PREPARE.into();
    if assignment.sandbox().as_bytes() == &[Mode::Managed.marker(); 16] {
        request.endpoint_ids = vec![vec![81; 16]];
    }
    Ok(request.encode_to_vec())
}

fn commit_or_recover(
    coordinator: &mut NetworkAdmissionCoordinator,
    request: &[u8],
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    preparation: &aos_sandbox_network::AuthenticatedNetworkPreparationV1,
    resolution: &aos_sandbox_network::ResolvedNetworkPreparationV1,
    namespace_path: &Path,
) -> Result<aos_sandbox_network::CommittedNetworkResultV1> {
    let outcome = coordinator.admit_apply_intent(
        request,
        artifacts,
        preparation,
        ProtocolVersion::new(1, 1),
        peer(),
        peer_policy(),
        &clock()?,
    )?;
    if let NetworkAdmissionOutcome::Replay(result) = outcome {
        return Ok(result);
    }
    let NetworkAdmissionOutcome::Prepared { effect_digest } = outcome else {
        bail!("observer qualification found an unfinished non-replay operation");
    };
    drop(coordinator.mark_effect_ambiguous(REQUEST_ID, effect_digest)?);

    let namespace_file = File::open(namespace_path).context("open observed namespace")?;
    let namespace = NamespaceFd::from_owned(namespace_file.into(), NamespaceKind::Network)
        .context("type observed namespace")?;
    let boot_id = KernelBootId::current()?.into_bytes();
    let identity = namespace.identity();
    let verified = VerifiedNetworkResultV1::verify_preparation(
        REQUEST_ID,
        ObjectDigest::from_bytes(Sha256::digest(request).into()),
        resolution,
        boot_id,
        identity.device,
        identity.inode,
        ObjectDigest::from_bytes([84; 32]),
    )?;
    coordinator
        .commit_verified(REQUEST_ID, effect_digest, verified)
        .context("commit typed namespace result")
}

fn peer() -> PeerCredentials {
    PeerCredentials {
        uid: 100,
        gid: 200,
        pid: Some(300),
    }
}

fn peer_policy() -> PeerPolicy {
    PeerPolicy {
        uid: 100,
        gid: Some(200),
        audience: Audience::AUDIENCE_NODE_CONTROLLER,
    }
}

fn clock() -> Result<RawPairedClockSample> {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")?,
        KernelBootId::current()?.into_bytes(),
        150,
        100,
    )
    .context("construct qualification clock sample")
}

fn format_mac(octets: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    )
}

fn format_ip(address: NetworkIpAddressV1) -> String {
    match address {
        NetworkIpAddressV1::Ipv4(octets) => Ipv4Addr::from(octets).to_string(),
        NetworkIpAddressV1::Ipv6(octets) => Ipv6Addr::from(octets).to_string(),
    }
}

fn format_digest(digest: ObjectDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn fixture_artifact_digest() -> Result<ObjectDigest> {
    let executable = std::env::current_exe().context("resolve fixture executable")?;

    artifact_digest(&executable)
}

fn gate_digest(mode: Mode, gate_object: &Path) -> Result<Option<ObjectDigest>> {
    match mode {
        Mode::Isolated => Ok(None),
        Mode::Managed => artifact_digest(gate_object).map(Some),
    }
}

fn artifact_digest(path: &Path) -> Result<ObjectDigest> {
    let bytes = fs::read(path).with_context(|| format!("measure artifact {}", path.display()))?;

    Ok(ObjectDigest::from_bytes(Sha256::digest(bytes).into()))
}

struct AuthorityFixture {
    plan_key: SigningKey,
    lease_key: SigningKey,
    plan_signer: KeyReference,
    lease_signer: KeyReference,
    plan_policy: Vec<u8>,
    plan_descriptor: ObjectDescriptor,
    lease_policy: Vec<u8>,
    lease_descriptor: ObjectDescriptor,
    plan_scope: TrustScopeId,
    lease_scope: TrustScopeId,
    revocation: RevocationScopeId,
}

impl AuthorityFixture {
    fn new() -> Result<Self> {
        let plan_key = SigningKey::from_bytes(&[41; 32]);
        let lease_key = SigningKey::from_bytes(&[42; 32]);
        let plan_signer = key_ref("network-plan", 3, KeyUsage::BrokerAuthorization, &plan_key)?;
        let lease_signer = key_ref("network-lease", 7, KeyUsage::OwnershipLease, &lease_key)?;
        let plan_scope = TrustScopeId::from_bytes([43; 16]);
        let lease_scope = TrustScopeId::from_bytes([44; 16]);
        let (plan_policy, plan_descriptor) = trust_policy(
            plan_scope,
            SignaturePurpose::BrokerAuthorization,
            plan_signer.clone(),
        )?;
        let (lease_policy, lease_descriptor) = trust_policy(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            lease_signer.clone(),
        )?;
        Ok(Self {
            plan_key,
            lease_key,
            plan_signer,
            lease_signer,
            plan_policy,
            plan_descriptor,
            lease_policy,
            lease_descriptor,
            plan_scope,
            lease_scope,
            revocation: RevocationScopeId::from_bytes([45; 16]),
        })
    }

    fn authority(&self) -> Result<aos_sandbox_network::NetworkAuthorityV1> {
        let plan = BrokerPlanTrustAnchor::from_trusted_configuration(
            self.plan_policy.clone(),
            self.plan_descriptor.clone(),
            self.plan_scope,
            self.plan_signer.clone(),
            self.plan_key.verifying_key().to_bytes(),
            self.revocation,
            DecodeLimits::default(),
        )?;
        let lease = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            self.lease_policy.clone(),
            self.lease_descriptor.clone(),
            self.lease_scope,
            self.lease_signer.clone(),
            self.lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )?;
        aos_sandbox_network::NetworkAuthorityV1::new(plan, lease, NODE, [46; 16], [47; 32])
            .context("construct Network authority")
    }

    fn artifacts(
        &self,
        request: &[u8],
        assignment: aos_sandbox_core::BrokerAssignment,
    ) -> Result<ValidatedUntrustedAuthorizationArtifacts> {
        let candidate = CanonicalNetworkSemanticsV1::decode(request, peer(), peer_policy(), 100)
            .context("decode canonical Network request")?;
        let grant = BrokerGrant::new(
            candidate.broker_verb(),
            candidate.grant_target(),
            candidate.argument_commitment(),
            u32::try_from(request.len()).context("request length exceeds u32")?,
            0,
        )?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Network,
            ProtocolId::NetworkBroker,
            ProtocolVersion::new(1, 1),
            assignment,
            NODE,
            self.lease_signer.clone(),
            vec![grant],
            ObjectDigest::from_bytes([48; 32]),
            self.revocation,
            100,
            300,
            Vec::new(),
        )?;
        let plan_bytes = encode_broker_authorization_plan(&plan);
        let lease = OwnershipLease::new(
            LeaseAssignment::new(
                assignment.sandbox(),
                assignment.incarnation(),
                assignment.epoch(),
                assignment.digest(),
            )?,
            NODE,
            1,
            100,
            300,
            10,
            [49; 16],
        )?;
        let lease_bytes = encode_ownership_lease(&lease);
        validated_artifacts(BrokerAuthorizationArtifactsV1 {
            broker_plan_signature: signed(
                &plan_bytes,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                self.plan_signer.clone(),
                SignaturePurpose::BrokerAuthorization,
                &self.plan_descriptor,
                &self.plan_key,
            )?,
            broker_plan: plan_bytes,
            ownership_lease_signature: signed(
                &lease_bytes,
                PortableMediaType::OwnershipLease,
                self.lease_scope,
                self.lease_signer.clone(),
                SignaturePurpose::OwnershipLease,
                &self.lease_descriptor,
                &self.lease_key,
            )?,
            ownership_lease: lease_bytes,
            ..Default::default()
        })
    }
}

fn key_ref(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> Result<KeyReference> {
    Ok(KeyReference::new(
        StableKeyId::new(id.to_owned())?,
        generation,
        ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    ))
}

fn trust_policy(
    scope: TrustScopeId,
    purpose: SignaturePurpose,
    signer: KeyReference,
) -> Result<(Vec<u8>, ObjectDescriptor)> {
    let bytes = encode_trust_policy(&TrustPolicy::new(scope, purpose, vec![signer], Vec::new())?);
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())?,
        &bytes,
    );
    Ok((bytes, descriptor))
}

#[allow(clippy::too_many_arguments)]
fn signed(
    bytes: &[u8],
    media: PortableMediaType,
    scope: TrustScopeId,
    signer: KeyReference,
    purpose: SignaturePurpose,
    policy: &ObjectDescriptor,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let subject = descriptor_for_bytes(MediaType::new(media.as_str().to_owned())?, bytes);
    let statement = SignatureStatement::new(
        subject,
        scope,
        signer,
        purpose,
        100,
        Some(300),
        policy.clone(),
    )?;
    Ok(encode_signature(&sign_statement(statement, key)?))
}

fn validated_artifacts(
    artifacts: BrokerAuthorizationArtifactsV1,
) -> Result<ValidatedUntrustedAuthorizationArtifacts> {
    let envelope = BrokerRequestEnvelope {
        method: BrokerMethod::BROKER_METHOD_NETWORK_APPLY.into(),
        body: vec![1],
        authorization: Some(artifacts).into(),
        ..Default::default()
    };
    decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::NetworkBroker, 0)
        .context("decode qualification request envelope")?
        .authorization()
        .cloned()
        .context("validated authorization artifacts are absent")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_observer_modes_have_valid_policy_catalogs() {
        assert!(policy_catalog(Mode::Isolated, None).is_ok());
        assert!(policy_catalog(Mode::Managed, Some(ObjectDigest::from_bytes([83; 32]))).is_ok());
    }
}
