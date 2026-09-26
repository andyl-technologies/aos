//! Node capability snapshots and their monotonic in-memory reducer.
//!
//! A snapshot is a bounded observation made by one node boot. It is scheduling
//! input only: accepting a snapshot cannot create an assignment, reserve
//! controller capacity, or grant ownership. Authentication and freshness at
//! the carrier boundary remain responsibilities of the coordinator-to-node
//! protocol implementation.

use std::cmp::Ordering;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{
    FeatureRef, NodeId, ObjectDigest, ObservationSequence, ProtocolVersion, ResourceDimension,
    ResourceVector,
};

use super::carrier_authority::AuthenticatedFrameSealV1;
use super::evidence::AuthenticatedEvidenceContextV1;

/// Maximum advertised semantic features in one node snapshot.
pub const MAX_NODE_FEATURES: usize = 256;
/// Maximum concrete host capability facts in one node snapshot.
pub const MAX_NODE_CAPABILITY_FACTS: usize = 32;
/// Maximum independently versioned protocol offers in one node snapshot.
pub const MAX_NODE_PROTOCOL_OFFERS: usize = 16;

/// Binds one versioned hard feature to the concrete probe fact that proves it.
///
/// Version 1.0 is closed: every namespace in the RFC-0021 hard-feature
/// registry appears exactly once here. A new feature semantic version requires
/// a new table rather than inheriting an older fact by prefix or namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardFeatureFactRequirementV1 {
    namespace: &'static str,
    version: ProtocolVersion,
    fact: NodeCapabilityKindV1,
}

impl HardFeatureFactRequirementV1 {
    /// Returns the exact registered hard-feature namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        self.namespace
    }

    /// Returns the exact feature semantics covered by this mapping.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns the required typed probe fact class.
    #[must_use]
    pub const fn fact(self) -> NodeCapabilityKindV1 {
        self.fact
    }
}

const HARD_FEATURE_FACT_REQUIREMENTS_V1_0: &[HardFeatureFactRequirementV1] = &[
    hard_feature(
        "aos.sandbox.runtime.linux-systemd",
        NodeCapabilityKindV1::NspawnVersion,
    ),
    hard_feature(
        "aos.sandbox.identity.posix32",
        NodeCapabilityKindV1::UserNamespaces,
    ),
    hard_feature(
        "aos.sandbox.metadata.posix-acl",
        NodeCapabilityKindV1::PosixAcl,
    ),
    hard_feature(
        "aos.sandbox.symlink.absolute",
        NodeCapabilityKindV1::AbsoluteSymlink,
    ),
    hard_feature(
        "aos.sandbox.symlink.parent-escape",
        NodeCapabilityKindV1::ParentEscapeSymlink,
    ),
    hard_feature(
        "aos.sandbox.enforcement.cgroup-v2",
        NodeCapabilityKindV1::CgroupV2,
    ),
    hard_feature(
        "aos.sandbox.enforcement.broker-ledger",
        NodeCapabilityKindV1::BrokerLedger,
    ),
    hard_feature(
        "aos.sandbox.authorization.signed-plan-lease",
        NodeCapabilityKindV1::SignedPlanLease,
    ),
    hard_feature(
        "aos.sandbox.authentication.broker-session",
        NodeCapabilityKindV1::BrokerSession,
    ),
    hard_feature(
        "aos.sandbox.mount.source-acquisition",
        NodeCapabilityKindV1::NewMountApi,
    ),
    hard_feature(
        "aos.sandbox.enforcement.zfs-quota",
        NodeCapabilityKindV1::ZfsPool,
    ),
    hard_feature(
        "aos.sandbox.residency.node-bounded-shared",
        NodeCapabilityKindV1::NodeBoundedSharedResidency,
    ),
    hard_feature(
        "aos.sandbox.residency.hard-isolated",
        NodeCapabilityKindV1::HardIsolatedResidency,
    ),
    hard_feature(
        "aos.sandbox.storage.portable",
        NodeCapabilityKindV1::SnapshotTransfer,
    ),
    hard_feature(
        "aos.sandbox.storage.zfs-held-snapshot",
        NodeCapabilityKindV1::ZfsPool,
    ),
    hard_feature(
        "aos.sandbox.quiesce.guest",
        NodeCapabilityKindV1::GuestQuiesce,
    ),
    hard_feature(
        "aos.sandbox.quiesce.storage",
        NodeCapabilityKindV1::StorageQuiesce,
    ),
];

const fn hard_feature(
    namespace: &'static str,
    fact: NodeCapabilityKindV1,
) -> HardFeatureFactRequirementV1 {
    HardFeatureFactRequirementV1 {
        namespace,
        version: ProtocolVersion::new(1, 0),
        fact,
    }
}

/// Returns the complete closed RFC-0021 v1.0 hard-feature/fact registry.
#[must_use]
pub const fn hard_feature_fact_requirements_v1_0() -> &'static [HardFeatureFactRequirementV1] {
    HARD_FEATURE_FACT_REQUIREMENTS_V1_0
}

/// Identifies one node boot without exposing a host path or process identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeBootId([u8; 16]);

impl NodeBootId {
    /// Constructs a nonzero boot identifier from exact opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::UnspecifiedIdentity`] for the all-zero
    /// sentinel.
    pub fn new(bytes: [u8; 16]) -> Result<Self, InvalidNodeCapability> {
        if bytes == [0; 16] {
            Err(InvalidNodeCapability::UnspecifiedIdentity)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Borrows the exact opaque boot-identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Commits one boot to a durable, non-ABA predecessor chain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeBootLineageV1 {
    boot: NodeBootId,
    generation: u64,
    predecessor_boot: Option<NodeBootId>,
    predecessor_digest: Option<ObjectDigest>,
    digest: ObjectDigest,
}

impl NodeBootLineageV1 {
    /// Computes the canonical commitment for one boot-lineage record.
    #[must_use]
    pub fn canonical_digest_for(
        boot: NodeBootId,
        generation: u64,
        predecessor_boot: Option<NodeBootId>,
        predecessor_digest: Option<ObjectDigest>,
    ) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.node-boot-lineage.v1\0");
        hasher.update(boot.as_bytes());
        hasher.update(generation.to_be_bytes());
        match (predecessor_boot, predecessor_digest) {
            (Some(prior_boot), Some(prior_digest)) => {
                hasher.update([1]);
                hasher.update(prior_boot.as_bytes());
                hasher.update(prior_digest.as_bytes());
            }
            _ => hasher.update([0]),
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Constructs one durable boot-lineage record.
    ///
    /// Generation one has no predecessor. Every later generation commits the
    /// immediately preceding boot and lineage digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::BootConflict`] for zero generations,
    /// missing or unexpected predecessor fields, self-predecessence, or a zero
    /// lineage digest.
    pub fn new(
        boot: NodeBootId,
        generation: u64,
        predecessor_boot: Option<NodeBootId>,
        predecessor_digest: Option<ObjectDigest>,
        digest: ObjectDigest,
    ) -> Result<Self, InvalidNodeCapability> {
        let predecessor_shape_valid = if generation == 1 {
            predecessor_boot.is_none() && predecessor_digest.is_none()
        } else {
            predecessor_boot.is_some() && predecessor_digest.is_some()
        };
        if generation == 0
            || !predecessor_shape_valid
            || predecessor_boot == Some(boot)
            || digest.as_bytes() == &[0; 32]
            || predecessor_digest.is_some_and(|value| value.as_bytes() == &[0; 32])
            || digest
                != Self::canonical_digest_for(
                    boot,
                    generation,
                    predecessor_boot,
                    predecessor_digest,
                )
        {
            return Err(InvalidNodeCapability::BootConflict);
        }
        Ok(Self {
            boot,
            generation,
            predecessor_boot,
            predecessor_digest,
            digest,
        })
    }

    /// Returns the opaque boot identity.
    #[must_use]
    pub const fn boot(self) -> NodeBootId {
        self.boot
    }

    /// Returns the durable monotonic boot generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the committed predecessor boot, when one exists.
    #[must_use]
    pub const fn predecessor_boot(self) -> Option<NodeBootId> {
        self.predecessor_boot
    }

    /// Returns the committed predecessor lineage digest, when one exists.
    #[must_use]
    pub const fn predecessor_digest(self) -> Option<ObjectDigest> {
        self.predecessor_digest
    }

    /// Returns this lineage record's canonical digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Reports whether this record is the exact direct successor of `prior`.
    #[must_use]
    pub fn is_direct_successor_of(self, prior: Self) -> bool {
        prior
            .generation
            .checked_add(1)
            .is_some_and(|next| next == self.generation)
            && self.predecessor_boot == Some(prior.boot)
            && self.predecessor_digest == Some(prior.digest)
            && self.boot != prior.boot
            && self.digest != prior.digest
    }
}

/// Binds typed probe facts and hard-feature conformance to immutable evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeProbeEvidenceV1 {
    probe_set_digest: ObjectDigest,
    conformance_profile_digest: ObjectDigest,
    conformance_version: ProtocolVersion,
    conformance_generation: u64,
}

impl NodeProbeEvidenceV1 {
    /// Constructs probe and conformance evidence commitments.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::InvalidProbeEvidence`] for zero
    /// commitments or generation.
    pub fn new(
        probe_set_digest: ObjectDigest,
        conformance_profile_digest: ObjectDigest,
        conformance_version: ProtocolVersion,
        conformance_generation: u64,
    ) -> Result<Self, InvalidNodeCapability> {
        if probe_set_digest.as_bytes() == &[0; 32]
            || conformance_profile_digest.as_bytes() == &[0; 32]
            || conformance_version != ProtocolVersion::new(1, 0)
            || conformance_generation == 0
        {
            return Err(InvalidNodeCapability::InvalidProbeEvidence);
        }
        Ok(Self {
            probe_set_digest,
            conformance_profile_digest,
            conformance_version,
            conformance_generation,
        })
    }

    /// Returns the digest of exact typed probe results.
    #[must_use]
    pub const fn probe_set_digest(self) -> ObjectDigest {
        self.probe_set_digest
    }

    /// Returns the digest of the passed semantic conformance profile.
    #[must_use]
    pub const fn conformance_profile_digest(self) -> ObjectDigest {
        self.conformance_profile_digest
    }

    /// Returns the exact v1.0 hard-feature/fact-map semantics covered by the evidence.
    #[must_use]
    pub const fn conformance_version(self) -> ProtocolVersion {
        self.conformance_version
    }

    /// Returns the monotonic conformance suite generation.
    #[must_use]
    pub const fn conformance_generation(self) -> u64 {
        self.conformance_generation
    }
}

/// Selects one independently negotiated node protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NodeProtocolV1 {
    /// Coordinator-to-node desired-state and observation protocol.
    CoordinatorNode = 0,
    /// Node-local host broker protocol.
    HostBroker = 1,
    /// Node-local storage broker protocol.
    StorageBroker = 2,
    /// Node-local mount broker protocol.
    MountBroker = 3,
    /// Node-local network broker protocol.
    NetworkBroker = 4,
    /// Assignment guardian protocol.
    Guardian = 5,
    /// Authenticated guest-agent protocol.
    GuestAgent = 6,
    /// Immutable integrity-checked snapshot transfer protocol.
    SnapshotTransfer = 7,
}

/// Identifies one concrete host capability fact class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NodeCapabilityKindV1 {
    /// Exact systemd-nspawn implementation version.
    NspawnVersion = 0,
    /// User namespace creation and mapping support.
    UserNamespaces = 1,
    /// Required new mount API operations.
    NewMountApi = 2,
    /// `listmount` and `statmount` observation support.
    MountObservation = 3,
    /// Idmapped mount support on admitted backing filesystems.
    IdmappedMounts = 4,
    /// FUSE protocol and optional passthrough support.
    Fuse = 5,
    /// ZFS pool and feature profile.
    ZfsPool = 6,
    /// Overlay behavior profile.
    Overlay = 7,
    /// KVM runtime availability.
    Kvm = 8,
    /// Cgroup-v2 enforcement support.
    CgroupV2 = 9,
    /// Seccomp enforcement support.
    Seccomp = 10,
    /// Immutable snapshot transfer support.
    SnapshotTransfer = 11,
    /// POSIX ACL normalization and enforcement conformance.
    PosixAcl = 12,
    /// Absolute symlink policy conformance.
    AbsoluteSymlink = 13,
    /// Parent-escape symlink policy conformance.
    ParentEscapeSymlink = 14,
    /// Durable broker-ledger enforcement conformance.
    BrokerLedger = 15,
    /// Signed plan/lease authorization conformance.
    SignedPlanLease = 16,
    /// Node-bounded shared residency conformance.
    NodeBoundedSharedResidency = 17,
    /// Hard-isolated residency conformance.
    HardIsolatedResidency = 18,
    /// Guest quiesce protocol conformance.
    GuestQuiesce = 19,
    /// Storage quiesce protocol conformance.
    StorageQuiesce = 20,
    /// Authenticated broker-session establishment conformance.
    BrokerSession = 21,
}

/// Stores one concrete, probe-derived host capability fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NodeCapabilityFactV1 {
    /// Reports exact systemd-nspawn release components.
    NspawnVersion {
        /// Major release component.
        major: u32,
        /// Minor release component.
        minor: u32,
        /// Patch release component.
        patch: u32,
    },
    /// Binds user-namespace mapping semantics to a conformance transcript.
    UserNamespaces(ObjectDigest),
    /// Binds the complete required new-mount-API operation set to conformance.
    NewMountApi(ObjectDigest),
    /// Reports `listmount` and `statmount` observation support.
    MountObservation,
    /// Binds supported idmap behavior to a normalized probe result.
    IdmappedMounts(ObjectDigest),
    /// Reports FUSE protocol and passthrough behavior.
    Fuse {
        /// FUSE protocol major version.
        major: u32,
        /// FUSE protocol minor version.
        minor: u32,
        /// Reports whether admitted immutable backing supports passthrough.
        passthrough: bool,
    },
    /// Binds exact usable ZFS pools and features to a normalized profile.
    ZfsPool(ObjectDigest),
    /// Binds observed overlay semantics to a normalized probe profile.
    Overlay(ObjectDigest),
    /// Reports KVM availability for admitted runtime profiles.
    Kvm,
    /// Binds cgroup-v2 hard-enforcement semantics to conformance.
    CgroupV2(ObjectDigest),
    /// Reports seccomp hard-enforcement support.
    Seccomp,
    /// Binds snapshot-transfer v1 integrity semantics to conformance.
    SnapshotTransfer(ObjectDigest),
    /// Binds POSIX ACL behavior to a conformance profile.
    PosixAcl(ObjectDigest),
    /// Binds absolute symlink behavior to a conformance profile.
    AbsoluteSymlink(ObjectDigest),
    /// Binds parent-escape symlink behavior to a conformance profile.
    ParentEscapeSymlink(ObjectDigest),
    /// Binds durable broker-ledger behavior to a conformance profile.
    BrokerLedger(ObjectDigest),
    /// Binds signed plan/lease enforcement to a conformance profile.
    SignedPlanLease(ObjectDigest),
    /// Binds node-bounded shared residency to a conformance profile.
    NodeBoundedSharedResidency(ObjectDigest),
    /// Binds hard-isolated residency to a conformance profile.
    HardIsolatedResidency(ObjectDigest),
    /// Binds guest quiesce semantics to a conformance profile.
    GuestQuiesce(ObjectDigest),
    /// Binds storage quiesce semantics to a conformance profile.
    StorageQuiesce(ObjectDigest),
    /// Binds broker-session authentication semantics to a conformance profile.
    BrokerSession(ObjectDigest),
}

impl NodeCapabilityFactV1 {
    /// Returns the unique concrete capability class.
    #[must_use]
    pub const fn kind(self) -> NodeCapabilityKindV1 {
        match self {
            Self::NspawnVersion { .. } => NodeCapabilityKindV1::NspawnVersion,
            Self::UserNamespaces(_) => NodeCapabilityKindV1::UserNamespaces,
            Self::NewMountApi(_) => NodeCapabilityKindV1::NewMountApi,
            Self::MountObservation => NodeCapabilityKindV1::MountObservation,
            Self::IdmappedMounts(_) => NodeCapabilityKindV1::IdmappedMounts,
            Self::Fuse { .. } => NodeCapabilityKindV1::Fuse,
            Self::ZfsPool(_) => NodeCapabilityKindV1::ZfsPool,
            Self::Overlay(_) => NodeCapabilityKindV1::Overlay,
            Self::Kvm => NodeCapabilityKindV1::Kvm,
            Self::CgroupV2(_) => NodeCapabilityKindV1::CgroupV2,
            Self::Seccomp => NodeCapabilityKindV1::Seccomp,
            Self::SnapshotTransfer(_) => NodeCapabilityKindV1::SnapshotTransfer,
            Self::PosixAcl(_) => NodeCapabilityKindV1::PosixAcl,
            Self::AbsoluteSymlink(_) => NodeCapabilityKindV1::AbsoluteSymlink,
            Self::ParentEscapeSymlink(_) => NodeCapabilityKindV1::ParentEscapeSymlink,
            Self::BrokerLedger(_) => NodeCapabilityKindV1::BrokerLedger,
            Self::SignedPlanLease(_) => NodeCapabilityKindV1::SignedPlanLease,
            Self::NodeBoundedSharedResidency(_) => NodeCapabilityKindV1::NodeBoundedSharedResidency,
            Self::HardIsolatedResidency(_) => NodeCapabilityKindV1::HardIsolatedResidency,
            Self::GuestQuiesce(_) => NodeCapabilityKindV1::GuestQuiesce,
            Self::StorageQuiesce(_) => NodeCapabilityKindV1::StorageQuiesce,
            Self::BrokerSession(_) => NodeCapabilityKindV1::BrokerSession,
        }
    }

    fn is_valid(self) -> bool {
        match self {
            Self::NspawnVersion { major, .. } | Self::Fuse { major, .. } => major != 0,
            Self::UserNamespaces(digest)
            | Self::NewMountApi(digest)
            | Self::IdmappedMounts(digest)
            | Self::ZfsPool(digest)
            | Self::Overlay(digest)
            | Self::PosixAcl(digest)
            | Self::AbsoluteSymlink(digest)
            | Self::ParentEscapeSymlink(digest)
            | Self::BrokerLedger(digest)
            | Self::CgroupV2(digest)
            | Self::SnapshotTransfer(digest)
            | Self::SignedPlanLease(digest)
            | Self::NodeBoundedSharedResidency(digest)
            | Self::HardIsolatedResidency(digest)
            | Self::GuestQuiesce(digest)
            | Self::StorageQuiesce(digest)
            | Self::BrokerSession(digest) => digest.as_bytes() != &[0; 32],
            Self::MountObservation | Self::Kvm | Self::Seccomp => true,
        }
    }
}

/// Advertises the highest semantic version implemented for one protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeProtocolOfferV1 {
    protocol: NodeProtocolV1,
    maximum_version: ProtocolVersion,
}

impl NodeProtocolOfferV1 {
    /// Constructs one protocol offer.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::InvalidProtocolVersion`] when the
    /// semantic major version is zero.
    pub const fn new(
        protocol: NodeProtocolV1,
        maximum_version: ProtocolVersion,
    ) -> Result<Self, InvalidNodeCapability> {
        if maximum_version.major() == 0 {
            return Err(InvalidNodeCapability::InvalidProtocolVersion);
        }
        Ok(Self {
            protocol,
            maximum_version,
        })
    }

    /// Returns the independently versioned protocol domain.
    #[must_use]
    pub const fn protocol(self) -> NodeProtocolV1 {
        self.protocol
    }

    /// Returns the maximum implemented semantic version.
    #[must_use]
    pub const fn maximum_version(self) -> ProtocolVersion {
        self.maximum_version
    }

    /// Reports whether this offer implements a required version.
    #[must_use]
    pub const fn supports(self, required: ProtocolVersion) -> bool {
        self.maximum_version.major() == required.major()
            && self.maximum_version.minor() >= required.minor()
    }
}

impl Ord for NodeProtocolOfferV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.protocol
            .cmp(&other.protocol)
            .then_with(|| self.maximum_version.cmp(&other.maximum_version))
    }
}

impl PartialOrd for NodeProtocolOfferV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Controls whether a valid node may receive new placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeAdmissionStateV1 {
    /// Allows new assignments.
    Accepting,
    /// Rejects new assignments while preserving existing assignments.
    Cordoned,
    /// Rejects new assignments and is actively evacuating selected work.
    Draining,
}

/// Reports a malformed or contradictory capability observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidNodeCapability {
    /// A node, boot, or sequence identity uses its zero sentinel.
    #[error("node capability snapshot contains an unspecified identity")]
    UnspecifiedIdentity,
    /// Feature entries are oversized, duplicated, or unordered.
    #[error("node features must be a canonical set of at most 256 entries")]
    FeaturesNotCanonical,
    /// Concrete host facts are oversized, malformed, duplicated, or unordered.
    #[error("node capability facts must be a canonical set of at most 32 entries")]
    FactsNotCanonical,
    /// Protocol entries are oversized, duplicated, or unordered by protocol.
    #[error("node protocols must be a canonical set of at most 16 entries")]
    ProtocolsNotCanonical,
    /// A protocol advertises semantic major version zero.
    #[error("node protocol semantic major version must be nonzero")]
    InvalidProtocolVersion,
    /// Reserved capacity exceeds allocatable capacity.
    #[error("node reserved capacity exceeds its allocatable capacity")]
    ReservedCapacityExceeded,
    /// A reducer received an observation for another node.
    #[error("node capability reducer received another node's snapshot")]
    NodeMismatch,
    /// One sequence names two different snapshots for the same boot.
    #[error("node capability sequence was reused for different content")]
    SequenceConflict,
    /// One boot identity is paired with different generations, or conversely.
    #[error("node boot identity and generation are inconsistent")]
    BootConflict,
    /// A boot advance skips or contradicts the committed predecessor chain.
    #[error("node boot lineage requires a durable complete bootstrap")]
    BootLineageGap,
    /// Probe or semantic conformance evidence is unspecified.
    #[error("node capability probe evidence is unspecified")]
    InvalidProbeEvidence,
    /// A hard semantic feature lacks its required typed probe fact.
    #[error("node hard feature contradicts its typed probe facts")]
    FeatureFactContradiction,
    /// Same coordinator epoch changed audience, disclosure, or carrier binding.
    #[error("node capability carrier binding equivocated within a coordinator epoch")]
    CarrierConflict,
    /// Authenticated carrier evidence is not current at the reduction time.
    #[error("node capability carrier evidence is not current")]
    EvidenceNotCurrent,
}

/// Stores one complete, bounded node capability observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCapabilitySnapshotV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    sequence: ObservationSequence,
    features: Vec<FeatureRef>,
    facts: Vec<NodeCapabilityFactV1>,
    protocols: Vec<NodeProtocolOfferV1>,
    allocatable: ResourceVector,
    reserved: ResourceVector,
    admission: NodeAdmissionStateV1,
    probe_evidence: NodeProbeEvidenceV1,
}

impl NodeCapabilitySnapshotV1 {
    /// Computes the canonical commitment to typed probe facts.
    ///
    /// The snapshot constructor separately validates fact shape and canonical
    /// ordering before accepting this commitment.
    #[must_use]
    pub fn canonical_probe_set_digest(facts: &[NodeCapabilityFactV1]) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.node-capability-probes.v1\0");
        hasher.update((facts.len() as u32).to_be_bytes());
        for fact in facts {
            hash_capability_fact(&mut hasher, *fact);
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Computes the versioned hard-feature conformance profile commitment.
    ///
    /// Version one maps every recognized hard feature at exactly `1.0` to one
    /// typed fact class; advertisements at another minor version fail closed
    /// until a new mapping is implemented.
    #[must_use]
    pub fn canonical_conformance_profile_digest(
        features: &[FeatureRef],
        facts: &[NodeCapabilityFactV1],
        version: ProtocolVersion,
        generation: u64,
    ) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.node-hard-feature-conformance.v1\0");
        hasher.update(version.major().to_be_bytes());
        hasher.update(version.minor().to_be_bytes());
        hasher.update(generation.to_be_bytes());
        hasher.update((features.len() as u32).to_be_bytes());
        for feature in features {
            hasher.update((feature.namespace().len() as u16).to_be_bytes());
            hasher.update(feature.namespace().as_bytes());
            hasher.update(feature.major().to_be_bytes());
            hasher.update(feature.minor().to_be_bytes());
        }
        hasher.update(Self::canonical_probe_set_digest(facts).as_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Constructs one complete node capability observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability`] for sentinel identities, noncanonical
    /// sets, or capacity that is already overcommitted.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: NodeId,
        lineage: NodeBootLineageV1,
        sequence: ObservationSequence,
        features: Vec<FeatureRef>,
        facts: Vec<NodeCapabilityFactV1>,
        protocols: Vec<NodeProtocolOfferV1>,
        allocatable: ResourceVector,
        reserved: ResourceVector,
        admission: NodeAdmissionStateV1,
        probe_evidence: NodeProbeEvidenceV1,
    ) -> Result<Self, InvalidNodeCapability> {
        if node.as_bytes() == &[0; 16] || sequence.get() == 0 {
            return Err(InvalidNodeCapability::UnspecifiedIdentity);
        }
        if features.len() > MAX_NODE_FEATURES || !strictly_increasing(&features) {
            return Err(InvalidNodeCapability::FeaturesNotCanonical);
        }
        if facts.len() > MAX_NODE_CAPABILITY_FACTS
            || facts.iter().any(|fact| !fact.is_valid())
            || !facts.windows(2).all(|pair| pair[0].kind() < pair[1].kind())
        {
            return Err(InvalidNodeCapability::FactsNotCanonical);
        }
        if protocols.len() > MAX_NODE_PROTOCOL_OFFERS
            || !protocols
                .windows(2)
                .all(|pair| pair[0].protocol() < pair[1].protocol())
        {
            return Err(InvalidNodeCapability::ProtocolsNotCanonical);
        }
        if !reserved.is_within(allocatable) {
            return Err(InvalidNodeCapability::ReservedCapacityExceeded);
        }
        if features.iter().any(|feature| {
            (is_known_hard_feature_namespace(feature.namespace())
                && (feature.major() != 1 || feature.minor() != 0))
                || required_fact_for_feature(feature)
                    .is_some_and(|kind| !facts.iter().any(|fact| fact.kind() == kind))
        }) || facts.iter().any(|fact| {
            is_hard_feature_fact(fact.kind()) && !fact_has_matching_feature(fact.kind(), &features)
        }) {
            return Err(InvalidNodeCapability::FeatureFactContradiction);
        }
        if features
            .iter()
            .any(|feature| feature.namespace() == "aos.sandbox.storage.portable")
            && !protocols.iter().any(|offer| {
                offer.protocol() == NodeProtocolV1::SnapshotTransfer
                    && offer.supports(ProtocolVersion::new(1, 0))
            })
        {
            return Err(InvalidNodeCapability::FeatureFactContradiction);
        }
        if probe_evidence.probe_set_digest() != Self::canonical_probe_set_digest(&facts) {
            return Err(InvalidNodeCapability::InvalidProbeEvidence);
        }
        if features.iter().any(|feature| {
            is_known_hard_feature_namespace(feature.namespace())
                && (feature.major() != u32::from(probe_evidence.conformance_version().major())
                    || feature.minor() > u32::from(probe_evidence.conformance_version().minor()))
        }) {
            return Err(InvalidNodeCapability::FeatureFactContradiction);
        }
        if probe_evidence.conformance_profile_digest()
            != Self::canonical_conformance_profile_digest(
                &features,
                &facts,
                probe_evidence.conformance_version(),
                probe_evidence.conformance_generation(),
            )
        {
            return Err(InvalidNodeCapability::InvalidProbeEvidence);
        }

        Ok(Self {
            node,
            lineage,
            sequence,
            features,
            facts,
            protocols,
            allocatable,
            reserved,
            admission,
            probe_evidence,
        })
    }

    /// Returns the observed node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the observed node boot.
    #[must_use]
    pub const fn boot(&self) -> NodeBootId {
        self.lineage.boot()
    }

    /// Returns the durable monotonic generation associated with the node boot.
    #[must_use]
    pub const fn boot_generation(&self) -> u64 {
        self.lineage.generation()
    }

    /// Returns the durable boot-lineage commitment.
    #[must_use]
    pub const fn lineage(&self) -> NodeBootLineageV1 {
        self.lineage
    }

    /// Returns the monotonic sequence within the node boot.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the canonical semantic feature set.
    #[must_use]
    pub fn features(&self) -> &[FeatureRef] {
        &self.features
    }

    /// Returns concrete probe-derived facts in canonical class order.
    #[must_use]
    pub fn facts(&self) -> &[NodeCapabilityFactV1] {
        &self.facts
    }

    /// Returns one concrete fact class when it was successfully probed.
    #[must_use]
    pub fn fact(&self, kind: NodeCapabilityKindV1) -> Option<NodeCapabilityFactV1> {
        self.facts
            .binary_search_by_key(&kind, |fact| fact.kind())
            .ok()
            .map(|index| self.facts[index])
    }

    /// Returns the canonical independently versioned protocol offers.
    #[must_use]
    pub fn protocols(&self) -> &[NodeProtocolOfferV1] {
        &self.protocols
    }

    /// Returns the total hard capacity exposed to placement.
    #[must_use]
    pub const fn allocatable(&self) -> ResourceVector {
        self.allocatable
    }

    /// Returns capacity already reserved by controller-known assignments.
    #[must_use]
    pub const fn reserved(&self) -> ResourceVector {
        self.reserved
    }

    /// Returns placement admission state.
    #[must_use]
    pub const fn admission(&self) -> NodeAdmissionStateV1 {
        self.admission
    }

    /// Returns immutable typed-probe and conformance commitments.
    #[must_use]
    pub const fn probe_evidence(&self) -> NodeProbeEvidenceV1 {
        self.probe_evidence
    }

    /// Returns unreserved capacity after validation.
    #[must_use]
    pub fn available(&self) -> ResourceVector {
        let mut available = ResourceVector::ZERO;
        for dimension in ResourceDimension::ALL {
            available = available.with(
                dimension,
                self.allocatable.get(dimension) - self.reserved.get(dimension),
            );
        }
        available
    }

    /// Reports whether the node implements the required feature semantics.
    #[must_use]
    pub fn supports_feature(&self, required: &FeatureRef) -> bool {
        self.features.iter().any(|offered| {
            offered.namespace() == required.namespace()
                && offered.major() == required.major()
                && offered.minor() >= required.minor()
        })
    }

    /// Reports whether the node implements the required protocol semantics.
    #[must_use]
    pub fn supports_protocol(&self, protocol: NodeProtocolV1, required: ProtocolVersion) -> bool {
        self.protocols
            .iter()
            .find(|offer| offer.protocol() == protocol)
            .is_some_and(|offer| offer.supports(required))
    }
}

/// Marks a capability snapshot whose exact carrier frame was authenticated.
///
/// Construction is crate-private so scheduling cannot consume a raw decoded
/// snapshot. The marker remains observation evidence and grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarrierValidatedCapabilityObservationV1 {
    snapshot: NodeCapabilitySnapshotV1,
    audience_node: NodeId,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    replay_fence: ObjectDigest,
}

impl CarrierValidatedCapabilityObservationV1 {
    /// Marks one snapshot after exact carrier authentication and canonical decoding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::InvalidProbeEvidence`] if either
    /// carrier or canonical observation commitment is zero.
    pub(super) fn from_authenticated_carrier(
        snapshot: NodeCapabilitySnapshotV1,
        context: AuthenticatedEvidenceContextV1,
        frame_seal: &AuthenticatedFrameSealV1,
        canonical_body_digest: ObjectDigest,
    ) -> Result<Self, InvalidNodeCapability> {
        let audience_node = context.node();
        let audience_digest = context.audience_digest();
        let disclosure_domain_digest = context.disclosure_domain_digest();
        let carrier_binding_digest = context.carrier_binding_digest();
        let canonical_frame_digest = context.canonical_frame_digest();
        let canonical_frame_bytes = context.canonical_frame_bytes();
        let coordinator_epoch = context.coordinator_epoch();
        let authenticated_at_unix_seconds = context.verified_at_unix_seconds();
        let valid_until_unix_seconds = context.valid_until_unix_seconds();
        let replay_fence = context.replay_fence();
        if snapshot.node() != audience_node
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || carrier_binding_digest.as_bytes() == &[0; 32]
            || canonical_frame_digest.as_bytes() == &[0; 32]
            || canonical_frame_bytes == 0
            || coordinator_epoch == 0
            || replay_fence.as_bytes() == &[0; 32]
            || valid_until_unix_seconds <= authenticated_at_unix_seconds
            || context.lineage() != snapshot.lineage()
            || !(frame_seal.matches(
                super::protocol::CanonicalNodeFrameKindV1::GetCapabilitiesResponse,
                canonical_body_digest,
                context,
            ) || frame_seal.matches(
                super::protocol::CanonicalNodeFrameKindV1::WatchResponse,
                canonical_body_digest,
                context,
            ))
        {
            return Err(InvalidNodeCapability::InvalidProbeEvidence);
        }
        Ok(Self {
            snapshot,
            audience_node,
            audience_digest,
            disclosure_domain_digest,
            carrier_binding_digest,
            canonical_frame_digest,
            canonical_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            replay_fence,
        })
    }

    /// Returns the validated capability semantics.
    #[must_use]
    pub const fn snapshot(&self) -> &NodeCapabilitySnapshotV1 {
        &self.snapshot
    }

    /// Returns the authenticated carrier binding commitment.
    #[must_use]
    pub const fn carrier_binding_digest(&self) -> ObjectDigest {
        self.carrier_binding_digest
    }

    /// Returns the exact authenticated node audience.
    #[must_use]
    pub const fn audience_node(&self) -> NodeId {
        self.audience_node
    }

    /// Returns the authenticated disclosure/audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the digest of exact canonical carrier bytes.
    #[must_use]
    pub const fn canonical_observation_digest(&self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Returns the exact bounded canonical carrier length.
    #[must_use]
    pub const fn canonical_frame_bytes(&self) -> u32 {
        self.canonical_frame_bytes
    }

    /// Returns the coordinator epoch that authenticated this observation.
    #[must_use]
    pub const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }

    /// Returns the authenticated carrier receipt time.
    #[must_use]
    pub const fn authenticated_at_unix_seconds(&self) -> u64 {
        self.authenticated_at_unix_seconds
    }

    /// Returns the fail-closed currentness deadline.
    #[must_use]
    pub const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }

    /// Returns the protected carrier verifier replay-fence commitment.
    #[must_use]
    pub const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }

    /// Reports whether carrier currentness holds at an exact coordinator time.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        coordinator_unix_seconds >= self.authenticated_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Returns a commitment to the complete placement observation identity and currentness.
    ///
    /// This binds the semantic snapshot, durable boot lineage, exact carrier,
    /// audience, disclosure domain, coordinator epoch, and verifier interval.
    /// Assignment acceptance records use it to prevent a current assignment
    /// from being paired with a different or expired placement observation.
    #[must_use]
    pub fn evidence_binding_digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.node-capability.evidence-binding.v1\0");
        hasher.update(self.snapshot.node().as_bytes());
        hasher.update(self.snapshot.boot().as_bytes());
        hasher.update(self.snapshot.boot_generation().to_be_bytes());
        hasher.update(self.snapshot.lineage().digest().as_bytes());
        hasher.update(self.snapshot.sequence().get().to_be_bytes());
        hasher.update(self.audience_node.as_bytes());
        hasher.update(self.audience_digest.as_bytes());
        hasher.update(self.disclosure_domain_digest.as_bytes());
        hasher.update(self.carrier_binding_digest.as_bytes());
        hasher.update(self.canonical_frame_digest.as_bytes());
        hasher.update(self.canonical_frame_bytes.to_be_bytes());
        hasher.update(self.coordinator_epoch.to_be_bytes());
        hasher.update(self.authenticated_at_unix_seconds.to_be_bytes());
        hasher.update(self.valid_until_unix_seconds.to_be_bytes());
        hasher.update(self.replay_fence.as_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Describes how a newly accepted capability snapshot changed reducer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityChangeV1 {
    /// Installs the first snapshot observed for the node.
    Initial,
    /// Advances observations within the same boot.
    Updated,
    /// Replaces observations after a node reboot.
    Rebooted,
}

/// Reports the pure result of reducing one capability snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityApplyOutcomeV1 {
    /// Reducer state changed.
    Applied(CapabilityChangeV1),
    /// The exact current snapshot was replayed.
    Replay,
    /// An older snapshot was ignored.
    Stale,
}

/// Reduces authenticated capability observations for one fixed node.
///
/// The reducer deliberately accepts no signature, lease, or ownership token.
/// Its output remains scheduling evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCapabilityReducerV1 {
    node: NodeId,
    current: Option<CarrierValidatedCapabilityObservationV1>,
}

impl NodeCapabilityReducerV1 {
    /// Creates an empty reducer for one nonzero node identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability::UnspecifiedIdentity`] for the zero
    /// node sentinel.
    pub fn new(node: NodeId) -> Result<Self, InvalidNodeCapability> {
        if node.as_bytes() == &[0; 16] {
            return Err(InvalidNodeCapability::UnspecifiedIdentity);
        }
        Ok(Self {
            node,
            current: None,
        })
    }

    /// Returns the latest accepted observation while its carrier remains current.
    #[must_use]
    pub fn current_at(
        &self,
        coordinator_unix_seconds: u64,
    ) -> Option<&CarrierValidatedCapabilityObservationV1> {
        self.current
            .as_ref()
            .filter(|observation| observation.is_current_at(coordinator_unix_seconds))
    }

    /// Reduces one already authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNodeCapability`] for stale carrier evidence, another
    /// node, same-sequence equivocation, or a non-advancing boot generation.
    pub fn apply(
        &mut self,
        observation: CarrierValidatedCapabilityObservationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<CapabilityApplyOutcomeV1, InvalidNodeCapability> {
        let snapshot = observation.snapshot();
        if snapshot.node() != self.node {
            return Err(InvalidNodeCapability::NodeMismatch);
        }
        if !observation.is_current_at(coordinator_unix_seconds) {
            return Err(InvalidNodeCapability::EvidenceNotCurrent);
        }

        let Some(current) = &self.current else {
            self.current = Some(observation);
            return Ok(CapabilityApplyOutcomeV1::Applied(
                CapabilityChangeV1::Initial,
            ));
        };

        let current_snapshot = current.snapshot();
        if observation.coordinator_epoch() < current.coordinator_epoch() {
            return Ok(CapabilityApplyOutcomeV1::Stale);
        }
        if observation.coordinator_epoch() == current.coordinator_epoch()
            && (observation.audience_digest() != current.audience_digest()
                || observation.disclosure_domain_digest() != current.disclosure_domain_digest()
                || observation.carrier_binding_digest() != current.carrier_binding_digest())
        {
            return Err(InvalidNodeCapability::CarrierConflict);
        }
        if observation.coordinator_epoch() > current.coordinator_epoch()
            && snapshot == current_snapshot
        {
            self.current = Some(observation);
            return Ok(CapabilityApplyOutcomeV1::Applied(
                CapabilityChangeV1::Updated,
            ));
        }
        if snapshot.boot_generation() < current_snapshot.boot_generation() {
            return Ok(CapabilityApplyOutcomeV1::Stale);
        }
        if snapshot.boot_generation() == current_snapshot.boot_generation()
            && snapshot.lineage() != current_snapshot.lineage()
        {
            return Err(InvalidNodeCapability::BootConflict);
        }
        if snapshot.boot_generation() > current_snapshot.boot_generation() {
            if !snapshot
                .lineage()
                .is_direct_successor_of(current_snapshot.lineage())
            {
                return Err(InvalidNodeCapability::BootLineageGap);
            }
            self.current = Some(observation);
            return Ok(CapabilityApplyOutcomeV1::Applied(
                CapabilityChangeV1::Rebooted,
            ));
        }

        match snapshot.sequence().cmp(&current_snapshot.sequence()) {
            Ordering::Less => Ok(CapabilityApplyOutcomeV1::Stale),
            Ordering::Equal if observation == *current => Ok(CapabilityApplyOutcomeV1::Replay),
            Ordering::Equal => Err(InvalidNodeCapability::SequenceConflict),
            Ordering::Greater => {
                self.current = Some(observation);
                Ok(CapabilityApplyOutcomeV1::Applied(
                    CapabilityChangeV1::Updated,
                ))
            }
        }
    }
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn required_fact_for_feature(feature: &FeatureRef) -> Option<NodeCapabilityKindV1> {
    HARD_FEATURE_FACT_REQUIREMENTS_V1_0
        .iter()
        .find(|requirement| {
            requirement.namespace == feature.namespace()
                && u32::from(requirement.version.major()) == feature.major()
                && u32::from(requirement.version.minor()) == feature.minor()
        })
        .map(|requirement| requirement.fact)
}

fn is_known_hard_feature_namespace(namespace: &str) -> bool {
    HARD_FEATURE_FACT_REQUIREMENTS_V1_0
        .iter()
        .any(|requirement| requirement.namespace == namespace)
}

fn is_hard_feature_fact(kind: NodeCapabilityKindV1) -> bool {
    matches!(
        kind,
        NodeCapabilityKindV1::NspawnVersion
            | NodeCapabilityKindV1::UserNamespaces
            | NodeCapabilityKindV1::NewMountApi
            | NodeCapabilityKindV1::ZfsPool
            | NodeCapabilityKindV1::CgroupV2
            | NodeCapabilityKindV1::SnapshotTransfer
            | NodeCapabilityKindV1::PosixAcl
            | NodeCapabilityKindV1::AbsoluteSymlink
            | NodeCapabilityKindV1::ParentEscapeSymlink
            | NodeCapabilityKindV1::BrokerLedger
            | NodeCapabilityKindV1::SignedPlanLease
            | NodeCapabilityKindV1::NodeBoundedSharedResidency
            | NodeCapabilityKindV1::HardIsolatedResidency
            | NodeCapabilityKindV1::GuestQuiesce
            | NodeCapabilityKindV1::StorageQuiesce
            | NodeCapabilityKindV1::BrokerSession
    )
}

fn fact_has_matching_feature(kind: NodeCapabilityKindV1, features: &[FeatureRef]) -> bool {
    HARD_FEATURE_FACT_REQUIREMENTS_V1_0
        .iter()
        .filter(|requirement| requirement.fact == kind)
        .any(|requirement| {
            features.iter().any(|feature| {
                feature.namespace() == requirement.namespace
                    && feature.major() == u32::from(requirement.version.major())
                    && feature.minor() == u32::from(requirement.version.minor())
            })
        })
}

fn hash_capability_fact(hasher: &mut Sha256, fact: NodeCapabilityFactV1) {
    hasher.update([fact.kind() as u8]);
    match fact {
        NodeCapabilityFactV1::NspawnVersion {
            major,
            minor,
            patch,
        } => {
            hasher.update(major.to_be_bytes());
            hasher.update(minor.to_be_bytes());
            hasher.update(patch.to_be_bytes());
        }
        NodeCapabilityFactV1::UserNamespaces(digest)
        | NodeCapabilityFactV1::NewMountApi(digest)
        | NodeCapabilityFactV1::IdmappedMounts(digest)
        | NodeCapabilityFactV1::ZfsPool(digest)
        | NodeCapabilityFactV1::Overlay(digest)
        | NodeCapabilityFactV1::PosixAcl(digest)
        | NodeCapabilityFactV1::AbsoluteSymlink(digest)
        | NodeCapabilityFactV1::ParentEscapeSymlink(digest)
        | NodeCapabilityFactV1::BrokerLedger(digest)
        | NodeCapabilityFactV1::CgroupV2(digest)
        | NodeCapabilityFactV1::SnapshotTransfer(digest)
        | NodeCapabilityFactV1::SignedPlanLease(digest)
        | NodeCapabilityFactV1::NodeBoundedSharedResidency(digest)
        | NodeCapabilityFactV1::HardIsolatedResidency(digest)
        | NodeCapabilityFactV1::GuestQuiesce(digest)
        | NodeCapabilityFactV1::StorageQuiesce(digest)
        | NodeCapabilityFactV1::BrokerSession(digest) => hasher.update(digest.as_bytes()),
        NodeCapabilityFactV1::Fuse {
            major,
            minor,
            passthrough,
        } => {
            hasher.update(major.to_be_bytes());
            hasher.update(minor.to_be_bytes());
            hasher.update([u8::from(passthrough)]);
        }
        NodeCapabilityFactV1::MountObservation
        | NodeCapabilityFactV1::Kvm
        | NodeCapabilityFactV1::Seccomp => {}
    }
}
