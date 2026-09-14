//! Closed canonical JSON schema for every version-one node method.
//!
//! This module is deliberately concrete: every frame kind has an explicit
//! body projection, every nested object rejects unknown fields, and decoding
//! reconstructs validated domain models through their constructors. Version
//! one never ignores fields; additive evolution requires a negotiated schema.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use aos_sandbox_core::state::{AssignmentPhase, DesiredSandboxState};
use aos_sandbox_core::{
    AssignmentEpoch, CanonicalAssignmentManifestV1, DecodeLimits, DesiredGeneration, FeatureRef,
    IncarnationId, NodeId, ObjectDescriptor, ObjectDigest, ObservationSequence, OperationId,
    ProjectId, ProtocolVersion, ResourceVector, SandboxId, SnapshotId,
};

use super::{
    AuthenticatedEvidenceContextV1, CanonicalNodeFrameKindV1, CanonicalNodeSemanticCodecV1,
    InvalidMultiNodeProtocol, NodeRequestBodyV1, NodeResponseBodyV1, NodeWatchBindingV1,
    NodeWatchCursorV1, NodeWatchEventBodyV1, NodeWatchEventV1, ResyncInventoryV1,
    RollingVersionWindowV1, canonical_frame_kind_name_v1,
};
use crate::multi_node::assignment::{
    AssignmentIntentV1, AssignmentObservationReasonV1, NodeAssignmentObservationV1,
    SelectedCapabilityBindingV1, SnapshotDependencyRangeV1, SnapshotTransferChunkRequestV1,
    SnapshotTransferChunkV1, SnapshotTransferIdentityV1, SnapshotTransferManifestV1,
    SnapshotTransferResumeV1, SnapshotTransferVersionV1,
};
use crate::multi_node::capability::{
    NodeAdmissionStateV1, NodeBootId, NodeBootLineageV1, NodeCapabilityFactV1,
    NodeCapabilitySnapshotV1, NodeProbeEvidenceV1, NodeProtocolOfferV1, NodeProtocolV1,
};
use crate::multi_node::draining::{
    DrainAssignmentObservationV1, DrainAssignmentPlanV1, DrainAssignmentProgressV1,
    DrainAssignmentStrategyV1, DrainBlockReasonV1, DrainDirectiveV1, DrainObservationV1,
    DrainPhaseV1, NodeDrainModeV1,
};

const SCHEMA: &str = "aos.node.semantic.v1";

#[derive(Serialize)]
struct EnvelopeRef<'a, T> {
    body: &'a T,
    kind: &'static str,
    schema: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeOwned<T> {
    body: T,
    kind: String,
    schema: String,
}

fn encode<T: Serialize>(
    kind: CanonicalNodeFrameKindV1,
    body: &T,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    let value = serde_json::to_value(EnvelopeRef {
        body,
        kind: canonical_frame_kind_name_v1(kind),
        schema: SCHEMA,
    })
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    serde_json::to_vec(&value).map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

fn decode<T: DeserializeOwned>(
    kind: CanonicalNodeFrameKindV1,
    bytes: &[u8],
) -> Result<T, InvalidMultiNodeProtocol> {
    let envelope: EnvelopeOwned<T> =
        serde_json::from_slice(bytes).map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    if envelope.schema != SCHEMA || envelope.kind != canonical_frame_kind_name_v1(kind) {
        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
    }
    Ok(envelope.body)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionWire {
    major: u16,
    minor: u16,
}

impl From<ProtocolVersion> for VersionWire {
    fn from(value: ProtocolVersion) -> Self {
        Self {
            major: value.major(),
            minor: value.minor(),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageWire {
    boot: [u8; 16],
    digest: ObjectDigest,
    generation: u64,
    predecessor_boot: Option<[u8; 16]>,
    predecessor_digest: Option<ObjectDigest>,
}

impl From<NodeBootLineageV1> for LineageWire {
    fn from(value: NodeBootLineageV1) -> Self {
        Self {
            boot: *value.boot().as_bytes(),
            digest: value.digest(),
            generation: value.generation(),
            predecessor_boot: value.predecessor_boot().map(|boot| *boot.as_bytes()),
            predecessor_digest: value.predecessor_digest(),
        }
    }
}

impl LineageWire {
    fn model(self) -> Result<NodeBootLineageV1, InvalidMultiNodeProtocol> {
        NodeBootLineageV1::new(
            NodeBootId::new(self.boot).map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
            self.generation,
            self.predecessor_boot
                .map(NodeBootId::new)
                .transpose()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
            self.predecessor_digest,
            self.digest,
        )
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FactWire {
    NspawnVersion {
        major: u32,
        minor: u32,
        patch: u32,
    },
    UserNamespaces {
        digest: ObjectDigest,
    },
    NewMountApi {
        digest: ObjectDigest,
    },
    MountObservation,
    IdmappedMounts {
        digest: ObjectDigest,
    },
    Fuse {
        major: u32,
        minor: u32,
        passthrough: bool,
    },
    ZfsPool {
        digest: ObjectDigest,
    },
    Overlay {
        digest: ObjectDigest,
    },
    Kvm,
    CgroupV2 {
        digest: ObjectDigest,
    },
    Seccomp,
    SnapshotTransfer {
        digest: ObjectDigest,
    },
    PosixAcl {
        digest: ObjectDigest,
    },
    AbsoluteSymlink {
        digest: ObjectDigest,
    },
    ParentEscapeSymlink {
        digest: ObjectDigest,
    },
    BrokerLedger {
        digest: ObjectDigest,
    },
    SignedPlanLease {
        digest: ObjectDigest,
    },
    NodeBoundedSharedResidency {
        digest: ObjectDigest,
    },
    HardIsolatedResidency {
        digest: ObjectDigest,
    },
    GuestQuiesce {
        digest: ObjectDigest,
    },
    StorageQuiesce {
        digest: ObjectDigest,
    },
    BrokerSession {
        digest: ObjectDigest,
    },
}

impl From<NodeCapabilityFactV1> for FactWire {
    fn from(value: NodeCapabilityFactV1) -> Self {
        use NodeCapabilityFactV1 as F;
        match value {
            F::NspawnVersion {
                major,
                minor,
                patch,
            } => Self::NspawnVersion {
                major,
                minor,
                patch,
            },
            F::UserNamespaces(digest) => Self::UserNamespaces { digest },
            F::NewMountApi(digest) => Self::NewMountApi { digest },
            F::MountObservation => Self::MountObservation,
            F::IdmappedMounts(digest) => Self::IdmappedMounts { digest },
            F::Fuse {
                major,
                minor,
                passthrough,
            } => Self::Fuse {
                major,
                minor,
                passthrough,
            },
            F::ZfsPool(digest) => Self::ZfsPool { digest },
            F::Overlay(digest) => Self::Overlay { digest },
            F::Kvm => Self::Kvm,
            F::CgroupV2(digest) => Self::CgroupV2 { digest },
            F::Seccomp => Self::Seccomp,
            F::SnapshotTransfer(digest) => Self::SnapshotTransfer { digest },
            F::PosixAcl(digest) => Self::PosixAcl { digest },
            F::AbsoluteSymlink(digest) => Self::AbsoluteSymlink { digest },
            F::ParentEscapeSymlink(digest) => Self::ParentEscapeSymlink { digest },
            F::BrokerLedger(digest) => Self::BrokerLedger { digest },
            F::SignedPlanLease(digest) => Self::SignedPlanLease { digest },
            F::NodeBoundedSharedResidency(digest) => Self::NodeBoundedSharedResidency { digest },
            F::HardIsolatedResidency(digest) => Self::HardIsolatedResidency { digest },
            F::GuestQuiesce(digest) => Self::GuestQuiesce { digest },
            F::StorageQuiesce(digest) => Self::StorageQuiesce { digest },
            F::BrokerSession(digest) => Self::BrokerSession { digest },
        }
    }
}

impl From<FactWire> for NodeCapabilityFactV1 {
    fn from(value: FactWire) -> Self {
        match value {
            FactWire::NspawnVersion {
                major,
                minor,
                patch,
            } => Self::NspawnVersion {
                major,
                minor,
                patch,
            },
            FactWire::UserNamespaces { digest } => Self::UserNamespaces(digest),
            FactWire::NewMountApi { digest } => Self::NewMountApi(digest),
            FactWire::MountObservation => Self::MountObservation,
            FactWire::IdmappedMounts { digest } => Self::IdmappedMounts(digest),
            FactWire::Fuse {
                major,
                minor,
                passthrough,
            } => Self::Fuse {
                major,
                minor,
                passthrough,
            },
            FactWire::ZfsPool { digest } => Self::ZfsPool(digest),
            FactWire::Overlay { digest } => Self::Overlay(digest),
            FactWire::Kvm => Self::Kvm,
            FactWire::CgroupV2 { digest } => Self::CgroupV2(digest),
            FactWire::Seccomp => Self::Seccomp,
            FactWire::SnapshotTransfer { digest } => Self::SnapshotTransfer(digest),
            FactWire::PosixAcl { digest } => Self::PosixAcl(digest),
            FactWire::AbsoluteSymlink { digest } => Self::AbsoluteSymlink(digest),
            FactWire::ParentEscapeSymlink { digest } => Self::ParentEscapeSymlink(digest),
            FactWire::BrokerLedger { digest } => Self::BrokerLedger(digest),
            FactWire::SignedPlanLease { digest } => Self::SignedPlanLease(digest),
            FactWire::NodeBoundedSharedResidency { digest } => {
                Self::NodeBoundedSharedResidency(digest)
            }
            FactWire::HardIsolatedResidency { digest } => Self::HardIsolatedResidency(digest),
            FactWire::GuestQuiesce { digest } => Self::GuestQuiesce(digest),
            FactWire::StorageQuiesce { digest } => Self::StorageQuiesce(digest),
            FactWire::BrokerSession { digest } => Self::BrokerSession(digest),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolWire {
    CoordinatorNode,
    HostBroker,
    StorageBroker,
    MountBroker,
    NetworkBroker,
    Guardian,
    GuestAgent,
    SnapshotTransfer,
}

impl From<NodeProtocolV1> for ProtocolWire {
    fn from(value: NodeProtocolV1) -> Self {
        match value {
            NodeProtocolV1::CoordinatorNode => Self::CoordinatorNode,
            NodeProtocolV1::HostBroker => Self::HostBroker,
            NodeProtocolV1::StorageBroker => Self::StorageBroker,
            NodeProtocolV1::MountBroker => Self::MountBroker,
            NodeProtocolV1::NetworkBroker => Self::NetworkBroker,
            NodeProtocolV1::Guardian => Self::Guardian,
            NodeProtocolV1::GuestAgent => Self::GuestAgent,
            NodeProtocolV1::SnapshotTransfer => Self::SnapshotTransfer,
        }
    }
}
impl From<ProtocolWire> for NodeProtocolV1 {
    fn from(value: ProtocolWire) -> Self {
        match value {
            ProtocolWire::CoordinatorNode => Self::CoordinatorNode,
            ProtocolWire::HostBroker => Self::HostBroker,
            ProtocolWire::StorageBroker => Self::StorageBroker,
            ProtocolWire::MountBroker => Self::MountBroker,
            ProtocolWire::NetworkBroker => Self::NetworkBroker,
            ProtocolWire::Guardian => Self::Guardian,
            ProtocolWire::GuestAgent => Self::GuestAgent,
            ProtocolWire::SnapshotTransfer => Self::SnapshotTransfer,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferWire {
    maximum_version: VersionWire,
    protocol: ProtocolWire,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AdmissionWire {
    Accepting,
    Cordoned,
    Draining,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeWire {
    conformance_generation: u64,
    conformance_profile_digest: ObjectDigest,
    conformance_version: VersionWire,
    probe_set_digest: ObjectDigest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::multi_node) struct CapabilityWire {
    admission: AdmissionWire,
    allocatable: ResourceVector,
    facts: Vec<FactWire>,
    features: Vec<FeatureRef>,
    lineage: LineageWire,
    node: NodeId,
    probe_evidence: ProbeWire,
    protocols: Vec<OfferWire>,
    reserved: ResourceVector,
    sequence: ObservationSequence,
}

pub(in crate::multi_node) fn capability_wire(value: &NodeCapabilitySnapshotV1) -> CapabilityWire {
    let probe = value.probe_evidence();
    CapabilityWire {
        admission: match value.admission() {
            NodeAdmissionStateV1::Accepting => AdmissionWire::Accepting,
            NodeAdmissionStateV1::Cordoned => AdmissionWire::Cordoned,
            NodeAdmissionStateV1::Draining => AdmissionWire::Draining,
        },
        allocatable: value.allocatable(),
        facts: value.facts().iter().copied().map(Into::into).collect(),
        features: value.features().to_vec(),
        lineage: value.lineage().into(),
        node: value.node(),
        probe_evidence: ProbeWire {
            conformance_generation: probe.conformance_generation(),
            conformance_profile_digest: probe.conformance_profile_digest(),
            conformance_version: probe.conformance_version().into(),
            probe_set_digest: probe.probe_set_digest(),
        },
        protocols: value
            .protocols()
            .iter()
            .copied()
            .map(|offer| OfferWire {
                maximum_version: offer.maximum_version().into(),
                protocol: offer.protocol().into(),
            })
            .collect(),
        reserved: value.reserved(),
        sequence: value.sequence(),
    }
}

pub(in crate::multi_node) fn capability_model(
    value: CapabilityWire,
) -> Result<NodeCapabilitySnapshotV1, InvalidMultiNodeProtocol> {
    let facts: Vec<_> = value.facts.into_iter().map(Into::into).collect();
    let protocols = value
        .protocols
        .into_iter()
        .map(|offer| {
            NodeProtocolOfferV1::new(
                offer.protocol.into(),
                ProtocolVersion::new(offer.maximum_version.major, offer.maximum_version.minor),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    let probe = NodeProbeEvidenceV1::new(
        value.probe_evidence.probe_set_digest,
        value.probe_evidence.conformance_profile_digest,
        ProtocolVersion::new(
            value.probe_evidence.conformance_version.major,
            value.probe_evidence.conformance_version.minor,
        ),
        value.probe_evidence.conformance_generation,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    NodeCapabilitySnapshotV1::new(
        value.node,
        value.lineage.model()?,
        value.sequence,
        value.features,
        facts,
        protocols,
        value.allocatable,
        value.reserved,
        match value.admission {
            AdmissionWire::Accepting => NodeAdmissionStateV1::Accepting,
            AdmissionWire::Cordoned => NodeAdmissionStateV1::Cordoned,
            AdmissionWire::Draining => NodeAdmissionStateV1::Draining,
        },
        probe,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    authenticated_at_unix_seconds: u64,
    audience_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    canonical_frame_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    coordinator_epoch: u64,
    disclosure_domain_digest: ObjectDigest,
    evidence_binding_digest: ObjectDigest,
    lineage: LineageWire,
    node: NodeId,
    replay_fence: ObjectDigest,
    sequence: ObservationSequence,
    valid_until_unix_seconds: u64,
}

impl From<SelectedCapabilityBindingV1> for BindingWire {
    fn from(v: SelectedCapabilityBindingV1) -> Self {
        Self {
            authenticated_at_unix_seconds: v.authenticated_at_unix_seconds(),
            audience_digest: v.audience_digest(),
            canonical_frame_bytes: v.canonical_frame_bytes(),
            canonical_frame_digest: v.canonical_frame_digest(),
            carrier_binding_digest: v.carrier_binding_digest(),
            coordinator_epoch: v.coordinator_epoch(),
            disclosure_domain_digest: v.disclosure_domain_digest(),
            evidence_binding_digest: v.evidence_binding_digest(),
            lineage: v.lineage().into(),
            node: v.node(),
            replay_fence: v.replay_fence(),
            sequence: v.sequence(),
            valid_until_unix_seconds: v.valid_until_unix_seconds(),
        }
    }
}
impl BindingWire {
    fn model(self) -> Result<SelectedCapabilityBindingV1, InvalidMultiNodeProtocol> {
        SelectedCapabilityBindingV1::new(
            self.node,
            self.lineage.model()?,
            self.sequence,
            self.evidence_binding_digest,
            self.canonical_frame_digest,
            self.canonical_frame_bytes,
            self.coordinator_epoch,
            self.authenticated_at_unix_seconds,
            self.valid_until_unix_seconds,
            self.audience_digest,
            self.disclosure_domain_digest,
            self.carrier_binding_digest,
            self.replay_fence,
        )
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::multi_node) struct IntentWire {
    assignment: Vec<u8>,
    desired_lifecycle: DesiredSandboxState,
    selected_capability: BindingWire,
}
pub(in crate::multi_node) fn intent_wire(v: &AssignmentIntentV1) -> IntentWire {
    IntentWire {
        assignment: v.assignment().canonical_bytes().to_vec(),
        desired_lifecycle: v.desired_lifecycle(),
        selected_capability: v.selected_capability_binding().into(),
    }
}
pub(in crate::multi_node) fn intent_model(
    v: IntentWire,
) -> Result<AssignmentIntentV1, InvalidMultiNodeProtocol> {
    let limits = DecodeLimits {
        maximum_bytes: v.assignment.len(),
        ..DecodeLimits::default()
    };
    let assignment = CanonicalAssignmentManifestV1::from_canonical_bytes(&v.assignment, limits)
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    AssignmentIntentV1::from_canonical_binding(
        assignment,
        v.desired_lifecycle,
        v.selected_capability.model()?,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReasonWire {
    None,
    AwaitingContent,
    AwaitingCapacity,
    CapabilityDrift,
    AwaitingOwnershipAuthority,
    AwaitingGuardian,
    OwnershipFenced,
    InventoryIncomplete,
    ResidualState,
    MissingDependency,
    NodeOperationFailed,
}
impl From<AssignmentObservationReasonV1> for ReasonWire {
    fn from(v: AssignmentObservationReasonV1) -> Self {
        match v {
            AssignmentObservationReasonV1::None => Self::None,
            AssignmentObservationReasonV1::AwaitingContent => Self::AwaitingContent,
            AssignmentObservationReasonV1::AwaitingCapacity => Self::AwaitingCapacity,
            AssignmentObservationReasonV1::CapabilityDrift => Self::CapabilityDrift,
            AssignmentObservationReasonV1::AwaitingOwnershipAuthority => {
                Self::AwaitingOwnershipAuthority
            }
            AssignmentObservationReasonV1::AwaitingGuardian => Self::AwaitingGuardian,
            AssignmentObservationReasonV1::OwnershipFenced => Self::OwnershipFenced,
            AssignmentObservationReasonV1::InventoryIncomplete => Self::InventoryIncomplete,
            AssignmentObservationReasonV1::ResidualState => Self::ResidualState,
            AssignmentObservationReasonV1::MissingDependency => Self::MissingDependency,
            AssignmentObservationReasonV1::NodeOperationFailed => Self::NodeOperationFailed,
        }
    }
}
impl From<ReasonWire> for AssignmentObservationReasonV1 {
    fn from(v: ReasonWire) -> Self {
        match v {
            ReasonWire::None => Self::None,
            ReasonWire::AwaitingContent => Self::AwaitingContent,
            ReasonWire::AwaitingCapacity => Self::AwaitingCapacity,
            ReasonWire::CapabilityDrift => Self::CapabilityDrift,
            ReasonWire::AwaitingOwnershipAuthority => Self::AwaitingOwnershipAuthority,
            ReasonWire::AwaitingGuardian => Self::AwaitingGuardian,
            ReasonWire::OwnershipFenced => Self::OwnershipFenced,
            ReasonWire::InventoryIncomplete => Self::InventoryIncomplete,
            ReasonWire::ResidualState => Self::ResidualState,
            ReasonWire::MissingDependency => Self::MissingDependency,
            ReasonWire::NodeOperationFailed => Self::NodeOperationFailed,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentObservationWire {
    assignment_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    epoch: AssignmentEpoch,
    incarnation: IncarnationId,
    observed_at_unix_seconds: u64,
    phase: AssignmentPhase,
    realized_lifecycle: Option<DesiredSandboxState>,
    reason: ReasonWire,
    sandbox: SandboxId,
    sequence: ObservationSequence,
}
fn assignment_observation_wire(v: &NodeAssignmentObservationV1) -> AssignmentObservationWire {
    AssignmentObservationWire {
        assignment_digest: v.assignment_digest(),
        desired_generation: v.desired_generation(),
        epoch: v.epoch(),
        incarnation: v.incarnation(),
        observed_at_unix_seconds: v.observed_at_unix_seconds(),
        phase: v.phase(),
        realized_lifecycle: v.realized_lifecycle(),
        reason: v.reason().into(),
        sandbox: v.sandbox(),
        sequence: v.sequence(),
    }
}
fn assignment_observation_model(
    v: AssignmentObservationWire,
    context: AuthenticatedEvidenceContextV1,
) -> Result<NodeAssignmentObservationV1, InvalidMultiNodeProtocol> {
    NodeAssignmentObservationV1::from_authenticated_node(
        context,
        v.sandbox,
        v.incarnation,
        v.epoch,
        v.desired_generation,
        v.assignment_digest,
        v.sequence,
        v.phase,
        v.realized_lifecycle,
        v.reason.into(),
        v.observed_at_unix_seconds,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DrainModeWire {
    CordonOnly,
    Evacuate,
    Decommission,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StrategyWire {
    SnapshotStopAndReplace,
    StopAndReplace,
    StopInPlace,
    LeaveStopped,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainPlanWire {
    assignment_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    epoch: AssignmentEpoch,
    incarnation: IncarnationId,
    sandbox: SandboxId,
    strategy: StrategyWire,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::multi_node) struct DrainDirectiveWire {
    accepted_at_unix_seconds: u64,
    assignments: Vec<DrainPlanWire>,
    deadline_unix_seconds: Option<u64>,
    generation: u64,
    mode: DrainModeWire,
    node: NodeId,
    operation: OperationId,
}
fn strategy_wire(v: DrainAssignmentStrategyV1) -> StrategyWire {
    match v {
        DrainAssignmentStrategyV1::SnapshotStopAndReplace => StrategyWire::SnapshotStopAndReplace,
        DrainAssignmentStrategyV1::StopAndReplace => StrategyWire::StopAndReplace,
        DrainAssignmentStrategyV1::StopInPlace => StrategyWire::StopInPlace,
        DrainAssignmentStrategyV1::LeaveStopped => StrategyWire::LeaveStopped,
    }
}
fn strategy_model(v: StrategyWire) -> DrainAssignmentStrategyV1 {
    match v {
        StrategyWire::SnapshotStopAndReplace => DrainAssignmentStrategyV1::SnapshotStopAndReplace,
        StrategyWire::StopAndReplace => DrainAssignmentStrategyV1::StopAndReplace,
        StrategyWire::StopInPlace => DrainAssignmentStrategyV1::StopInPlace,
        StrategyWire::LeaveStopped => DrainAssignmentStrategyV1::LeaveStopped,
    }
}
pub(in crate::multi_node) fn drain_directive_wire(v: &DrainDirectiveV1) -> DrainDirectiveWire {
    DrainDirectiveWire {
        accepted_at_unix_seconds: v.accepted_at_unix_seconds(),
        assignments: v
            .assignments()
            .iter()
            .map(|p| DrainPlanWire {
                assignment_digest: p.assignment_digest(),
                desired_generation: p.desired_generation(),
                epoch: p.epoch(),
                incarnation: p.incarnation(),
                sandbox: p.sandbox(),
                strategy: strategy_wire(p.strategy()),
            })
            .collect(),
        deadline_unix_seconds: v.deadline_unix_seconds(),
        generation: v.generation(),
        mode: match v.mode() {
            NodeDrainModeV1::CordonOnly => DrainModeWire::CordonOnly,
            NodeDrainModeV1::Evacuate => DrainModeWire::Evacuate,
            NodeDrainModeV1::Decommission => DrainModeWire::Decommission,
        },
        node: v.node(),
        operation: v.operation(),
    }
}
pub(in crate::multi_node) fn drain_directive_model(
    v: DrainDirectiveWire,
) -> Result<DrainDirectiveV1, InvalidMultiNodeProtocol> {
    let assignments = v
        .assignments
        .into_iter()
        .map(|p| {
            DrainAssignmentPlanV1::new(
                p.sandbox,
                p.incarnation,
                p.epoch,
                p.desired_generation,
                p.assignment_digest,
                strategy_model(p.strategy),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    DrainDirectiveV1::new(
        v.operation,
        v.node,
        v.generation,
        match v.mode {
            DrainModeWire::CordonOnly => NodeDrainModeV1::CordonOnly,
            DrainModeWire::Evacuate => NodeDrainModeV1::Evacuate,
            DrainModeWire::Decommission => NodeDrainModeV1::Decommission,
        },
        v.accepted_at_unix_seconds,
        v.deadline_unix_seconds,
        assignments,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DrainPhaseWire {
    Requested,
    Cordoned,
    Draining,
    Contained,
    ReadyForReassignment,
    Complete,
    Blocked,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BlockWire {
    SnapshotUnavailable,
    MissingDependency,
    OwnershipAuthorityUnavailable,
    ContainmentUnconfirmed,
    ResidualState,
    DestinationUnavailable,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "reason",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ProgressWire {
    Pending,
    Preparing,
    Stopping,
    Contained,
    Released,
    Blocked(BlockWire),
}
fn progress_wire(v: DrainAssignmentProgressV1) -> ProgressWire {
    match v {
        DrainAssignmentProgressV1::Pending => ProgressWire::Pending,
        DrainAssignmentProgressV1::Preparing => ProgressWire::Preparing,
        DrainAssignmentProgressV1::Stopping => ProgressWire::Stopping,
        DrainAssignmentProgressV1::Contained => ProgressWire::Contained,
        DrainAssignmentProgressV1::Released => ProgressWire::Released,
        DrainAssignmentProgressV1::Blocked(r) => ProgressWire::Blocked(match r {
            DrainBlockReasonV1::SnapshotUnavailable => BlockWire::SnapshotUnavailable,
            DrainBlockReasonV1::MissingDependency => BlockWire::MissingDependency,
            DrainBlockReasonV1::OwnershipAuthorityUnavailable => {
                BlockWire::OwnershipAuthorityUnavailable
            }
            DrainBlockReasonV1::ContainmentUnconfirmed => BlockWire::ContainmentUnconfirmed,
            DrainBlockReasonV1::ResidualState => BlockWire::ResidualState,
            DrainBlockReasonV1::DestinationUnavailable => BlockWire::DestinationUnavailable,
        }),
    }
}
fn progress_model(v: ProgressWire) -> DrainAssignmentProgressV1 {
    match v {
        ProgressWire::Pending => DrainAssignmentProgressV1::Pending,
        ProgressWire::Preparing => DrainAssignmentProgressV1::Preparing,
        ProgressWire::Stopping => DrainAssignmentProgressV1::Stopping,
        ProgressWire::Contained => DrainAssignmentProgressV1::Contained,
        ProgressWire::Released => DrainAssignmentProgressV1::Released,
        ProgressWire::Blocked(r) => DrainAssignmentProgressV1::Blocked(match r {
            BlockWire::SnapshotUnavailable => DrainBlockReasonV1::SnapshotUnavailable,
            BlockWire::MissingDependency => DrainBlockReasonV1::MissingDependency,
            BlockWire::OwnershipAuthorityUnavailable => {
                DrainBlockReasonV1::OwnershipAuthorityUnavailable
            }
            BlockWire::ContainmentUnconfirmed => DrainBlockReasonV1::ContainmentUnconfirmed,
            BlockWire::ResidualState => DrainBlockReasonV1::ResidualState,
            BlockWire::DestinationUnavailable => DrainBlockReasonV1::DestinationUnavailable,
        }),
    }
}
fn drain_phase_wire(v: DrainPhaseV1) -> DrainPhaseWire {
    match v {
        DrainPhaseV1::Requested => DrainPhaseWire::Requested,
        DrainPhaseV1::Cordoned => DrainPhaseWire::Cordoned,
        DrainPhaseV1::Draining => DrainPhaseWire::Draining,
        DrainPhaseV1::Contained => DrainPhaseWire::Contained,
        DrainPhaseV1::ReadyForReassignment => DrainPhaseWire::ReadyForReassignment,
        DrainPhaseV1::Complete => DrainPhaseWire::Complete,
        DrainPhaseV1::Blocked => DrainPhaseWire::Blocked,
    }
}
fn drain_phase_model(v: DrainPhaseWire) -> DrainPhaseV1 {
    match v {
        DrainPhaseWire::Requested => DrainPhaseV1::Requested,
        DrainPhaseWire::Cordoned => DrainPhaseV1::Cordoned,
        DrainPhaseWire::Draining => DrainPhaseV1::Draining,
        DrainPhaseWire::Contained => DrainPhaseV1::Contained,
        DrainPhaseWire::ReadyForReassignment => DrainPhaseV1::ReadyForReassignment,
        DrainPhaseWire::Complete => DrainPhaseV1::Complete,
        DrainPhaseWire::Blocked => DrainPhaseV1::Blocked,
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainAssignmentObservationWire {
    assignment_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    epoch: AssignmentEpoch,
    incarnation: IncarnationId,
    progress: ProgressWire,
    sandbox: SandboxId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainObservationWire {
    assignments: Vec<DrainAssignmentObservationWire>,
    generation: u64,
    observed_at_unix_seconds: u64,
    operation: OperationId,
    phase: DrainPhaseWire,
    sequence: ObservationSequence,
}
fn drain_observation_wire(v: &DrainObservationV1) -> DrainObservationWire {
    DrainObservationWire {
        assignments: v
            .assignments()
            .iter()
            .map(|r| DrainAssignmentObservationWire {
                assignment_digest: r.assignment_digest(),
                desired_generation: r.desired_generation(),
                epoch: r.epoch(),
                incarnation: r.incarnation(),
                progress: progress_wire(r.progress()),
                sandbox: r.sandbox(),
            })
            .collect(),
        generation: v.generation(),
        observed_at_unix_seconds: v.observed_at_unix_seconds(),
        operation: v.operation(),
        phase: drain_phase_wire(v.phase()),
        sequence: v.sequence(),
    }
}
fn drain_observation_model(
    v: DrainObservationWire,
    context: AuthenticatedEvidenceContextV1,
) -> Result<DrainObservationV1, InvalidMultiNodeProtocol> {
    let rows = v
        .assignments
        .into_iter()
        .map(|r| {
            DrainAssignmentPlanV1::new(
                r.sandbox,
                r.incarnation,
                r.epoch,
                r.desired_generation,
                r.assignment_digest,
                DrainAssignmentStrategyV1::StopInPlace,
            )
            .map(|p| {
                DrainAssignmentObservationV1::from_reported_progress(p, progress_model(r.progress))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    DrainObservationV1::from_authenticated_wire(
        v.operation,
        v.generation,
        context,
        v.sequence,
        drain_phase_model(v.phase),
        rows,
        v.observed_at_unix_seconds,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchBindingWire {
    authorization_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    bootstrap_watermark: u64,
    coordinator_epoch: u64,
    disclosure_domain_digest: ObjectDigest,
    history_floor_event_uid: ObjectDigest,
    history_floor_sequence: u64,
    query_digest: ObjectDigest,
    schema_maximum: VersionWire,
    schema_minimum: VersionWire,
}
impl From<NodeWatchBindingV1> for WatchBindingWire {
    fn from(v: NodeWatchBindingV1) -> Self {
        Self {
            authorization_digest: v.authorization_digest(),
            audience_digest: v.audience_digest(),
            bootstrap_watermark: v.bootstrap_watermark(),
            coordinator_epoch: v.coordinator_epoch(),
            disclosure_domain_digest: v.disclosure_domain_digest(),
            history_floor_event_uid: v.history_floor_event_uid(),
            history_floor_sequence: v.history_floor_sequence(),
            query_digest: v.query_digest(),
            schema_maximum: v.schema().writer().into(),
            schema_minimum: v.schema().minimum_reader().into(),
        }
    }
}
impl WatchBindingWire {
    fn model(self) -> Result<NodeWatchBindingV1, InvalidMultiNodeProtocol> {
        let schema = RollingVersionWindowV1::new(
            ProtocolVersion::new(self.schema_minimum.major, self.schema_minimum.minor),
            ProtocolVersion::new(self.schema_maximum.major, self.schema_maximum.minor),
        )?;
        NodeWatchBindingV1::new(
            self.coordinator_epoch,
            self.history_floor_sequence,
            self.history_floor_event_uid,
            self.bootstrap_watermark,
            self.query_digest,
            self.authorization_digest,
            self.audience_digest,
            self.disclosure_domain_digest,
            schema,
        )
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    binding: WatchBindingWire,
    event_sequence: u64,
    last_event_uid: ObjectDigest,
    lineage: LineageWire,
    node: NodeId,
}
impl From<NodeWatchCursorV1> for CursorWire {
    fn from(v: NodeWatchCursorV1) -> Self {
        Self {
            binding: v.binding().into(),
            event_sequence: v.event_sequence(),
            last_event_uid: v.last_event_uid(),
            lineage: v.lineage().into(),
            node: v.node(),
        }
    }
}
impl CursorWire {
    fn model(self) -> Result<NodeWatchCursorV1, InvalidMultiNodeProtocol> {
        NodeWatchCursorV1::new(
            self.node,
            self.lineage.model()?,
            self.binding.model()?,
            self.event_sequence,
            self.last_event_uid,
        )
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    assignment_digest: ObjectDigest,
    assignment_epoch: AssignmentEpoch,
    audience_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    destination_node: NodeId,
    disclosure_domain_digest: ObjectDigest,
    incarnation: IncarnationId,
    manifest_digest: ObjectDigest,
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    snapshot: SnapshotId,
    source_node: NodeId,
    storage_domain_digest: ObjectDigest,
}
impl From<SnapshotTransferIdentityV1> for IdentityWire {
    fn from(v: SnapshotTransferIdentityV1) -> Self {
        Self {
            assignment_digest: v.assignment_digest(),
            assignment_epoch: v.assignment_epoch(),
            audience_digest: v.audience_digest(),
            desired_generation: v.desired_generation(),
            destination_node: v.destination_node(),
            disclosure_domain_digest: v.disclosure_domain_digest(),
            incarnation: v.incarnation(),
            manifest_digest: v.manifest_digest(),
            operation: v.operation(),
            project: v.project(),
            sandbox: v.sandbox(),
            snapshot: v.snapshot(),
            source_node: v.source_node(),
            storage_domain_digest: v.storage_domain_digest(),
        }
    }
}
impl IdentityWire {
    fn model(self) -> Result<SnapshotTransferIdentityV1, InvalidMultiNodeProtocol> {
        SnapshotTransferIdentityV1::new(
            self.operation,
            self.project,
            self.sandbox,
            self.incarnation,
            self.assignment_epoch,
            self.desired_generation,
            self.assignment_digest,
            self.snapshot,
            self.source_node,
            self.destination_node,
            self.storage_domain_digest,
            self.audience_digest,
            self.disclosure_domain_digest,
            self.manifest_digest,
        )
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkWire {
    digest: ObjectDigest,
    index: u32,
    length: u32,
    offset: u64,
}
impl From<SnapshotTransferChunkV1> for ChunkWire {
    fn from(v: SnapshotTransferChunkV1) -> Self {
        Self {
            digest: v.digest(),
            index: v.index(),
            length: v.length(),
            offset: v.offset(),
        }
    }
}
impl ChunkWire {
    fn model(self) -> Result<SnapshotTransferChunkV1, InvalidMultiNodeProtocol> {
        SnapshotTransferChunkV1::new(self.index, self.offset, self.length, self.digest)
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::multi_node) struct ManifestWire {
    chunks: Vec<ChunkWire>,
    dependencies: Vec<ObjectDescriptor>,
    identity: IdentityWire,
    required_features: Vec<FeatureRef>,
    root: ObjectDescriptor,
    version: VersionWire,
}
pub(in crate::multi_node) fn manifest_wire(v: &SnapshotTransferManifestV1) -> ManifestWire {
    ManifestWire {
        chunks: v.chunks().iter().copied().map(Into::into).collect(),
        dependencies: v.dependencies().to_vec(),
        identity: v.identity().into(),
        required_features: v.required_features().to_vec(),
        root: v.root().clone(),
        version: VersionWire {
            major: v.version().major(),
            minor: v.version().minor(),
        },
    }
}
pub(in crate::multi_node) fn manifest_model(
    v: ManifestWire,
) -> Result<SnapshotTransferManifestV1, InvalidMultiNodeProtocol> {
    let chunks = v
        .chunks
        .into_iter()
        .map(ChunkWire::model)
        .collect::<Result<Vec<_>, _>>()?;
    let version = SnapshotTransferVersionV1::new(v.version.major, v.version.minor)
        .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    SnapshotTransferManifestV1::new(
        v.identity.model()?,
        version,
        v.root,
        chunks,
        v.dependencies,
        v.required_features,
    )
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeWire {
    identity: IdentityWire,
    next_chunk: u32,
    verified_prefix_digest: ObjectDigest,
}
fn resume_wire(v: SnapshotTransferResumeV1) -> ResumeWire {
    ResumeWire {
        identity: v.identity().into(),
        next_chunk: v.next_chunk(),
        verified_prefix_digest: v.verified_prefix_digest(),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapBody {
    snapshot: CapabilityWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentBody {
    intent: IntentWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentBody {
    observation: AssignmentObservationWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelistBody {
    binding: WatchBindingWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryWire {
    assignments: Vec<AssignmentObservationWire>,
    capabilities: CapabilityWire,
    cursor: CursorWire,
    observation_sequence: ObservationSequence,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryBody {
    inventory: InventoryWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainDirectiveBody {
    directive: DrainDirectiveWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainBody {
    observation: DrainObservationWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginBody {
    manifest: ManifestWire,
    resume: Option<ResumeWire>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyBody {
    identity: IdentityWire,
    next_chunk: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkRequestWire {
    chunk: ChunkWire,
    identity: IdentityWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkRequestBody {
    request: ChunkRequestWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkResponseBody {
    bytes: Vec<u8>,
    identity: IdentityWire,
    index: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyRequestWire {
    dependency: ObjectDescriptor,
    identity: IdentityWire,
    length: u32,
    offset: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyRequestBody {
    request: DependencyRequestWire,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyResponseBody {
    bytes: Vec<u8>,
    dependency: ObjectDescriptor,
    identity: IdentityWire,
    offset: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchRequestBody {
    after: CursorWire,
    maximum_events: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    body: EventBodyWire,
    cursor: CursorWire,
    predecessor_event_uid: ObjectDigest,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum EventBodyWire {
    Capability(CapabilityWire),
    Assignment(AssignmentObservationWire),
    Drain(DrainObservationWire),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchBody {
    cursor_gap: Option<WatchBindingWire>,
    events: Vec<EventWire>,
}

pub(super) fn encode_request(
    body: &NodeRequestBodyV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    match body {
        NodeRequestBodyV1::GetCapabilities => encode(body.frame_kind(), &EmptyBody {}),
        NodeRequestBodyV1::ReconcileAssignment(intent) => encode(
            body.frame_kind(),
            &IntentBody {
                intent: intent_wire(intent),
            },
        ),
        NodeRequestBodyV1::RelistAssignments { binding } => encode(
            body.frame_kind(),
            &RelistBody {
                binding: (*binding).into(),
            },
        ),
        NodeRequestBodyV1::ReconcileDrain(directive) => encode(
            body.frame_kind(),
            &DrainDirectiveBody {
                directive: drain_directive_wire(directive),
            },
        ),
        NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } => encode(
            body.frame_kind(),
            &BeginBody {
                manifest: manifest_wire(manifest),
                resume: resume.as_ref().copied().map(resume_wire),
            },
        ),
        NodeRequestBodyV1::FetchSnapshotChunk { request } => encode(
            body.frame_kind(),
            &ChunkRequestBody {
                request: ChunkRequestWire {
                    chunk: request.chunk().into(),
                    identity: request.identity().into(),
                },
            },
        ),
        NodeRequestBodyV1::FetchSnapshotDependency { request } => encode(
            body.frame_kind(),
            &DependencyRequestBody {
                request: DependencyRequestWire {
                    dependency: request.dependency().clone(),
                    identity: request.identity().into(),
                    length: request.length(),
                    offset: request.offset(),
                },
            },
        ),
        NodeRequestBodyV1::Watch {
            after,
            maximum_events,
        } => encode(
            body.frame_kind(),
            &WatchRequestBody {
                after: (*after).into(),
                maximum_events: *maximum_events,
            },
        ),
    }
}

pub(super) fn decode_request(
    _session: &super::AuthenticatedNodeSessionV1,
    kind: CanonicalNodeFrameKindV1,
    bytes: &[u8],
    _now: u64,
) -> Result<NodeRequestBodyV1, InvalidMultiNodeProtocol> {
    Ok(match kind {
        CanonicalNodeFrameKindV1::GetCapabilitiesRequest => {
            let _: EmptyBody = decode(kind, bytes)?;
            NodeRequestBodyV1::GetCapabilities
        }
        CanonicalNodeFrameKindV1::ReconcileAssignmentRequest => {
            NodeRequestBodyV1::ReconcileAssignment(Box::new(intent_model(
                decode::<IntentBody>(kind, bytes)?.intent,
            )?))
        }
        CanonicalNodeFrameKindV1::RelistAssignmentsRequest => {
            NodeRequestBodyV1::RelistAssignments {
                binding: decode::<RelistBody>(kind, bytes)?.binding.model()?,
            }
        }
        CanonicalNodeFrameKindV1::ReconcileDrainRequest => {
            NodeRequestBodyV1::ReconcileDrain(Box::new(drain_directive_model(
                decode::<DrainDirectiveBody>(kind, bytes)?.directive,
            )?))
        }
        CanonicalNodeFrameKindV1::BeginSnapshotTransferRequest => {
            let body = decode::<BeginBody>(kind, bytes)?;
            let manifest = manifest_model(body.manifest)?;
            let resume = match body.resume {
                Some(r) => {
                    let model =
                        SnapshotTransferResumeV1::new(&manifest, r.identity.model()?, r.next_chunk)
                            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
                    if model.verified_prefix_digest() != r.verified_prefix_digest {
                        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
                    }
                    Some(model)
                }
                None => None,
            };
            NodeRequestBodyV1::BeginSnapshotTransfer {
                manifest: Box::new(manifest),
                resume,
            }
        }
        CanonicalNodeFrameKindV1::SnapshotChunkRequest => {
            let r = decode::<ChunkRequestBody>(kind, bytes)?.request;
            NodeRequestBodyV1::FetchSnapshotChunk {
                request: SnapshotTransferChunkRequestV1::from_exact_commitment(
                    r.identity.model()?,
                    r.chunk.model()?,
                ),
            }
        }
        CanonicalNodeFrameKindV1::SnapshotDependencyRequest => {
            let r = decode::<DependencyRequestBody>(kind, bytes)?.request;
            NodeRequestBodyV1::FetchSnapshotDependency {
                request: SnapshotDependencyRangeV1::from_exact_commitment(
                    r.identity.model()?,
                    r.dependency,
                    r.offset,
                    r.length,
                )
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
            }
        }
        CanonicalNodeFrameKindV1::WatchRequest => {
            let b = decode::<WatchRequestBody>(kind, bytes)?;
            NodeRequestBodyV1::Watch {
                after: b.after.model()?,
                maximum_events: b.maximum_events,
            }
        }
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    })
}

fn event_wire(v: &NodeWatchEventV1) -> EventWire {
    EventWire {
        body: match v.body() {
            NodeWatchEventBodyV1::Capability(c) => EventBodyWire::Capability(capability_wire(c)),
            NodeWatchEventBodyV1::Assignment(a) => {
                EventBodyWire::Assignment(assignment_observation_wire(a))
            }
            NodeWatchEventBodyV1::Drain(d) => EventBodyWire::Drain(drain_observation_wire(d)),
        },
        cursor: v.cursor().into(),
        predecessor_event_uid: v.predecessor_event_uid(),
    }
}
fn event_model(
    v: EventWire,
    context: AuthenticatedEvidenceContextV1,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<NodeWatchEventV1, InvalidMultiNodeProtocol> {
    let body = match v.body {
        EventBodyWire::Capability(c) => {
            NodeWatchEventBodyV1::Capability(Box::new(capability_model(c)?))
        }
        EventBodyWire::Assignment(a) => {
            NodeWatchEventBodyV1::Assignment(Box::new(assignment_observation_model(a, context)?))
        }
        EventBodyWire::Drain(d) => {
            NodeWatchEventBodyV1::Drain(Box::new(drain_observation_model(d, context)?))
        }
    };
    NodeWatchEventV1::from_authenticated_history(
        v.cursor.model()?,
        v.predecessor_event_uid,
        body,
        codec,
    )
}

pub(super) fn encode_response(
    body: &NodeResponseBodyV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    match body {
        NodeResponseBodyV1::Capabilities(snapshot) => encode(
            body.frame_kind(),
            &CapBody {
                snapshot: capability_wire(snapshot),
            },
        ),
        NodeResponseBodyV1::Assignment(observation) => encode(
            body.frame_kind(),
            &AssignmentBody {
                observation: assignment_observation_wire(observation),
            },
        ),
        NodeResponseBodyV1::AssignmentInventory(inventory) => encode(
            body.frame_kind(),
            &InventoryBody {
                inventory: InventoryWire {
                    assignments: inventory
                        .assignments()
                        .iter()
                        .map(assignment_observation_wire)
                        .collect(),
                    capabilities: capability_wire(inventory.capabilities()),
                    cursor: inventory.cursor().into(),
                    observation_sequence: inventory.observation_sequence(),
                },
            },
        ),
        NodeResponseBodyV1::Drain(observation) => encode(
            body.frame_kind(),
            &DrainBody {
                observation: drain_observation_wire(observation),
            },
        ),
        NodeResponseBodyV1::SnapshotTransferReady {
            identity,
            next_chunk,
        } => encode(
            body.frame_kind(),
            &ReadyBody {
                identity: (*identity).into(),
                next_chunk: *next_chunk,
            },
        ),
        NodeResponseBodyV1::SnapshotChunk {
            identity,
            index,
            bytes,
        } => encode(
            body.frame_kind(),
            &ChunkResponseBody {
                bytes: bytes.clone(),
                identity: (*identity).into(),
                index: *index,
            },
        ),
        NodeResponseBodyV1::SnapshotDependency {
            identity,
            dependency,
            offset,
            bytes,
        } => encode(
            body.frame_kind(),
            &DependencyResponseBody {
                bytes: bytes.clone(),
                dependency: dependency.clone(),
                identity: (*identity).into(),
                offset: *offset,
            },
        ),
        NodeResponseBodyV1::WatchBatch { events, cursor_gap } => encode(
            body.frame_kind(),
            &WatchBody {
                cursor_gap: cursor_gap.as_ref().copied().map(Into::into),
                events: events.iter().map(event_wire).collect(),
            },
        ),
    }
}

pub(super) fn decode_response(
    context: AuthenticatedEvidenceContextV1,
    kind: CanonicalNodeFrameKindV1,
    bytes: &[u8],
    _now: u64,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<NodeResponseBodyV1, InvalidMultiNodeProtocol> {
    Ok(match kind {
        CanonicalNodeFrameKindV1::GetCapabilitiesResponse => NodeResponseBodyV1::Capabilities(
            Box::new(capability_model(decode::<CapBody>(kind, bytes)?.snapshot)?),
        ),
        CanonicalNodeFrameKindV1::ReconcileAssignmentResponse => {
            NodeResponseBodyV1::Assignment(Box::new(assignment_observation_model(
                decode::<AssignmentBody>(kind, bytes)?.observation,
                context,
            )?))
        }
        CanonicalNodeFrameKindV1::RelistAssignmentsResponse => {
            let i = decode::<InventoryBody>(kind, bytes)?.inventory;
            let assignments = i
                .assignments
                .into_iter()
                .map(|a| assignment_observation_model(a, context))
                .collect::<Result<Vec<_>, _>>()?;
            NodeResponseBodyV1::AssignmentInventory(Box::new(ResyncInventoryV1::new(
                i.cursor.model()?,
                capability_model(i.capabilities)?,
                i.observation_sequence,
                assignments,
            )?))
        }
        CanonicalNodeFrameKindV1::ReconcileDrainResponse => NodeResponseBodyV1::Drain(Box::new(
            drain_observation_model(decode::<DrainBody>(kind, bytes)?.observation, context)?,
        )),
        CanonicalNodeFrameKindV1::BeginSnapshotTransferResponse => {
            let b = decode::<ReadyBody>(kind, bytes)?;
            NodeResponseBodyV1::SnapshotTransferReady {
                identity: b.identity.model()?,
                next_chunk: b.next_chunk,
            }
        }
        CanonicalNodeFrameKindV1::SnapshotChunkResponse => {
            let b = decode::<ChunkResponseBody>(kind, bytes)?;
            NodeResponseBodyV1::SnapshotChunk {
                identity: b.identity.model()?,
                index: b.index,
                bytes: b.bytes,
            }
        }
        CanonicalNodeFrameKindV1::SnapshotDependencyResponse => {
            let b = decode::<DependencyResponseBody>(kind, bytes)?;
            NodeResponseBodyV1::SnapshotDependency {
                identity: b.identity.model()?,
                dependency: b.dependency,
                offset: b.offset,
                bytes: b.bytes,
            }
        }
        CanonicalNodeFrameKindV1::WatchResponse => {
            let b = decode::<WatchBody>(kind, bytes)?;
            NodeResponseBodyV1::WatchBatch {
                events: b
                    .events
                    .into_iter()
                    .map(|e| event_model(e, context, codec))
                    .collect::<Result<Vec<_>, _>>()?,
                cursor_gap: b.cursor_gap.map(WatchBindingWire::model).transpose()?,
            }
        }
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    })
}

pub(super) fn encode_watch_event_body(
    body: &NodeWatchEventBodyV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    match body {
        NodeWatchEventBodyV1::Capability(snapshot) => encode_watch(
            "watch_capability_event",
            &CapBody {
                snapshot: capability_wire(snapshot),
            },
        ),
        NodeWatchEventBodyV1::Assignment(observation) => encode_watch(
            "watch_assignment_event",
            &AssignmentBody {
                observation: assignment_observation_wire(observation),
            },
        ),
        NodeWatchEventBodyV1::Drain(observation) => encode_watch(
            "watch_drain_event",
            &DrainBody {
                observation: drain_observation_wire(observation),
            },
        ),
    }
}
fn encode_watch<T: Serialize>(
    kind: &'static str,
    body: &T,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    let value = serde_json::to_value(EnvelopeRef {
        body,
        kind,
        schema: SCHEMA,
    })
    .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    serde_json::to_vec(&value).map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)
}
