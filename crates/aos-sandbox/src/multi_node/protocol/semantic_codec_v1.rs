//! Legacy canonical JSON compatibility for coordinator/node semantics.
//!
//! Current version-one traffic uses the typed protobuf conversion at the end
//! of this module. The JSON projection remains only for an explicit legacy
//! decode branch and is never emitted as a current protobuf field.

use buffa::MessageField;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use aos_proto::aos::sandbox::coordinator::v1 as protobuf;
use aos_sandbox_core::model::{
    AssignmentManifestV1, MAX_ANCESTRY_DEPTH, MAX_ASSIGNMENT_REQUIRED_FEATURES,
    MAX_ASSIGNMENT_SOURCE_COMMITMENTS, SandboxAncestry,
};
use aos_sandbox_core::state::{AssignmentPhase, DesiredSandboxState, SuspensionMode};
use aos_sandbox_core::{
    AssignmentEpoch, CanonicalAssignmentManifestV1, DecodeLimits, DesiredGeneration, FeatureRef,
    IncarnationId, MediaType, NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest,
    ObservationSequence, OperationId, ProjectId, ProtocolVersion, ResourceDimension,
    ResourceVector, SandboxId, SnapshotId,
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

pub(super) fn decode_watch_event_body(
    bytes: &[u8],
    context: AuthenticatedEvidenceContextV1,
) -> Result<NodeWatchEventBodyV1, InvalidMultiNodeProtocol> {
    let envelope: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    let kind = envelope
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)?;
    let body = match kind {
        "watch_capability_event" => {
            let decoded: EnvelopeOwned<CapBody> = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
            if decoded.schema != SCHEMA || decoded.kind != kind {
                return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
            }
            NodeWatchEventBodyV1::Capability(Box::new(capability_model(decoded.body.snapshot)?))
        }
        "watch_assignment_event" => {
            let decoded: EnvelopeOwned<AssignmentBody> = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
            if decoded.schema != SCHEMA || decoded.kind != kind {
                return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
            }
            NodeWatchEventBodyV1::Assignment(Box::new(assignment_observation_model(
                decoded.body.observation,
                context,
            )?))
        }
        "watch_drain_event" => {
            let decoded: EnvelopeOwned<DrainBody> = serde_json::from_slice(bytes)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
            if decoded.schema != SCHEMA || decoded.kind != kind {
                return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
            }
            NodeWatchEventBodyV1::Drain(Box::new(drain_observation_model(
                decoded.body.observation,
                context,
            )?))
        }
        _ => return Err(InvalidMultiNodeProtocol::NonCanonicalFrame),
    };
    if encode_watch_event_body(&body)?.as_slice() != bytes {
        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
    }
    Ok(body)
}

pub(super) fn encode_watch_inventory(
    inventory: &ResyncInventoryV1,
) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
    encode_response(&NodeResponseBodyV1::AssignmentInventory(Box::new(
        inventory.clone(),
    )))
}

pub(super) fn decode_watch_inventory(
    bytes: &[u8],
    context: AuthenticatedEvidenceContextV1,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<ResyncInventoryV1, InvalidMultiNodeProtocol> {
    let body = decode_response(
        context,
        CanonicalNodeFrameKindV1::RelistAssignmentsResponse,
        bytes,
        context.verified_at_unix_seconds(),
        codec,
    )?;
    let NodeResponseBodyV1::AssignmentInventory(inventory) = body else {
        return Err(InvalidMultiNodeProtocol::MethodMismatch);
    };
    if encode_watch_inventory(&inventory)?.as_slice() != bytes {
        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
    }
    Ok(*inventory)
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

// Current protobuf 1.0 conversion. JSON above is retained only for decoding
// explicitly selected legacy schema bytes; current envelopes never carry it.

fn invalid() -> InvalidMultiNodeProtocol {
    InvalidMultiNodeProtocol::NonCanonicalFrame
}

fn parse<T: std::str::FromStr>(value: &str) -> Result<T, InvalidMultiNodeProtocol> {
    value.parse().map_err(|_| invalid())
}

trait RequiredValue<T> {
    fn into_option(self) -> Option<T>;
}

impl<T> RequiredValue<T> for Option<T> {
    fn into_option(self) -> Option<T> {
        self
    }
}

impl<T: Default> RequiredValue<T> for MessageField<T> {
    fn into_option(self) -> Option<T> {
        MessageField::into_option(self)
    }
}

fn required<T>(value: impl RequiredValue<T>) -> Result<T, InvalidMultiNodeProtocol> {
    value.into_option().ok_or_else(invalid)
}

fn pb_version(value: VersionWire) -> protobuf::Version {
    protobuf::Version {
        major: u32::from(value.major),
        minor: u32::from(value.minor),
        ..Default::default()
    }
}

fn wire_version(value: protobuf::Version) -> Result<VersionWire, InvalidMultiNodeProtocol> {
    Ok(VersionWire {
        major: u16::try_from(value.major).map_err(|_| invalid())?,
        minor: u16::try_from(value.minor).map_err(|_| invalid())?,
    })
}

fn pb_feature(value: &FeatureRef) -> protobuf::Feature {
    protobuf::Feature {
        namespace: value.namespace().to_owned(),
        major: value.major(),
        minor: value.minor(),
        ..Default::default()
    }
}

fn wire_feature(value: protobuf::Feature) -> Result<FeatureRef, InvalidMultiNodeProtocol> {
    FeatureRef::new(value.namespace, value.major, value.minor).map_err(|_| invalid())
}

fn pb_descriptor(value: &ObjectDescriptor) -> protobuf::Descriptor {
    protobuf::Descriptor {
        media_type: value.media_type().as_str().to_owned(),
        digest: value.digest().to_string(),
        encoded_size: value.encoded_size(),
        ..Default::default()
    }
}

fn wire_descriptor(
    value: protobuf::Descriptor,
) -> Result<ObjectDescriptor, InvalidMultiNodeProtocol> {
    if value.encoded_size == 0 {
        return Err(invalid());
    }
    Ok(ObjectDescriptor::new(
        MediaType::new(value.media_type).map_err(|_| invalid())?,
        parse(&value.digest)?,
        value.encoded_size,
    ))
}

fn pb_lineage(value: LineageWire) -> protobuf::Lineage {
    protobuf::Lineage {
        boot: value.boot.to_vec(),
        digest: value.digest.to_string(),
        generation: value.generation,
        predecessor_boot: value.predecessor_boot.map_or_else(Vec::new, |v| v.to_vec()),
        predecessor_digest: value.predecessor_digest.map(|v| v.to_string()),
        ..Default::default()
    }
}

fn wire_lineage(value: protobuf::Lineage) -> Result<LineageWire, InvalidMultiNodeProtocol> {
    Ok(LineageWire {
        boot: value.boot.try_into().map_err(|_| invalid())?,
        digest: parse(&value.digest)?,
        generation: value.generation,
        predecessor_boot: if value.predecessor_boot.is_empty() {
            None
        } else {
            Some(value.predecessor_boot.try_into().map_err(|_| invalid())?)
        },
        predecessor_digest: value.predecessor_digest.map(|v| parse(&v)).transpose()?,
    })
}

fn pb_resources(value: ResourceVector) -> Vec<u64> {
    ResourceDimension::ALL
        .into_iter()
        .map(|dimension| value.get(dimension))
        .collect()
}

fn wire_resources(value: Vec<u64>) -> Result<ResourceVector, InvalidMultiNodeProtocol> {
    let values: [u64; ResourceDimension::COUNT] = value.try_into().map_err(|_| invalid())?;
    Ok(ResourceVector::new(values))
}

fn pb_fact(value: FactWire) -> protobuf::CapabilityFact {
    let mut fact = protobuf::CapabilityFact::default();
    match value {
        FactWire::NspawnVersion {
            major,
            minor,
            patch,
        } => {
            fact.kind = 1.into();
            fact.major = Some(major);
            fact.minor = Some(minor);
            fact.patch = Some(patch);
        }
        FactWire::Fuse {
            major,
            minor,
            passthrough,
        } => {
            fact.kind = 2.into();
            fact.major = Some(major);
            fact.minor = Some(minor);
            fact.passthrough = Some(passthrough);
        }
        FactWire::MountObservation => fact.kind = 3.into(),
        FactWire::Kvm => fact.kind = 4.into(),
        FactWire::Seccomp => fact.kind = 5.into(),
        FactWire::UserNamespaces { digest } => {
            fact.kind = 6.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::NewMountApi { digest } => {
            fact.kind = 7.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::IdmappedMounts { digest } => {
            fact.kind = 8.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::ZfsPool { digest } => {
            fact.kind = 9.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::Overlay { digest } => {
            fact.kind = 10.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::CgroupV2 { digest } => {
            fact.kind = 11.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::SnapshotTransfer { digest } => {
            fact.kind = 12.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::PosixAcl { digest } => {
            fact.kind = 13.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::AbsoluteSymlink { digest } => {
            fact.kind = 14.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::ParentEscapeSymlink { digest } => {
            fact.kind = 15.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::BrokerLedger { digest } => {
            fact.kind = 16.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::SignedPlanLease { digest } => {
            fact.kind = 17.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::NodeBoundedSharedResidency { digest } => {
            fact.kind = 18.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::HardIsolatedResidency { digest } => {
            fact.kind = 19.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::GuestQuiesce { digest } => {
            fact.kind = 20.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::StorageQuiesce { digest } => {
            fact.kind = 21.into();
            fact.digest = Some(digest.to_string());
        }
        FactWire::BrokerSession { digest } => {
            fact.kind = 22.into();
            fact.digest = Some(digest.to_string());
        }
    }
    fact
}

fn wire_fact(value: protobuf::CapabilityFact) -> Result<FactWire, InvalidMultiNodeProtocol> {
    let allowed_shape = match value.kind.to_i32() {
        1 => {
            value.digest.is_none()
                && value.major.is_some()
                && value.minor.is_some()
                && value.patch.is_some()
                && value.passthrough.is_none()
        }
        2 => {
            value.digest.is_none()
                && value.major.is_some()
                && value.minor.is_some()
                && value.patch.is_none()
                && value.passthrough.is_some()
        }
        3..=5 => {
            value.digest.is_none()
                && value.major.is_none()
                && value.minor.is_none()
                && value.patch.is_none()
                && value.passthrough.is_none()
        }
        6..=22 => {
            value.digest.is_some()
                && value.major.is_none()
                && value.minor.is_none()
                && value.patch.is_none()
                && value.passthrough.is_none()
        }
        _ => false,
    };
    if !allowed_shape {
        return Err(invalid());
    }
    let digest = || value.digest.as_deref().ok_or_else(invalid).and_then(parse);
    Ok(match value.kind.to_i32() {
        1 => FactWire::NspawnVersion {
            major: required(value.major)?,
            minor: required(value.minor)?,
            patch: required(value.patch)?,
        },
        2 => FactWire::Fuse {
            major: required(value.major)?,
            minor: required(value.minor)?,
            passthrough: required(value.passthrough)?,
        },
        3 => FactWire::MountObservation,
        4 => FactWire::Kvm,
        5 => FactWire::Seccomp,
        6 => FactWire::UserNamespaces { digest: digest()? },
        7 => FactWire::NewMountApi { digest: digest()? },
        8 => FactWire::IdmappedMounts { digest: digest()? },
        9 => FactWire::ZfsPool { digest: digest()? },
        10 => FactWire::Overlay { digest: digest()? },
        11 => FactWire::CgroupV2 { digest: digest()? },
        12 => FactWire::SnapshotTransfer { digest: digest()? },
        13 => FactWire::PosixAcl { digest: digest()? },
        14 => FactWire::AbsoluteSymlink { digest: digest()? },
        15 => FactWire::ParentEscapeSymlink { digest: digest()? },
        16 => FactWire::BrokerLedger { digest: digest()? },
        17 => FactWire::SignedPlanLease { digest: digest()? },
        18 => FactWire::NodeBoundedSharedResidency { digest: digest()? },
        19 => FactWire::HardIsolatedResidency { digest: digest()? },
        20 => FactWire::GuestQuiesce { digest: digest()? },
        21 => FactWire::StorageQuiesce { digest: digest()? },
        22 => FactWire::BrokerSession { digest: digest()? },
        _ => return Err(invalid()),
    })
}

fn protocol_number(value: ProtocolWire) -> i32 {
    match value {
        ProtocolWire::CoordinatorNode => 1,
        ProtocolWire::HostBroker => 2,
        ProtocolWire::StorageBroker => 3,
        ProtocolWire::MountBroker => 4,
        ProtocolWire::NetworkBroker => 5,
        ProtocolWire::Guardian => 6,
        ProtocolWire::GuestAgent => 7,
        ProtocolWire::SnapshotTransfer => 8,
    }
}
fn wire_protocol(value: i32) -> Result<ProtocolWire, InvalidMultiNodeProtocol> {
    Ok(match value {
        1 => ProtocolWire::CoordinatorNode,
        2 => ProtocolWire::HostBroker,
        3 => ProtocolWire::StorageBroker,
        4 => ProtocolWire::MountBroker,
        5 => ProtocolWire::NetworkBroker,
        6 => ProtocolWire::Guardian,
        7 => ProtocolWire::GuestAgent,
        8 => ProtocolWire::SnapshotTransfer,
        _ => return Err(invalid()),
    })
}

fn pb_capability(value: CapabilityWire) -> protobuf::CapabilitySnapshot {
    protobuf::CapabilitySnapshot {
        node: value.node.to_string(),
        lineage: Some(pb_lineage(value.lineage)).into(),
        sequence: value.sequence.get(),
        features: value.features.iter().map(pb_feature).collect(),
        facts: value.facts.into_iter().map(pb_fact).collect(),
        protocols: value
            .protocols
            .into_iter()
            .map(|offer| protobuf::ProtocolOffer {
                protocol: protocol_number(offer.protocol).into(),
                maximum_version: Some(pb_version(offer.maximum_version)).into(),
                ..Default::default()
            })
            .collect(),
        allocatable: pb_resources(value.allocatable),
        reserved: pb_resources(value.reserved),
        admission: match value.admission {
            AdmissionWire::Accepting => 1,
            AdmissionWire::Cordoned => 2,
            AdmissionWire::Draining => 3,
        }
        .into(),
        probe_evidence: Some(protobuf::ProbeEvidence {
            probe_set_digest: value.probe_evidence.probe_set_digest.to_string(),
            conformance_profile_digest: value.probe_evidence.conformance_profile_digest.to_string(),
            conformance_version: Some(pb_version(value.probe_evidence.conformance_version)).into(),
            conformance_generation: value.probe_evidence.conformance_generation,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

fn wire_capability(
    value: protobuf::CapabilitySnapshot,
) -> Result<CapabilityWire, InvalidMultiNodeProtocol> {
    if value.facts.len() > crate::multi_node::MAX_NODE_CAPABILITY_FACTS
        || value.features.len() > crate::multi_node::MAX_NODE_FEATURES
        || value.protocols.len() > crate::multi_node::MAX_NODE_PROTOCOL_OFFERS
    {
        return Err(invalid());
    }
    let probe = required(value.probe_evidence)?;
    Ok(CapabilityWire {
        node: parse(&value.node)?,
        lineage: wire_lineage(required(value.lineage)?)?,
        sequence: ObservationSequence::new(value.sequence),
        features: value
            .features
            .into_iter()
            .map(wire_feature)
            .collect::<Result<_, _>>()?,
        facts: value
            .facts
            .into_iter()
            .map(wire_fact)
            .collect::<Result<_, _>>()?,
        protocols: value
            .protocols
            .into_iter()
            .map(|offer| {
                Ok(OfferWire {
                    protocol: wire_protocol(offer.protocol.to_i32())?,
                    maximum_version: wire_version(required(offer.maximum_version)?)?,
                })
            })
            .collect::<Result<_, InvalidMultiNodeProtocol>>()?,
        allocatable: wire_resources(value.allocatable)?,
        reserved: wire_resources(value.reserved)?,
        admission: match value.admission.to_i32() {
            1 => AdmissionWire::Accepting,
            2 => AdmissionWire::Cordoned,
            3 => AdmissionWire::Draining,
            _ => return Err(invalid()),
        },
        probe_evidence: ProbeWire {
            probe_set_digest: parse(&probe.probe_set_digest)?,
            conformance_profile_digest: parse(&probe.conformance_profile_digest)?,
            conformance_version: wire_version(required(probe.conformance_version)?)?,
            conformance_generation: probe.conformance_generation,
        },
    })
}

fn pb_binding(value: BindingWire) -> protobuf::CapabilityBinding {
    protobuf::CapabilityBinding {
        node: value.node.to_string(),
        lineage: Some(pb_lineage(value.lineage)).into(),
        sequence: value.sequence.get(),
        evidence_binding_digest: value.evidence_binding_digest.to_string(),
        canonical_frame_digest: value.canonical_frame_digest.to_string(),
        canonical_frame_bytes: value.canonical_frame_bytes,
        coordinator_epoch: value.coordinator_epoch,
        authenticated_at_unix_seconds: value.authenticated_at_unix_seconds,
        valid_until_unix_seconds: value.valid_until_unix_seconds,
        audience_digest: value.audience_digest.to_string(),
        disclosure_domain_digest: value.disclosure_domain_digest.to_string(),
        carrier_binding_digest: value.carrier_binding_digest.to_string(),
        replay_fence: value.replay_fence.to_string(),
        ..Default::default()
    }
}
fn wire_binding(
    value: protobuf::CapabilityBinding,
) -> Result<BindingWire, InvalidMultiNodeProtocol> {
    Ok(BindingWire {
        node: parse(&value.node)?,
        lineage: wire_lineage(required(value.lineage)?)?,
        sequence: ObservationSequence::new(value.sequence),
        evidence_binding_digest: parse(&value.evidence_binding_digest)?,
        canonical_frame_digest: parse(&value.canonical_frame_digest)?,
        canonical_frame_bytes: value.canonical_frame_bytes,
        coordinator_epoch: value.coordinator_epoch,
        authenticated_at_unix_seconds: value.authenticated_at_unix_seconds,
        valid_until_unix_seconds: value.valid_until_unix_seconds,
        audience_digest: parse(&value.audience_digest)?,
        disclosure_domain_digest: parse(&value.disclosure_domain_digest)?,
        carrier_binding_digest: parse(&value.carrier_binding_digest)?,
        replay_fence: parse(&value.replay_fence)?,
    })
}

fn pb_lifecycle(value: DesiredSandboxState) -> i32 {
    match value {
        DesiredSandboxState::Running => 1,
        DesiredSandboxState::Suspended(SuspensionMode::MemoryResident) => 2,
        DesiredSandboxState::Suspended(SuspensionMode::Hibernate) => 3,
        DesiredSandboxState::Stopped => 4,
        DesiredSandboxState::Deleted => 5,
    }
}
fn wire_lifecycle(value: i32) -> Result<DesiredSandboxState, InvalidMultiNodeProtocol> {
    Ok(match value {
        1 => DesiredSandboxState::Running,
        2 => DesiredSandboxState::Suspended(SuspensionMode::MemoryResident),
        3 => DesiredSandboxState::Suspended(SuspensionMode::Hibernate),
        4 => DesiredSandboxState::Stopped,
        5 => DesiredSandboxState::Deleted,
        _ => return Err(invalid()),
    })
}

fn pb_assignment_observation(value: AssignmentObservationWire) -> protobuf::AssignmentObservation {
    protobuf::AssignmentObservation {
        sandbox: value.sandbox.to_string(),
        incarnation: value.incarnation.to_string(),
        epoch: value.epoch.get(),
        desired_generation: value.desired_generation.get(),
        assignment_digest: value.assignment_digest.to_string(),
        sequence: value.sequence.get(),
        phase: match value.phase {
            AssignmentPhase::Proposed => 1,
            AssignmentPhase::Accepted => 2,
            AssignmentPhase::Arming => 3,
            AssignmentPhase::Active => 4,
            AssignmentPhase::Draining => 5,
            AssignmentPhase::Fenced => 6,
            AssignmentPhase::Released => 7,
            AssignmentPhase::Failed => 8,
        }
        .into(),
        realized_lifecycle: value
            .realized_lifecycle
            .map(|lifecycle| pb_lifecycle(lifecycle).into()),
        reason: match value.reason {
            ReasonWire::None => 1,
            ReasonWire::AwaitingContent => 2,
            ReasonWire::AwaitingCapacity => 3,
            ReasonWire::CapabilityDrift => 4,
            ReasonWire::AwaitingOwnershipAuthority => 5,
            ReasonWire::AwaitingGuardian => 6,
            ReasonWire::OwnershipFenced => 7,
            ReasonWire::InventoryIncomplete => 8,
            ReasonWire::ResidualState => 9,
            ReasonWire::MissingDependency => 10,
            ReasonWire::NodeOperationFailed => 11,
        }
        .into(),
        observed_at_unix_seconds: value.observed_at_unix_seconds,
        ..Default::default()
    }
}
fn wire_assignment_observation(
    value: protobuf::AssignmentObservation,
) -> Result<AssignmentObservationWire, InvalidMultiNodeProtocol> {
    Ok(AssignmentObservationWire {
        sandbox: parse(&value.sandbox)?,
        incarnation: parse(&value.incarnation)?,
        epoch: AssignmentEpoch::new(value.epoch),
        desired_generation: DesiredGeneration::new(value.desired_generation),
        assignment_digest: parse(&value.assignment_digest)?,
        sequence: ObservationSequence::new(value.sequence),
        phase: match value.phase.to_i32() {
            1 => AssignmentPhase::Proposed,
            2 => AssignmentPhase::Accepted,
            3 => AssignmentPhase::Arming,
            4 => AssignmentPhase::Active,
            5 => AssignmentPhase::Draining,
            6 => AssignmentPhase::Fenced,
            7 => AssignmentPhase::Released,
            8 => AssignmentPhase::Failed,
            _ => return Err(invalid()),
        },
        realized_lifecycle: value
            .realized_lifecycle
            .map(|lifecycle| wire_lifecycle(lifecycle.to_i32()))
            .transpose()?,
        reason: match value.reason.to_i32() {
            1 => ReasonWire::None,
            2 => ReasonWire::AwaitingContent,
            3 => ReasonWire::AwaitingCapacity,
            4 => ReasonWire::CapabilityDrift,
            5 => ReasonWire::AwaitingOwnershipAuthority,
            6 => ReasonWire::AwaitingGuardian,
            7 => ReasonWire::OwnershipFenced,
            8 => ReasonWire::InventoryIncomplete,
            9 => ReasonWire::ResidualState,
            10 => ReasonWire::MissingDependency,
            11 => ReasonWire::NodeOperationFailed,
            _ => return Err(invalid()),
        },
        observed_at_unix_seconds: value.observed_at_unix_seconds,
    })
}

fn pb_watch_binding(value: WatchBindingWire) -> protobuf::WatchBinding {
    protobuf::WatchBinding {
        coordinator_epoch: value.coordinator_epoch,
        history_floor_sequence: value.history_floor_sequence,
        history_floor_event_uid: value.history_floor_event_uid.to_string(),
        bootstrap_watermark: value.bootstrap_watermark,
        query_digest: value.query_digest.to_string(),
        authorization_digest: value.authorization_digest.to_string(),
        audience_digest: value.audience_digest.to_string(),
        disclosure_domain_digest: value.disclosure_domain_digest.to_string(),
        schema_minimum: Some(pb_version(value.schema_minimum)).into(),
        schema_maximum: Some(pb_version(value.schema_maximum)).into(),
        ..Default::default()
    }
}
fn wire_watch_binding(
    value: protobuf::WatchBinding,
) -> Result<WatchBindingWire, InvalidMultiNodeProtocol> {
    Ok(WatchBindingWire {
        coordinator_epoch: value.coordinator_epoch,
        history_floor_sequence: value.history_floor_sequence,
        history_floor_event_uid: parse(&value.history_floor_event_uid)?,
        bootstrap_watermark: value.bootstrap_watermark,
        query_digest: parse(&value.query_digest)?,
        authorization_digest: parse(&value.authorization_digest)?,
        audience_digest: parse(&value.audience_digest)?,
        disclosure_domain_digest: parse(&value.disclosure_domain_digest)?,
        schema_minimum: wire_version(required(value.schema_minimum)?)?,
        schema_maximum: wire_version(required(value.schema_maximum)?)?,
    })
}
fn pb_cursor(value: CursorWire) -> protobuf::WatchCursor {
    protobuf::WatchCursor {
        node: value.node.to_string(),
        lineage: Some(pb_lineage(value.lineage)).into(),
        binding: Some(pb_watch_binding(value.binding)).into(),
        event_sequence: value.event_sequence,
        last_event_uid: value.last_event_uid.to_string(),
        ..Default::default()
    }
}
fn wire_cursor(value: protobuf::WatchCursor) -> Result<CursorWire, InvalidMultiNodeProtocol> {
    Ok(CursorWire {
        node: parse(&value.node)?,
        lineage: wire_lineage(required(value.lineage)?)?,
        binding: wire_watch_binding(required(value.binding)?)?,
        event_sequence: value.event_sequence,
        last_event_uid: parse(&value.last_event_uid)?,
    })
}

fn pb_identity(value: IdentityWire) -> protobuf::SnapshotIdentity {
    protobuf::SnapshotIdentity {
        operation: value.operation.to_string(),
        project: value.project.to_string(),
        sandbox: value.sandbox.to_string(),
        incarnation: value.incarnation.to_string(),
        assignment_epoch: value.assignment_epoch.get(),
        desired_generation: value.desired_generation.get(),
        assignment_digest: value.assignment_digest.to_string(),
        snapshot: value.snapshot.to_string(),
        source_node: value.source_node.to_string(),
        destination_node: value.destination_node.to_string(),
        storage_domain_digest: value.storage_domain_digest.to_string(),
        audience_digest: value.audience_digest.to_string(),
        disclosure_domain_digest: value.disclosure_domain_digest.to_string(),
        manifest_digest: value.manifest_digest.to_string(),
        ..Default::default()
    }
}
fn wire_identity(
    value: protobuf::SnapshotIdentity,
) -> Result<IdentityWire, InvalidMultiNodeProtocol> {
    Ok(IdentityWire {
        operation: parse(&value.operation)?,
        project: parse(&value.project)?,
        sandbox: parse(&value.sandbox)?,
        incarnation: parse(&value.incarnation)?,
        assignment_epoch: AssignmentEpoch::new(value.assignment_epoch),
        desired_generation: DesiredGeneration::new(value.desired_generation),
        assignment_digest: parse(&value.assignment_digest)?,
        snapshot: parse(&value.snapshot)?,
        source_node: parse(&value.source_node)?,
        destination_node: parse(&value.destination_node)?,
        storage_domain_digest: parse(&value.storage_domain_digest)?,
        audience_digest: parse(&value.audience_digest)?,
        disclosure_domain_digest: parse(&value.disclosure_domain_digest)?,
        manifest_digest: parse(&value.manifest_digest)?,
    })
}
fn pb_chunk(value: ChunkWire) -> protobuf::SnapshotChunk {
    protobuf::SnapshotChunk {
        index: value.index,
        offset: value.offset,
        length: value.length,
        digest: value.digest.to_string(),
        ..Default::default()
    }
}
fn wire_chunk(value: protobuf::SnapshotChunk) -> Result<ChunkWire, InvalidMultiNodeProtocol> {
    Ok(ChunkWire {
        index: value.index,
        offset: value.offset,
        length: value.length,
        digest: parse(&value.digest)?,
    })
}
fn pb_manifest(value: ManifestWire) -> protobuf::SnapshotManifest {
    protobuf::SnapshotManifest {
        identity: Some(pb_identity(value.identity)).into(),
        version: Some(pb_version(value.version)).into(),
        root: Some(pb_descriptor(&value.root)).into(),
        chunks: value.chunks.into_iter().map(pb_chunk).collect(),
        dependencies: value.dependencies.iter().map(pb_descriptor).collect(),
        required_features: value.required_features.iter().map(pb_feature).collect(),
        ..Default::default()
    }
}
fn wire_manifest(
    value: protobuf::SnapshotManifest,
) -> Result<ManifestWire, InvalidMultiNodeProtocol> {
    if value.chunks.len() > crate::multi_node::MAX_SNAPSHOT_TRANSFER_CHUNKS
        || value.dependencies.len() > crate::multi_node::MAX_SNAPSHOT_TRANSFER_DEPENDENCIES
        || value.required_features.len() > crate::multi_node::MAX_NODE_FEATURES
    {
        return Err(invalid());
    }
    Ok(ManifestWire {
        identity: wire_identity(required(value.identity)?)?,
        version: wire_version(required(value.version)?)?,
        root: wire_descriptor(required(value.root)?)?,
        chunks: value
            .chunks
            .into_iter()
            .map(wire_chunk)
            .collect::<Result<_, _>>()?,
        dependencies: value
            .dependencies
            .into_iter()
            .map(wire_descriptor)
            .collect::<Result<_, _>>()?,
        required_features: value
            .required_features
            .into_iter()
            .map(wire_feature)
            .collect::<Result<_, _>>()?,
    })
}

fn strategy_number(value: StrategyWire) -> i32 {
    match value {
        StrategyWire::SnapshotStopAndReplace => 1,
        StrategyWire::StopAndReplace => 2,
        StrategyWire::StopInPlace => 3,
        StrategyWire::LeaveStopped => 4,
    }
}
fn wire_strategy(value: i32) -> Result<StrategyWire, InvalidMultiNodeProtocol> {
    Ok(match value {
        1 => StrategyWire::SnapshotStopAndReplace,
        2 => StrategyWire::StopAndReplace,
        3 => StrategyWire::StopInPlace,
        4 => StrategyWire::LeaveStopped,
        _ => return Err(invalid()),
    })
}
fn pb_drain_directive(value: DrainDirectiveWire) -> protobuf::DrainDirective {
    protobuf::DrainDirective {
        operation: value.operation.to_string(),
        node: value.node.to_string(),
        generation: value.generation,
        mode: match value.mode {
            DrainModeWire::CordonOnly => 1,
            DrainModeWire::Evacuate => 2,
            DrainModeWire::Decommission => 3,
        }
        .into(),
        accepted_at_unix_seconds: value.accepted_at_unix_seconds,
        deadline_unix_seconds: value.deadline_unix_seconds,
        assignments: value
            .assignments
            .into_iter()
            .map(|row| protobuf::DrainAssignmentPlan {
                sandbox: row.sandbox.to_string(),
                incarnation: row.incarnation.to_string(),
                epoch: row.epoch.get(),
                desired_generation: row.desired_generation.get(),
                assignment_digest: row.assignment_digest.to_string(),
                strategy: strategy_number(row.strategy).into(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}
fn wire_drain_directive(
    value: protobuf::DrainDirective,
) -> Result<DrainDirectiveWire, InvalidMultiNodeProtocol> {
    if value.assignments.len() > crate::multi_node::MAX_DRAIN_ASSIGNMENTS {
        return Err(invalid());
    }
    Ok(DrainDirectiveWire {
        operation: parse(&value.operation)?,
        node: parse(&value.node)?,
        generation: value.generation,
        mode: match value.mode.to_i32() {
            1 => DrainModeWire::CordonOnly,
            2 => DrainModeWire::Evacuate,
            3 => DrainModeWire::Decommission,
            _ => return Err(invalid()),
        },
        accepted_at_unix_seconds: value.accepted_at_unix_seconds,
        deadline_unix_seconds: value.deadline_unix_seconds,
        assignments: value
            .assignments
            .into_iter()
            .map(|row| {
                Ok(DrainPlanWire {
                    sandbox: parse(&row.sandbox)?,
                    incarnation: parse(&row.incarnation)?,
                    epoch: AssignmentEpoch::new(row.epoch),
                    desired_generation: DesiredGeneration::new(row.desired_generation),
                    assignment_digest: parse(&row.assignment_digest)?,
                    strategy: wire_strategy(row.strategy.to_i32())?,
                })
            })
            .collect::<Result<_, InvalidMultiNodeProtocol>>()?,
    })
}
fn progress_parts(
    value: ProgressWire,
) -> (
    buffa::EnumValue<protobuf::DrainProgress>,
    Option<buffa::EnumValue<protobuf::DrainBlockReason>>,
) {
    match value {
        ProgressWire::Pending => (1.into(), None),
        ProgressWire::Preparing => (2.into(), None),
        ProgressWire::Stopping => (3.into(), None),
        ProgressWire::Contained => (4.into(), None),
        ProgressWire::Released => (5.into(), None),
        ProgressWire::Blocked(reason) => (
            6.into(),
            Some(
                (match reason {
                    BlockWire::SnapshotUnavailable => 1,
                    BlockWire::MissingDependency => 2,
                    BlockWire::OwnershipAuthorityUnavailable => 3,
                    BlockWire::ContainmentUnconfirmed => 4,
                    BlockWire::ResidualState => 5,
                    BlockWire::DestinationUnavailable => 6,
                })
                .into(),
            ),
        ),
    }
}
fn wire_progress(
    value: protobuf::DrainProgressValue,
) -> Result<ProgressWire, InvalidMultiNodeProtocol> {
    Ok(
        match (
            value.state.to_i32(),
            value.reason.map(|reason| reason.to_i32()),
        ) {
            (1, None) => ProgressWire::Pending,
            (2, None) => ProgressWire::Preparing,
            (3, None) => ProgressWire::Stopping,
            (4, None) => ProgressWire::Contained,
            (5, None) => ProgressWire::Released,
            (6, Some(reason)) => ProgressWire::Blocked(match reason {
                1 => BlockWire::SnapshotUnavailable,
                2 => BlockWire::MissingDependency,
                3 => BlockWire::OwnershipAuthorityUnavailable,
                4 => BlockWire::ContainmentUnconfirmed,
                5 => BlockWire::ResidualState,
                6 => BlockWire::DestinationUnavailable,
                _ => return Err(invalid()),
            }),
            _ => return Err(invalid()),
        },
    )
}
fn pb_drain_observation(value: DrainObservationWire) -> protobuf::DrainObservation {
    protobuf::DrainObservation {
        operation: value.operation.to_string(),
        generation: value.generation,
        sequence: value.sequence.get(),
        phase: match value.phase {
            DrainPhaseWire::Requested => 1,
            DrainPhaseWire::Cordoned => 2,
            DrainPhaseWire::Draining => 3,
            DrainPhaseWire::Contained => 4,
            DrainPhaseWire::ReadyForReassignment => 5,
            DrainPhaseWire::Complete => 6,
            DrainPhaseWire::Blocked => 7,
        }
        .into(),
        assignments: value
            .assignments
            .into_iter()
            .map(|row| {
                let (state, reason) = progress_parts(row.progress);
                protobuf::DrainAssignmentObservation {
                    sandbox: row.sandbox.to_string(),
                    incarnation: row.incarnation.to_string(),
                    epoch: row.epoch.get(),
                    desired_generation: row.desired_generation.get(),
                    assignment_digest: row.assignment_digest.to_string(),
                    progress: Some(protobuf::DrainProgressValue {
                        state,
                        reason,
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                }
            })
            .collect(),
        observed_at_unix_seconds: value.observed_at_unix_seconds,
        ..Default::default()
    }
}
fn wire_drain_observation(
    value: protobuf::DrainObservation,
) -> Result<DrainObservationWire, InvalidMultiNodeProtocol> {
    if value.assignments.len() > crate::multi_node::MAX_DRAIN_ASSIGNMENTS {
        return Err(invalid());
    }
    Ok(DrainObservationWire {
        operation: parse(&value.operation)?,
        generation: value.generation,
        sequence: ObservationSequence::new(value.sequence),
        phase: match value.phase.to_i32() {
            1 => DrainPhaseWire::Requested,
            2 => DrainPhaseWire::Cordoned,
            3 => DrainPhaseWire::Draining,
            4 => DrainPhaseWire::Contained,
            5 => DrainPhaseWire::ReadyForReassignment,
            6 => DrainPhaseWire::Complete,
            7 => DrainPhaseWire::Blocked,
            _ => return Err(invalid()),
        },
        assignments: value
            .assignments
            .into_iter()
            .map(|row| {
                Ok(DrainAssignmentObservationWire {
                    sandbox: parse(&row.sandbox)?,
                    incarnation: parse(&row.incarnation)?,
                    epoch: AssignmentEpoch::new(row.epoch),
                    desired_generation: DesiredGeneration::new(row.desired_generation),
                    assignment_digest: parse(&row.assignment_digest)?,
                    progress: wire_progress(required(row.progress)?)?,
                })
            })
            .collect::<Result<_, InvalidMultiNodeProtocol>>()?,
        observed_at_unix_seconds: value.observed_at_unix_seconds,
    })
}

fn pb_assignment(value: &CanonicalAssignmentManifestV1) -> protobuf::AssignmentManifest {
    let manifest = value.manifest();
    protobuf::AssignmentManifest {
        sandbox: manifest.sandbox().to_string(),
        project: manifest.project().to_string(),
        ancestors: manifest
            .ancestry()
            .ancestors()
            .iter()
            .map(ToString::to_string)
            .collect(),
        incarnation: manifest.incarnation().to_string(),
        node: manifest.node().to_string(),
        epoch: manifest.epoch().get(),
        desired_generation: manifest.desired_generation().get(),
        namespace_generation: manifest.namespace_generation().get(),
        sandbox_spec: Some(pb_descriptor(manifest.sandbox_spec())).into(),
        policy: Some(pb_descriptor(manifest.policy())).into(),
        environment: Some(pb_descriptor(manifest.environment())).into(),
        root_view: Some(pb_descriptor(manifest.root_view())).into(),
        source_commitments: manifest
            .source_commitments()
            .iter()
            .map(pb_descriptor)
            .collect(),
        resource_commitment: manifest.resource_commitment().to_string(),
        reservations: pb_resources(manifest.reservations()),
        required_features: manifest
            .required_features()
            .iter()
            .map(pb_feature)
            .collect(),
        ..Default::default()
    }
}

fn wire_assignment(
    value: protobuf::AssignmentManifest,
) -> Result<CanonicalAssignmentManifestV1, InvalidMultiNodeProtocol> {
    if value.ancestors.len() > MAX_ANCESTRY_DEPTH
        || value.source_commitments.len() > MAX_ASSIGNMENT_SOURCE_COMMITMENTS
        || value.required_features.len() > MAX_ASSIGNMENT_REQUIRED_FEATURES
    {
        return Err(invalid());
    }
    let sandbox = parse(&value.sandbox)?;
    let ancestry = SandboxAncestry::new(
        sandbox,
        value
            .ancestors
            .into_iter()
            .map(|identity| parse(&identity))
            .collect::<Result<_, _>>()?,
    )
    .map_err(|_| invalid())?;
    let manifest = AssignmentManifestV1::new(
        sandbox,
        parse(&value.project)?,
        ancestry,
        parse(&value.incarnation)?,
        parse(&value.node)?,
        AssignmentEpoch::new(value.epoch),
        DesiredGeneration::new(value.desired_generation),
        NamespaceGeneration::new(value.namespace_generation),
        wire_descriptor(required(value.sandbox_spec)?)?,
        wire_descriptor(required(value.policy)?)?,
        wire_descriptor(required(value.environment)?)?,
        wire_descriptor(required(value.root_view)?)?,
        value
            .source_commitments
            .into_iter()
            .map(wire_descriptor)
            .collect::<Result<_, _>>()?,
        parse(&value.resource_commitment)?,
        wire_resources(value.reservations)?,
        value
            .required_features
            .into_iter()
            .map(wire_feature)
            .collect::<Result<_, _>>()?,
    )
    .map_err(|_| invalid())?;
    Ok(CanonicalAssignmentManifestV1::new(manifest))
}

pub(super) fn protobuf_request(
    body: &NodeRequestBodyV1,
) -> Result<protobuf::semantic_envelope::Body, InvalidMultiNodeProtocol> {
    use protobuf::semantic_envelope::Body;

    Ok(match body {
        NodeRequestBodyV1::GetCapabilities => Body::GetCapabilitiesRequest(Box::default()),
        NodeRequestBodyV1::ReconcileAssignment(intent) => {
            Body::ReconcileAssignmentRequest(Box::new(protobuf::ReconcileAssignmentRequest {
                intent: Some(protobuf::AssignmentIntent {
                    assignment: Some(pb_assignment(intent.assignment())).into(),
                    desired_lifecycle: pb_lifecycle(intent.desired_lifecycle()).into(),
                    selected_capability: Some(pb_binding(
                        intent.selected_capability_binding().into(),
                    ))
                    .into(),
                    assignment_digest: intent.assignment_digest().to_string(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }))
        }
        NodeRequestBodyV1::RelistAssignments { binding } => {
            Body::RelistAssignmentsRequest(Box::new(protobuf::RelistAssignmentsRequest {
                binding: Some(pb_watch_binding((*binding).into())).into(),
                ..Default::default()
            }))
        }
        NodeRequestBodyV1::ReconcileDrain(directive) => {
            Body::ReconcileDrainRequest(Box::new(protobuf::ReconcileDrainRequest {
                directive: Some(pb_drain_directive(drain_directive_wire(directive))).into(),
                ..Default::default()
            }))
        }
        NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } => {
            Body::BeginSnapshotTransferRequest(Box::new(protobuf::BeginSnapshotTransferRequest {
                manifest: Some(pb_manifest(manifest_wire(manifest))).into(),
                resume: resume
                    .map(|resume| {
                        let resume = resume_wire(resume);
                        protobuf::SnapshotResume {
                            identity: Some(pb_identity(resume.identity)).into(),
                            next_chunk: resume.next_chunk,
                            verified_prefix_digest: resume.verified_prefix_digest.to_string(),
                            ..Default::default()
                        }
                    })
                    .into(),
                ..Default::default()
            }))
        }
        NodeRequestBodyV1::FetchSnapshotChunk { request } => {
            Body::SnapshotChunkRequest(Box::new(protobuf::SnapshotChunkRequest {
                request: Some(protobuf::SnapshotChunkRange {
                    identity: Some(pb_identity(request.identity().into())).into(),
                    chunk: Some(pb_chunk(request.chunk().into())).into(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }))
        }
        NodeRequestBodyV1::FetchSnapshotDependency { request } => {
            Body::SnapshotDependencyRequest(Box::new(protobuf::SnapshotDependencyRequest {
                request: Some(protobuf::SnapshotDependencyRange {
                    identity: Some(pb_identity(request.identity().into())).into(),
                    dependency: Some(pb_descriptor(request.dependency())).into(),
                    offset: request.offset(),
                    length: request.length(),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }))
        }
        NodeRequestBodyV1::Watch {
            after,
            maximum_events,
        } => Body::WatchRequest(Box::new(protobuf::WatchRequest {
            after: Some(pb_cursor((*after).into())).into(),
            maximum_events: u32::from(*maximum_events),
            ..Default::default()
        })),
    })
}

pub(super) fn protobuf_request_model(
    kind: CanonicalNodeFrameKindV1,
    body: protobuf::semantic_envelope::Body,
) -> Result<NodeRequestBodyV1, InvalidMultiNodeProtocol> {
    use protobuf::semantic_envelope::Body;

    Ok(match (kind, body) {
        (CanonicalNodeFrameKindV1::GetCapabilitiesRequest, Body::GetCapabilitiesRequest(_)) => {
            NodeRequestBodyV1::GetCapabilities
        }
        (
            CanonicalNodeFrameKindV1::ReconcileAssignmentRequest,
            Body::ReconcileAssignmentRequest(value),
        ) => {
            let value = required(value.intent)?;
            let assignment = wire_assignment(required(value.assignment)?)?;
            if value.assignment_digest != assignment.digest().to_string() {
                return Err(invalid());
            }
            let intent = AssignmentIntentV1::from_canonical_binding(
                assignment,
                wire_lifecycle(value.desired_lifecycle.to_i32())?,
                wire_binding(required(value.selected_capability)?)?.model()?,
            )
            .map_err(|_| invalid())?;
            NodeRequestBodyV1::ReconcileAssignment(Box::new(intent))
        }
        (
            CanonicalNodeFrameKindV1::RelistAssignmentsRequest,
            Body::RelistAssignmentsRequest(value),
        ) => NodeRequestBodyV1::RelistAssignments {
            binding: wire_watch_binding(required(value.binding)?)?.model()?,
        },
        (CanonicalNodeFrameKindV1::ReconcileDrainRequest, Body::ReconcileDrainRequest(value)) => {
            NodeRequestBodyV1::ReconcileDrain(Box::new(drain_directive_model(
                wire_drain_directive(required(value.directive)?)?,
            )?))
        }
        (
            CanonicalNodeFrameKindV1::BeginSnapshotTransferRequest,
            Body::BeginSnapshotTransferRequest(value),
        ) => {
            let manifest = manifest_model(wire_manifest(required(value.manifest)?)?)?;
            let resume = value
                .resume
                .into_option()
                .map(|resume| {
                    let identity = wire_identity(required(resume.identity)?)?.model()?;
                    let model =
                        SnapshotTransferResumeV1::new(&manifest, identity, resume.next_chunk)
                            .map_err(|_| invalid())?;
                    if model.verified_prefix_digest() != parse(&resume.verified_prefix_digest)? {
                        return Err(invalid());
                    }
                    Ok(model)
                })
                .transpose()?;
            NodeRequestBodyV1::BeginSnapshotTransfer {
                manifest: Box::new(manifest),
                resume,
            }
        }
        (CanonicalNodeFrameKindV1::SnapshotChunkRequest, Body::SnapshotChunkRequest(value)) => {
            let request = required(value.request)?;
            NodeRequestBodyV1::FetchSnapshotChunk {
                request: SnapshotTransferChunkRequestV1::from_exact_commitment(
                    wire_identity(required(request.identity)?)?.model()?,
                    wire_chunk(required(request.chunk)?)?.model()?,
                ),
            }
        }
        (
            CanonicalNodeFrameKindV1::SnapshotDependencyRequest,
            Body::SnapshotDependencyRequest(value),
        ) => {
            let request = required(value.request)?;
            NodeRequestBodyV1::FetchSnapshotDependency {
                request: SnapshotDependencyRangeV1::from_exact_commitment(
                    wire_identity(required(request.identity)?)?.model()?,
                    wire_descriptor(required(request.dependency)?)?,
                    request.offset,
                    request.length,
                )
                .map_err(|_| invalid())?,
            }
        }
        (CanonicalNodeFrameKindV1::WatchRequest, Body::WatchRequest(value)) => {
            let maximum_events = u16::try_from(value.maximum_events).map_err(|_| invalid())?;
            if maximum_events == 0
                || usize::from(maximum_events) > crate::multi_node::MAX_WATCH_EVENTS
            {
                return Err(invalid());
            }
            NodeRequestBodyV1::Watch {
                after: wire_cursor(required(value.after)?)?.model()?,
                maximum_events,
            }
        }
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    })
}

fn pb_event_body(body: &NodeWatchEventBodyV1) -> protobuf::watch_event::Body {
    use protobuf::watch_event::Body;
    match body {
        NodeWatchEventBodyV1::Capability(value) => {
            Body::Capability(Box::new(pb_capability(capability_wire(value))))
        }
        NodeWatchEventBodyV1::Assignment(value) => Body::Assignment(Box::new(
            pb_assignment_observation(assignment_observation_wire(value)),
        )),
        NodeWatchEventBodyV1::Drain(value) => Body::Drain(Box::new(pb_drain_observation(
            drain_observation_wire(value),
        ))),
    }
}

fn protobuf_event(event: &NodeWatchEventV1) -> protobuf::WatchEvent {
    protobuf::WatchEvent {
        cursor: Some(pb_cursor(event.cursor().into())).into(),
        predecessor_event_uid: event.predecessor_event_uid().to_string(),
        body: Some(pb_event_body(event.body())),
        ..Default::default()
    }
}

fn protobuf_event_model(
    value: protobuf::WatchEvent,
    context: AuthenticatedEvidenceContextV1,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<NodeWatchEventV1, InvalidMultiNodeProtocol> {
    use protobuf::watch_event::Body;
    let body = match required(value.body)? {
        Body::Capability(value) => {
            NodeWatchEventBodyV1::Capability(Box::new(capability_model(wire_capability(*value)?)?))
        }
        Body::Assignment(value) => NodeWatchEventBodyV1::Assignment(Box::new(
            assignment_observation_model(wire_assignment_observation(*value)?, context)?,
        )),
        Body::Drain(value) => NodeWatchEventBodyV1::Drain(Box::new(drain_observation_model(
            wire_drain_observation(*value)?,
            context,
        )?)),
    };
    NodeWatchEventV1::from_authenticated_history(
        wire_cursor(required(value.cursor)?)?.model()?,
        parse(&value.predecessor_event_uid)?,
        body,
        codec,
    )
}

pub(super) fn protobuf_response(
    body: &NodeResponseBodyV1,
) -> Result<protobuf::semantic_envelope::Body, InvalidMultiNodeProtocol> {
    use protobuf::semantic_envelope::Body;
    Ok(match body {
        NodeResponseBodyV1::Capabilities(value) => {
            Body::GetCapabilitiesResponse(Box::new(protobuf::GetCapabilitiesResponse {
                snapshot: Some(pb_capability(capability_wire(value))).into(),
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::Assignment(value) => {
            Body::ReconcileAssignmentResponse(Box::new(protobuf::ReconcileAssignmentResponse {
                observation: Some(pb_assignment_observation(assignment_observation_wire(
                    value,
                )))
                .into(),
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::AssignmentInventory(value) => {
            Body::RelistAssignmentsResponse(Box::new(protobuf::RelistAssignmentsResponse {
                inventory: Some(protobuf_inventory(value)).into(),
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::Drain(value) => {
            Body::ReconcileDrainResponse(Box::new(protobuf::ReconcileDrainResponse {
                observation: Some(pb_drain_observation(drain_observation_wire(value))).into(),
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::SnapshotTransferReady {
            identity,
            next_chunk,
        } => {
            Body::BeginSnapshotTransferResponse(Box::new(protobuf::BeginSnapshotTransferResponse {
                identity: Some(pb_identity((*identity).into())).into(),
                next_chunk: *next_chunk,
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::SnapshotChunk {
            identity,
            index,
            bytes,
        } => {
            if bytes.is_empty() || bytes.len() > crate::multi_node::MAX_NODE_RESPONSE_BYTES as usize
            {
                return Err(invalid());
            }
            Body::SnapshotChunkResponse(Box::new(protobuf::SnapshotChunkResponse {
                identity: Some(pb_identity((*identity).into())).into(),
                index: *index,
                data: bytes.clone(),
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::SnapshotDependency {
            identity,
            dependency,
            offset,
            bytes,
        } => {
            if bytes.is_empty() || bytes.len() > crate::multi_node::MAX_NODE_RESPONSE_BYTES as usize
            {
                return Err(invalid());
            }
            Body::SnapshotDependencyResponse(Box::new(protobuf::SnapshotDependencyResponse {
                identity: Some(pb_identity((*identity).into())).into(),
                dependency: Some(pb_descriptor(dependency)).into(),
                offset: *offset,
                data: bytes.clone(),
                ..Default::default()
            }))
        }
        NodeResponseBodyV1::WatchBatch { events, cursor_gap } => {
            if events.len() > crate::multi_node::MAX_WATCH_EVENTS {
                return Err(invalid());
            }
            Body::WatchResponse(Box::new(protobuf::WatchResponse {
                events: events.iter().map(protobuf_event).collect(),
                cursor_gap: cursor_gap
                    .map(|value| pb_watch_binding(value.into()))
                    .into(),
                ..Default::default()
            }))
        }
    })
}

fn protobuf_inventory(value: &ResyncInventoryV1) -> protobuf::AssignmentInventory {
    protobuf::AssignmentInventory {
        cursor: Some(pb_cursor(value.cursor().into())).into(),
        capabilities: Some(pb_capability(capability_wire(value.capabilities()))).into(),
        observation_sequence: value.observation_sequence().get(),
        assignments: value
            .assignments()
            .iter()
            .map(|row| pb_assignment_observation(assignment_observation_wire(row)))
            .collect(),
        ..Default::default()
    }
}

fn protobuf_inventory_model(
    value: protobuf::AssignmentInventory,
    context: AuthenticatedEvidenceContextV1,
) -> Result<ResyncInventoryV1, InvalidMultiNodeProtocol> {
    if value.assignments.len() > crate::multi_node::MAX_RESYNC_ASSIGNMENTS {
        return Err(invalid());
    }
    ResyncInventoryV1::new(
        wire_cursor(required(value.cursor)?)?.model()?,
        capability_model(wire_capability(required(value.capabilities)?)?)?,
        ObservationSequence::new(value.observation_sequence),
        value
            .assignments
            .into_iter()
            .map(|row| assignment_observation_model(wire_assignment_observation(row)?, context))
            .collect::<Result<_, _>>()?,
    )
}

pub(super) fn protobuf_response_model(
    context: AuthenticatedEvidenceContextV1,
    kind: CanonicalNodeFrameKindV1,
    body: protobuf::semantic_envelope::Body,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<NodeResponseBodyV1, InvalidMultiNodeProtocol> {
    use protobuf::semantic_envelope::Body;
    Ok(match (kind, body) {
        (
            CanonicalNodeFrameKindV1::GetCapabilitiesResponse,
            Body::GetCapabilitiesResponse(value),
        ) => NodeResponseBodyV1::Capabilities(Box::new(capability_model(wire_capability(
            required(value.snapshot)?,
        )?)?)),
        (
            CanonicalNodeFrameKindV1::ReconcileAssignmentResponse,
            Body::ReconcileAssignmentResponse(value),
        ) => NodeResponseBodyV1::Assignment(Box::new(assignment_observation_model(
            wire_assignment_observation(required(value.observation)?)?,
            context,
        )?)),
        (
            CanonicalNodeFrameKindV1::RelistAssignmentsResponse,
            Body::RelistAssignmentsResponse(value),
        ) => NodeResponseBodyV1::AssignmentInventory(Box::new(protobuf_inventory_model(
            required(value.inventory)?,
            context,
        )?)),
        (CanonicalNodeFrameKindV1::ReconcileDrainResponse, Body::ReconcileDrainResponse(value)) => {
            NodeResponseBodyV1::Drain(Box::new(drain_observation_model(
                wire_drain_observation(required(value.observation)?)?,
                context,
            )?))
        }
        (
            CanonicalNodeFrameKindV1::BeginSnapshotTransferResponse,
            Body::BeginSnapshotTransferResponse(value),
        ) => NodeResponseBodyV1::SnapshotTransferReady {
            identity: wire_identity(required(value.identity)?)?.model()?,
            next_chunk: value.next_chunk,
        },
        (CanonicalNodeFrameKindV1::SnapshotChunkResponse, Body::SnapshotChunkResponse(value)) => {
            if value.data.is_empty()
                || value.data.len() > crate::multi_node::MAX_NODE_RESPONSE_BYTES as usize
            {
                return Err(invalid());
            }
            NodeResponseBodyV1::SnapshotChunk {
                identity: wire_identity(required(value.identity)?)?.model()?,
                index: value.index,
                bytes: value.data,
            }
        }
        (
            CanonicalNodeFrameKindV1::SnapshotDependencyResponse,
            Body::SnapshotDependencyResponse(value),
        ) => {
            if value.data.is_empty()
                || value.data.len() > crate::multi_node::MAX_NODE_RESPONSE_BYTES as usize
            {
                return Err(invalid());
            }
            NodeResponseBodyV1::SnapshotDependency {
                identity: wire_identity(required(value.identity)?)?.model()?,
                dependency: wire_descriptor(required(value.dependency)?)?,
                offset: value.offset,
                bytes: value.data,
            }
        }
        (CanonicalNodeFrameKindV1::WatchResponse, Body::WatchResponse(value)) => {
            if value.events.len() > crate::multi_node::MAX_WATCH_EVENTS {
                return Err(invalid());
            }
            NodeResponseBodyV1::WatchBatch {
                events: value
                    .events
                    .into_iter()
                    .map(|event| protobuf_event_model(event, context, codec))
                    .collect::<Result<_, _>>()?,
                cursor_gap: value
                    .cursor_gap
                    .into_option()
                    .map(wire_watch_binding)
                    .transpose()?
                    .map(WatchBindingWire::model)
                    .transpose()?,
            }
        }
        _ => return Err(InvalidMultiNodeProtocol::MethodMismatch),
    })
}

pub(super) fn protobuf_watch_event_body(body: &NodeWatchEventBodyV1) -> protobuf::WatchEvent {
    protobuf::WatchEvent {
        cursor: MessageField::none(),
        predecessor_event_uid: String::new(),
        body: Some(pb_event_body(body)),
        ..Default::default()
    }
}

pub(super) fn protobuf_watch_event_body_model(
    value: protobuf::WatchEvent,
    context: AuthenticatedEvidenceContextV1,
) -> Result<NodeWatchEventBodyV1, InvalidMultiNodeProtocol> {
    use protobuf::watch_event::Body;
    if value.cursor.is_set() || !value.predecessor_event_uid.is_empty() {
        return Err(invalid());
    }
    Ok(match required(value.body)? {
        Body::Capability(value) => {
            NodeWatchEventBodyV1::Capability(Box::new(capability_model(wire_capability(*value)?)?))
        }
        Body::Assignment(value) => NodeWatchEventBodyV1::Assignment(Box::new(
            assignment_observation_model(wire_assignment_observation(*value)?, context)?,
        )),
        Body::Drain(value) => NodeWatchEventBodyV1::Drain(Box::new(drain_observation_model(
            wire_drain_observation(*value)?,
            context,
        )?)),
    })
}

pub(in crate::multi_node) fn protobuf_cursor(value: NodeWatchCursorV1) -> protobuf::WatchCursor {
    pb_cursor(value.into())
}
pub(in crate::multi_node) fn protobuf_cursor_model(
    value: protobuf::WatchCursor,
) -> Result<NodeWatchCursorV1, InvalidMultiNodeProtocol> {
    wire_cursor(value)?.model()
}
pub(in crate::multi_node) fn protobuf_binding(value: NodeWatchBindingV1) -> protobuf::WatchBinding {
    pb_watch_binding(value.into())
}
pub(in crate::multi_node) fn protobuf_binding_model(
    value: protobuf::WatchBinding,
) -> Result<NodeWatchBindingV1, InvalidMultiNodeProtocol> {
    wire_watch_binding(value)?.model()
}
pub(in crate::multi_node) fn protobuf_ordered_event(
    value: &NodeWatchEventV1,
) -> protobuf::WatchEvent {
    protobuf_event(value)
}
pub(in crate::multi_node) fn protobuf_ordered_event_model(
    value: protobuf::WatchEvent,
    context: AuthenticatedEvidenceContextV1,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<NodeWatchEventV1, InvalidMultiNodeProtocol> {
    protobuf_event_model(value, context, codec)
}
