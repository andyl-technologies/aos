//! Logical ancestry, placement, and attachment control-domain values.
//!
//! These values are durable controller state but are not canonical portable
//! objects. In particular, node identity, incarnation, assignment epoch,
//! namespace generation, local placement constraints, and lease expiry never
//! enter a portable sandbox specification or snapshot identity.

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    AssignmentEpoch, AttachmentId, AttachmentSlotId, DesiredGeneration, FeatureRef, IncarnationId,
    LeaseId, NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest, ResourceVector, Revision,
    SandboxId, ViewId, validate_descriptor_role,
};

use super::ViewMutation;

/// Maximum logical sandbox-parent edges in one ancestry chain.
pub const MAX_ANCESTRY_DEPTH: usize = 4_096;

/// Reports invalid ancestry, placement, or attachment intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidDomainModel {
    /// An ancestry chain is too deep, cyclic, or contains its subject.
    #[error("ancestry must be a bounded root-to-parent chain without repeats")]
    InvalidAncestry,
    /// A set-valued placement collection is not strictly ordered and unique.
    #[error("placement sets must be strictly ordered and unique")]
    PlacementNotCanonical,
    /// A placement requests co-location with its own sandbox.
    #[error("a sandbox cannot request co-location with itself")]
    SelfColocation,
    /// Lease expiry is not later than its issue time.
    #[error("attachment lease expiry must be later than issue time")]
    InvalidLeaseInterval,
    /// An attachment identity, generation, or lease uses its zero sentinel.
    #[error("attachment intent contains an unspecified identity, generation, or lease")]
    UnspecifiedAttachment,
    /// The attachment's view descriptor is not a registered view revision.
    #[error("attachment view descriptor is invalid")]
    InvalidAttachmentView,
    /// Mount attributes would broaden the selected mutation mode.
    #[error("mount attributes are incompatible with attachment mutation semantics")]
    IncompatibleMountAttributes,
    /// A non-live consistency class carries an inapplicable source incarnation.
    #[error("attachment source incarnation is incompatible with consistency class")]
    IncompatibleSourceIncarnation,
}

/// Stores one sandbox's ancestry from root through immediate parent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SandboxAncestry {
    sandbox: SandboxId,
    ancestors: Vec<SandboxId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxAncestryWire {
    sandbox: SandboxId,
    ancestors: Vec<SandboxId>,
}

impl<'de> Deserialize<'de> for SandboxAncestry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SandboxAncestryWire::deserialize(deserializer)?;
        Self::new(wire.sandbox, wire.ancestors).map_err(serde::de::Error::custom)
    }
}

impl SandboxAncestry {
    /// Constructs one bounded root-to-parent ancestry chain.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDomainModel::InvalidAncestry`] if the chain exceeds
    /// 4096 edges, repeats an identity, or contains the subject sandbox.
    pub fn new(sandbox: SandboxId, ancestors: Vec<SandboxId>) -> Result<Self, InvalidDomainModel> {
        if ancestors.len() > MAX_ANCESTRY_DEPTH
            || ancestors.contains(&sandbox)
            || ancestors
                .iter()
                .enumerate()
                .any(|(index, item)| ancestors[..index].contains(item))
        {
            return Err(InvalidDomainModel::InvalidAncestry);
        }
        Ok(Self { sandbox, ancestors })
    }

    /// Returns the subject sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the root-to-parent identity sequence.
    #[must_use]
    pub fn ancestors(&self) -> &[SandboxId] {
        &self.ancestors
    }

    /// Returns the immediate parent, or `None` for a project-root sandbox.
    #[must_use]
    pub fn parent(&self) -> Option<SandboxId> {
        self.ancestors.last().copied()
    }

    /// Returns the number of authority-delegation edges from project root.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.ancestors.len()
    }
}

/// Stores semantic scheduler inputs without selecting a particular node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlacementRequest {
    sandbox: SandboxId,
    required_features: Vec<FeatureRef>,
    same_node_sandboxes: Vec<SandboxId>,
    reserved_resources: ResourceVector,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlacementRequestWire {
    sandbox: SandboxId,
    required_features: Vec<FeatureRef>,
    same_node_sandboxes: Vec<SandboxId>,
    reserved_resources: ResourceVector,
}

impl<'de> Deserialize<'de> for PlacementRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PlacementRequestWire::deserialize(deserializer)?;
        Self::new(
            wire.sandbox,
            wire.required_features,
            wire.same_node_sandboxes,
            wire.reserved_resources,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl PlacementRequest {
    /// Constructs one scheduler request with exact feature and affinity sets.
    ///
    /// # Errors
    ///
    /// Returns an error for unordered/duplicate sets or self-colocation.
    pub fn new(
        sandbox: SandboxId,
        required_features: Vec<FeatureRef>,
        same_node_sandboxes: Vec<SandboxId>,
        reserved_resources: ResourceVector,
    ) -> Result<Self, InvalidDomainModel> {
        if !strictly_increasing(&required_features) || !strictly_increasing(&same_node_sandboxes) {
            return Err(InvalidDomainModel::PlacementNotCanonical);
        }
        if same_node_sandboxes.contains(&sandbox) {
            return Err(InvalidDomainModel::SelfColocation);
        }
        Ok(Self {
            sandbox,
            required_features,
            same_node_sandboxes,
            reserved_resources,
        })
    }

    /// Returns the sandbox to place.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns exact required runtime/backend semantic features.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }

    /// Returns sandboxes joined by local-live attachment affinity.
    #[must_use]
    pub fn same_node_sandboxes(&self) -> &[SandboxId] {
        &self.same_node_sandboxes
    }

    /// Returns resources atomically reserved along the logical ancestry.
    #[must_use]
    pub const fn reserved_resources(&self) -> ResourceVector {
        self.reserved_resources
    }
}

/// Stores one generation-fenced node assignment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlacementAssignment {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    namespace_generation: NamespaceGeneration,
    assignment_digest: ObjectDigest,
    sandbox_spec: ObjectDescriptor,
    policy: ObjectDescriptor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlacementAssignmentWire {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    namespace_generation: NamespaceGeneration,
    assignment_digest: ObjectDigest,
    sandbox_spec: ObjectDescriptor,
    policy: ObjectDescriptor,
}

impl<'de> Deserialize<'de> for PlacementAssignment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PlacementAssignmentWire::deserialize(deserializer)?;
        Ok(Self::new(
            wire.sandbox,
            wire.incarnation,
            wire.node,
            wire.epoch,
            wire.desired_generation,
            wire.namespace_generation,
            wire.assignment_digest,
            wire.sandbox_spec,
            wire.policy,
        ))
    }
}

impl PlacementAssignment {
    /// Constructs a complete immutable assignment-semantic tuple.
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        node: NodeId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        namespace_generation: NamespaceGeneration,
        assignment_digest: ObjectDigest,
        sandbox_spec: ObjectDescriptor,
        policy: ObjectDescriptor,
    ) -> Self {
        Self {
            sandbox,
            incarnation,
            node,
            epoch,
            desired_generation,
            namespace_generation,
            assignment_digest,
            sandbox_spec,
            policy,
        }
    }

    /// Returns the assignment ordering and idempotency tuple.
    #[must_use]
    pub const fn fence(&self) -> (AssignmentEpoch, DesiredGeneration, ObjectDigest) {
        (self.epoch, self.desired_generation, self.assignment_digest)
    }

    /// Returns the logical sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assigned node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the exact portable sandbox specification.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Returns the exact resolved policy.
    #[must_use]
    pub const fn policy(&self) -> &ObjectDescriptor {
        &self.policy
    }
}

/// Selects one attachment dependency and placement contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentConsistency {
    /// Uses a fixed immutable view revision on any capable node.
    ImmutableRevision,
    /// Requires source and consumer incarnations on the same node.
    LocalLive,
    /// Uses a protocol endpoint instead of a shared mount.
    TransactionalService,
    /// Allows a stale replica only for explicitly reconstructible data.
    BestEffortReplica,
}

/// Stores one closed mount-attribute request without option strings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountAttributes {
    read_only: bool,
    no_exec: bool,
    no_suid: bool,
    no_dev: bool,
    no_atime: bool,
    recursive: bool,
}

impl MountAttributes {
    /// Constructs explicit closed mount attributes.
    #[must_use]
    pub const fn new(
        read_only: bool,
        no_exec: bool,
        no_suid: bool,
        no_dev: bool,
        no_atime: bool,
        recursive: bool,
    ) -> Self {
        Self {
            read_only,
            no_exec,
            no_suid,
            no_dev,
            no_atime,
            recursive,
        }
    }

    /// Reports whether VFS mutation is disabled.
    #[must_use]
    pub const fn read_only(self) -> bool {
        self.read_only
    }

    /// Reports whether execution through the attachment is disabled.
    #[must_use]
    pub const fn no_exec(self) -> bool {
        self.no_exec
    }

    /// Reports whether set-user/group-ID bits are disabled.
    #[must_use]
    pub const fn no_suid(self) -> bool {
        self.no_suid
    }

    /// Reports whether device-node interpretation is disabled.
    #[must_use]
    pub const fn no_dev(self) -> bool {
        self.no_dev
    }

    /// Reports whether access-time updates are disabled.
    #[must_use]
    pub const fn no_atime(self) -> bool {
        self.no_atime
    }

    /// Reports whether source submounts are included.
    #[must_use]
    pub const fn recursive(self) -> bool {
        self.recursive
    }
}

/// Stores a time-bounded attachment lease identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AttachmentLease {
    id: LeaseId,
    issued_seconds: i64,
    expires_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentLeaseWire {
    id: LeaseId,
    issued_seconds: i64,
    expires_seconds: i64,
}

impl<'de> Deserialize<'de> for AttachmentLease {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AttachmentLeaseWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.issued_seconds, wire.expires_seconds)
            .map_err(serde::de::Error::custom)
    }
}

impl AttachmentLease {
    /// Constructs an attachment lease with a nonempty wall-clock interval.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDomainModel::UnspecifiedAttachment`] for the reserved
    /// zero lease identity, or [`InvalidDomainModel::InvalidLeaseInterval`]
    /// unless expiry is later than issue time.
    pub const fn new(
        id: LeaseId,
        issued_seconds: i64,
        expires_seconds: i64,
    ) -> Result<Self, InvalidDomainModel> {
        if u128::from_be_bytes(*id.as_bytes()) == 0 {
            Err(InvalidDomainModel::UnspecifiedAttachment)
        } else if expires_seconds <= issued_seconds {
            Err(InvalidDomainModel::InvalidLeaseInterval)
        } else {
            Ok(Self {
                id,
                issued_seconds,
                expires_seconds,
            })
        }
    }

    /// Returns the opaque lease identity.
    #[must_use]
    pub const fn id(self) -> LeaseId {
        self.id
    }

    /// Returns the inclusive issue time as a Unix second.
    #[must_use]
    pub const fn issued_seconds(self) -> i64 {
        self.issued_seconds
    }

    /// Returns the exclusive expiry time as a Unix second.
    #[must_use]
    pub const fn expires_seconds(self) -> i64 {
        self.expires_seconds
    }
}

/// Stores a generation-fenced logical attachment request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttachmentIntent {
    id: AttachmentId,
    desired_generation: DesiredGeneration,
    consumer_sandbox: SandboxId,
    consumer_incarnation: IncarnationId,
    expected_namespace_generation: NamespaceGeneration,
    source_view: ViewId,
    source_view_revision: Revision,
    source_incarnation: Option<IncarnationId>,
    view: ObjectDescriptor,
    destination_slot: AttachmentSlotId,
    consistency: AttachmentConsistency,
    mutation: ViewMutation,
    mount_attributes: MountAttributes,
    lease: AttachmentLease,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentIntentWire {
    id: AttachmentId,
    desired_generation: DesiredGeneration,
    consumer_sandbox: SandboxId,
    consumer_incarnation: IncarnationId,
    expected_namespace_generation: NamespaceGeneration,
    source_view: ViewId,
    source_view_revision: Revision,
    source_incarnation: Option<IncarnationId>,
    view: ObjectDescriptor,
    destination_slot: AttachmentSlotId,
    consistency: AttachmentConsistency,
    mutation: ViewMutation,
    mount_attributes: MountAttributes,
    lease: AttachmentLease,
}

impl<'de> Deserialize<'de> for AttachmentIntent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AttachmentIntentWire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.desired_generation,
            wire.consumer_sandbox,
            wire.consumer_incarnation,
            wire.expected_namespace_generation,
            wire.source_view,
            wire.source_view_revision,
            wire.source_incarnation,
            wire.view,
            wire.destination_slot,
            wire.consistency,
            wire.mutation,
            wire.mount_attributes,
            wire.lease,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl AttachmentIntent {
    /// Constructs one logical attachment intent.
    ///
    /// # Errors
    ///
    /// Returns an error for zero identities or generations, a descriptor that
    /// is not a filesystem-view revision, mount attributes that widen the
    /// mutation mode or enable set-ID/device interpretation, or source
    /// incarnation presence that differs from the local-live contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AttachmentId,
        desired_generation: DesiredGeneration,
        consumer_sandbox: SandboxId,
        consumer_incarnation: IncarnationId,
        expected_namespace_generation: NamespaceGeneration,
        source_view: ViewId,
        source_view_revision: Revision,
        source_incarnation: Option<IncarnationId>,
        view: ObjectDescriptor,
        destination_slot: AttachmentSlotId,
        consistency: AttachmentConsistency,
        mutation: ViewMutation,
        mount_attributes: MountAttributes,
        lease: AttachmentLease,
    ) -> Result<Self, InvalidDomainModel> {
        if id.as_bytes() == &[0; 16]
            || desired_generation.get() == 0
            || consumer_sandbox.as_bytes() == &[0; 16]
            || consumer_incarnation.as_bytes() == &[0; 16]
            || expected_namespace_generation.get() == 0
            || source_view.as_bytes() == &[0; 16]
            || source_view_revision.get() == 0
            || source_incarnation.is_some_and(|value| value.as_bytes() == &[0; 16])
            || destination_slot.as_bytes() == &[0; 16]
        {
            return Err(InvalidDomainModel::UnspecifiedAttachment);
        }
        if validate_descriptor_role(crate::DescriptorRole::FilesystemViewRevision, &view).is_err() {
            return Err(InvalidDomainModel::InvalidAttachmentView);
        }
        if mount_attributes.read_only() != (mutation == ViewMutation::ReadOnly)
            || !mount_attributes.no_suid()
            || !mount_attributes.no_dev()
        {
            return Err(InvalidDomainModel::IncompatibleMountAttributes);
        }
        let requires_source_incarnation = consistency == AttachmentConsistency::LocalLive;
        if source_incarnation.is_some() != requires_source_incarnation {
            return Err(InvalidDomainModel::IncompatibleSourceIncarnation);
        }
        Ok(Self {
            id,
            desired_generation,
            consumer_sandbox,
            consumer_incarnation,
            expected_namespace_generation,
            source_view,
            source_view_revision,
            source_incarnation,
            view,
            destination_slot,
            consistency,
            mutation,
            mount_attributes,
            lease,
        })
    }

    /// Returns the logical attachment identity.
    #[must_use]
    pub const fn id(&self) -> AttachmentId {
        self.id
    }

    /// Returns the desired attachment generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the consumer sandbox and incarnation.
    #[must_use]
    pub const fn consumer(&self) -> (SandboxId, IncarnationId) {
        (self.consumer_sandbox, self.consumer_incarnation)
    }

    /// Returns the expected consumer namespace generation.
    #[must_use]
    pub const fn expected_namespace_generation(&self) -> NamespaceGeneration {
        self.expected_namespace_generation
    }

    /// Returns the logical source view and immutable revision.
    #[must_use]
    pub const fn source_view(&self) -> (ViewId, Revision) {
        (self.source_view, self.source_view_revision)
    }

    /// Returns the source incarnation required by local-live attachment.
    #[must_use]
    pub const fn source_incarnation(&self) -> Option<IncarnationId> {
        self.source_incarnation
    }

    /// Returns the exact portable view descriptor.
    #[must_use]
    pub const fn view(&self) -> &ObjectDescriptor {
        &self.view
    }

    /// Returns the broker-owned destination slot.
    #[must_use]
    pub const fn destination_slot(&self) -> AttachmentSlotId {
        self.destination_slot
    }

    /// Returns the attachment consistency contract.
    #[must_use]
    pub const fn consistency(&self) -> AttachmentConsistency {
        self.consistency
    }

    /// Returns the maximum mutation semantics.
    #[must_use]
    pub const fn mutation(&self) -> ViewMutation {
        self.mutation
    }

    /// Returns the closed mount attributes.
    #[must_use]
    pub const fn mount_attributes(&self) -> MountAttributes {
        self.mount_attributes
    }

    /// Returns the current attachment lease.
    #[must_use]
    pub const fn lease(&self) -> AttachmentLease {
        self.lease
    }
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediaType;

    fn descriptor() -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.view.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            1,
        )
    }

    fn lease() -> AttachmentLease {
        AttachmentLease::new(LeaseId::from_bytes([8; 16]), 10, 20)
            .unwrap_or_else(|error| panic!("test lease failed: {error}"))
    }

    #[test]
    fn ancestry_rejects_repeated_nodes() {
        let ancestor = SandboxId::from_bytes([2; 16]);
        assert_eq!(
            SandboxAncestry::new(SandboxId::from_bytes([1; 16]), vec![ancestor, ancestor]),
            Err(InvalidDomainModel::InvalidAncestry)
        );
    }

    #[test]
    fn placement_rejects_self_colocation() {
        let sandbox = SandboxId::from_bytes([1; 16]);
        assert_eq!(
            PlacementRequest::new(sandbox, Vec::new(), vec![sandbox], ResourceVector::ZERO),
            Err(InvalidDomainModel::SelfColocation)
        );
    }

    #[test]
    fn attachment_lease_rejects_the_reserved_identity() {
        assert_eq!(
            AttachmentLease::new(LeaseId::from_bytes([0; 16]), 10, 20),
            Err(InvalidDomainModel::UnspecifiedAttachment)
        );
    }

    #[test]
    fn local_live_attachment_requires_source_incarnation() {
        let result = AttachmentIntent::new(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(1),
            SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]),
            NamespaceGeneration::new(1),
            ViewId::from_bytes([4; 16]),
            Revision::new(1),
            None,
            descriptor(),
            AttachmentSlotId::from_bytes([5; 16]),
            AttachmentConsistency::LocalLive,
            ViewMutation::ReadOnly,
            MountAttributes::new(true, true, true, true, true, false),
            lease(),
        );

        assert_eq!(
            result,
            Err(InvalidDomainModel::IncompatibleSourceIncarnation)
        );
    }

    #[test]
    fn read_only_semantics_require_read_only_mount() {
        let result = AttachmentIntent::new(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(1),
            SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]),
            NamespaceGeneration::new(1),
            ViewId::from_bytes([4; 16]),
            Revision::new(1),
            None,
            descriptor(),
            AttachmentSlotId::from_bytes([5; 16]),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadOnly,
            MountAttributes::new(false, true, true, true, true, false),
            lease(),
        );

        assert_eq!(result, Err(InvalidDomainModel::IncompatibleMountAttributes));
    }

    #[test]
    fn writable_semantics_reject_read_only_mounts() {
        let result = AttachmentIntent::new(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(1),
            SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]),
            NamespaceGeneration::new(1),
            ViewId::from_bytes([4; 16]),
            Revision::new(1),
            None,
            descriptor(),
            AttachmentSlotId::from_bytes([5; 16]),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadWrite,
            MountAttributes::new(true, true, true, true, true, false),
            lease(),
        );

        assert_eq!(result, Err(InvalidDomainModel::IncompatibleMountAttributes));
    }
}
