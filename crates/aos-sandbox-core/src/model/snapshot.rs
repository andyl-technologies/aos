//! Portable snapshot manifests and external dependency claims.
//!
//! Snapshot values contain immutable descriptors and non-secret retention
//! receipts. They never contain an operational hold token, credential, host
//! path, process identifier, namespace identifier, or backend-private object.
//! Restore always reauthorizes dependencies and creates a new assignment.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    AssignmentEpoch, AttachmentSlotId, FeatureRef, IncarnationId, IssuerId, NetworkEndpointId,
    ObjectDescriptor, ObjectDigest, ResourceId, RestoreScopeId, SandboxId, SecretId, ServiceId,
};

use super::ViewMutation;

const MAX_OPAQUE_VERSION_BYTES: usize = 255;
const MAX_ANCESTRY_DEPTH: usize = 4_096;

/// Reports an invalid portable snapshot value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidSnapshotModel {
    /// An opaque external version is empty or oversized.
    #[error("opaque version must contain 1..=255 bytes")]
    InvalidOpaqueVersion,
    /// A set-valued snapshot collection is not unique.
    #[error("set-valued snapshot collection must not contain duplicates")]
    DuplicateSetMember,
    /// A canonically keyed snapshot collection is not strictly ordered.
    #[error("snapshot collection is not in its required key order")]
    CollectionNotCanonical,
    /// Snapshot ancestry is too deep, cyclic, or contains the source sandbox.
    #[error("snapshot ancestry must be a bounded root-to-parent chain")]
    InvalidAncestry,
    /// The quiesce evidence does not establish the declared consistency class.
    #[error("quiesce evidence is incompatible with the snapshot consistency class")]
    InvalidQuiesceEvidence,
}

/// Stores one bounded opaque external version without interpreting its bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueVersion(Vec<u8>);

impl OpaqueVersion {
    /// Constructs a bounded non-secret external version.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotModel::InvalidOpaqueVersion`] for an empty or
    /// oversized value.
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidSnapshotModel> {
        if bytes.is_empty() || bytes.len() > MAX_OPAQUE_VERSION_BYTES {
            Err(InvalidSnapshotModel::InvalidOpaqueVersion)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the uninterpreted external version bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for OpaqueVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for OpaqueVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OpaqueVersionVisitor;

        impl<'de> Visitor<'de> for OpaqueVersionVisitor {
            type Value = OpaqueVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an opaque version byte string of length 1..=255")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                OpaqueVersion::new(bytes.to_vec()).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(bytes)
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                OpaqueVersion::new(bytes).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(OpaqueVersionVisitor)
    }
}

/// Stores SHA-256 of one bounded non-secret retention acknowledgement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Receipt(ObjectDigest);

impl Receipt {
    /// Constructs a receipt digest under the only v1 receipt algorithm.
    #[must_use]
    pub const fn sha256(digest: ObjectDigest) -> Self {
        Self(digest)
    }

    /// Returns the exact SHA-256 acknowledgement digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Commits to one retained dependency without embedding its operational token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum RetentionClaim {
    /// Records a held storage version and its controller-ledger receipt.
    Storage {
        /// Logical storage resource identity.
        resource: ResourceId,
        /// Exact backend version interpreted only by its owner.
        opaque_version: OpaqueVersion,
        /// SHA-256 of the exact opaque version bytes.
        version_sha256: ObjectDigest,
        /// Non-secret acknowledgement digest.
        receipt: Receipt,
    },
    /// Records a content/object lease.
    Content {
        /// Exact retained object descriptor.
        object: ObjectDescriptor,
        /// Non-secret acknowledgement digest.
        receipt: Receipt,
    },
    /// Records a Nix/environment garbage-collection root.
    Nix {
        /// Exact retained environment descriptor.
        environment: ObjectDescriptor,
        /// Non-secret acknowledgement digest.
        receipt: Receipt,
    },
    /// Records a service checkpoint retained until an optional deadline.
    Service {
        /// Logical service identity.
        service: ServiceId,
        /// Exact service-owned checkpoint version.
        checkpoint_version: OpaqueVersion,
        /// SHA-256 of the exact checkpoint bytes or record.
        checkpoint_sha256: ObjectDigest,
        /// Non-secret acknowledgement digest.
        receipt: Receipt,
        /// Last promised availability as a Unix second, when bounded.
        available_until: Option<i64>,
    },
    /// Records a secret version reference without secret material.
    Secret {
        /// Authority that owns and versions the secret.
        issuer: IssuerId,
        /// Logical secret identity.
        secret: SecretId,
        /// Exact issuer-owned secret version.
        opaque_version: OpaqueVersion,
        /// Scope in which restore may request reauthorization.
        restore_scope: RestoreScopeId,
        /// Non-secret acknowledgement digest.
        receipt: Receipt,
        /// Secret-version expiry as a Unix second, when bounded.
        expires_seconds: Option<i64>,
    },
}

/// Stores one portable state checkpoint owned by a storage backend profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCheckpoint {
    backend: FeatureRef,
    portable_state: ObjectDescriptor,
}

impl StorageCheckpoint {
    /// Constructs a storage checkpoint with no backend-private payload.
    #[must_use]
    pub const fn new(backend: FeatureRef, portable_state: ObjectDescriptor) -> Self {
        Self {
            backend,
            portable_state,
        }
    }

    /// Returns the registered storage backend profile.
    #[must_use]
    pub const fn backend(&self) -> &FeatureRef {
        &self.backend
    }

    /// Returns the complete portable tree or delta state.
    #[must_use]
    pub const fn portable_state(&self) -> &ObjectDescriptor {
        &self.portable_state
    }
}

/// Stores one snapshot-time filesystem attachment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentSnapshot {
    view: ObjectDescriptor,
    destination_slot: AttachmentSlotId,
    mode: ViewMutation,
}

impl AttachmentSnapshot {
    /// Constructs an attachment snapshot over one exact view revision.
    #[must_use]
    pub const fn new(
        view: ObjectDescriptor,
        destination_slot: AttachmentSlotId,
        mode: ViewMutation,
    ) -> Self {
        Self {
            view,
            destination_slot,
            mode,
        }
    }

    /// Returns the exact view descriptor.
    #[must_use]
    pub const fn view(&self) -> &ObjectDescriptor {
        &self.view
    }

    /// Returns the broker-owned destination slot.
    #[must_use]
    pub const fn destination_slot(&self) -> AttachmentSlotId {
        self.destination_slot
    }

    /// Returns the attachment's maximum mutation semantics.
    #[must_use]
    pub const fn mode(&self) -> ViewMutation {
        self.mode
    }
}

/// Records one external dependency that restore must resolve or reject.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ExternalDependency {
    /// Requires one immutable filesystem view.
    ImmutableView {
        /// Exact view descriptor.
        view: ObjectDescriptor,
        /// Whether missing availability fails restore.
        required: bool,
    },
    /// Requires one immutable package environment.
    Package {
        /// Exact environment descriptor.
        environment: ObjectDescriptor,
        /// Whether missing availability fails restore.
        required: bool,
    },
    /// Requires current authorization to reacquire a secret version.
    Secret {
        /// Authority that owns and versions the secret.
        issuer: IssuerId,
        /// Logical secret identity.
        secret: SecretId,
        /// Exact issuer-owned secret version.
        opaque_version: OpaqueVersion,
        /// Scope in which restore may request reauthorization.
        restore_scope: RestoreScopeId,
        /// Secret-version expiry as a Unix second, when bounded.
        expires_seconds: Option<i64>,
        /// Whether missing authorization or availability fails restore.
        required: bool,
    },
    /// Requires one exact externally retained service checkpoint.
    Service {
        /// Logical service identity.
        service: ServiceId,
        /// Exact service-owned checkpoint version.
        checkpoint_version: OpaqueVersion,
        /// SHA-256 of the exact checkpoint bytes or record.
        checkpoint_sha256: ObjectDigest,
        /// Last promised availability as a Unix second, when bounded.
        available_until: Option<i64>,
        /// Whether missing availability fails restore.
        required: bool,
    },
    /// Requires one versioned logical network endpoint contract.
    Network {
        /// Logical network endpoint identity.
        endpoint: NetworkEndpointId,
        /// Exact endpoint-policy contract version.
        contract_version: OpaqueVersion,
        /// Last promised availability as a Unix second, when bounded.
        available_until: Option<i64>,
        /// Whether missing availability fails restore.
        required: bool,
    },
}

/// Selects one closed snapshot consistency class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotConsistency {
    /// Captures a crash-consistent boundary without guest acknowledgement.
    CrashConsistent,
    /// Captures after an application/guest quiesce acknowledgement.
    ApplicationQuiesced,
    /// Captures an exact state under a registered backend contract.
    BackendExact,
}

/// Stores evidence supporting the declared snapshot consistency class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum QuiesceEvidence {
    /// Records that no quiesce acknowledgement was used.
    None,
    /// Records a guest-agent version and bounded transcript digest.
    Guest {
        /// Guest agent semantic version/profile.
        agent_version: FeatureRef,
        /// SHA-256 of the retained non-secret audit transcript.
        result_sha256: ObjectDigest,
    },
    /// Records a backend profile and bounded transcript digest.
    Backend {
        /// Registered backend quiesce semantics.
        backend: FeatureRef,
        /// SHA-256 of the retained non-secret audit transcript.
        result_sha256: ObjectDigest,
    },
}

/// Records source placement solely as snapshot provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAssignment {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    epoch: AssignmentEpoch,
}

impl SourceAssignment {
    /// Constructs source-assignment provenance.
    #[must_use]
    pub const fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        epoch: AssignmentEpoch,
    ) -> Self {
        Self {
            sandbox,
            incarnation,
            epoch,
        }
    }

    /// Returns the source logical sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the source runtime incarnation.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the source assignment epoch.
    #[must_use]
    pub const fn epoch(self) -> AssignmentEpoch {
        self.epoch
    }
}

/// Stores one complete execution-independent portable snapshot manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Snapshot {
    sandbox_spec: ObjectDescriptor,
    historical_policy: ObjectDescriptor,
    ancestry: Vec<SandboxId>,
    private_roots: Vec<ObjectDescriptor>,
    storage_checkpoints: Vec<StorageCheckpoint>,
    retention_claims: Vec<RetentionClaim>,
    environment: ObjectDescriptor,
    attachments: Vec<AttachmentSnapshot>,
    external_dependencies: Vec<ExternalDependency>,
    consistency: SnapshotConsistency,
    quiesce_evidence: QuiesceEvidence,
    required_restore_features: Vec<FeatureRef>,
    source_assignment: SourceAssignment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    sandbox_spec: ObjectDescriptor,
    historical_policy: ObjectDescriptor,
    ancestry: Vec<SandboxId>,
    private_roots: Vec<ObjectDescriptor>,
    storage_checkpoints: Vec<StorageCheckpoint>,
    retention_claims: Vec<RetentionClaim>,
    environment: ObjectDescriptor,
    attachments: Vec<AttachmentSnapshot>,
    external_dependencies: Vec<ExternalDependency>,
    consistency: SnapshotConsistency,
    quiesce_evidence: QuiesceEvidence,
    required_restore_features: Vec<FeatureRef>,
    source_assignment: SourceAssignment,
}

impl<'de> Deserialize<'de> for Snapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SnapshotWire::deserialize(deserializer)?;
        Self::new(
            wire.sandbox_spec,
            wire.historical_policy,
            wire.ancestry,
            wire.private_roots,
            wire.storage_checkpoints,
            wire.retention_claims,
            wire.environment,
            wire.attachments,
            wire.external_dependencies,
            wire.consistency,
            wire.quiesce_evidence,
            wire.required_restore_features,
            wire.source_assignment,
        )
        .map_err(de::Error::custom)
    }
}

impl Snapshot {
    /// Constructs a portable snapshot and validates keyed collections.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid ancestry, unordered descriptor/features,
    /// duplicate retention/dependency claims, or unordered checkpoint and
    /// attachment keys.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox_spec: ObjectDescriptor,
        historical_policy: ObjectDescriptor,
        ancestry: Vec<SandboxId>,
        private_roots: Vec<ObjectDescriptor>,
        storage_checkpoints: Vec<StorageCheckpoint>,
        retention_claims: Vec<RetentionClaim>,
        environment: ObjectDescriptor,
        attachments: Vec<AttachmentSnapshot>,
        external_dependencies: Vec<ExternalDependency>,
        consistency: SnapshotConsistency,
        quiesce_evidence: QuiesceEvidence,
        required_restore_features: Vec<FeatureRef>,
        source_assignment: SourceAssignment,
    ) -> Result<Self, InvalidSnapshotModel> {
        validate_ancestry(&ancestry, source_assignment.sandbox())?;
        validate_strict_set(&private_roots)?;
        validate_strict_set(&required_restore_features)?;
        validate_unique(&retention_claims)?;
        validate_unique(&external_dependencies)?;

        let evidence_matches = matches!(
            (consistency, &quiesce_evidence),
            (SnapshotConsistency::CrashConsistent, QuiesceEvidence::None)
                | (
                    SnapshotConsistency::ApplicationQuiesced,
                    QuiesceEvidence::Guest { .. }
                )
                | (
                    SnapshotConsistency::BackendExact,
                    QuiesceEvidence::Backend { .. }
                )
        );
        if !evidence_matches {
            return Err(InvalidSnapshotModel::InvalidQuiesceEvidence);
        }

        if !storage_checkpoints
            .windows(2)
            .all(|pair| pair[0].backend() < pair[1].backend())
            || !attachments
                .windows(2)
                .all(|pair| pair[0].destination_slot() < pair[1].destination_slot())
        {
            return Err(InvalidSnapshotModel::CollectionNotCanonical);
        }

        Ok(Self {
            sandbox_spec,
            historical_policy,
            ancestry,
            private_roots,
            storage_checkpoints,
            retention_claims,
            environment,
            attachments,
            external_dependencies,
            consistency,
            quiesce_evidence,
            required_restore_features,
            source_assignment,
        })
    }

    /// Returns sandbox ancestry from root through immediate parent.
    #[must_use]
    pub fn ancestry(&self) -> &[SandboxId] {
        &self.ancestry
    }

    /// Returns the exact sandbox specification descriptor.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Returns the exact historical policy descriptor.
    #[must_use]
    pub const fn historical_policy(&self) -> &ObjectDescriptor {
        &self.historical_policy
    }

    /// Returns portable private tree or delta roots.
    #[must_use]
    pub fn private_roots(&self) -> &[ObjectDescriptor] {
        &self.private_roots
    }

    /// Returns storage checkpoints in backend-feature order.
    #[must_use]
    pub fn storage_checkpoints(&self) -> &[StorageCheckpoint] {
        &self.storage_checkpoints
    }

    /// Returns non-secret retention claims.
    #[must_use]
    pub fn retention_claims(&self) -> &[RetentionClaim] {
        &self.retention_claims
    }

    /// Returns the exact project environment descriptor.
    #[must_use]
    pub const fn environment(&self) -> &ObjectDescriptor {
        &self.environment
    }

    /// Returns attachments in destination-slot order.
    #[must_use]
    pub fn attachments(&self) -> &[AttachmentSnapshot] {
        &self.attachments
    }

    /// Returns unique external dependencies.
    #[must_use]
    pub fn external_dependencies(&self) -> &[ExternalDependency] {
        &self.external_dependencies
    }

    /// Returns the declared consistency class.
    #[must_use]
    pub const fn consistency(&self) -> SnapshotConsistency {
        self.consistency
    }

    /// Returns quiesce evidence appropriate to the consistency contract.
    #[must_use]
    pub const fn quiesce_evidence(&self) -> &QuiesceEvidence {
        &self.quiesce_evidence
    }

    /// Returns exact features that restore must support.
    #[must_use]
    pub fn required_restore_features(&self) -> &[FeatureRef] {
        &self.required_restore_features
    }

    /// Returns source assignment provenance.
    #[must_use]
    pub const fn source_assignment(&self) -> SourceAssignment {
        self.source_assignment
    }
}

fn validate_ancestry(
    ancestry: &[SandboxId],
    subject: SandboxId,
) -> Result<(), InvalidSnapshotModel> {
    if ancestry.len() > MAX_ANCESTRY_DEPTH
        || ancestry.contains(&subject)
        || ancestry
            .iter()
            .enumerate()
            .any(|(index, item)| ancestry[..index].contains(item))
    {
        Err(InvalidSnapshotModel::InvalidAncestry)
    } else {
        Ok(())
    }
}

fn validate_strict_set<T: Ord>(values: &[T]) -> Result<(), InvalidSnapshotModel> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(InvalidSnapshotModel::CollectionNotCanonical)
    }
}

fn validate_unique<T: Eq>(values: &[T]) -> Result<(), InvalidSnapshotModel> {
    if values
        .iter()
        .enumerate()
        .any(|(index, item)| values[..index].contains(item))
    {
        Err(InvalidSnapshotModel::DuplicateSetMember)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediaType;

    fn descriptor(kind: &str, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(format!("application/vnd.aos.sandbox.{kind}.v1+cbor"))
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn source() -> SourceAssignment {
        SourceAssignment::new(
            SandboxId::from_bytes([9; 16]),
            IncarnationId::from_bytes([8; 16]),
            AssignmentEpoch::new(1),
        )
    }

    #[test]
    fn opaque_versions_are_bounded_and_nonempty() {
        assert_eq!(
            OpaqueVersion::new(Vec::new()),
            Err(InvalidSnapshotModel::InvalidOpaqueVersion)
        );
        assert!(OpaqueVersion::new(vec![7; 255]).is_ok());
        assert_eq!(
            OpaqueVersion::new(vec![7; 256]),
            Err(InvalidSnapshotModel::InvalidOpaqueVersion)
        );
    }

    #[test]
    fn source_sandbox_cannot_appear_in_ancestry() {
        let result = Snapshot::new(
            descriptor("spec", 1),
            descriptor("policy", 2),
            vec![source().sandbox()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            descriptor("environment", 3),
            Vec::new(),
            Vec::new(),
            SnapshotConsistency::CrashConsistent,
            QuiesceEvidence::None,
            Vec::new(),
            source(),
        );

        assert_eq!(result, Err(InvalidSnapshotModel::InvalidAncestry));
    }

    #[test]
    fn attachment_slots_are_unique_and_ordered() {
        let slot = AttachmentSlotId::from_bytes([4; 16]);
        let attachments = vec![
            AttachmentSnapshot::new(descriptor("view", 1), slot, ViewMutation::ReadOnly),
            AttachmentSnapshot::new(descriptor("view", 2), slot, ViewMutation::ReadOnly),
        ];
        let result = Snapshot::new(
            descriptor("spec", 1),
            descriptor("policy", 2),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            descriptor("environment", 3),
            attachments,
            Vec::new(),
            SnapshotConsistency::CrashConsistent,
            QuiesceEvidence::None,
            Vec::new(),
            source(),
        );

        assert_eq!(result, Err(InvalidSnapshotModel::CollectionNotCanonical));
    }

    #[test]
    fn duplicate_external_dependencies_fail() {
        let dependency = ExternalDependency::ImmutableView {
            view: descriptor("view", 1),
            required: true,
        };
        let result = Snapshot::new(
            descriptor("spec", 1),
            descriptor("policy", 2),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            descriptor("environment", 3),
            Vec::new(),
            vec![dependency.clone(), dependency],
            SnapshotConsistency::CrashConsistent,
            QuiesceEvidence::None,
            Vec::new(),
            source(),
        );

        assert_eq!(result, Err(InvalidSnapshotModel::DuplicateSetMember));
    }
}
