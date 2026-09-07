//! Controller-known immutable node-assignment semantics.
//!
//! Assignment manifests bind logical identities and content-addressed inputs.
//! They deliberately have no field for ownership-lease time, node-local paths,
//! backend names, process identities, or descriptor numbers.

use crate::{
    AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NamespaceGeneration, NodeId,
    ObjectDescriptor, ObjectDigest, ProjectId, ResourceVector, SandboxId,
};

use super::SandboxAncestry;

/// Maximum immutable source commitments in one assignment generation.
pub const MAX_ASSIGNMENT_SOURCE_COMMITMENTS: usize = 1_024;
/// Maximum required semantic features in one assignment generation.
pub const MAX_ASSIGNMENT_REQUIRED_FEATURES: usize = 64;

/// Reports assignment semantics that are incomplete or noncanonical.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidAssignmentManifest {
    /// A stable identity, generation, or required commitment uses its zero sentinel.
    #[error("assignment manifest contains an unspecified identity, generation, or commitment")]
    Unspecified,
    /// The ancestry subject is not the assigned sandbox.
    #[error("assignment ancestry belongs to another sandbox")]
    AncestryMismatch,
    /// Source commitments are oversized, duplicated, or not in canonical order.
    #[error("assignment source commitments must be a canonical set of at most 1024 entries")]
    SourceCommitmentsNotCanonical,
    /// Required features are oversized, duplicated, or not in canonical order.
    #[error("assignment required features must be a canonical set of at most 64 entries")]
    RequiredFeaturesNotCanonical,
    /// A descriptor has an unknown or context-inappropriate media type.
    #[error("assignment descriptor is invalid: {0}")]
    Descriptor(#[from] crate::RegistryError),
}

/// Stores the complete controller-known semantic preimage of an assignment digest.
///
/// The value is validated independently from its canonical encoding. Its
/// digest is created only by [`crate::CanonicalAssignmentManifestV1`], so no
/// caller can pair these fields with an invented digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentManifestV1 {
    sandbox: SandboxId,
    project: ProjectId,
    ancestry: SandboxAncestry,
    incarnation: IncarnationId,
    node: NodeId,
    epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    namespace_generation: NamespaceGeneration,
    sandbox_spec: ObjectDescriptor,
    policy: ObjectDescriptor,
    environment: ObjectDescriptor,
    root_view: ObjectDescriptor,
    source_commitments: Vec<ObjectDescriptor>,
    resource_commitment: ObjectDigest,
    reservations: ResourceVector,
    required_features: Vec<FeatureRef>,
}

impl AssignmentManifestV1 {
    /// Constructs one complete controller-known assignment generation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentManifest`] for sentinel identities or
    /// commitments, mismatched ancestry, invalid descriptor roles, or
    /// noncanonical bounded sets.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox: SandboxId,
        project: ProjectId,
        ancestry: SandboxAncestry,
        incarnation: IncarnationId,
        node: NodeId,
        epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        namespace_generation: NamespaceGeneration,
        sandbox_spec: ObjectDescriptor,
        policy: ObjectDescriptor,
        environment: ObjectDescriptor,
        root_view: ObjectDescriptor,
        source_commitments: Vec<ObjectDescriptor>,
        resource_commitment: ObjectDigest,
        reservations: ResourceVector,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidAssignmentManifest> {
        if sandbox.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || node.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || desired_generation.get() == 0
            || namespace_generation.get() == 0
            || resource_commitment.as_bytes() == &[0; 32]
        {
            return Err(InvalidAssignmentManifest::Unspecified);
        }
        if ancestry.sandbox() != sandbox {
            return Err(InvalidAssignmentManifest::AncestryMismatch);
        }
        if ancestry
            .ancestors()
            .iter()
            .any(|ancestor| ancestor.as_bytes() == &[0; 16])
        {
            return Err(InvalidAssignmentManifest::Unspecified);
        }
        if source_commitments.len() > MAX_ASSIGNMENT_SOURCE_COMMITMENTS
            || !strictly_increasing(&source_commitments)
        {
            return Err(InvalidAssignmentManifest::SourceCommitmentsNotCanonical);
        }
        if required_features.len() > MAX_ASSIGNMENT_REQUIRED_FEATURES
            || !strictly_increasing(&required_features)
        {
            return Err(InvalidAssignmentManifest::RequiredFeaturesNotCanonical);
        }
        crate::validate_required_features(&required_features)?;

        validate_descriptor(crate::DescriptorRole::SnapshotSpec, &sandbox_spec)?;
        validate_descriptor(crate::DescriptorRole::SnapshotPolicy, &policy)?;
        validate_descriptor(crate::DescriptorRole::SandboxEnvironment, &environment)?;
        validate_descriptor(crate::DescriptorRole::SandboxRootView, &root_view)?;
        for source in &source_commitments {
            validate_descriptor(crate::DescriptorRole::ContentRetention, source)?;
        }

        Ok(Self {
            sandbox,
            project,
            ancestry,
            incarnation,
            node,
            epoch,
            desired_generation,
            namespace_generation,
            sandbox_spec,
            policy,
            environment,
            root_view,
            source_commitments,
            resource_commitment,
            reservations,
            required_features,
        })
    }

    /// Returns the durable sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the project that owns the sandbox tree.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the complete root-to-parent ancestry commitment.
    #[must_use]
    pub const fn ancestry(&self) -> &SandboxAncestry {
        &self.ancestry
    }

    /// Returns the assigned runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assigned node identity.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the monotonic assignment epoch.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.epoch
    }

    /// Returns the desired generation within the assignment epoch.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the expected payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the immutable portable sandbox specification.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor {
        &self.sandbox_spec
    }

    /// Returns the immutable normalized effective policy.
    #[must_use]
    pub const fn policy(&self) -> &ObjectDescriptor {
        &self.policy
    }

    /// Returns the immutable project environment generation.
    #[must_use]
    pub const fn environment(&self) -> &ObjectDescriptor {
        &self.environment
    }

    /// Returns the immutable root filesystem-view generation.
    #[must_use]
    pub const fn root_view(&self) -> &ObjectDescriptor {
        &self.root_view
    }

    /// Returns immutable source objects required to realize the assignment.
    #[must_use]
    pub fn source_commitments(&self) -> &[ObjectDescriptor] {
        &self.source_commitments
    }

    /// Returns the digest of the complete resolved hard-resource policy.
    #[must_use]
    pub const fn resource_commitment(&self) -> ObjectDigest {
        self.resource_commitment
    }

    /// Returns resources reserved for this assignment in stable dimension order.
    #[must_use]
    pub const fn reservations(&self) -> ResourceVector {
        self.reservations
    }

    /// Returns the exact required semantic feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

fn validate_descriptor(
    role: crate::DescriptorRole,
    descriptor: &ObjectDescriptor,
) -> Result<(), InvalidAssignmentManifest> {
    if descriptor.digest().as_bytes() == &[0; 32] || descriptor.encoded_size() == 0 {
        return Err(InvalidAssignmentManifest::Unspecified);
    }
    crate::validate_descriptor_role(role, descriptor)?;
    Ok(())
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
