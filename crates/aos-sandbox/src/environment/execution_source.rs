//! Protected-current environment input for execution specification production.
//!
//! This snapshot is derived only from a cold-replayed activation and its
//! retained execution lease. It is an input commitment, not a runtime effect
//! capability: other owners must independently authorize the remaining spec
//! fields and coordinate currentness before any Host handoff.

use aos_sandbox_core::format::{descriptor_for_bytes, try_encode_environment};
use aos_sandbox_core::model::Environment;
use aos_sandbox_core::{
    ExecutionId, ObjectDescriptor, ObjectDigest, ProjectId, Revision, SandboxId,
};

use super::{
    EnvironmentActivationPhaseV1, EnvironmentActivationTransactionV1, EnvironmentExecutionErrorV1,
    EnvironmentGcRootAcknowledgementV1, EnvironmentGenerationLeaseStatusV1,
    EnvironmentGenerationLeaseV1, EnvironmentLeaseConsumerV1, EnvironmentManifestDigestV1,
    environment_activation_digest_v1,
};

/// Holds exact environment bytes selected by protected-current activation.
///
/// The snapshot is nonauthorizing after the environment owner's borrow ends.
/// Consumers must revalidate it and establish an ordered cross-owner barrier
/// before using it to authorize a runtime effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentExecutionSourceV1 {
    project: ProjectId,
    sandbox: SandboxId,
    execution: ExecutionId,
    activation_revision: Revision,
    activation_digest: ObjectDigest,
    generation: Revision,
    manifest: EnvironmentManifestDigestV1,
    descriptor: ObjectDescriptor,
    environment: Environment,
    canonical_bytes: Vec<u8>,
}

impl EnvironmentExecutionSourceV1 {
    pub(super) fn from_activation(
        activation: &EnvironmentActivationTransactionV1,
        execution: ExecutionId,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if execution.as_bytes() == &[0; 16] {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let selector = activation
            .current()
            .filter(|selector| activation.observed() == Some(*selector))
            .ok_or(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch)?;
        if !matches!(
            activation.phase(),
            EnvironmentActivationPhaseV1::Observed | EnvironmentActivationPhaseV1::Released
        ) {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        ensure_execution_retention(
            execution,
            selector.generation(),
            selector.closure(),
            activation.leases(),
            activation.gc_roots(),
        )?;

        let manifest = selector.manifest_record();
        let canonical_bytes = try_encode_environment(manifest.environment())
            .map_err(|_| EnvironmentExecutionErrorV1::InvalidExecutionSpecification)?;
        let descriptor = descriptor_for_bytes(
            manifest.environment_descriptor().media_type().clone(),
            &canonical_bytes,
        );
        if descriptor != *manifest.environment_descriptor() {
            return Err(EnvironmentExecutionErrorV1::InvalidExecutionSpecification);
        }
        let activation_digest = environment_activation_digest_v1(activation)
            .map_err(|_| EnvironmentExecutionErrorV1::ProtectedEvidenceUnavailable)?;

        Ok(Self {
            project: activation.project(),
            sandbox: activation.sandbox(),
            execution,
            activation_revision: activation.revision(),
            activation_digest,
            generation: selector.generation(),
            manifest: selector.manifest(),
            descriptor,
            environment: manifest.environment().clone(),
            canonical_bytes,
        })
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the owning sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the execution whose active lease retained this generation.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact activation revision observed by the owner.
    #[must_use]
    pub const fn activation_revision(&self) -> Revision {
        self.activation_revision
    }

    /// Returns the canonical protected activation-record commitment.
    #[must_use]
    pub const fn activation_digest(&self) -> ObjectDigest {
        self.activation_digest
    }

    /// Returns the selected environment generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }

    /// Returns the immutable generation-manifest commitment.
    #[must_use]
    pub const fn manifest(&self) -> EnvironmentManifestDigestV1 {
        self.manifest
    }

    /// Borrows the descriptor of the canonical inline environment.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }

    /// Borrows the typed canonical environment for spec construction.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Borrows the exact canonical environment bytes selected by the owner.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

fn ensure_execution_retention(
    execution: ExecutionId,
    generation: Revision,
    closure: &[ObjectDescriptor],
    leases: &[EnvironmentGenerationLeaseV1],
    roots: &[EnvironmentGcRootAcknowledgementV1],
) -> Result<(), EnvironmentExecutionErrorV1> {
    let active_lease = leases.iter().any(|lease| {
        lease.consumer() == EnvironmentLeaseConsumerV1::Execution(execution)
            && lease.generation() == generation
            && lease.status() == EnvironmentGenerationLeaseStatusV1::Active
    });
    let complete_roots = closure.iter().all(|descriptor| {
        roots
            .iter()
            .any(|root| root.generation() == generation && root.descriptor() == descriptor)
    });
    if !active_lease || !complete_roots {
        return Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{
        ExecutionId, MediaType, ObjectDescriptor, ObjectDigest, ResourceId, Revision,
    };

    use super::super::{
        EnvironmentGcRootAcknowledgementV1, EnvironmentGenerationLeaseV1,
        EnvironmentLeaseConsumerV1, EnvironmentLeaseTimeV1, EnvironmentTrustedTimeV1,
    };
    use super::{EnvironmentExecutionErrorV1, ensure_execution_retention};

    #[test]
    fn execution_source_requires_exact_active_lease_and_complete_roots() {
        let execution = ExecutionId::from_bytes([1; 16]);
        let other_execution = ExecutionId::from_bytes([2; 16]);
        let generation = Revision::new(3);
        let other_generation = Revision::new(4);
        let clock = EnvironmentTrustedTimeV1::from_verified_observation(
            ObjectDigest::from_bytes([5; 32]),
            EnvironmentLeaseTimeV1::new(10).expect("time"),
        )
        .expect("verified time");
        let lease = EnvironmentGenerationLeaseV1::new(
            EnvironmentLeaseConsumerV1::Execution(execution),
            generation,
            ResourceId::from_bytes([6; 16]),
            20,
            &clock,
        )
        .expect("lease");
        let other_lease = EnvironmentGenerationLeaseV1::new(
            EnvironmentLeaseConsumerV1::Execution(other_execution),
            generation,
            ResourceId::from_bytes([7; 16]),
            20,
            &clock,
        )
        .expect("other lease");
        let descriptor = ObjectDescriptor::new(
            MediaType::new("application/octet-stream".to_owned()).expect("media type"),
            ObjectDigest::from_bytes([8; 32]),
            1,
        );
        let root = EnvironmentGcRootAcknowledgementV1::new(
            generation,
            descriptor.clone(),
            ResourceId::from_bytes([9; 16]),
            Revision::new(1),
            ObjectDigest::from_bytes([10; 32]),
        )
        .expect("root");
        let second_descriptor = ObjectDescriptor::new(
            MediaType::new("application/octet-stream".to_owned()).expect("media type"),
            ObjectDigest::from_bytes([11; 32]),
            1,
        );
        let second_root = EnvironmentGcRootAcknowledgementV1::new(
            generation,
            second_descriptor.clone(),
            ResourceId::from_bytes([12; 16]),
            Revision::new(1),
            ObjectDigest::from_bytes([13; 32]),
        )
        .expect("second root");

        assert_eq!(
            ensure_execution_retention(
                execution,
                generation,
                &[descriptor.clone()],
                &[],
                &[root.clone()]
            ),
            Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing)
        );
        assert_eq!(
            ensure_execution_retention(
                execution,
                generation,
                &[descriptor.clone()],
                &[other_lease],
                &[root.clone()]
            ),
            Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing)
        );
        assert_eq!(
            ensure_execution_retention(
                execution,
                other_generation,
                &[descriptor.clone()],
                &[lease],
                &[root.clone()]
            ),
            Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing)
        );
        assert_eq!(
            ensure_execution_retention(execution, generation, &[descriptor.clone()], &[lease], &[]),
            Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing)
        );
        assert_eq!(
            ensure_execution_retention(
                execution,
                generation,
                &[descriptor.clone(), second_descriptor.clone()],
                &[lease],
                &[root.clone()]
            ),
            Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing)
        );
        assert_eq!(
            ensure_execution_retention(
                execution,
                generation,
                &[descriptor, second_descriptor],
                &[lease],
                &[root, second_root]
            ),
            Ok(())
        );
    }
}
