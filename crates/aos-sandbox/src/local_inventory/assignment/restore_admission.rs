//! Optional destination restore authorization and admission evidence.
//!
//! The sealed factories consume the original verifier grant and completed
//! publication evidence, retaining their scoped joins and currentness checks.
//! Local snapshot DATA and retained-history validation remain in the parent.

use aos_sandbox_core::{
    NodeId, ObjectDigest, ProjectId, ProtocolVersion, RestoreScopeId, SandboxId,
};

use crate::local_inventory::capability::{
    CarrierValidatedCapabilityObservationV1, NodeAdmissionStateV1, NodeCapabilityKindV1,
    NodeProtocolV1,
};
use crate::local_inventory::evidence::AuthenticatedEvidenceContextV1;
use crate::local_inventory::evidence_authority::VerifierEvidenceGrantV1;

use super::{
    InvalidSnapshotTransfer, SnapshotTransferCompletionV1, SnapshotTransferIdentityV1,
    SnapshotTransferManifestV1,
};

/// Carries current policy/owner approval observed for one exact restore scope.
///
/// The value is verifier evidence, not an ownership lease or effect capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRestoreAuthorizationV1 {
    context: AuthenticatedEvidenceContextV1,
    project: ProjectId,
    sandbox: SandboxId,
    destination: NodeId,
    storage_domain_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    restore_scope: RestoreScopeId,
    generation: u64,
    authorization_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

impl VerifiedRestoreAuthorizationV1 {
    /// Constructs evidence only inside the current policy/owner verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::RestoreAdmissionMismatch`] for zero
    /// or noncurrent scope, identity, domain, or authorization values.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::local_inventory) fn from_owner_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            ProjectId,
            SandboxId,
            NodeId,
            ObjectDigest,
            ObjectDigest,
            ObjectDigest,
            RestoreScopeId,
            u64,
            ObjectDigest,
            u64,
            u64,
        )>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let (
            (
                context,
                project,
                sandbox,
                destination,
                storage_domain_digest,
                audience_digest,
                disclosure_domain_digest,
                restore_scope,
                generation,
                authorization_digest,
                verified_at_unix_seconds,
                valid_until_unix_seconds,
            ),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != context
            || project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || destination.as_bytes() == &[0; 16]
            || storage_domain_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || restore_scope.as_bytes() == &[0; 16]
            || generation == 0
            || authorization_digest.as_bytes() == &[0; 32]
            || valid_until_unix_seconds <= verified_at_unix_seconds
            || context.node() != destination
            || context.audience_digest() != audience_digest
            || context.disclosure_domain_digest() != disclosure_domain_digest
            || !context.is_current_at(verified_at_unix_seconds)
            || !context.is_current_at(valid_until_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        Ok(Self {
            context,
            project,
            sandbox,
            destination,
            storage_domain_digest,
            audience_digest,
            disclosure_domain_digest,
            restore_scope,
            generation,
            authorization_digest,
            verified_at_unix_seconds,
            valid_until_unix_seconds,
        })
    }

    /// Reports whether authorization is current and bound to the transfer identity.
    #[must_use]
    pub fn is_current_for(
        self,
        identity: SnapshotTransferIdentityV1,
        coordinator_unix_seconds: u64,
    ) -> bool {
        self.project == identity.project()
            && self.sandbox == identity.sandbox()
            && self.destination == identity.destination_node()
            && self.storage_domain_digest == identity.storage_domain_digest()
            && self.audience_digest == identity.audience_digest()
            && self.disclosure_domain_digest == identity.disclosure_domain_digest()
            && self.context.node() == identity.destination_node()
            && self.context.is_current_at(coordinator_unix_seconds)
            && coordinator_unix_seconds >= self.verified_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Returns the exact restore scope.
    #[must_use]
    pub const fn restore_scope(self) -> RestoreScopeId {
        self.restore_scope
    }

    /// Returns the monotonic policy authorization generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the authorization observation commitment.
    #[must_use]
    pub const fn authorization_digest(self) -> ObjectDigest {
        self.authorization_digest
    }

    /// Returns the exact authenticated owner-verifier carrier context.
    #[must_use]
    pub const fn evidence_context(self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Records current policy evidence required to consider restore, without authorizing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRestoreAdmissionV1 {
    identity: SnapshotTransferIdentityV1,
    destination: NodeId,
    destination_capability: CarrierValidatedCapabilityObservationV1,
    authorization: VerifiedRestoreAuthorizationV1,
    restore_scope: RestoreScopeId,
    reauthorization_generation: u64,
    reauthorization_digest: ObjectDigest,
    capability_observation_digest: ObjectDigest,
    capability_carrier_binding_digest: ObjectDigest,
    completion: SnapshotTransferCompletionV1,
    dependency_inventory_digest: ObjectDigest,
}

impl SnapshotRestoreAdmissionV1 {
    /// Evaluates evidence issued by the protected destination owner.
    ///
    /// The only production callsite is the fixed destination authority owner,
    /// which supplies its independently authenticated capability, journal,
    /// publication, dependency, and reauthorization evidence. This creates
    /// admission evidence only. It is not an ownership lease, assignment,
    /// restore command, or permission to mutate destination state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for identity mismatches or malformed
    /// evidence. Policy or capability deficiencies produce a typed blocked result.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::local_inventory) fn from_verified_publication(
        manifest: &SnapshotTransferManifestV1,
        completion: SnapshotTransferCompletionV1,
        destination: &CarrierValidatedCapabilityObservationV1,
        authorization: VerifiedRestoreAuthorizationV1,
        coordinator_unix_seconds: u64,
    ) -> Result<SnapshotRestoreAdmissionDecisionV1, InvalidSnapshotTransfer> {
        if completion.identity() != manifest.identity()
            || completion.verified_bytes() != manifest.root().encoded_size()
            || completion.root_digest() != manifest.root().digest()
            || !completion
                .evidence_context()
                .is_current_at(coordinator_unix_seconds)
            || !completion
                .protected_journal_record()
                .context()
                .is_current_at(coordinator_unix_seconds)
            || !authorization.is_current_for(manifest.identity(), coordinator_unix_seconds)
            || authorization.evidence_context().audience_digest() != destination.audience_digest()
            || authorization.evidence_context().coordinator_epoch()
                != destination.coordinator_epoch()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }

        let snapshot = destination.snapshot();
        if snapshot.node() != manifest.identity().destination_node()
            || destination.disclosure_domain_digest()
                != manifest.identity().disclosure_domain_digest()
            || destination.audience_digest() != manifest.identity().audience_digest()
            || !destination.is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        let block = if !completion.dependencies_current_at(coordinator_unix_seconds) {
            Some(SnapshotRestoreBlockReasonV1::MissingDependency)
        } else if snapshot.admission() != NodeAdmissionStateV1::Accepting {
            Some(SnapshotRestoreBlockReasonV1::DestinationAdmissionClosed)
        } else if !snapshot
            .supports_protocol(NodeProtocolV1::SnapshotTransfer, ProtocolVersion::new(1, 0))
        {
            Some(SnapshotRestoreBlockReasonV1::SnapshotTransferProtocolIncompatible)
        } else if snapshot
            .fact(NodeCapabilityKindV1::SnapshotTransfer)
            .is_none()
        {
            Some(SnapshotRestoreBlockReasonV1::SnapshotTransferUnsupported)
        } else if manifest
            .required_features()
            .iter()
            .any(|feature| !snapshot.supports_feature(feature))
        {
            Some(SnapshotRestoreBlockReasonV1::MissingFeature)
        } else {
            None
        };
        if let Some(reason) = block {
            return Ok(SnapshotRestoreAdmissionDecisionV1::Blocked(reason));
        }

        let dependency_inventory_digest = completion.dependency_set_digest();
        Ok(SnapshotRestoreAdmissionDecisionV1::Eligible(Self {
            identity: manifest.identity(),
            destination: snapshot.node(),
            destination_capability: destination.clone(),
            authorization,
            restore_scope: authorization.restore_scope(),
            reauthorization_generation: authorization.generation(),
            reauthorization_digest: authorization.authorization_digest(),
            capability_observation_digest: destination.canonical_observation_digest(),
            capability_carrier_binding_digest: destination.carrier_binding_digest(),
            completion,
            dependency_inventory_digest,
        }))
    }

    /// Returns the exact immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the evaluated destination node.
    #[must_use]
    pub const fn destination(&self) -> NodeId {
        self.destination
    }

    /// Returns the exact carrier-validated destination capability observation.
    #[must_use]
    pub const fn destination_capability(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.destination_capability
    }

    /// Returns the exact verifier-issued restore authorization observation.
    #[must_use]
    pub const fn authorization(&self) -> VerifiedRestoreAuthorizationV1 {
        self.authorization
    }

    /// Reports whether every exact admission prerequisite remains current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.destination_capability
            .is_current_at(coordinator_unix_seconds)
            && self
                .authorization
                .is_current_for(self.identity, coordinator_unix_seconds)
            && self
                .completion
                .evidence_context()
                .is_current_at(coordinator_unix_seconds)
            && self
                .completion
                .protected_journal_record()
                .context()
                .is_current_at(coordinator_unix_seconds)
            && self
                .completion
                .dependencies_current_at(coordinator_unix_seconds)
    }

    /// Returns the policy restore scope.
    #[must_use]
    pub const fn restore_scope(&self) -> RestoreScopeId {
        self.restore_scope
    }

    /// Returns the current policy reauthorization generation.
    #[must_use]
    pub const fn reauthorization_generation(&self) -> u64 {
        self.reauthorization_generation
    }

    /// Returns the current policy reauthorization commitment.
    #[must_use]
    pub const fn reauthorization_digest(&self) -> ObjectDigest {
        self.reauthorization_digest
    }

    /// Returns the exact carrier-validated destination capability commitment.
    #[must_use]
    pub const fn capability_observation_digest(&self) -> ObjectDigest {
        self.capability_observation_digest
    }

    /// Returns the authenticated carrier binding for destination capabilities.
    #[must_use]
    pub const fn capability_carrier_binding_digest(&self) -> ObjectDigest {
        self.capability_carrier_binding_digest
    }

    /// Returns the exact integrity-verified transfer completion receipt.
    #[must_use]
    pub const fn transfer_completion_digest(&self) -> ObjectDigest {
        self.completion.completion_digest()
    }

    /// Returns the exact verified and durably published transfer completion.
    #[must_use]
    pub const fn completion(&self) -> &SnapshotTransferCompletionV1 {
        &self.completion
    }

    /// Returns the authenticated verified-dependency inventory commitment.
    #[must_use]
    pub const fn dependency_inventory_digest(&self) -> ObjectDigest {
        self.dependency_inventory_digest
    }
}

/// Explains a fail-closed restore-admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotRestoreBlockReasonV1 {
    /// Destination is cordoned or draining for new placement.
    DestinationAdmissionClosed,
    /// Destination does not implement exact snapshot-transfer v1 semantics.
    SnapshotTransferProtocolIncompatible,
    /// Destination lacks integrity-checked snapshot-transfer support.
    SnapshotTransferUnsupported,
    /// Destination lacks a hard semantic feature from the manifest.
    MissingFeature,
    /// Complete dependency durability/current-liveness proof is absent or stale.
    MissingDependency,
}

/// Reports whether inert restore admission evidence can be constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotRestoreAdmissionDecisionV1 {
    /// All modeled immutable and current-policy prerequisites are present.
    Eligible(SnapshotRestoreAdmissionV1),
    /// Restore remains blocked without producing effect authority.
    Blocked(SnapshotRestoreBlockReasonV1),
}
