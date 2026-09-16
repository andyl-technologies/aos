//! Fixed protected owner for dormant advanced Network policy replacement.
//!
//! The owner is the only bridge from the pure replacement reducer to durable
//! state and worker handoff. It opens one root-owned, no-symlink journal at the
//! compiled-in path, replays the complete canonical recovery record and its
//! opaque currentness inventory, and retains the protected authority claim
//! across transition, commit, exact readback, and optional handoff creation.
//! Nothing in this module dispatches a worker or mutates kernel state.

use std::collections::BTreeMap;

use aos_sandbox::{
    Journal, JournalLimits, JournalRecord, JournalTransaction, ProtectedJournalAuthority,
    RecordNamespace,
};
use aos_sandbox_core::{
    BrokerAssignment, FeatureRef, NodeId, ObjectDigest, OperationId, ProjectId,
};
use sha2::{Digest as _, Sha256};

use super::handoff::DurablyCommittedAdvancedNetworkPolicyV1;
use super::identity::{
    NetworkPolicyRevisionV1, ProtectedCurrentnessWitnessV1, ProtectedJournalIdentityV1,
    ProtectedRecoveryAuthoritiesV1, ProtectedWitnessPurposeV1, assignment_namespace,
    node_namespace, project_namespace, protected_source_key,
};
use super::ingress::{
    ExternalIngressRegistryV1, IngressPoolAuthorityV1, IngressPoolPortRangeV1, IngressRegistryRowV1,
};
use super::quota::{
    AdvancedNetworkQuotaV1, ProjectNetworkUsageV1, ProtectedNetworkQuotaV1,
    ProtectedNetworkTransactionV1,
};
use super::replacement::{
    AdvancedNetworkRecoveryCompanionsV1, AdvancedNetworkRecoveryRecordV1,
    NetworkPolicyReplacementEventV1, NetworkPolicyReplacementPhaseV1,
    NetworkPolicyReplacementStateV1, NetworkReplacementObservationV1,
    ProtectedNetworkObservationInputV1, combined_state_components, effect_currentness_inventory,
    protected_currentness_inventory, protected_recovery_authorization, protected_recovery_fence,
    rebind_combined_state, recovery_authority_binding, reduce_network_policy_replacement_v1,
};
use super::service_discovery::{DiscoveredProjectServiceV1, ProjectServiceDiscoverySnapshotV1};
use super::source_authority::{
    BrokerAssignmentLeaseProofV1, DiscoveryPublisherProofV1, IngressPoolAuthorityProofV1,
    KernelCapabilityProbeProofV1, QuotaAuthorityProofV1,
};
use super::{
    AdvancedNetworkPolicyError, AdvancedNetworkPolicyWorkerHandoffV1,
    CompiledAdvancedNetworkPolicyV1,
};
use crate::policy::NetworkIpPrefixV1;

const FIXED_DIRECTORY: &str = "/var/lib/aos/sandbox/network/advanced-policy";
const JOURNAL_NAME: &str = "replacement.journal";
const SOURCE_ISSUER_JOURNAL_NAME: &str = "source-issuers.journal";
const STATE_KEY: &[u8] = b"advanced-policy-replacement-v1";
const STATE_AUTHORITY_PREFIX: &[u8] = b"state-authority-v1/";
const SOURCE_AUTHORITY_PREFIX: &[u8] = b"source-authority-v1/";
const SOURCE_HISTORY_PREFIX: &[u8] = b"source-history-v1/";
const ISSUER_AUTHORITY_PREFIX: &[u8] = b"issuer-authority-v1/";
const ISSUER_HISTORY_PREFIX: &[u8] = b"issuer-history-v1/";
const ISSUER_HISTORY_MAGIC: &[u8; 8] = b"AOSAISH1";
const ENVELOPE_MAGIC: &[u8; 8] = b"AOSANPO1";
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_FIXED_BYTES: usize = 8 + 2 + 2 + 4 + 8 + 201 + 201 + 376 + 4 + 32;
const MAXIMUM_AUTHORITIES: usize = 8_192;
const MAXIMUM_COMPANION_BYTES: usize = 24 * 1024 * 1024;

struct IssuerCommitTargetV1 {
    witness: ProtectedCurrentnessWitnessV1,
    predecessor: Option<ProtectedCurrentnessWitnessV1>,
    history: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssuerCommitRecoveryV1 {
    Applied,
    Retry,
    Diverged,
}

/// Supplies opaque protected heads needed by one initial state or transition.
///
/// The wrapper accepts only already-sealed currentness values. Its contents
/// are merged into the journal's canonical inventory and must be exactly
/// sufficient for recovery decoding; scalar journal coordinates are never a
/// public input.
#[must_use]
pub struct AdvancedNetworkPolicyProtectedAuthoritiesV1 {
    witnesses: Vec<ProtectedCurrentnessWitnessV1>,
}

/// Binds one registry value to the protected current head that authenticated it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedIngressRegistrySnapshotV1 {
    registry: ExternalIngressRegistryV1,
    currentness: ProtectedCurrentnessWitnessV1,
}

/// Carries one atomically published registry, quota, and combined head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedCombinedNetworkStateV1 {
    registry: ProtectedIngressRegistrySnapshotV1,
    quota: ProtectedNetworkQuotaV1,
    transaction: ProtectedNetworkTransactionV1,
}

/// Carries an assignment authenticated by the fixed protected broker issuer.
pub struct ProtectedAssignmentSourceInputV1<'authority> {
    assignment: BrokerAssignment,
    revision: u64,
    authentication: ObjectDigest,
    issuer: ProtectedCurrentnessWitnessV1,
    broker: BrokerAssignmentLeaseProofV1<'authority>,
}

/// Carries discovery data authenticated by the fixed protected discovery issuer.
pub struct ProtectedDiscoverySourceInputV1<'authority> {
    project: ProjectId,
    generation: u64,
    services: Vec<DiscoveredProjectServiceV1>,
    authentication: ObjectDigest,
    issuer: ProtectedCurrentnessWitnessV1,
    upstream: DiscoveryPublisherProofV1<'authority>,
}

/// Carries capabilities authenticated by the fixed protected capability issuer.
pub struct ProtectedCapabilitiesSourceInputV1<'authority> {
    features: Vec<FeatureRef>,
    authentication: ObjectDigest,
    issuer: ProtectedCurrentnessWitnessV1,
    upstream: KernelCapabilityProbeProofV1<'authority>,
}

/// Carries an ingress pool authenticated by the fixed protected pool issuer.
pub struct ProtectedIngressPoolSourceInputV1<'authority> {
    node: NodeId,
    address_prefixes: Vec<NetworkIpPrefixV1>,
    port_ranges: Vec<IngressPoolPortRangeV1>,
    maximum_live: u16,
    reuse_delay_generations: u64,
    authentication: ObjectDigest,
    issuer: ProtectedCurrentnessWitnessV1,
    upstream: IngressPoolAuthorityProofV1<'authority>,
}

/// Carries registry and quota genesis authenticated by their fixed issuers.
pub struct ProtectedCombinedNetworkSourceInputV1<'authority> {
    node: NodeId,
    registry_generation: u64,
    rows: Vec<IngressRegistryRowV1>,
    project_limit: AdvancedNetworkQuotaV1,
    node_limit: AdvancedNetworkQuotaV1,
    projects: Vec<ProjectNetworkUsageV1>,
    registry_authentication: ObjectDigest,
    quota_authentication: ObjectDigest,
    registry_issuer: ProtectedCurrentnessWitnessV1,
    quota_issuer: ProtectedCurrentnessWitnessV1,
    ingress_upstream: IngressPoolAuthorityProofV1<'authority>,
    quota_upstream: QuotaAuthorityProofV1<'authority>,
}

/// Owns the fixed protected producers for advanced-policy source projections.
///
/// This dormant issuer authenticates raw control-plane projections before the
/// replacement owner can consume them. It performs no worker or kernel action.
pub struct AdvancedNetworkPolicyProtectedSourceOwnerV1 {
    journal: Option<Journal>,
}

/// Selects the exact terminal mutation for one protected reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedCombinedNetworkOutcomeV1 {
    /// Promotes the candidate and releases predecessor accounting.
    CommitCandidate,
    /// Removes candidate reservations and retains predecessor accounting.
    RollbackCandidate,
}

impl ProtectedCombinedNetworkStateV1 {
    /// Returns the exact protected registry snapshot.
    #[must_use]
    pub const fn registry(&self) -> &ProtectedIngressRegistrySnapshotV1 {
        &self.registry
    }

    /// Returns the exact protected aggregate quota.
    #[must_use]
    pub const fn quota(&self) -> &ProtectedNetworkQuotaV1 {
        &self.quota
    }

    /// Returns the exact atomic registry/quota transaction successor.
    #[must_use]
    pub const fn transaction(&self) -> ProtectedNetworkTransactionV1 {
        self.transaction
    }
}

impl ProtectedIngressRegistrySnapshotV1 {
    /// Returns the exact protected registry value.
    #[must_use]
    pub const fn registry(&self) -> &ExternalIngressRegistryV1 {
        &self.registry
    }

    /// Returns its opaque currentness commitment.
    #[must_use]
    pub const fn currentness(&self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }
}

impl AdvancedNetworkPolicyProtectedAuthoritiesV1 {
    /// Collects opaque currentness handles for one owner operation.
    #[must_use]
    pub fn new(witnesses: Vec<ProtectedCurrentnessWitnessV1>) -> Self {
        Self { witnesses }
    }
}

impl AdvancedNetworkPolicyProtectedSourceOwnerV1 {
    /// Opens the sole fixed protected source-issuer journal.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::ProtectedStorage`] when the
    /// protected journal cannot be opened or fully validated.
    pub fn open() -> Result<Self, AdvancedNetworkPolicyError> {
        let (journal, _) = Journal::open_protected_at(
            FIXED_DIRECTORY,
            SOURCE_ISSUER_JOURNAL_NAME,
            protected_journal_limits(),
        )
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let mut issuer = Self {
            journal: Some(journal),
        };
        let authority = issuer.claim()?;
        validate_issuer_records(&authority)?;
        Ok(issuer)
    }

    /// Authenticates one broker assignment for the fixed replacement owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected source commit is unavailable.
    pub(crate) fn issue_assignment<'authority>(
        &mut self,
        proof: BrokerAssignmentLeaseProofV1<'authority>,
    ) -> Result<ProtectedAssignmentSourceInputV1<'authority>, AdvancedNetworkPolicyError> {
        proof.revalidate_current()?;
        let assignment = proof.assignment();
        let revision = assignment.desired_generation().get();
        let namespace = assignment_namespace(assignment);
        let content = assignment_revision_digest(assignment, revision);
        let authentication = proof.binding();
        let issuer = self.issue(
            ProtectedWitnessPurposeV1::Assignment,
            namespace,
            content,
            authentication,
            proof.issuer_bytes(),
        )?;
        Ok(ProtectedAssignmentSourceInputV1 {
            assignment,
            revision,
            authentication,
            issuer,
            broker: proof,
        })
    }

    /// Authenticates one immutable service-discovery projection.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical data or unavailable protected commit.
    #[allow(dead_code)]
    pub(crate) fn issue_discovery<'authority>(
        &mut self,
        proof: DiscoveryPublisherProofV1<'authority>,
        services: Vec<DiscoveredProjectServiceV1>,
    ) -> Result<ProtectedDiscoverySourceInputV1<'authority>, AdvancedNetworkPolicyError> {
        proof.revalidate_current()?;
        let project = proof.project();
        let generation = proof.generation();
        let content = ProjectServiceDiscoverySnapshotV1::commitment(project, generation, &services);
        let authentication = proof.binding();
        let issuer = self.issue(
            ProtectedWitnessPurposeV1::Discovery,
            project_namespace(project),
            content,
            authentication,
            proof.issuer_bytes(),
        )?;
        Ok(ProtectedDiscoverySourceInputV1 {
            project,
            generation,
            services,
            authentication,
            issuer,
            upstream: proof,
        })
    }

    /// Authenticates the exact supported-feature projection.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical features or unavailable protected commit.
    #[allow(dead_code)]
    pub(crate) fn issue_capabilities<'authority>(
        &mut self,
        proof: KernelCapabilityProbeProofV1<'authority>,
    ) -> Result<ProtectedCapabilitiesSourceInputV1<'authority>, AdvancedNetworkPolicyError> {
        proof.revalidate_current()?;
        let (features, issuer_bytes, authentication) = proof.parts();
        let content = super::ReplacementCapabilitiesV1::commitment(&features);
        let namespace = capabilities_namespace();
        let issuer = self.issue(
            ProtectedWitnessPurposeV1::Capabilities,
            namespace,
            content,
            authentication,
            issuer_bytes,
        )?;
        Ok(ProtectedCapabilitiesSourceInputV1 {
            features,
            authentication,
            issuer,
            upstream: proof,
        })
    }

    /// Authenticates one node ingress-pool projection.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid pool or unavailable protected commit.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(crate) fn issue_ingress_pool<'authority>(
        &mut self,
        proof: IngressPoolAuthorityProofV1<'authority>,
    ) -> Result<ProtectedIngressPoolSourceInputV1<'authority>, AdvancedNetworkPolicyError> {
        proof.revalidate_current()?;
        let (node, address_prefixes, port_ranges, maximum_live, reuse_delay_generations) =
            proof.pool_parts();
        let content = IngressPoolAuthorityV1::commitment(
            node,
            &address_prefixes,
            &port_ranges,
            maximum_live,
            reuse_delay_generations,
        );
        let authentication = proof.binding();
        let issuer = self.issue(
            ProtectedWitnessPurposeV1::IngressPool,
            node_namespace(node),
            content,
            authentication,
            proof.issuer_bytes(),
        )?;
        Ok(ProtectedIngressPoolSourceInputV1 {
            node,
            address_prefixes,
            port_ranges,
            maximum_live,
            reuse_delay_generations,
            authentication,
            issuer,
            upstream: proof,
        })
    }

    /// Atomically authenticates registry and aggregate quota genesis.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical values or unavailable protected commit.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(crate) fn issue_combined_network_state<'authority>(
        &mut self,
        ingress: IngressPoolAuthorityProofV1<'authority>,
        quota: QuotaAuthorityProofV1<'authority>,
    ) -> Result<ProtectedCombinedNetworkSourceInputV1<'authority>, AdvancedNetworkPolicyError> {
        ingress.revalidate_current()?;
        quota.revalidate_current()?;
        let node = ingress.node();
        if quota.node() != node {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let (registry_generation, rows) = ingress.registry_parts();
        let registry_authentication = ingress.binding();
        let ingress_issuer_bytes = ingress.issuer_bytes();
        let quota_authentication = quota.binding();
        let quota_issuer_bytes = quota.issuer_bytes();
        let (project_limit, node_limit, projects) = quota.parts();
        let registry_content =
            ExternalIngressRegistryV1::commitment(node, registry_generation, &rows);
        let quota_content =
            ProtectedNetworkQuotaV1::commitment(project_limit, node_limit, &projects);
        let namespace = node_namespace(node);
        let [registry_issuer, quota_issuer] = self.issue_many([
            (
                ProtectedWitnessPurposeV1::IngressRegistry,
                namespace,
                registry_content,
                registry_authentication,
                ingress_issuer_bytes,
            ),
            (
                ProtectedWitnessPurposeV1::Quota,
                namespace,
                quota_content,
                quota_authentication,
                quota_issuer_bytes,
            ),
        ])?;
        Ok(ProtectedCombinedNetworkSourceInputV1 {
            node,
            registry_generation,
            rows,
            project_limit,
            node_limit,
            projects,
            registry_authentication,
            quota_authentication,
            registry_issuer,
            quota_issuer,
            ingress_upstream: ingress,
            quota_upstream: quota,
        })
    }

    fn issue(
        &mut self,
        purpose: ProtectedWitnessPurposeV1,
        namespace: ObjectDigest,
        content: ObjectDigest,
        authentication: ObjectDigest,
        issuer_bytes: Vec<u8>,
    ) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError> {
        self.issue_many([(purpose, namespace, content, authentication, issuer_bytes)])
            .map(|[value]| value)
    }

    fn issue_many<const N: usize>(
        &mut self,
        inputs: [(
            ProtectedWitnessPurposeV1,
            ObjectDigest,
            ObjectDigest,
            ObjectDigest,
            Vec<u8>,
        ); N],
    ) -> Result<[ProtectedCurrentnessWitnessV1; N], AdvancedNetworkPolicyError> {
        let targets = {
            let authority = self.claim()?;
            inputs
                .into_iter()
                .map(
                    |(purpose, namespace, content, authentication, issuer_bytes)| {
                        prepare_issuer_target(
                            &authority,
                            purpose,
                            namespace,
                            content,
                            authentication,
                            issuer_bytes,
                        )
                    },
                )
                .collect::<Result<Vec<_>, _>>()?
        };
        self.commit_issuer_targets(&targets)?;
        let witnesses = targets
            .into_iter()
            .map(|target| target.witness)
            .collect::<Vec<_>>();
        witnesses
            .try_into()
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
    }

    fn commit_issuer_targets(
        &mut self,
        targets: &[IssuerCommitTargetV1],
    ) -> Result<(), AdvancedNetworkPolicyError> {
        // Retain one exact transaction across every ambiguity readback and the
        // sole bounded retry; never reconstruct it from newly observed state.
        let transaction = issuer_transaction(targets)?;
        let initial_applied = {
            let mut authority = self.claim()?;
            validate_issuer_predecessors(&authority, targets)?;
            authority.commit(&transaction).is_ok()
                && matches!(
                    classify_issuer_targets(&authority, targets),
                    Ok(IssuerCommitRecoveryV1::Applied)
                )
        };
        if initial_applied {
            return Ok(());
        }

        self.reopen_issuer()?;
        match self.classify_current_issuer_targets(targets)? {
            IssuerCommitRecoveryV1::Applied => return Ok(()),
            IssuerCommitRecoveryV1::Diverged => {
                return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
            }
            IssuerCommitRecoveryV1::Retry => {}
        }

        let retry = {
            let mut authority = self.claim()?;
            validate_issuer_predecessors(&authority, targets)?;
            authority.commit(&transaction)
        };
        if retry.is_ok()
            && matches!(
                self.classify_current_issuer_targets(targets),
                Ok(IssuerCommitRecoveryV1::Applied)
            )
        {
            return Ok(());
        }

        self.reopen_issuer()?;
        if self.classify_current_issuer_targets(targets)? == IssuerCommitRecoveryV1::Applied {
            Ok(())
        } else {
            Err(AdvancedNetworkPolicyError::CommitIndeterminate)
        }
    }

    fn classify_current_issuer_targets(
        &mut self,
        targets: &[IssuerCommitTargetV1],
    ) -> Result<IssuerCommitRecoveryV1, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        classify_issuer_targets(&authority, targets)
    }

    fn reopen_issuer(&mut self) -> Result<(), AdvancedNetworkPolicyError> {
        drop(self.journal.take());
        let (journal, _) = Journal::open_protected_at(
            FIXED_DIRECTORY,
            SOURCE_ISSUER_JOURNAL_NAME,
            protected_journal_limits(),
        )
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        self.journal = Some(journal);
        let authority = self.claim()?;
        validate_issuer_records(&authority)
    }

    fn while_current<R>(
        &mut self,
        inputs: &[(
            ProtectedCurrentnessWitnessV1,
            ProtectedWitnessPurposeV1,
            ObjectDigest,
            ObjectDigest,
            ObjectDigest,
        )],
        operation: impl FnOnce() -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        if inputs.is_empty() || inputs.len() > MAXIMUM_AUTHORITIES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }

        let authority = self.claim()?;
        validate_issuer_records(&authority)?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        validate_current_issuer_inputs(&authority, inputs)?;

        let result = operation()?;
        validate_current_issuer_inputs(&authority, inputs)?;
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| AdvancedNetworkPolicyError::StaleAuthority)?;
        Ok(result)
    }

    fn claim(&mut self) -> Result<ProtectedJournalAuthority<'_>, AdvancedNetworkPolicyError> {
        self.journal
            .as_mut()
            .ok_or(AdvancedNetworkPolicyError::ProtectedStorage)?
            .claim_protected_authority(RecordNamespace::DesiredState)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
    }
}

/// Reports one exact durable owner transition.
#[must_use]
pub enum AdvancedNetworkPolicyOwnerCommitV1 {
    /// The transition is durable and exposes no effect authority.
    Durable {
        /// Exact committed reducer phase.
        phase: NetworkPolicyReplacementPhaseV1,
        /// Exact committed reducer generation.
        generation: u64,
    },
}

/// Carries a replayed protected state without worker or kernel authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvancedNetworkPolicyOwnerSnapshotV1 {
    state: NetworkPolicyReplacementStateV1,
    checkpoint: ObjectDigest,
}

impl AdvancedNetworkPolicyOwnerSnapshotV1 {
    /// Returns the complete replayed reducer state.
    #[must_use]
    pub const fn state(&self) -> &NetworkPolicyReplacementStateV1 {
        &self.state
    }

    /// Returns the current protected recovery-checkpoint record digest.
    #[must_use]
    pub const fn checkpoint(&self) -> ObjectDigest {
        self.checkpoint
    }
}

/// Owns the sole fixed protected advanced-policy replacement journal.
pub struct AdvancedNetworkPolicyProtectedOwnerV1 {
    journal: Option<Journal>,
}

impl AdvancedNetworkPolicyProtectedOwnerV1 {
    /// Opens and fully replays the fixed root-owned journal.
    ///
    /// An empty journal is accepted only so [`Self::initialize`] can publish
    /// its first state. Every nonempty journal must contain exactly one
    /// canonical owner envelope.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::ProtectedStorage`] when the fixed
    /// filesystem boundary, journal replay, authority claim, or record shape
    /// is invalid.
    pub fn open() -> Result<Self, AdvancedNetworkPolicyError> {
        let (journal, _) =
            Journal::open_protected_at(FIXED_DIRECTORY, JOURNAL_NAME, protected_journal_limits())
                .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let mut owner = Self {
            journal: Some(journal),
        };
        owner.validate_replay_allowing_empty()?;
        let has_state = {
            let authority = owner.claim()?;
            authority
                .get(STATE_KEY)
                .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
                .is_some()
        };
        if has_state {
            owner.reconcile_recovery_orphan()?;
            let _ = owner.reconcile_combined_sources()?;
        }
        Ok(owner)
    }

    /// Publishes an assignment head and constructs its protected policy revision.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for an invalid revision or when
    /// the fixed source journal cannot commit and read back the exact head.
    pub fn protect_assignment_revision(
        &mut self,
        input: ProtectedAssignmentSourceInputV1<'_>,
        source_owner: &mut AdvancedNetworkPolicyProtectedSourceOwnerV1,
    ) -> Result<NetworkPolicyRevisionV1, AdvancedNetworkPolicyError> {
        input.broker.revalidate_current()?;
        source_owner.while_current(
            &[(
                input.issuer,
                ProtectedWitnessPurposeV1::Assignment,
                assignment_namespace(input.assignment),
                assignment_revision_digest(input.assignment, input.revision),
                input.authentication,
            )],
            || {
                input.broker.revalidate_current()?;
                let mut authority = self.claim()?;
                let witness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::Assignment,
                    assignment_namespace(input.assignment),
                    input.assignment.digest(),
                )?;
                commit_source_updates(&mut authority, &[witness])?;
                NetworkPolicyRevisionV1::new(input.assignment, input.revision, witness)
            },
        )
    }

    /// Publishes and returns one protected immutable discovery snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for a noncanonical snapshot or
    /// unavailable exact source commit/readback.
    pub fn protect_discovery_snapshot(
        &mut self,
        input: ProtectedDiscoverySourceInputV1<'_>,
        source_owner: &mut AdvancedNetworkPolicyProtectedSourceOwnerV1,
    ) -> Result<ProjectServiceDiscoverySnapshotV1, AdvancedNetworkPolicyError> {
        input.upstream.revalidate_current()?;
        let digest = ProjectServiceDiscoverySnapshotV1::commitment(
            input.project,
            input.generation,
            &input.services,
        );
        source_owner.while_current(
            &[(
                input.issuer,
                ProtectedWitnessPurposeV1::Discovery,
                project_namespace(input.project),
                digest,
                input.authentication,
            )],
            || {
                input.upstream.revalidate_current()?;
                let mut authority = self.claim()?;
                let witness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::Discovery,
                    project_namespace(input.project),
                    digest,
                )?;
                commit_source_updates(&mut authority, &[witness])?;
                ProjectServiceDiscoverySnapshotV1::new(
                    input.project,
                    input.generation,
                    input.services,
                    witness,
                )
            },
        )
    }

    /// Publishes and returns one exact protected feature-capability set.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for noncanonical features or
    /// unavailable exact source commit/readback.
    pub fn protect_capabilities(
        &mut self,
        input: ProtectedCapabilitiesSourceInputV1<'_>,
        source_owner: &mut AdvancedNetworkPolicyProtectedSourceOwnerV1,
    ) -> Result<super::ReplacementCapabilitiesV1, AdvancedNetworkPolicyError> {
        input.upstream.revalidate_current()?;
        let digest = super::ReplacementCapabilitiesV1::commitment(&input.features);
        source_owner.while_current(
            &[(
                input.issuer,
                ProtectedWitnessPurposeV1::Capabilities,
                capabilities_namespace(),
                digest,
                input.authentication,
            )],
            || {
                input.upstream.revalidate_current()?;
                let mut authority = self.claim()?;
                let witness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::Capabilities,
                    capabilities_namespace(),
                    digest,
                )?;
                commit_source_updates(&mut authority, &[witness])?;
                super::ReplacementCapabilitiesV1::new(input.features, witness)
            },
        )
    }

    /// Publishes and returns one protected node ingress-pool definition.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for invalid pool shape or an
    /// unavailable exact source commit/readback.
    #[allow(clippy::too_many_arguments)]
    pub fn protect_ingress_pool(
        &mut self,
        input: ProtectedIngressPoolSourceInputV1<'_>,
        source_owner: &mut AdvancedNetworkPolicyProtectedSourceOwnerV1,
    ) -> Result<IngressPoolAuthorityV1, AdvancedNetworkPolicyError> {
        input.upstream.revalidate_current()?;
        let digest = IngressPoolAuthorityV1::commitment(
            input.node,
            &input.address_prefixes,
            &input.port_ranges,
            input.maximum_live,
            input.reuse_delay_generations,
        );
        source_owner.while_current(
            &[(
                input.issuer,
                ProtectedWitnessPurposeV1::IngressPool,
                node_namespace(input.node),
                digest,
                input.authentication,
            )],
            || {
                input.upstream.revalidate_current()?;
                let mut authority = self.claim()?;
                let witness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::IngressPool,
                    node_namespace(input.node),
                    digest,
                )?;
                commit_source_updates(&mut authority, &[witness])?;
                IngressPoolAuthorityV1::new(
                    input.node,
                    input.address_prefixes,
                    input.port_ranges,
                    input.maximum_live,
                    input.reuse_delay_generations,
                    witness,
                )
            },
        )
    }

    /// Authenticates one crate-sealed kernel projection in protected storage.
    ///
    /// The input can only be constructed by the concrete kernel-observer
    /// adapter. Every normalized fact is bound to the boot and physical
    /// allocation before the resulting observation reaches the reducer.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for an invalid projection or an
    /// unavailable exact source commit/readback.
    pub fn protect_kernel_observation(
        &mut self,
        input: ProtectedNetworkObservationInputV1,
    ) -> Result<NetworkReplacementObservationV1, AdvancedNetworkPolicyError> {
        let (namespace, digest) = input.protected_binding();
        let mut authority = self.claim()?;
        let recovery_predecessor = if authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .is_some()
        {
            let current = read_current(&authority)?;
            validate_live_sources(&authority, &current.witnesses)?;
            if current.state.phase() == NetworkPolicyReplacementPhaseV1::RecoveryAuthorized {
                return Err(AdvancedNetworkPolicyError::InvalidTransition);
            } else {
                None
            }
        } else {
            None
        };
        let witness =
            next_kernel_observation_witness(&authority, namespace, digest, recovery_predecessor)?;
        commit_source_updates(&mut authority, &[witness])?;
        input.seal(witness)
    }

    /// Atomically authenticates the recovery fence observation and its reducer edge.
    ///
    /// This is the only recovery-authorized observation seam. The K_n+2
    /// observation source head and `FenceRecovery` envelope share one protected
    /// journal transaction, so no observation authority can escape ahead of the
    /// durable recovery phase.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless recovery is authorized,
    /// the observation exactly succeeds its recovery authority, and commit
    /// readback is exact.
    pub fn fence_recovery_observation(
        &mut self,
        input: ProtectedNetworkObservationInputV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        self.reconcile_recovery_orphan()?;
        let (namespace, digest) = input.protected_binding();
        let mut authority = self.claim()?;
        let current = read_current(&authority)?;
        if current.state.phase() != NetworkPolicyReplacementPhaseV1::RecoveryAuthorized {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        validate_live_sources(&authority, &current.witnesses)?;
        let recovery_predecessor = current
            .witnesses
            .iter()
            .copied()
            .find(|witness| {
                witness.purpose() == ProtectedWitnessPurposeV1::RecoveryAuthority
                    && witness.namespace() == namespace
            })
            .ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let witness = next_kernel_observation_witness(
            &authority,
            namespace,
            digest,
            Some(recovery_predecessor),
        )?;
        validate_source_successors(&authority, &[witness])?;
        let observation = input.seal(witness)?;
        let event = protected_recovery_fence(&current.state, observation)?;
        let next_state = reduce_network_policy_replacement_v1(&current.state, event)?;
        let next_witnesses = protected_currentness_inventory(&next_state);
        validate_exact_successor_authorities(&current.witnesses, &[witness], &next_witnesses)?;
        let envelope =
            OwnerEnvelopeV1::seal(next_state, current.checkpoint, next_witnesses.clone())?;
        let encoded = envelope.encode()?;
        let transaction =
            owner_transaction(&encoded, &current.witnesses, &next_witnesses, &[witness])?;
        if authority.commit(&transaction).is_err()
            && (authority.get(STATE_KEY).ok().flatten() != Some(encoded.as_slice())
                || authority.get(&source_authority_key(witness)).ok().flatten()
                    != Some(witness.encode_recovery().as_slice()))
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        if authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            != Some(encoded.as_slice())
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        let committed = read_current(&authority)?;
        validate_live_sources(&authority, &committed.witnesses)?;
        Ok(AdvancedNetworkPolicyOwnerCommitV1::Durable {
            phase: committed.state.phase(),
            generation: committed.state.generation(),
        })
    }

    /// Atomically publishes registry, quota, and their combined transaction.
    ///
    /// This is the genesis and recovery seam for the cross-domain protected
    /// transaction. All three heads reach one journal commit or none do.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for invalid registry/quota state
    /// or unavailable exact source commit/readback.
    #[allow(clippy::too_many_arguments)]
    pub fn protect_combined_network_state(
        &mut self,
        input: ProtectedCombinedNetworkSourceInputV1<'_>,
        source_owner: &mut AdvancedNetworkPolicyProtectedSourceOwnerV1,
    ) -> Result<ProtectedCombinedNetworkStateV1, AdvancedNetworkPolicyError> {
        input.ingress_upstream.revalidate_current()?;
        input.quota_upstream.revalidate_current()?;
        let registry_digest = ExternalIngressRegistryV1::commitment(
            input.node,
            input.registry_generation,
            &input.rows,
        );
        let quota_digest = ProtectedNetworkQuotaV1::commitment(
            input.project_limit,
            input.node_limit,
            &input.projects,
        );
        source_owner.while_current(
            &[
                (
                    input.registry_issuer,
                    ProtectedWitnessPurposeV1::IngressRegistry,
                    node_namespace(input.node),
                    registry_digest,
                    input.registry_authentication,
                ),
                (
                    input.quota_issuer,
                    ProtectedWitnessPurposeV1::Quota,
                    node_namespace(input.node),
                    quota_digest,
                    input.quota_authentication,
                ),
            ],
            || {
                input.ingress_upstream.revalidate_current()?;
                input.quota_upstream.revalidate_current()?;
                let mut authority = self.claim()?;
                let registry_currentness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::IngressRegistry,
                    node_namespace(input.node),
                    registry_digest,
                )?;
                let quota_currentness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::Quota,
                    node_namespace(input.node),
                    quota_digest,
                )?;
                let registry = ExternalIngressRegistryV1::recover(
                    input.node,
                    input.registry_generation,
                    input.rows,
                    registry_currentness,
                )?;
                let quota = ProtectedNetworkQuotaV1::new(
                    input.project_limit,
                    input.node_limit,
                    input.projects,
                    quota_currentness,
                )?;
                let transaction_digest = ProtectedNetworkTransactionV1::commitment(
                    &registry,
                    registry_currentness,
                    &quota,
                );
                let transaction_currentness = next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::CombinedTransaction,
                    node_namespace(input.node),
                    transaction_digest,
                )?;
                let transaction = ProtectedNetworkTransactionV1::mint(
                    &registry,
                    registry_currentness,
                    &quota,
                    transaction_currentness,
                )?;
                commit_source_updates(
                    &mut authority,
                    &[
                        registry_currentness,
                        quota_currentness,
                        transaction_currentness,
                    ],
                )?;
                Ok(ProtectedCombinedNetworkStateV1 {
                    registry: ProtectedIngressRegistrySnapshotV1 {
                        registry,
                        currentness: registry_currentness,
                    },
                    quota,
                    transaction,
                })
            },
        )
    }

    /// Atomically reserves ingress and quota and issues their combined successor.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for stale source heads,
    /// collision/exhaustion, quota failure, or ambiguous protected commit.
    pub fn protect_combined_reservation(
        &mut self,
        current: &ProtectedCombinedNetworkStateV1,
        predecessor: &CompiledAdvancedNetworkPolicyV1,
        candidate: &CompiledAdvancedNetworkPolicyV1,
        pool: &IngressPoolAuthorityV1,
    ) -> Result<ProtectedCombinedNetworkStateV1, AdvancedNetworkPolicyError> {
        let mut authority = self.claim()?;
        validate_live_sources(
            &authority,
            &[
                current.registry.currentness,
                current.quota.currentness(),
                current.transaction.currentness(),
                pool.currentness(),
            ],
        )?;
        let registry = current.registry.registry.reserve_replacement(
            current.registry.registry.cas(),
            current.registry.currentness,
            predecessor.source().ingress(),
            candidate.source().ingress(),
            pool,
        )?;
        let registry_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::IngressRegistry,
            node_namespace(registry.node()),
            registry.digest(),
        )?;
        let quota = current.quota.reserve_candidate_from_protected_owner(
            candidate.source().identity().project(),
            candidate.usage(),
            |digest| {
                next_source_witness(
                    &authority,
                    ProtectedWitnessPurposeV1::Quota,
                    node_namespace(registry.node()),
                    digest,
                )
            },
        )?;
        let transaction_digest =
            ProtectedNetworkTransactionV1::commitment(&registry, registry_currentness, &quota);
        let transaction_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::CombinedTransaction,
            node_namespace(registry.node()),
            transaction_digest,
        )?;
        let transaction = ProtectedNetworkTransactionV1::mint(
            &registry,
            registry_currentness,
            &quota,
            transaction_currentness,
        )?;
        commit_source_updates(
            &mut authority,
            &[
                registry_currentness,
                quota.currentness(),
                transaction_currentness,
            ],
        )?;
        Ok(ProtectedCombinedNetworkStateV1 {
            registry: ProtectedIngressRegistrySnapshotV1 {
                registry,
                currentness: registry_currentness,
            },
            quota,
            transaction,
        })
    }

    /// Atomically commits or rolls back both sides of one protected reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for stale source heads, an
    /// invalid reservation outcome, or ambiguous protected commit.
    pub fn protect_combined_outcome(
        &mut self,
        current: &ProtectedCombinedNetworkStateV1,
        predecessor: &CompiledAdvancedNetworkPolicyV1,
        candidate: &CompiledAdvancedNetworkPolicyV1,
        pool: &IngressPoolAuthorityV1,
        outcome: ProtectedCombinedNetworkOutcomeV1,
    ) -> Result<ProtectedCombinedNetworkStateV1, AdvancedNetworkPolicyError> {
        let mut authority = self.claim()?;
        validate_live_sources(
            &authority,
            &[
                current.registry.currentness,
                current.quota.currentness(),
                current.transaction.currentness(),
                pool.currentness(),
            ],
        )?;
        let registry = match outcome {
            ProtectedCombinedNetworkOutcomeV1::CommitCandidate => {
                current.registry.registry.commit_replacement(
                    candidate.source().ingress(),
                    pool.reuse_delay_generations(),
                    current.registry.currentness.sequence(),
                )?
            }
            ProtectedCombinedNetworkOutcomeV1::RollbackCandidate => {
                current.registry.registry.rollback_reservation(
                    predecessor.source().ingress(),
                    candidate.source().ingress(),
                )?
            }
        };
        let registry_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::IngressRegistry,
            node_namespace(registry.node()),
            registry.digest(),
        )?;
        let quota = match outcome {
            ProtectedCombinedNetworkOutcomeV1::CommitCandidate => {
                current.quota.commit_replacement_from_protected_owner(
                    candidate.source().identity().project(),
                    predecessor.usage(),
                    candidate.usage(),
                    |digest| {
                        next_source_witness(
                            &authority,
                            ProtectedWitnessPurposeV1::Quota,
                            node_namespace(registry.node()),
                            digest,
                        )
                    },
                )?
            }
            ProtectedCombinedNetworkOutcomeV1::RollbackCandidate => {
                current.quota.rollback_reservation_from_protected_owner(
                    candidate.source().identity().project(),
                    candidate.usage(),
                    |digest| {
                        next_source_witness(
                            &authority,
                            ProtectedWitnessPurposeV1::Quota,
                            node_namespace(registry.node()),
                            digest,
                        )
                    },
                )?
            }
        };
        let transaction_digest =
            ProtectedNetworkTransactionV1::commitment(&registry, registry_currentness, &quota);
        let transaction_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::CombinedTransaction,
            node_namespace(registry.node()),
            transaction_digest,
        )?;
        let transaction = ProtectedNetworkTransactionV1::mint(
            &registry,
            registry_currentness,
            &quota,
            transaction_currentness,
        )?;
        commit_source_updates(
            &mut authority,
            &[
                registry_currentness,
                quota.currentness(),
                transaction_currentness,
            ],
        )?;
        Ok(ProtectedCombinedNetworkStateV1 {
            registry: ProtectedIngressRegistrySnapshotV1 {
                registry,
                currentness: registry_currentness,
            },
            quota,
            transaction,
        })
    }

    /// Publishes the sole initial stable state into an empty fixed journal.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] if the journal is nonempty, the
    /// state cannot be encoded and rebound to every supplied opaque authority,
    /// or durable commit/readback is unavailable or ambiguous.
    pub fn initialize(
        &mut self,
        state: NetworkPolicyReplacementStateV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerSnapshotV1, AdvancedNetworkPolicyError> {
        if state.phase() != NetworkPolicyReplacementPhaseV1::Stable {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        let authority = self.claim()?;
        if authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .is_some()
        {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        let witnesses = normalize_witnesses(authorities.witnesses)?;
        if witnesses != protected_currentness_inventory(&state) {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        validate_live_sources(&authority, &witnesses)?;
        commit_initial(authority, state, witnesses)
    }

    /// Atomically persists a checked reservation and hard-feature decision.
    ///
    /// Unsupported hard features fail in the reducer before any journal write.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless `event` is an exact
    /// `Prepare` transition over current protected state, or storage fails.
    pub fn prepare(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        if !matches!(event, NetworkPolicyReplacementEventV1::Prepare { .. }) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_durable_transition(event, authorities)
    }

    /// Persists the candidate ambiguity boundary and returns its exact handoff.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless `event` is an exact
    /// current `ReleaseEffects` transition and commit/readback remains exact.
    pub fn release_atomic_replace<'broker, R>(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
        broker_currentness: BrokerAssignmentLeaseProofV1<'broker>,
        handoff: impl for<'guard> FnOnce(AdvancedNetworkPolicyWorkerHandoffV1<'guard, 'broker>) -> R,
    ) -> Result<(AdvancedNetworkPolicyOwnerCommitV1, R), AdvancedNetworkPolicyError> {
        if !matches!(
            event,
            NetworkPolicyReplacementEventV1::ReleaseEffects { .. }
        ) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_transition(event, authorities, |authority, committed| {
            validate_live_sources(
                authority,
                &protected_currentness_inventory(&committed.state),
            )?;
            validate_retained_sources(authority, &effect_currentness_inventory(&committed.state)?)?;
            let handoff_value = DurablyCommittedAdvancedNetworkPolicyV1::from_protected_readback(
                committed.state.clone(),
            )?
            .into_worker_handoff(authority, broker_currentness)?;
            Ok(handoff(handoff_value))
        })
    }

    /// Persists one exact typed observation and its resulting closed phase.
    ///
    /// The reducer binds the opaque observation to the exact predecessor,
    /// candidate, allocation, boot, and replacement attempt before commit.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless `event` is an exact
    /// `Observe` transition whose protected authorities survive readback.
    pub fn observe(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        if !matches!(event, NetworkPolicyReplacementEventV1::Observe { .. }) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_durable_transition(event, authorities)
    }

    /// Persists one recovery authorization, fence, or apply preparation.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for another event kind, stale
    /// protected authority, invalid recovery ordering, or storage failure.
    pub fn recover_transition(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        if !matches!(
            event,
            NetworkPolicyReplacementEventV1::AuthorizeRecovery { .. }
                | NetworkPolicyReplacementEventV1::FenceRecovery { .. }
                | NetworkPolicyReplacementEventV1::PrepareRecoveryApply { .. }
        ) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_durable_transition(event, authorities)
    }

    /// Mints and commits the exact recovery authority before advancing state.
    ///
    /// The authority is derived from the protected recovery-required state and
    /// its latest exact observation. No raw authority witness escapes this
    /// owner method.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless current state requires
    /// recovery, `recovery_id` is valid, and both source and state commits have
    /// exact protected readback.
    pub fn authorize_recovery(
        &mut self,
        recovery_id: OperationId,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        self.reconcile_recovery_orphan()?;
        let mut authority = self.claim()?;
        let current = read_current(&authority)?;
        validate_live_sources(&authority, &current.witnesses)?;
        let (namespace, digest, predecessor_sequence, predecessor_head) =
            recovery_authority_binding(&current.state, recovery_id)?;
        let sequence = predecessor_sequence
            .checked_add(1)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let witness = ProtectedCurrentnessWitnessV1::mint(
            ProtectedWitnessPurposeV1::RecoveryAuthority,
            fixed_source_identity(namespace)?,
            sequence,
            predecessor_head,
            digest,
        )?;
        validate_source_successors(&authority, &[witness])?;
        let event = protected_recovery_authorization(&current.state, recovery_id, witness)?;
        let next_state = reduce_network_policy_replacement_v1(&current.state, event)?;
        let next_witnesses = protected_currentness_inventory(&next_state);
        validate_exact_successor_authorities(&current.witnesses, &[witness], &next_witnesses)?;
        let envelope =
            OwnerEnvelopeV1::seal(next_state, current.checkpoint, next_witnesses.clone())?;
        let encoded = envelope.encode()?;
        let transaction =
            owner_transaction(&encoded, &current.witnesses, &next_witnesses, &[witness])?;
        if authority.commit(&transaction).is_err()
            && (authority.get(STATE_KEY).ok().flatten() != Some(encoded.as_slice())
                || authority.get(&source_authority_key(witness)).ok().flatten()
                    != Some(witness.encode_recovery().as_slice()))
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        if authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            != Some(encoded.as_slice())
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        let committed = read_current(&authority)?;
        validate_live_sources(&authority, &[witness])?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        Ok(AdvancedNetworkPolicyOwnerCommitV1::Durable {
            phase: committed.state.phase(),
            generation: committed.state.generation(),
        })
    }

    /// Persists the predecessor-restore ambiguity boundary and returns a handoff.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless `event` is an exact
    /// `ReleaseRecoveryEffects` transition with exact commit/readback.
    pub fn release_recovery<'broker, R>(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
        broker_currentness: BrokerAssignmentLeaseProofV1<'broker>,
        handoff: impl for<'guard> FnOnce(AdvancedNetworkPolicyWorkerHandoffV1<'guard, 'broker>) -> R,
    ) -> Result<(AdvancedNetworkPolicyOwnerCommitV1, R), AdvancedNetworkPolicyError> {
        if !matches!(
            event,
            NetworkPolicyReplacementEventV1::ReleaseRecoveryEffects { .. }
        ) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_transition(event, authorities, |authority, committed| {
            validate_live_sources(
                authority,
                &protected_currentness_inventory(&committed.state),
            )?;
            validate_retained_sources(authority, &effect_currentness_inventory(&committed.state)?)?;
            let handoff_value = DurablyCommittedAdvancedNetworkPolicyV1::from_protected_readback(
                committed.state.clone(),
            )?
            .into_worker_handoff(authority, broker_currentness)?;
            Ok(handoff(handoff_value))
        })
    }

    /// Persists a pre-effect reservation rollback.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless `event` is an exact
    /// `AbortReserved` transition or protected storage fails.
    pub fn rollback_reserved(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        if !matches!(event, NetworkPolicyReplacementEventV1::AbortReserved { .. }) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_durable_transition(event, authorities)
    }

    /// Persists terminal acknowledgement back to stable state.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] unless `event` is an exact
    /// `Settle` transition or protected storage fails.
    pub fn settle(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        if !matches!(event, NetworkPolicyReplacementEventV1::Settle { .. }) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.commit_durable_transition(event, authorities)
    }

    /// Reopens the fixed journal and fully replays its durable prefix.
    ///
    /// Call this after [`AdvancedNetworkPolicyError::CommitIndeterminate`] to
    /// resolve the actual durable phase before attempting another transition.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::ProtectedStorage`] for an empty,
    /// corrupt, noncanonical, or unavailable fixed journal.
    pub fn recover(
        &mut self,
    ) -> Result<AdvancedNetworkPolicyOwnerSnapshotV1, AdvancedNetworkPolicyError> {
        drop(self.journal.take());
        let (journal, _) =
            Journal::open_protected_at(FIXED_DIRECTORY, JOURNAL_NAME, protected_journal_limits())
                .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        self.journal = Some(journal);
        self.reconcile_recovery_orphan()?;
        self.reconcile_combined_sources()
    }

    /// Fully replays and returns the exact current protected state.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::ProtectedStorage`] for missing or
    /// invalid protected state.
    pub fn current(
        &mut self,
    ) -> Result<AdvancedNetworkPolicyOwnerSnapshotV1, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let decoded = read_current(&authority)?;
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        Ok(decoded.snapshot())
    }

    /// Replays the current committed ambiguity boundary into a dormant handoff.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::InvalidTransition`] unless the
    /// durable phase is an effect-release boundary, or protected replay fails.
    pub fn postcommit_handoff<'broker, R>(
        &mut self,
        broker_currentness: BrokerAssignmentLeaseProofV1<'broker>,
        consume: impl for<'guard> FnOnce(AdvancedNetworkPolicyWorkerHandoffV1<'guard, 'broker>) -> R,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let decoded = read_current(&authority)?;
        validate_live_sources(&authority, &protected_currentness_inventory(&decoded.state))?;
        validate_retained_sources(&authority, &effect_currentness_inventory(&decoded.state)?)?;
        let handoff = DurablyCommittedAdvancedNetworkPolicyV1::from_protected_readback(
            decoded.state.clone(),
        )?
        .into_worker_handoff(&authority, broker_currentness)?;
        let result = consume(handoff);
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        Ok(result)
    }

    fn commit_durable_transition(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
    ) -> Result<AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyError> {
        self.commit_transition(event, authorities, |_, _| Ok(()))
            .map(|(outcome, ())| outcome)
    }

    fn commit_transition<R>(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: AdvancedNetworkPolicyProtectedAuthoritiesV1,
        postcommit: impl for<'guard> FnOnce(
            &'guard ProtectedJournalAuthority<'_>,
            &OwnerEnvelopeV1,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<(AdvancedNetworkPolicyOwnerCommitV1, R), AdvancedNetworkPolicyError> {
        let mut authority = self.claim()?;
        let current = read_current(&authority)?;
        let additional = normalize_witnesses(authorities.witnesses)?;
        let mut session = current.witnesses.clone();
        session.extend_from_slice(&additional);
        validate_live_sources(&authority, &normalize_witnesses(session)?)?;
        let next_state = reduce_network_policy_replacement_v1(&current.state, event)?;
        let next_witnesses = protected_currentness_inventory(&next_state);
        validate_exact_successor_authorities(&current.witnesses, &additional, &next_witnesses)?;
        let envelope =
            OwnerEnvelopeV1::seal(next_state, current.checkpoint, next_witnesses.clone())?;
        let encoded = envelope.encode()?;
        let transaction = owner_transaction(&encoded, &current.witnesses, &next_witnesses, &[])?;
        if authority.commit(&transaction).is_err() {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }

        let readback = authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .ok_or(AdvancedNetworkPolicyError::ProtectedStorage)?;
        if readback != encoded {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        let committed = read_current(&authority)?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let outcome = AdvancedNetworkPolicyOwnerCommitV1::Durable {
            phase: committed.state.phase(),
            generation: committed.state.generation(),
        };
        let postcommit_result = postcommit(&authority, &committed)?;
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        Ok((outcome, postcommit_result))
    }

    fn reconcile_combined_sources(
        &mut self,
    ) -> Result<AdvancedNetworkPolicyOwnerSnapshotV1, AdvancedNetworkPolicyError> {
        let mut authority = self.claim()?;
        let current = read_current(&authority)?;
        let (registry, registry_currentness, quota, transaction) =
            combined_state_components(&current.state);
        let expected = [
            registry_currentness,
            quota.currentness(),
            transaction.currentness(),
        ];
        match validate_live_sources(&authority, &expected) {
            Ok(()) => return Ok(current.snapshot()),
            Err(AdvancedNetworkPolicyError::StaleAuthority) => {}
            Err(error) => return Err(error),
        }

        let registry = registry.clone();
        let registry_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::IngressRegistry,
            node_namespace(registry.node()),
            registry.digest(),
        )?;
        let quota_content = ProtectedNetworkQuotaV1::commitment(
            quota.project_limit(),
            quota.node_limit(),
            quota.projects(),
        );
        let quota_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::Quota,
            node_namespace(registry.node()),
            quota_content,
        )?;
        let quota = ProtectedNetworkQuotaV1::new(
            quota.project_limit(),
            quota.node_limit(),
            quota.projects().to_vec(),
            quota_currentness,
        )?;
        let transaction_content =
            ProtectedNetworkTransactionV1::commitment(&registry, registry_currentness, &quota);
        let transaction_currentness = next_source_witness(
            &authority,
            ProtectedWitnessPurposeV1::CombinedTransaction,
            node_namespace(registry.node()),
            transaction_content,
        )?;
        let transaction = ProtectedNetworkTransactionV1::mint(
            &registry,
            registry_currentness,
            &quota,
            transaction_currentness,
        )?;
        let state =
            rebind_combined_state(&current.state, registry_currentness, quota, transaction)?;
        let next_witnesses = protected_currentness_inventory(&state);
        let envelope = OwnerEnvelopeV1::seal(state, current.checkpoint, next_witnesses.clone())?;
        let encoded = envelope.encode()?;
        let source_updates = [
            registry_currentness,
            quota_currentness,
            transaction_currentness,
        ];
        validate_source_successors(&authority, &source_updates)?;
        let transaction = owner_transaction(
            &encoded,
            &current.witnesses,
            &next_witnesses,
            &source_updates,
        )?;
        if authority.commit(&transaction).is_err() {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        if authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            != Some(encoded.as_slice())
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        let readback = read_current(&authority)?;
        validate_live_sources(&authority, &source_updates)?;
        let snapshot = authority
            .snapshot()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        authority
            .validate_snapshot_for_effect(&snapshot)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        Ok(readback.snapshot())
    }

    fn reconcile_recovery_orphan(&mut self) -> Result<(), AdvancedNetworkPolicyError> {
        let mut authority = self.claim()?;
        let current = read_current(&authority)?;
        let phase = current.state.phase();
        if !matches!(
            phase,
            NetworkPolicyReplacementPhaseV1::RecoveryRequired
                | NetworkPolicyReplacementPhaseV1::RecoveryAuthorized
        ) {
            return Ok(());
        }
        let retained = protected_currentness_inventory(&current.state);
        let retained_observation = retained
            .iter()
            .copied()
            .filter(|witness| witness.purpose() == ProtectedWitnessPurposeV1::KernelObservation)
            .max_by_key(|witness| witness.sequence())
            .ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        let live_observation = authority
            .get(&source_authority_key(retained_observation))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .map(ProtectedCurrentnessWitnessV1::decode_protected_record)
            .transpose()?
            .ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        if live_observation != retained_observation {
            let orphan_is_exact = match phase {
                NetworkPolicyReplacementPhaseV1::RecoveryRequired => {
                    live_observation.is_exact_successor_of(retained_observation)
                }
                NetworkPolicyReplacementPhaseV1::RecoveryAuthorized => retained
                    .iter()
                    .copied()
                    .find(|witness| {
                        witness.purpose() == ProtectedWitnessPurposeV1::RecoveryAuthority
                            && witness.namespace() == retained_observation.namespace()
                    })
                    .is_some_and(|recovery| {
                        live_observation.is_exact_journal_successor_of(recovery)
                    }),
                _ => false,
            };
            if !orphan_is_exact
                || authority
                    .get(&source_history_key(live_observation))
                    .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
                    != Some(live_observation.encode_recovery().as_slice())
            {
                return Err(AdvancedNetworkPolicyError::StaleAuthority);
            }
            reactivate_source_head(&mut authority, retained_observation)?;
        }
        validate_live_sources(&authority, &retained)?;
        if phase == NetworkPolicyReplacementPhaseV1::RecoveryAuthorized {
            return Ok(());
        }
        let mut orphan = None;
        for (key, value) in authority
            .records()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        {
            if !key.starts_with(SOURCE_AUTHORITY_PREFIX) {
                continue;
            }
            let witness = ProtectedCurrentnessWitnessV1::decode_protected_record(value)?;
            let exact_observation = retained.iter().any(|observation| {
                observation.purpose() == ProtectedWitnessPurposeV1::KernelObservation
                    && witness.is_exact_journal_successor_of(*observation)
            });
            if witness.purpose() == ProtectedWitnessPurposeV1::RecoveryAuthority
                && exact_observation
            {
                if orphan.replace(witness).is_some() {
                    return Err(AdvancedNetworkPolicyError::NonCanonical);
                }
            }
        }
        let Some(orphan) = orphan else {
            return Ok(());
        };
        let encoded = orphan.encode_recovery();
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&envelope_digest(&encoded).as_bytes()[..16]);
        if transaction_id == [0; 16] {
            transaction_id[15] = 1;
        }
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::delete(
                RecordNamespace::DesiredState,
                source_authority_key(orphan),
            )],
        )
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        if authority.commit(&transaction).is_err()
            && authority
                .get(&source_authority_key(orphan))
                .ok()
                .flatten()
                .is_some()
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        if authority
            .get(&source_authority_key(orphan))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .is_some()
        {
            return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
        }
        Ok(())
    }

    fn validate_replay_allowing_empty(&mut self) -> Result<(), AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        if authority
            .get(STATE_KEY)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .is_none()
        {
            for (key, value) in authority
                .records()
                .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            {
                if !key.starts_with(SOURCE_AUTHORITY_PREFIX)
                    && !key.starts_with(SOURCE_HISTORY_PREFIX)
                {
                    return Err(AdvancedNetworkPolicyError::ProtectedStorage);
                }
                validate_source_record(key, value)?;
            }
            return Ok(());
        }
        let _ = read_current(&authority)?;
        Ok(())
    }

    fn claim(&mut self) -> Result<ProtectedJournalAuthority<'_>, AdvancedNetworkPolicyError> {
        self.journal
            .as_mut()
            .ok_or(AdvancedNetworkPolicyError::ProtectedStorage)?
            .claim_protected_authority(RecordNamespace::DesiredState)
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
    }
}

struct OwnerEnvelopeV1 {
    state: NetworkPolicyReplacementStateV1,
    checkpoint_predecessor: ProtectedCurrentnessWitnessV1,
    checkpoint: ProtectedCurrentnessWitnessV1,
    witnesses: Vec<ProtectedCurrentnessWitnessV1>,
    index: AdvancedNetworkRecoveryRecordV1,
    companions: AdvancedNetworkRecoveryCompanionsV1,
}

impl OwnerEnvelopeV1 {
    fn seal(
        state: NetworkPolicyReplacementStateV1,
        checkpoint_predecessor: ProtectedCurrentnessWitnessV1,
        witnesses: Vec<ProtectedCurrentnessWitnessV1>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let index = AdvancedNetworkRecoveryRecordV1::encode(&state);
        let companions = AdvancedNetworkRecoveryCompanionsV1::seal(state.clone())?;
        let sequence = checkpoint_predecessor
            .sequence()
            .checked_add(1)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let checkpoint = ProtectedCurrentnessWitnessV1::mint(
            ProtectedWitnessPurposeV1::RecoveryCheckpoint,
            fixed_identity()?,
            sequence,
            checkpoint_predecessor.current_head(),
            AdvancedNetworkRecoveryCompanionsV1::checkpoint_commitment(companions.as_bytes()),
        )?;
        let authorities = ProtectedRecoveryAuthoritiesV1::from_protected_owner(
            checkpoint,
            checkpoint_predecessor,
            witnesses.clone(),
        )?;
        let decoded =
            AdvancedNetworkRecoveryCompanionsV1::decode(companions.as_bytes(), &authorities)?;
        if decoded.rehydrate(&index)? != state {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Self {
            state,
            checkpoint_predecessor,
            checkpoint,
            witnesses,
            index,
            companions,
        })
    }

    fn decode(
        bytes: &[u8],
        witnesses: Vec<ProtectedCurrentnessWitnessV1>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() < ENVELOPE_FIXED_BYTES
            || &bytes[..8] != ENVELOPE_MAGIC
            || u16::from_be_bytes(copy_array(&bytes[8..10])?) != ENVELOPE_VERSION
            || bytes[10..12].iter().any(|byte| *byte != 0)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let count = usize::try_from(u32::from_be_bytes(copy_array(&bytes[12..16])?))
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        if count != 0 || witnesses.len() > MAXIMUM_AUTHORITIES {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let expected_sequence = u64::from_be_bytes(copy_array(&bytes[16..24])?);
        let checkpoint_predecessor =
            ProtectedCurrentnessWitnessV1::decode_protected_record(&bytes[24..225])?;
        let checkpoint = ProtectedCurrentnessWitnessV1::decode_protected_record(&bytes[225..426])?;
        let expected_checkpoint = ProtectedCurrentnessWitnessV1::mint(
            ProtectedWitnessPurposeV1::RecoveryCheckpoint,
            fixed_identity()?,
            checkpoint.sequence(),
            checkpoint_predecessor.current_head(),
            checkpoint.record_digest(),
        )?;
        if checkpoint.sequence() != expected_sequence || checkpoint != expected_checkpoint {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let index = AdvancedNetworkRecoveryRecordV1::decode(&bytes[426..802])?;
        let companion_length = usize::try_from(u32::from_be_bytes(copy_array(&bytes[802..806])?))
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let companion_start = 806usize;
        let checksum_start = companion_start
            .checked_add(companion_length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        if companion_length > MAXIMUM_COMPANION_BYTES
            || checksum_start.checked_add(32) != Some(bytes.len())
            || envelope_digest(&bytes[..checksum_start]).as_bytes() != &bytes[checksum_start..]
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let authorities = ProtectedRecoveryAuthoritiesV1::from_protected_owner(
            checkpoint,
            checkpoint_predecessor,
            witnesses.clone(),
        )?;
        let companions = AdvancedNetworkRecoveryCompanionsV1::decode(
            &bytes[companion_start..checksum_start],
            &authorities,
        )?;
        let state = companions.rehydrate(&index)?;
        if witnesses != protected_currentness_inventory(&state) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let envelope = Self {
            state,
            checkpoint_predecessor,
            checkpoint,
            witnesses,
            index,
            companions,
        };
        if envelope.encode()?.as_slice() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(envelope)
    }

    fn encode(&self) -> Result<Vec<u8>, AdvancedNetworkPolicyError> {
        let companion_length = u32::try_from(self.companions.as_bytes().len())
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        let capacity = ENVELOPE_FIXED_BYTES
            .checked_add(self.companions.as_bytes().len())
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(ENVELOPE_MAGIC);
        bytes.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint.sequence().to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_predecessor.encode_recovery());
        bytes.extend_from_slice(&self.checkpoint.encode_recovery());
        bytes.extend_from_slice(self.index.as_bytes());
        bytes.extend_from_slice(&companion_length.to_be_bytes());
        bytes.extend_from_slice(self.companions.as_bytes());
        let checksum = envelope_digest(&bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        Ok(bytes)
    }

    fn snapshot(&self) -> AdvancedNetworkPolicyOwnerSnapshotV1 {
        AdvancedNetworkPolicyOwnerSnapshotV1 {
            state: self.state.clone(),
            checkpoint: self.checkpoint.record_digest(),
        }
    }
}

fn commit_initial(
    mut authority: ProtectedJournalAuthority<'_>,
    state: NetworkPolicyReplacementStateV1,
    witnesses: Vec<ProtectedCurrentnessWitnessV1>,
) -> Result<AdvancedNetworkPolicyOwnerSnapshotV1, AdvancedNetworkPolicyError> {
    let anchor = ProtectedCurrentnessWitnessV1::mint(
        ProtectedWitnessPurposeV1::RecoveryCheckpoint,
        fixed_identity()?,
        1,
        ObjectDigest::from_bytes([0; 32]),
        fixed_anchor_digest(),
    )?;
    let envelope = OwnerEnvelopeV1::seal(state, anchor, witnesses.clone())?;
    let encoded = envelope.encode()?;
    let transaction = owner_transaction(&encoded, &[], &witnesses, &[])?;
    if authority.commit(&transaction).is_err() {
        return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
    }
    let readback = authority
        .get(STATE_KEY)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        .ok_or(AdvancedNetworkPolicyError::ProtectedStorage)?;
    if readback != encoded {
        return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
    }
    let decoded = read_current(&authority)?;
    let snapshot = authority
        .snapshot()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    authority
        .validate_snapshot_for_effect(&snapshot)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    Ok(decoded.snapshot())
}

fn read_current(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<OwnerEnvelopeV1, AdvancedNetworkPolicyError> {
    let records = authority
        .records()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    let mut state = None;
    let mut witnesses = Vec::new();
    for (key, value) in records {
        if key == STATE_KEY {
            if state.replace(value).is_some() {
                return Err(AdvancedNetworkPolicyError::ProtectedStorage);
            }
        } else if key.starts_with(STATE_AUTHORITY_PREFIX) {
            let witness = ProtectedCurrentnessWitnessV1::decode_protected_record(value)?;
            if state_authority_key(witness).as_slice() != key {
                return Err(AdvancedNetworkPolicyError::NonCanonical);
            }
            witnesses.push(witness);
        } else if key.starts_with(SOURCE_AUTHORITY_PREFIX) || key.starts_with(SOURCE_HISTORY_PREFIX)
        {
            validate_source_record(key, value)?;
        } else {
            return Err(AdvancedNetworkPolicyError::ProtectedStorage);
        }
    }
    let witnesses = normalize_witnesses(witnesses)?;
    OwnerEnvelopeV1::decode(
        state.ok_or(AdvancedNetworkPolicyError::ProtectedStorage)?,
        witnesses,
    )
}

fn normalize_witnesses(
    mut witnesses: Vec<ProtectedCurrentnessWitnessV1>,
) -> Result<Vec<ProtectedCurrentnessWitnessV1>, AdvancedNetworkPolicyError> {
    witnesses.sort_unstable_by_key(|witness| witness.encode_recovery());
    witnesses.dedup_by_key(|witness| witness.encode_recovery());
    if witnesses.len() > MAXIMUM_AUTHORITIES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(witnesses)
}

fn validate_exact_successor_authorities(
    current: &[ProtectedCurrentnessWitnessV1],
    additional: &[ProtectedCurrentnessWitnessV1],
    next: &[ProtectedCurrentnessWitnessV1],
) -> Result<(), AdvancedNetworkPolicyError> {
    if additional.iter().any(|witness| !next.contains(witness))
        || next
            .iter()
            .any(|witness| !current.contains(witness) && !additional.contains(witness))
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(())
}

fn validate_live_sources(
    authority: &ProtectedJournalAuthority<'_>,
    witnesses: &[ProtectedCurrentnessWitnessV1],
) -> Result<(), AdvancedNetworkPolicyError> {
    validate_retained_sources(authority, witnesses)?;
    let mut ordered = witnesses.to_vec();
    ordered.sort_unstable_by_key(|witness| (witness.protected_source_key(), witness.sequence()));
    let mut latest = Vec::new();
    for witness in ordered {
        if latest
            .last()
            .is_some_and(|prior: &ProtectedCurrentnessWitnessV1| {
                prior.protected_source_key() == witness.protected_source_key()
            })
        {
            if let Some(prior) = latest.last_mut() {
                *prior = witness;
            }
        } else {
            latest.push(witness);
        }
    }
    for witness in latest {
        let value = authority
            .get(&source_authority_key(witness))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .ok_or(AdvancedNetworkPolicyError::StaleAuthority)?;
        if value != witness.encode_recovery().as_slice() {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
    }
    Ok(())
}

fn validate_retained_sources(
    authority: &ProtectedJournalAuthority<'_>,
    witnesses: &[ProtectedCurrentnessWitnessV1],
) -> Result<(), AdvancedNetworkPolicyError> {
    for witness in witnesses {
        let encoded = witness.encode_recovery();
        let head = authority
            .get(&source_authority_key(*witness))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let history = authority
            .get(&source_history_key(*witness))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        if head != Some(encoded.as_slice()) && history != Some(encoded.as_slice()) {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
    }
    Ok(())
}

fn validate_source_record(key: &[u8], value: &[u8]) -> Result<(), AdvancedNetworkPolicyError> {
    let witness = ProtectedCurrentnessWitnessV1::decode_protected_record(value)?;
    if !witness.belongs_to(fixed_source_identity(witness.namespace())?)
        || (source_authority_key(witness).as_slice() != key
            && source_history_key(witness).as_slice() != key)
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(())
}

fn owner_transaction(
    bytes: &[u8],
    current: &[ProtectedCurrentnessWitnessV1],
    next: &[ProtectedCurrentnessWitnessV1],
    source_updates: &[ProtectedCurrentnessWitnessV1],
) -> Result<JournalTransaction, AdvancedNetworkPolicyError> {
    let digest = envelope_digest(bytes);
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    let mut records = source_updates
        .iter()
        .flat_map(|witness| {
            let encoded = witness.encode_recovery().to_vec();
            [
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    source_authority_key(*witness),
                    encoded.clone(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    source_history_key(*witness),
                    encoded,
                ),
            ]
        })
        .collect::<Vec<_>>();
    records.extend(
        current
            .iter()
            .filter(|witness| !next.contains(witness))
            .map(|witness| {
                JournalRecord::delete(RecordNamespace::DesiredState, state_authority_key(*witness))
            }),
    );
    records.extend(next.iter().map(|witness| {
        JournalRecord::put(
            RecordNamespace::DesiredState,
            state_authority_key(*witness),
            witness.encode_recovery().to_vec(),
        )
    }));
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        STATE_KEY.to_vec(),
        bytes.to_vec(),
    ));
    JournalTransaction::new(transaction_id, records)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
}

fn state_authority_key(witness: ProtectedCurrentnessWitnessV1) -> Vec<u8> {
    let mut key = STATE_AUTHORITY_PREFIX.to_vec();
    key.extend_from_slice(envelope_digest(&witness.encode_recovery()).as_bytes());
    key
}

fn source_authority_key(witness: ProtectedCurrentnessWitnessV1) -> Vec<u8> {
    source_authority_key_for(witness.purpose(), witness.namespace())
}

fn source_history_key(witness: ProtectedCurrentnessWitnessV1) -> Vec<u8> {
    let mut key = SOURCE_HISTORY_PREFIX.to_vec();
    key.extend_from_slice(&witness.protected_source_key());
    key.extend_from_slice(&witness.sequence().to_be_bytes());
    key
}

fn source_authority_key_for(
    purpose: ProtectedWitnessPurposeV1,
    namespace: ObjectDigest,
) -> Vec<u8> {
    let mut key = SOURCE_AUTHORITY_PREFIX.to_vec();
    key.extend_from_slice(&protected_source_key(purpose, namespace));
    key
}

fn next_source_witness(
    authority: &ProtectedJournalAuthority<'_>,
    purpose: ProtectedWitnessPurposeV1,
    namespace: ObjectDigest,
    record_digest: ObjectDigest,
) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError> {
    let prior = authority
        .get(&source_authority_key_for(purpose, namespace))
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        .map(ProtectedCurrentnessWitnessV1::decode_protected_record)
        .transpose()?;
    let (sequence, predecessor_head) = match prior {
        Some(prior) => (
            prior
                .sequence()
                .checked_add(1)
                .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
            prior.current_head(),
        ),
        None => (1, ObjectDigest::from_bytes([0; 32])),
    };
    ProtectedCurrentnessWitnessV1::mint(
        purpose,
        fixed_source_identity(namespace)?,
        sequence,
        predecessor_head,
        record_digest,
    )
}

fn next_kernel_observation_witness(
    authority: &ProtectedJournalAuthority<'_>,
    namespace: ObjectDigest,
    record_digest: ObjectDigest,
    recovery_predecessor: Option<ProtectedCurrentnessWitnessV1>,
) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError> {
    let Some(recovery_predecessor) = recovery_predecessor else {
        return next_source_witness(
            authority,
            ProtectedWitnessPurposeV1::KernelObservation,
            namespace,
            record_digest,
        );
    };
    if recovery_predecessor.purpose() != ProtectedWitnessPurposeV1::RecoveryAuthority
        || recovery_predecessor.namespace() != namespace
        || authority
            .get(&source_authority_key(recovery_predecessor))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            != Some(recovery_predecessor.encode_recovery().as_slice())
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    ProtectedCurrentnessWitnessV1::mint(
        ProtectedWitnessPurposeV1::KernelObservation,
        fixed_source_identity(namespace)?,
        recovery_predecessor
            .sequence()
            .checked_add(1)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
        recovery_predecessor.current_head(),
        record_digest,
    )
}

fn commit_source_updates(
    authority: &mut ProtectedJournalAuthority<'_>,
    witnesses: &[ProtectedCurrentnessWitnessV1],
) -> Result<(), AdvancedNetworkPolicyError> {
    if witnesses.is_empty() || witnesses.len() > MAXIMUM_AUTHORITIES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut ordered = witnesses.to_vec();
    ordered.sort_unstable_by_key(|witness| witness.protected_source_key());
    if ordered
        .windows(2)
        .any(|pair| pair[0].protected_source_key() == pair[1].protected_source_key())
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    validate_source_successors(authority, &ordered)?;
    if ordered.iter().all(|witness| {
        authority
            .get(&source_authority_key(*witness))
            .ok()
            .flatten()
            == Some(witness.encode_recovery().as_slice())
            && authority.get(&source_history_key(*witness)).ok().flatten()
                == Some(witness.encode_recovery().as_slice())
    }) {
        return Ok(());
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.advanced-source-transaction.v1\0");
    let records = ordered
        .iter()
        .flat_map(|witness| {
            let encoded = witness.encode_recovery();
            digest.update(encoded);
            [
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    source_authority_key(*witness),
                    encoded.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    source_history_key(*witness),
                    encoded.to_vec(),
                ),
            ]
        })
        .collect::<Vec<_>>();
    let digest = ObjectDigest::from_bytes(digest.finalize().into());
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    let transaction = JournalTransaction::new(transaction_id, records)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    if authority.commit(&transaction).is_err()
        && witnesses.iter().any(|witness| {
            authority
                .get(&source_authority_key(*witness))
                .ok()
                .flatten()
                != Some(witness.encode_recovery().as_slice())
        })
    {
        return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
    }
    let snapshot = authority
        .snapshot()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    validate_live_sources(authority, &ordered)?;
    authority
        .validate_snapshot_for_effect(&snapshot)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
}

fn reactivate_source_head(
    authority: &mut ProtectedJournalAuthority<'_>,
    witness: ProtectedCurrentnessWitnessV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    if authority
        .get(&source_history_key(witness))
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        != Some(witness.encode_recovery().as_slice())
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    let encoded = witness.encode_recovery();
    let digest = envelope_digest(&encoded);
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            source_authority_key(witness),
            encoded.to_vec(),
        )],
    )
    .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    if authority.commit(&transaction).is_err()
        && authority.get(&source_authority_key(witness)).ok().flatten() != Some(encoded.as_slice())
    {
        return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
    }
    if authority
        .get(&source_authority_key(witness))
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        != Some(encoded.as_slice())
    {
        return Err(AdvancedNetworkPolicyError::CommitIndeterminate);
    }
    Ok(())
}

fn validate_source_successors(
    authority: &ProtectedJournalAuthority<'_>,
    witnesses: &[ProtectedCurrentnessWitnessV1],
) -> Result<(), AdvancedNetworkPolicyError> {
    for witness in witnesses {
        let history = authority
            .get(&source_history_key(*witness))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        if let Some(history) = history {
            if history != witness.encode_recovery().as_slice() {
                return Err(AdvancedNetworkPolicyError::StaleAuthority);
            }
        }
        let prior = authority
            .get(&source_authority_key(*witness))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .map(ProtectedCurrentnessWitnessV1::decode_protected_record)
            .transpose()?;
        if let Some(prior) = prior {
            let exact_replay = prior == *witness;
            let cross_purpose_recovery_successor =
                if witness.purpose() == ProtectedWitnessPurposeV1::KernelObservation {
                    authority
                        .get(&source_authority_key_for(
                            ProtectedWitnessPurposeV1::RecoveryAuthority,
                            witness.namespace(),
                        ))
                        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
                        .map(ProtectedCurrentnessWitnessV1::decode_protected_record)
                        .transpose()?
                        .is_some_and(|recovery| witness.is_exact_journal_successor_of(recovery))
                } else {
                    false
                };
            let valid_successor =
                if witness.purpose() == ProtectedWitnessPurposeV1::RecoveryAuthority {
                    witness.is_later_in_same_journal(prior)
                } else {
                    witness.is_exact_successor_of(prior) || cross_purpose_recovery_successor
                };
            if !exact_replay && !valid_successor {
                return Err(AdvancedNetworkPolicyError::StaleAuthority);
            }
        } else if witness.sequence() != 1
            && witness.purpose() != ProtectedWitnessPurposeV1::RecoveryAuthority
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
    }
    Ok(())
}

fn fixed_identity() -> Result<ProtectedJournalIdentityV1, AdvancedNetworkPolicyError> {
    ProtectedJournalIdentityV1::seal(
        domain_digest(b"aos.sandbox.network.advanced-owner.v1\0"),
        domain_digest(b"aos.sandbox.network.advanced-owner.namespace.v1\0"),
        domain_digest(b"aos.sandbox.network.advanced-owner.journal.v1\0"),
    )
}

fn fixed_source_identity(
    namespace: ObjectDigest,
) -> Result<ProtectedJournalIdentityV1, AdvancedNetworkPolicyError> {
    ProtectedJournalIdentityV1::seal(
        domain_digest(b"aos.sandbox.network.advanced-owner.v1\0"),
        namespace,
        domain_digest(b"aos.sandbox.network.advanced-owner.sources.v1\0"),
    )
}

fn fixed_issuer_identity(
    namespace: ObjectDigest,
) -> Result<ProtectedJournalIdentityV1, AdvancedNetworkPolicyError> {
    ProtectedJournalIdentityV1::seal(
        domain_digest(b"aos.sandbox.network.advanced-source-issuer.v1\0"),
        namespace,
        domain_digest(b"aos.sandbox.network.advanced-source-issuer.journal.v1\0"),
    )
}

fn capabilities_namespace() -> ObjectDigest {
    domain_digest(b"aos.sandbox.network.capabilities.namespace.v1\0")
}

fn assignment_revision_digest(assignment: BrokerAssignment, revision: u64) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.authenticated-assignment-revision.v1\0");
    digest.update(assignment.digest().as_bytes());
    digest.update(revision.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn authenticated_source_digest(
    purpose: ProtectedWitnessPurposeV1,
    namespace: ObjectDigest,
    content: ObjectDigest,
    authentication: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.authenticated-source-audience.v1\0");
    digest.update(protected_source_key(purpose, namespace));
    digest.update(content.as_bytes());
    digest.update(authentication.as_bytes());
    digest.update(domain_digest(b"aos.sandbox.network.advanced-owner.v1\0").as_bytes());
    digest.update(domain_digest(b"aos.sandbox.network.advanced-owner.namespace.v1\0").as_bytes());
    digest.update(domain_digest(b"aos.sandbox.network.advanced-owner.journal.v1\0").as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn issuer_authority_key(purpose: ProtectedWitnessPurposeV1, namespace: ObjectDigest) -> Vec<u8> {
    let mut key = ISSUER_AUTHORITY_PREFIX.to_vec();
    key.extend_from_slice(&protected_source_key(purpose, namespace));
    key
}

fn issuer_history_key(witness: ProtectedCurrentnessWitnessV1) -> Vec<u8> {
    let mut key = ISSUER_HISTORY_PREFIX.to_vec();
    key.extend_from_slice(&witness.protected_source_key());
    key.extend_from_slice(&witness.sequence().to_be_bytes());
    key
}

fn prepare_issuer_target(
    authority: &ProtectedJournalAuthority<'_>,
    purpose: ProtectedWitnessPurposeV1,
    namespace: ObjectDigest,
    content: ObjectDigest,
    authentication: ObjectDigest,
    issuer_bytes: Vec<u8>,
) -> Result<IssuerCommitTargetV1, AdvancedNetworkPolicyError> {
    if authentication.as_bytes() == &[0; 32]
        || issuer_bytes.is_empty()
        || issuer_bytes.len() > MAXIMUM_COMPANION_BYTES
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let prior = authority
        .get(&issuer_authority_key(purpose, namespace))
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        .map(ProtectedCurrentnessWitnessV1::decode_protected_record)
        .transpose()?;
    let (sequence, predecessor) = match prior {
        Some(prior) => (
            prior
                .sequence()
                .checked_add(1)
                .ok_or(AdvancedNetworkPolicyError::NonCanonical)?,
            prior.current_head(),
        ),
        None => (1, ObjectDigest::from_bytes([0; 32])),
    };
    let maximum_sequence =
        u64::try_from(MAXIMUM_AUTHORITIES).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    if sequence > maximum_sequence {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let witness = ProtectedCurrentnessWitnessV1::mint(
        purpose,
        fixed_issuer_identity(namespace)?,
        sequence,
        predecessor,
        authenticated_source_digest(purpose, namespace, content, authentication),
    )?;
    let history = encode_issuer_history(witness, content, authentication, &issuer_bytes)?;
    Ok(IssuerCommitTargetV1 {
        witness,
        predecessor: prior,
        history,
    })
}

fn issuer_transaction(
    targets: &[IssuerCommitTargetV1],
) -> Result<JournalTransaction, AdvancedNetworkPolicyError> {
    if targets.is_empty() || targets.len() > MAXIMUM_AUTHORITIES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let mut records = Vec::with_capacity(targets.len() * 2);
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.source-issuer-transaction.v1\0");
    for target in targets {
        let witness = target.witness;
        let encoded = witness.encode_recovery();
        digest.update(encoded);
        digest.update(&target.history);
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            issuer_authority_key(witness.purpose(), witness.namespace()),
            encoded.to_vec(),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            issuer_history_key(witness),
            target.history.clone(),
        ));
    }
    let digest = ObjectDigest::from_bytes(digest.finalize().into());
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    JournalTransaction::new(transaction_id, records)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
}

fn validate_issuer_predecessors(
    authority: &ProtectedJournalAuthority<'_>,
    targets: &[IssuerCommitTargetV1],
) -> Result<(), AdvancedNetworkPolicyError> {
    if classify_issuer_targets(authority, targets)? != IssuerCommitRecoveryV1::Retry {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(())
}

fn classify_issuer_targets(
    authority: &ProtectedJournalAuthority<'_>,
    targets: &[IssuerCommitTargetV1],
) -> Result<IssuerCommitRecoveryV1, AdvancedNetworkPolicyError> {
    let mut applied = true;
    let mut retry = true;
    for target in targets {
        let witness = target.witness;
        if !witness.belongs_to(fixed_issuer_identity(witness.namespace())?) {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let current = authority
            .get(&issuer_authority_key(
                witness.purpose(),
                witness.namespace(),
            ))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let history = authority
            .get(&issuer_history_key(witness))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        applied &= current == Some(witness.encode_recovery().as_slice())
            && history == Some(target.history.as_slice());
        let predecessor = target
            .predecessor
            .map(ProtectedCurrentnessWitnessV1::encode_recovery);
        retry &= current == predecessor.as_ref().map(<[u8; 201]>::as_slice) && history.is_none();
    }
    Ok(if applied {
        IssuerCommitRecoveryV1::Applied
    } else if retry {
        IssuerCommitRecoveryV1::Retry
    } else {
        IssuerCommitRecoveryV1::Diverged
    })
}

fn encode_issuer_history(
    witness: ProtectedCurrentnessWitnessV1,
    content: ObjectDigest,
    authentication: ObjectDigest,
    issuer_bytes: &[u8],
) -> Result<Vec<u8>, AdvancedNetworkPolicyError> {
    let length =
        u32::try_from(issuer_bytes.len()).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    let mut bytes = Vec::with_capacity(8 + 201 + 32 + 32 + 4 + issuer_bytes.len() + 32);
    bytes.extend_from_slice(ISSUER_HISTORY_MAGIC);
    bytes.extend_from_slice(&witness.encode_recovery());
    bytes.extend_from_slice(content.as_bytes());
    bytes.extend_from_slice(authentication.as_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(issuer_bytes);
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode_issuer_history(
    bytes: &[u8],
) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError> {
    let fixed = 8 + 201 + 32 + 32 + 4 + 32;
    if bytes.len() < fixed || bytes.len() > MAXIMUM_COMPANION_BYTES {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    if bytes.get(..8) != Some(ISSUER_HISTORY_MAGIC) {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let issuer_length = usize::try_from(u32::from_be_bytes(copy_array(&bytes[273..277])?))
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
    let checksum_offset = 277usize
        .checked_add(issuer_length)
        .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
    if checksum_offset.checked_add(32) != Some(bytes.len()) {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes[..checksum_offset]).into();
    if checksum.as_slice() != &bytes[checksum_offset..] {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let witness = ProtectedCurrentnessWitnessV1::decode_protected_record(&bytes[8..209])?;
    let content = ObjectDigest::from_bytes(copy_array(&bytes[209..241])?);
    let authentication = ObjectDigest::from_bytes(copy_array(&bytes[241..273])?);
    if witness.record_digest()
        != authenticated_source_digest(
            witness.purpose(),
            witness.namespace(),
            content,
            authentication,
        )
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(witness)
}

fn validate_issuer_records(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(), AdvancedNetworkPolicyError> {
    let mut heads = BTreeMap::new();
    let mut history = BTreeMap::<[u8; 33], Vec<ProtectedCurrentnessWitnessV1>>::new();
    for (key, value) in authority
        .records()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
    {
        let (witness, expected_key) = if key.starts_with(ISSUER_AUTHORITY_PREFIX) {
            let witness = ProtectedCurrentnessWitnessV1::decode_protected_record(value)?;
            let expected_key = issuer_authority_key(witness.purpose(), witness.namespace());
            heads.insert(witness.protected_source_key(), witness);
            (witness, expected_key)
        } else if key.starts_with(ISSUER_HISTORY_PREFIX) {
            let witness = decode_issuer_history(value)?;
            let expected_key = issuer_history_key(witness);
            history
                .entry(witness.protected_source_key())
                .or_default()
                .push(witness);
            (witness, expected_key)
        } else {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        };
        if !witness.belongs_to(fixed_issuer_identity(witness.namespace())?)
            || key != expected_key.as_slice()
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
    }
    if heads.len() != history.len() {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    for (source, head) in heads {
        let witnesses = history
            .get_mut(&source)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        if witnesses.is_empty()
            || witnesses.len() > MAXIMUM_AUTHORITIES
            || witnesses
                .first()
                .is_none_or(|witness| witness.sequence() != 1)
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        witnesses.sort_unstable();
        if witnesses.last() != Some(&head)
            || witnesses
                .windows(2)
                .any(|pair| !pair[1].is_exact_successor_of(pair[0]))
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
    }
    Ok(())
}

fn validate_current_issuer_inputs(
    authority: &ProtectedJournalAuthority<'_>,
    inputs: &[(
        ProtectedCurrentnessWitnessV1,
        ProtectedWitnessPurposeV1,
        ObjectDigest,
        ObjectDigest,
        ObjectDigest,
    )],
) -> Result<(), AdvancedNetworkPolicyError> {
    for (witness, purpose, namespace, content, authentication) in inputs {
        if witness.purpose() != *purpose
            || witness.namespace() != *namespace
            || !witness.belongs_to(fixed_issuer_identity(*namespace)?)
            || witness.record_digest()
                != authenticated_source_digest(*purpose, *namespace, *content, *authentication)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
    }
    for (witness, purpose, namespace, _, _) in inputs {
        if authority
            .get(&issuer_authority_key(*purpose, *namespace))
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            != Some(witness.encode_recovery().as_slice())
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
    }
    Ok(())
}

fn fixed_anchor_digest() -> ObjectDigest {
    domain_digest(b"aos.sandbox.network.advanced-owner.anchor.v1\0")
}

fn envelope_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.advanced-owner-envelope.v1\0");
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn domain_digest(domain: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(domain).into())
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AdvancedNetworkPolicyError> {
    bytes
        .try_into()
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
}

const fn protected_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 32 * 1024 * 1024,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 16_386,
        maximum_transaction_bytes: 40 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 32 * 1024 * 1024,
        maximum_materialized_records: 16_385,
    }
}
