//! Fixed upstream authority owners for advanced Network policy sources.
//!
//! Non-broker facts become authority only when they exactly match a current
//! record in the compiled-in root-owned journal. The owner retains that journal
//! lock and an opaque snapshot across a consuming closure, so its proof cannot
//! escape or be replaced by caller scalars. Broker proofs borrow an already
//! authenticated Network admission and resample the fixed kernel clock at each
//! consumption boundary.

use aos_sandbox::{
    Journal, JournalLimits, ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
};
use aos_sandbox_broker::{
    BrokerEffectClockDispositionV1, BrokerEffectStatusV1, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    BrokerAssignment, FeatureRef, NodeId, ObjectDigest, ProjectId, RawClockProvenance,
    RawPairedClockSample,
};
use aos_sandbox_linux::boot::KernelBootId;
use sha2::{Digest as _, Sha256};

use super::ingress::{
    ExternalIngressRegistryV1, IngressPoolAuthorityV1, IngressPoolPortRangeV1, IngressRegistryRowV1,
};
use super::quota::{AdvancedNetworkQuotaV1, ProjectNetworkUsageV1, ProtectedNetworkQuotaV1};
use super::service_discovery::{DiscoveredProjectServiceV1, ProjectServiceDiscoverySnapshotV1};
use super::{
    AdvancedNetworkPolicyError, AdvancedNetworkPolicyProtectedOwnerV1,
    AdvancedNetworkPolicyProtectedSourceOwnerV1, AdvancedNetworkPolicyWorkerHandoffV1,
    NetworkPolicyReplacementEventV1, NetworkPolicyRevisionV1, ReplacementCapabilitiesV1,
};
use crate::authorization::NetworkAuthorityV1;
use crate::policy::NetworkIpPrefixV1;

const FIXED_DIRECTORY: &str = "/var/lib/aos/sandbox/network/advanced-policy";
const UPSTREAM_JOURNAL_NAME: &str = "upstream-authorities.journal";
const BROKER_KEY: &[u8] = b"broker-assignment-current-v1";
const DISCOVERY_KEY: &[u8] = b"discovery-publisher-current-v1";
const CAPABILITY_KEY: &[u8] = b"kernel-capability-current-v1";
const INGRESS_KEY: &[u8] = b"ingress-authority-current-v1";
const QUOTA_KEY: &[u8] = b"quota-authority-current-v1";
const RECORD_MAGIC: &[u8; 8] = b"AOSAPUA1";
const RECORD_VERSION: u16 = 1;
const RECORD_BYTES: usize = 244;

const BROKER_PROOF_DOMAIN: &[u8] = b"aos.sandbox.network.assignment-lease-proof.v2\0";
const DISCOVERY_PROOF_DOMAIN: &[u8] = b"aos.sandbox.network.discovery-publisher-proof.v2\0";
const CAPABILITY_PROOF_DOMAIN: &[u8] = b"aos.sandbox.network.kernel-capability-proof.v2\0";
const INGRESS_PROOF_DOMAIN: &[u8] = b"aos.sandbox.network.ingress-authority-proof.v2\0";
const QUOTA_PROOF_DOMAIN: &[u8] = b"aos.sandbox.network.quota-authority-proof.v2\0";

/// Owns the fixed protected current records for non-broker policy sources.
pub struct AdvancedNetworkPolicyUpstreamAuthorityOwnerV1 {
    journal: Option<Journal>,
}

/// Composes the fixed upstream, source, and replacement owners without activation.
///
/// This source-only composition opens protected state and makes the only proof
/// consumption paths constructible. It does not start a listener, worker, or
/// service and contains no kernel mutation capability.
pub struct AdvancedNetworkPolicyAuthorityCompositionV1<'broker> {
    broker_authority: &'broker NetworkAuthorityV1,
    broker_admission: &'broker VerifiedBrokerAdmission,
    upstream: AdvancedNetworkPolicyUpstreamAuthorityOwnerV1,
    source: AdvancedNetworkPolicyProtectedSourceOwnerV1,
    policy: AdvancedNetworkPolicyProtectedOwnerV1,
}

/// Proves a current assignment and lease from the fixed Network broker.
#[must_use]
pub struct BrokerAssignmentLeaseProofV1<'authority> {
    authority: &'authority NetworkAuthorityV1,
    admission: &'authority VerifiedBrokerAdmission,
    protected_current: &'authority ProtectedJournalAuthority<'authority>,
    protected_snapshot: &'authority ProtectedJournalSnapshot,
    protected_record: UpstreamAuthorityRecordV1,
    assignment: BrokerAssignment,
    broker_node: NodeId,
    plan_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    host_boot_id: [u8; 16],
    observed_boottime_nanoseconds: u64,
    fail_stop_boottime_nanoseconds: u64,
    binding: ObjectDigest,
}

/// Proves one exact protected signed project-discovery catalog.
#[must_use]
pub struct DiscoveryPublisherProofV1<'guard> {
    protected_current: &'guard ProtectedJournalAuthority<'guard>,
    protected_snapshot: &'guard ProtectedJournalSnapshot,
    protected_record: UpstreamAuthorityRecordV1,
    project: ProjectId,
    generation: u64,
    publisher_identity: [u8; 16],
    publisher_key_generation: u64,
    signed_catalog_digest: ObjectDigest,
    authority_digest: ObjectDigest,
    binding: ObjectDigest,
}

/// Proves one exact protected live-boot kernel capability projection.
#[must_use]
pub struct KernelCapabilityProbeProofV1<'guard> {
    protected_current: &'guard ProtectedJournalAuthority<'guard>,
    protected_snapshot: &'guard ProtectedJournalSnapshot,
    protected_record: UpstreamAuthorityRecordV1,
    host_boot_id: [u8; 16],
    monotonic_sample_nanoseconds: u64,
    probe_generation: u64,
    authority_generation: u64,
    authority_digest: ObjectDigest,
    features: Vec<FeatureRef>,
    binding: ObjectDigest,
}

/// Proves one exact protected ingress pool and registry projection.
#[must_use]
pub struct IngressPoolAuthorityProofV1<'guard> {
    protected_current: &'guard ProtectedJournalAuthority<'guard>,
    protected_snapshot: &'guard ProtectedJournalSnapshot,
    protected_record: UpstreamAuthorityRecordV1,
    node: NodeId,
    authority_generation: u64,
    authority_digest: ObjectDigest,
    address_prefixes: Vec<NetworkIpPrefixV1>,
    port_ranges: Vec<IngressPoolPortRangeV1>,
    maximum_live: u16,
    reuse_delay_generations: u64,
    registry_generation: u64,
    registry_rows: Vec<IngressRegistryRowV1>,
    binding: ObjectDigest,
}

/// Proves one exact protected aggregate Network quota projection.
#[must_use]
pub struct QuotaAuthorityProofV1<'guard> {
    protected_current: &'guard ProtectedJournalAuthority<'guard>,
    protected_snapshot: &'guard ProtectedJournalSnapshot,
    protected_record: UpstreamAuthorityRecordV1,
    node: NodeId,
    projection_generation: u64,
    authority_generation: u64,
    authority_digest: ObjectDigest,
    project_limit: AdvancedNetworkQuotaV1,
    node_limit: AdvancedNetworkQuotaV1,
    projects: Vec<ProjectNetworkUsageV1>,
    binding: ObjectDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpstreamAuthorityKindV1 {
    Broker,
    Discovery,
    Capability,
    Ingress,
    Quota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UpstreamAuthorityRecordV1 {
    kind: UpstreamAuthorityKindV1,
    record_generation: u64,
    authority_generation: u64,
    subject: [u8; 16],
    issuer: [u8; 16],
    authority_digest: ObjectDigest,
    content_digest: ObjectDigest,
    auxiliary_digest: ObjectDigest,
    host_boot_id: [u8; 16],
    sampled_monotonic_nanoseconds: u64,
    record_digest: ObjectDigest,
}

impl AdvancedNetworkPolicyUpstreamAuthorityOwnerV1 {
    /// Opens the sole fixed protected upstream-authority journal.
    ///
    /// Empty journals are valid dormant provisioning state. Every present row
    /// must use its fixed key and exact closed record format.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::ProtectedStorage`] when protected
    /// open, replay, or complete record validation fails.
    pub fn open() -> Result<Self, AdvancedNetworkPolicyError> {
        let (journal, _) = Journal::open_protected_at(
            FIXED_DIRECTORY,
            UPSTREAM_JOURNAL_NAME,
            upstream_journal_limits(),
        )
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
        let mut owner = Self {
            journal: Some(journal),
        };
        let authority = owner.claim()?;
        validate_upstream_records(&authority)?;
        Ok(owner)
    }

    pub(crate) fn consume_broker<R>(
        &mut self,
        broker_authority: &NetworkAuthorityV1,
        broker_admission: &VerifiedBrokerAdmission,
        consume: impl for<'guard> FnOnce(
            BrokerAssignmentLeaseProofV1<'guard>,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let protected = self.claim()?;
        let snapshot = protected_snapshot(&protected)?;
        let record = current_record(&protected, BROKER_KEY, UpstreamAuthorityKindV1::Broker)?;
        validate_broker_record(record, broker_authority, broker_admission)?;

        let proof = BrokerAssignmentLeaseProofV1::from_owner(
            broker_authority,
            broker_admission,
            &protected,
            &snapshot,
            record,
        )?;
        proof.revalidate_current()?;
        let result = consume(proof)?;
        validate_upstream_snapshot(&protected, &snapshot, BROKER_KEY, record)?;
        validate_broker_current(broker_authority, broker_admission, &protected_clock()?)?;
        Ok(result)
    }

    pub(crate) fn consume_discovery<R>(
        &mut self,
        project: ProjectId,
        generation: u64,
        services: Vec<DiscoveredProjectServiceV1>,
        consume: impl for<'guard> FnOnce(
            DiscoveryPublisherProofV1<'guard>,
            Vec<DiscoveredProjectServiceV1>,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = protected_snapshot(&authority)?;
        let record = current_record(
            &authority,
            DISCOVERY_KEY,
            UpstreamAuthorityKindV1::Discovery,
        )?;
        let catalog_digest =
            ProjectServiceDiscoverySnapshotV1::commitment(project, generation, &services);
        if record.subject != *project.as_bytes()
            || record.record_generation != generation
            || record.content_digest != catalog_digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }

        let proof = bind_discovery_proof(&authority, &snapshot, record, project);
        let result = consume(proof, services)?;
        validate_upstream_snapshot(&authority, &snapshot, DISCOVERY_KEY, record)?;
        Ok(result)
    }

    pub(crate) fn consume_capabilities<R>(
        &mut self,
        features: Vec<FeatureRef>,
        consume: impl for<'guard> FnOnce(
            KernelCapabilityProbeProofV1<'guard>,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = protected_snapshot(&authority)?;
        let record = current_record(
            &authority,
            CAPABILITY_KEY,
            UpstreamAuthorityKindV1::Capability,
        )?;
        if record.content_digest != ReplacementCapabilitiesV1::commitment(&features) {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        validate_live_kernel_record(record)?;

        let proof = bind_capability_proof(&authority, &snapshot, record, features);
        let result = consume(proof)?;
        validate_upstream_snapshot(&authority, &snapshot, CAPABILITY_KEY, record)?;
        validate_live_kernel_record(record)?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_ingress<R>(
        &mut self,
        node: NodeId,
        address_prefixes: Vec<NetworkIpPrefixV1>,
        port_ranges: Vec<IngressPoolPortRangeV1>,
        maximum_live: u16,
        reuse_delay_generations: u64,
        registry_generation: u64,
        registry_rows: Vec<IngressRegistryRowV1>,
        consume: impl for<'guard> FnOnce(
            IngressPoolAuthorityProofV1<'guard>,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = protected_snapshot(&authority)?;
        let record = current_record(&authority, INGRESS_KEY, UpstreamAuthorityKindV1::Ingress)?;
        let pool_digest = IngressPoolAuthorityV1::commitment(
            node,
            &address_prefixes,
            &port_ranges,
            maximum_live,
            reuse_delay_generations,
        );
        let registry_digest =
            ExternalIngressRegistryV1::commitment(node, registry_generation, &registry_rows);
        if record.subject != *node.as_bytes()
            || record.record_generation != registry_generation
            || record.content_digest != pool_digest
            || record.auxiliary_digest != registry_digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }

        let proof = bind_ingress_proof(
            &authority,
            &snapshot,
            record,
            node,
            address_prefixes,
            port_ranges,
            maximum_live,
            reuse_delay_generations,
            registry_generation,
            registry_rows,
        );
        let result = consume(proof)?;
        validate_upstream_snapshot(&authority, &snapshot, INGRESS_KEY, record)?;
        Ok(result)
    }

    pub(crate) fn consume_quota<R>(
        &mut self,
        node: NodeId,
        project_limit: AdvancedNetworkQuotaV1,
        node_limit: AdvancedNetworkQuotaV1,
        projects: Vec<ProjectNetworkUsageV1>,
        consume: impl for<'guard> FnOnce(
            QuotaAuthorityProofV1<'guard>,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = protected_snapshot(&authority)?;
        let record = current_record(&authority, QUOTA_KEY, UpstreamAuthorityKindV1::Quota)?;
        let quota_digest =
            ProtectedNetworkQuotaV1::commitment(project_limit, node_limit, &projects);
        if record.subject != *node.as_bytes() || record.content_digest != quota_digest {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }

        let proof = bind_quota_proof(
            &authority,
            &snapshot,
            record,
            node,
            project_limit,
            node_limit,
            projects,
        );
        let result = consume(proof)?;
        validate_upstream_snapshot(&authority, &snapshot, QUOTA_KEY, record)?;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_combined_network_state<R>(
        &mut self,
        node: NodeId,
        address_prefixes: Vec<NetworkIpPrefixV1>,
        port_ranges: Vec<IngressPoolPortRangeV1>,
        maximum_live: u16,
        reuse_delay_generations: u64,
        registry_generation: u64,
        registry_rows: Vec<IngressRegistryRowV1>,
        project_limit: AdvancedNetworkQuotaV1,
        node_limit: AdvancedNetworkQuotaV1,
        projects: Vec<ProjectNetworkUsageV1>,
        consume: impl for<'guard> FnOnce(
            IngressPoolAuthorityProofV1<'guard>,
            QuotaAuthorityProofV1<'guard>,
        ) -> Result<R, AdvancedNetworkPolicyError>,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let authority = self.claim()?;
        let snapshot = protected_snapshot(&authority)?;
        let ingress_record =
            current_record(&authority, INGRESS_KEY, UpstreamAuthorityKindV1::Ingress)?;
        let quota_record = current_record(&authority, QUOTA_KEY, UpstreamAuthorityKindV1::Quota)?;
        let pool_digest = IngressPoolAuthorityV1::commitment(
            node,
            &address_prefixes,
            &port_ranges,
            maximum_live,
            reuse_delay_generations,
        );
        let registry_digest =
            ExternalIngressRegistryV1::commitment(node, registry_generation, &registry_rows);
        let quota_digest =
            ProtectedNetworkQuotaV1::commitment(project_limit, node_limit, &projects);
        if ingress_record.subject != *node.as_bytes()
            || ingress_record.record_generation != registry_generation
            || ingress_record.content_digest != pool_digest
            || ingress_record.auxiliary_digest != registry_digest
            || quota_record.subject != *node.as_bytes()
            || quota_record.content_digest != quota_digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }

        let ingress = bind_ingress_proof(
            &authority,
            &snapshot,
            ingress_record,
            node,
            address_prefixes,
            port_ranges,
            maximum_live,
            reuse_delay_generations,
            registry_generation,
            registry_rows,
        );
        let quota = bind_quota_proof(
            &authority,
            &snapshot,
            quota_record,
            node,
            project_limit,
            node_limit,
            projects,
        );
        let result = consume(ingress, quota)?;
        validate_upstream_snapshot(&authority, &snapshot, INGRESS_KEY, ingress_record)?;
        validate_upstream_snapshot(&authority, &snapshot, QUOTA_KEY, quota_record)?;
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

impl<'broker> AdvancedNetworkPolicyAuthorityCompositionV1<'broker> {
    /// Opens every fixed protected owner used by the dormant policy path.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] when any protected journal is
    /// unavailable, corrupt, or not in an exactly recoverable state.
    pub fn open(
        authority: &'broker NetworkAuthorityV1,
        admission: &'broker VerifiedBrokerAdmission,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        Ok(Self {
            broker_authority: authority,
            broker_admission: admission,
            upstream: AdvancedNetworkPolicyUpstreamAuthorityOwnerV1::open()?,
            source: AdvancedNetworkPolicyProtectedSourceOwnerV1::open()?,
            policy: AdvancedNetworkPolicyProtectedOwnerV1::open()?,
        })
    }

    /// Publishes the current broker assignment through both protected owners.
    ///
    /// # Errors
    ///
    /// Returns an error unless the authenticated broker assignment remains
    /// current through the final protected policy-source CAS.
    pub fn protect_current_assignment(
        &mut self,
    ) -> Result<NetworkPolicyRevisionV1, AdvancedNetworkPolicyError> {
        let source = &mut self.source;
        let policy = &mut self.policy;
        self.upstream
            .consume_broker(self.broker_authority, self.broker_admission, |proof| {
                let input = source.issue_assignment(proof)?;
                policy.protect_assignment_revision(input, source)
            })
    }

    /// Converts one owner-matched discovery projection into protected state.
    ///
    /// # Errors
    ///
    /// Returns an error when the projection is not the exact current signed
    /// catalog or either protected commit cannot be read back exactly.
    pub fn protect_discovery(
        &mut self,
        project: ProjectId,
        generation: u64,
        services: Vec<DiscoveredProjectServiceV1>,
    ) -> Result<ProjectServiceDiscoverySnapshotV1, AdvancedNetworkPolicyError> {
        let source = &mut self.source;
        let policy = &mut self.policy;
        self.upstream
            .consume_discovery(project, generation, services, |proof, services| {
                let input = source.issue_discovery(proof, services)?;
                policy.protect_discovery_snapshot(input, source)
            })
    }

    /// Converts one live owner-matched capability projection into protected state.
    ///
    /// # Errors
    ///
    /// Returns an error after boot rollover, monotonic rollback, projection
    /// mismatch, or an inexact protected commit.
    pub fn protect_capabilities(
        &mut self,
        features: Vec<FeatureRef>,
    ) -> Result<ReplacementCapabilitiesV1, AdvancedNetworkPolicyError> {
        let source = &mut self.source;
        let policy = &mut self.policy;
        self.upstream.consume_capabilities(features, |proof| {
            let input = source.issue_capabilities(proof)?;
            policy.protect_capabilities(input, source)
        })
    }

    /// Converts one owner-matched ingress projection into protected state.
    ///
    /// # Errors
    ///
    /// Returns an error unless pool and registry inputs match the same current
    /// fixed-authority record through protected consumption.
    #[allow(clippy::too_many_arguments)]
    pub fn protect_ingress_pool(
        &mut self,
        node: NodeId,
        address_prefixes: Vec<NetworkIpPrefixV1>,
        port_ranges: Vec<IngressPoolPortRangeV1>,
        maximum_live: u16,
        reuse_delay_generations: u64,
        registry_generation: u64,
        registry_rows: Vec<IngressRegistryRowV1>,
    ) -> Result<IngressPoolAuthorityV1, AdvancedNetworkPolicyError> {
        let source = &mut self.source;
        let policy = &mut self.policy;
        self.upstream.consume_ingress(
            node,
            address_prefixes,
            port_ranges,
            maximum_live,
            reuse_delay_generations,
            registry_generation,
            registry_rows,
            |proof| {
                let input = source.issue_ingress_pool(proof)?;
                policy.protect_ingress_pool(input, source)
            },
        )
    }

    /// Converts matched ingress and quota authority heads atomically.
    ///
    /// # Errors
    ///
    /// Returns an error unless both projections are current under one retained
    /// protected upstream snapshot and both downstream commits are exact.
    #[allow(clippy::too_many_arguments)]
    pub fn protect_combined_network_state(
        &mut self,
        node: NodeId,
        address_prefixes: Vec<NetworkIpPrefixV1>,
        port_ranges: Vec<IngressPoolPortRangeV1>,
        maximum_live: u16,
        reuse_delay_generations: u64,
        registry_generation: u64,
        registry_rows: Vec<IngressRegistryRowV1>,
        project_limit: AdvancedNetworkQuotaV1,
        node_limit: AdvancedNetworkQuotaV1,
        projects: Vec<ProjectNetworkUsageV1>,
    ) -> Result<super::ProtectedCombinedNetworkStateV1, AdvancedNetworkPolicyError> {
        let source = &mut self.source;
        let policy = &mut self.policy;
        self.upstream.consume_combined_network_state(
            node,
            address_prefixes,
            port_ranges,
            maximum_live,
            reuse_delay_generations,
            registry_generation,
            registry_rows,
            project_limit,
            node_limit,
            projects,
            |ingress, quota| {
                let input = source.issue_combined_network_state(ingress, quota)?;
                policy.protect_combined_network_state(input, source)
            },
        )
    }

    /// Releases a durable candidate handoff under a current broker lease.
    ///
    /// # Errors
    ///
    /// Returns an error unless the reducer transition, protected authorities,
    /// broker assignment, lease, boot, and BOOTTIME sample are all current.
    pub fn release_atomic_replace<R>(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: super::AdvancedNetworkPolicyProtectedAuthoritiesV1,
        handoff: impl for<'owner, 'current> FnOnce(
            AdvancedNetworkPolicyWorkerHandoffV1<'owner, 'current>,
        ) -> R,
    ) -> Result<(super::AdvancedNetworkPolicyOwnerCommitV1, R), AdvancedNetworkPolicyError> {
        let policy = &mut self.policy;
        self.upstream
            .consume_broker(self.broker_authority, self.broker_admission, |proof| {
                policy.release_atomic_replace(event, authorities, proof, handoff)
            })
    }

    /// Releases a durable predecessor-restore handoff under a current broker lease.
    ///
    /// # Errors
    ///
    /// Returns an error unless the recovery transition and broker currentness
    /// remain exact through handoff construction.
    pub fn release_recovery<R>(
        &mut self,
        event: NetworkPolicyReplacementEventV1,
        authorities: super::AdvancedNetworkPolicyProtectedAuthoritiesV1,
        handoff: impl for<'owner, 'current> FnOnce(
            AdvancedNetworkPolicyWorkerHandoffV1<'owner, 'current>,
        ) -> R,
    ) -> Result<(super::AdvancedNetworkPolicyOwnerCommitV1, R), AdvancedNetworkPolicyError> {
        let policy = &mut self.policy;
        self.upstream
            .consume_broker(self.broker_authority, self.broker_admission, |proof| {
                policy.release_recovery(event, authorities, proof, handoff)
            })
    }

    /// Replays a durable effect boundary under a current broker lease.
    ///
    /// # Errors
    ///
    /// Returns an error unless protected replay and broker currentness remain
    /// exact through handoff construction.
    pub fn postcommit_handoff<R>(
        &mut self,
        consume: impl for<'owner, 'current> FnOnce(
            AdvancedNetworkPolicyWorkerHandoffV1<'owner, 'current>,
        ) -> R,
    ) -> Result<R, AdvancedNetworkPolicyError> {
        let policy = &mut self.policy;
        self.upstream
            .consume_broker(self.broker_authority, self.broker_admission, |proof| {
                policy.postcommit_handoff(proof, consume)
            })
    }
}

impl<'authority> BrokerAssignmentLeaseProofV1<'authority> {
    fn from_owner(
        authority: &'authority NetworkAuthorityV1,
        admission: &'authority VerifiedBrokerAdmission,
        protected_current: &'authority ProtectedJournalAuthority<'authority>,
        protected_snapshot: &'authority ProtectedJournalSnapshot,
        protected_record: UpstreamAuthorityRecordV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let clock = protected_clock()?;
        validate_broker_current(authority, admission, &clock)?;
        validate_broker_record(protected_record, authority, admission)?;
        let assignment = admission.fence.assignment();
        let local_lease = admission.fence.local_lease_record();
        let mut proof = Self {
            authority,
            admission,
            protected_current,
            protected_snapshot,
            protected_record,
            assignment,
            broker_node: admission.fence.node(),
            plan_digest: admission.fence.plan_digest(),
            lease_generation: local_lease.lease_generation(),
            lease_digest: local_lease.lease_digest(),
            host_boot_id: *local_lease.host_boot_id(),
            observed_boottime_nanoseconds: clock.boottime_nanoseconds(),
            fail_stop_boottime_nanoseconds: local_lease.fail_stop_boottime_nanoseconds(),
            binding: ObjectDigest::from_bytes([0; 32]),
        };
        proof.binding = digest_with_domain(BROKER_PROOF_DOMAIN, &proof.issuer_bytes());
        Ok(proof)
    }

    pub(crate) fn revalidate_current(&self) -> Result<(), AdvancedNetworkPolicyError> {
        let clock = protected_clock()?;
        validate_broker_current(self.authority, self.admission, &clock)?;
        validate_upstream_snapshot(
            self.protected_current,
            self.protected_snapshot,
            BROKER_KEY,
            self.protected_record,
        )?;
        validate_broker_record(self.protected_record, self.authority, self.admission)?;
        let local_lease = self.admission.fence.local_lease_record();
        if self.assignment != self.admission.fence.assignment()
            || self.broker_node != self.admission.fence.node()
            || self.plan_digest != self.admission.fence.plan_digest()
            || self.lease_generation != local_lease.lease_generation()
            || self.lease_digest != local_lease.lease_digest()
            || self.host_boot_id != *local_lease.host_boot_id()
            || self.fail_stop_boottime_nanoseconds != local_lease.fail_stop_boottime_nanoseconds()
            || clock.host_boot_id() != self.host_boot_id
            || clock.boottime_nanoseconds() < self.observed_boottime_nanoseconds
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        Ok(())
    }

    /// Returns the authenticated assignment.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the broker node.
    #[must_use]
    pub const fn broker_node(&self) -> NodeId {
        self.broker_node
    }

    /// Returns the authenticated broker-plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the current ownership-lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the current signed lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the retained host boot identity.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        &self.host_boot_id
    }

    /// Returns the BOOTTIME sample observed at proof creation.
    #[must_use]
    pub const fn observed_boottime_nanoseconds(&self) -> u64 {
        self.observed_boottime_nanoseconds
    }

    /// Returns the exclusive fail-stop deadline.
    #[must_use]
    pub const fn fail_stop_boottime_nanoseconds(&self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }

    pub(crate) const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    pub(crate) fn issuer_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(184);
        bytes.extend_from_slice(self.broker_node.as_bytes());
        bytes.extend_from_slice(self.assignment.sandbox().as_bytes());
        bytes.extend_from_slice(self.assignment.incarnation().as_bytes());
        bytes.extend_from_slice(&self.assignment.epoch().get().to_be_bytes());
        bytes.extend_from_slice(&self.assignment.desired_generation().get().to_be_bytes());
        bytes.extend_from_slice(self.assignment.digest().as_bytes());
        bytes.extend_from_slice(self.plan_digest.as_bytes());
        bytes.extend_from_slice(&self.lease_generation.to_be_bytes());
        bytes.extend_from_slice(self.lease_digest.as_bytes());
        bytes.extend_from_slice(&self.host_boot_id);
        bytes.extend_from_slice(&self.observed_boottime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(&self.fail_stop_boottime_nanoseconds.to_be_bytes());
        bytes
    }
}

impl DiscoveryPublisherProofV1<'_> {
    pub(crate) fn revalidate_current(&self) -> Result<(), AdvancedNetworkPolicyError> {
        validate_upstream_snapshot(
            self.protected_current,
            self.protected_snapshot,
            DISCOVERY_KEY,
            self.protected_record,
        )
    }

    /// Returns the authenticated project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the fixed publisher identity.
    #[must_use]
    pub const fn publisher_identity(&self) -> &[u8; 16] {
        &self.publisher_identity
    }

    /// Returns the publisher signing-key generation.
    #[must_use]
    pub const fn publisher_key_generation(&self) -> u64 {
        self.publisher_key_generation
    }

    /// Returns the signed catalog digest.
    #[must_use]
    pub const fn signed_catalog_digest(&self) -> ObjectDigest {
        self.signed_catalog_digest
    }

    /// Returns the protected publisher-authority commitment.
    #[must_use]
    pub const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    pub(crate) const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    pub(crate) fn issuer_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.publisher_identity);
        bytes.extend_from_slice(&self.publisher_key_generation.to_be_bytes());
        bytes.extend_from_slice(self.signed_catalog_digest.as_bytes());
        bytes.extend_from_slice(self.authority_digest.as_bytes());
        bytes
    }
}

impl KernelCapabilityProbeProofV1<'_> {
    pub(crate) fn revalidate_current(&self) -> Result<(), AdvancedNetworkPolicyError> {
        validate_upstream_snapshot(
            self.protected_current,
            self.protected_snapshot,
            CAPABILITY_KEY,
            self.protected_record,
        )?;
        validate_live_kernel_record(self.protected_record)
    }

    /// Returns the live boot observed by the probe.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        &self.host_boot_id
    }

    /// Returns the monotonic sample paired with the probe.
    #[must_use]
    pub const fn monotonic_sample_nanoseconds(&self) -> u64 {
        self.monotonic_sample_nanoseconds
    }

    /// Returns the protected probe generation.
    #[must_use]
    pub const fn probe_generation(&self) -> u64 {
        self.probe_generation
    }

    /// Returns the protected probe-authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    /// Returns the protected kernel-probe authority commitment.
    #[must_use]
    pub const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    /// Returns the exact supported-feature projection.
    #[must_use]
    pub fn features(&self) -> &[FeatureRef] {
        &self.features
    }

    pub(crate) fn parts(&self) -> (Vec<FeatureRef>, Vec<u8>, ObjectDigest) {
        let bytes = capability_proof_bytes(&self);
        (self.features.clone(), bytes, self.binding)
    }
}

impl IngressPoolAuthorityProofV1<'_> {
    pub(crate) fn revalidate_current(&self) -> Result<(), AdvancedNetworkPolicyError> {
        validate_upstream_snapshot(
            self.protected_current,
            self.protected_snapshot,
            INGRESS_KEY,
            self.protected_record,
        )
    }

    /// Returns the governed node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the ingress-authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    /// Returns the authenticated authority digest.
    #[must_use]
    pub const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    /// Returns the authenticated address prefixes.
    #[must_use]
    pub fn address_prefixes(&self) -> &[NetworkIpPrefixV1] {
        &self.address_prefixes
    }

    /// Returns the authenticated port ranges.
    #[must_use]
    pub fn port_ranges(&self) -> &[IngressPoolPortRangeV1] {
        &self.port_ranges
    }

    /// Returns the maximum live ingress rows.
    #[must_use]
    pub const fn maximum_live(&self) -> u16 {
        self.maximum_live
    }

    /// Returns the protected-generation reuse delay.
    #[must_use]
    pub const fn reuse_delay_generations(&self) -> u64 {
        self.reuse_delay_generations
    }

    /// Returns the authenticated registry generation.
    #[must_use]
    pub const fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    /// Returns the authenticated registry rows.
    #[must_use]
    pub fn registry_rows(&self) -> &[IngressRegistryRowV1] {
        &self.registry_rows
    }

    pub(crate) const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    pub(crate) fn issuer_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.node.as_bytes());
        bytes.extend_from_slice(&self.authority_generation.to_be_bytes());
        bytes.extend_from_slice(self.authority_digest.as_bytes());
        bytes.extend_from_slice(&self.registry_generation.to_be_bytes());
        bytes
    }

    pub(crate) fn pool_parts(
        &self,
    ) -> (
        NodeId,
        Vec<NetworkIpPrefixV1>,
        Vec<IngressPoolPortRangeV1>,
        u16,
        u64,
    ) {
        (
            self.node,
            self.address_prefixes.clone(),
            self.port_ranges.clone(),
            self.maximum_live,
            self.reuse_delay_generations,
        )
    }

    pub(crate) fn registry_parts(&self) -> (u64, Vec<IngressRegistryRowV1>) {
        (self.registry_generation, self.registry_rows.clone())
    }
}

impl QuotaAuthorityProofV1<'_> {
    pub(crate) fn revalidate_current(&self) -> Result<(), AdvancedNetworkPolicyError> {
        validate_upstream_snapshot(
            self.protected_current,
            self.protected_snapshot,
            QUOTA_KEY,
            self.protected_record,
        )
    }

    /// Returns the governed node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the protected quota projection generation.
    #[must_use]
    pub const fn projection_generation(&self) -> u64 {
        self.projection_generation
    }

    /// Returns the quota-authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    /// Returns the authenticated authority digest.
    #[must_use]
    pub const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    /// Returns the exact per-project ceiling.
    #[must_use]
    pub const fn project_limit(&self) -> AdvancedNetworkQuotaV1 {
        self.project_limit
    }

    /// Returns the exact node-wide ceiling.
    #[must_use]
    pub const fn node_limit(&self) -> AdvancedNetworkQuotaV1 {
        self.node_limit
    }

    /// Returns the exact project-account projection.
    #[must_use]
    pub fn projects(&self) -> &[ProjectNetworkUsageV1] {
        &self.projects
    }

    pub(crate) const fn binding(&self) -> ObjectDigest {
        self.binding
    }

    pub(crate) fn issuer_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.node.as_bytes());
        bytes.extend_from_slice(&self.projection_generation.to_be_bytes());
        bytes.extend_from_slice(&self.authority_generation.to_be_bytes());
        bytes.extend_from_slice(self.authority_digest.as_bytes());
        bytes
    }

    pub(crate) fn parts(
        &self,
    ) -> (
        AdvancedNetworkQuotaV1,
        AdvancedNetworkQuotaV1,
        Vec<ProjectNetworkUsageV1>,
    ) {
        (self.project_limit, self.node_limit, self.projects.clone())
    }
}

fn bind_discovery_proof<'guard, 'journal: 'guard>(
    authority: &'guard ProtectedJournalAuthority<'journal>,
    snapshot: &'guard ProtectedJournalSnapshot,
    record: UpstreamAuthorityRecordV1,
    project: ProjectId,
) -> DiscoveryPublisherProofV1<'guard> {
    let mut proof = DiscoveryPublisherProofV1 {
        protected_current: authority,
        protected_snapshot: snapshot,
        protected_record: record,
        project,
        generation: record.record_generation,
        publisher_identity: record.issuer,
        publisher_key_generation: record.authority_generation,
        signed_catalog_digest: record.content_digest,
        authority_digest: record.authority_digest,
        binding: ObjectDigest::from_bytes([0; 32]),
    };
    proof.binding = digest_with_domain(DISCOVERY_PROOF_DOMAIN, &proof.issuer_bytes());
    proof
}

fn bind_capability_proof<'guard, 'journal: 'guard>(
    authority: &'guard ProtectedJournalAuthority<'journal>,
    snapshot: &'guard ProtectedJournalSnapshot,
    record: UpstreamAuthorityRecordV1,
    features: Vec<FeatureRef>,
) -> KernelCapabilityProbeProofV1<'guard> {
    let mut proof = KernelCapabilityProbeProofV1 {
        protected_current: authority,
        protected_snapshot: snapshot,
        protected_record: record,
        host_boot_id: record.host_boot_id,
        monotonic_sample_nanoseconds: record.sampled_monotonic_nanoseconds,
        probe_generation: record.record_generation,
        authority_generation: record.authority_generation,
        authority_digest: record.authority_digest,
        features,
        binding: ObjectDigest::from_bytes([0; 32]),
    };
    proof.binding = digest_with_domain(CAPABILITY_PROOF_DOMAIN, &capability_proof_bytes(&proof));
    proof
}

#[allow(clippy::too_many_arguments)]
fn bind_ingress_proof<'guard, 'journal: 'guard>(
    authority: &'guard ProtectedJournalAuthority<'journal>,
    snapshot: &'guard ProtectedJournalSnapshot,
    record: UpstreamAuthorityRecordV1,
    node: NodeId,
    address_prefixes: Vec<NetworkIpPrefixV1>,
    port_ranges: Vec<IngressPoolPortRangeV1>,
    maximum_live: u16,
    reuse_delay_generations: u64,
    registry_generation: u64,
    registry_rows: Vec<IngressRegistryRowV1>,
) -> IngressPoolAuthorityProofV1<'guard> {
    let mut proof = IngressPoolAuthorityProofV1 {
        protected_current: authority,
        protected_snapshot: snapshot,
        protected_record: record,
        node,
        authority_generation: record.authority_generation,
        authority_digest: record.authority_digest,
        address_prefixes,
        port_ranges,
        maximum_live,
        reuse_delay_generations,
        registry_generation,
        registry_rows,
        binding: ObjectDigest::from_bytes([0; 32]),
    };
    let mut bytes = proof.issuer_bytes();
    bytes.extend_from_slice(record.content_digest.as_bytes());
    bytes.extend_from_slice(record.auxiliary_digest.as_bytes());
    proof.binding = digest_with_domain(INGRESS_PROOF_DOMAIN, &bytes);
    proof
}

fn bind_quota_proof<'guard, 'journal: 'guard>(
    authority: &'guard ProtectedJournalAuthority<'journal>,
    snapshot: &'guard ProtectedJournalSnapshot,
    record: UpstreamAuthorityRecordV1,
    node: NodeId,
    project_limit: AdvancedNetworkQuotaV1,
    node_limit: AdvancedNetworkQuotaV1,
    projects: Vec<ProjectNetworkUsageV1>,
) -> QuotaAuthorityProofV1<'guard> {
    let mut proof = QuotaAuthorityProofV1 {
        protected_current: authority,
        protected_snapshot: snapshot,
        protected_record: record,
        node,
        projection_generation: record.record_generation,
        authority_generation: record.authority_generation,
        authority_digest: record.authority_digest,
        project_limit,
        node_limit,
        projects,
        binding: ObjectDigest::from_bytes([0; 32]),
    };
    let mut bytes = proof.issuer_bytes();
    bytes.extend_from_slice(record.content_digest.as_bytes());
    proof.binding = digest_with_domain(QUOTA_PROOF_DOMAIN, &bytes);
    proof
}

fn capability_proof_bytes(proof: &KernelCapabilityProbeProofV1<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&proof.host_boot_id);
    bytes.extend_from_slice(&proof.monotonic_sample_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&proof.probe_generation.to_be_bytes());
    bytes.extend_from_slice(&proof.authority_generation.to_be_bytes());
    bytes.extend_from_slice(proof.authority_digest.as_bytes());
    for feature in &proof.features {
        bytes.extend_from_slice(&(feature.namespace().len() as u16).to_be_bytes());
        bytes.extend_from_slice(feature.namespace().as_bytes());
        bytes.extend_from_slice(&feature.major().to_be_bytes());
        bytes.extend_from_slice(&feature.minor().to_be_bytes());
    }
    bytes
}

fn validate_broker_current(
    authority: &NetworkAuthorityV1,
    admission: &VerifiedBrokerAdmission,
    clock: &RawPairedClockSample,
) -> Result<(), AdvancedNetworkPolicyError> {
    authority
        .check_current_fence(&admission.fence)
        .map_err(|_| AdvancedNetworkPolicyError::StaleAuthority)?;
    if admission.effect.status() != BrokerEffectStatusV1::Pending
        || admission.effect.plan_digest() != admission.fence.plan_digest()
        || admission.effect.lease_digest() != admission.fence.local_lease_record().lease_digest()
        || authority
            .classify_effect_clock(&admission.effect, clock)
            .map_err(|_| AdvancedNetworkPolicyError::StaleAuthority)?
            != BrokerEffectClockDispositionV1::Fresh
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(())
}

fn validate_broker_record(
    record: UpstreamAuthorityRecordV1,
    authority: &NetworkAuthorityV1,
    admission: &VerifiedBrokerAdmission,
) -> Result<(), AdvancedNetworkPolicyError> {
    let assignment = admission.fence.assignment();
    let lease = admission.fence.local_lease_record();
    if record.kind != UpstreamAuthorityKindV1::Broker
        || record.subject != *assignment.sandbox().as_bytes()
        || record.issuer != *admission.fence.node().as_bytes()
        || record.record_generation != lease.lease_generation()
        || record.authority_generation != assignment.desired_generation().get()
        || record.authority_digest != lease.lease_digest()
        || record.content_digest != assignment.digest()
        || record.auxiliary_digest != admission.fence.plan_digest()
        || record.host_boot_id != *lease.host_boot_id()
        || record.sampled_monotonic_nanoseconds != lease.fail_stop_boottime_nanoseconds()
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    authority
        .check_current_fence(&admission.fence)
        .map_err(|_| AdvancedNetworkPolicyError::StaleAuthority)
}

fn protected_clock() -> Result<RawPairedClockSample, AdvancedNetworkPolicyError> {
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        KernelBootId::current()
            .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
            .into_bytes(),
        realtime.tv_sec,
        clock_nanoseconds(rustix::time::ClockId::Boottime)?,
    )
    .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
}

fn validate_live_kernel_record(
    record: UpstreamAuthorityRecordV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    if KernelBootId::current()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        .into_bytes()
        != record.host_boot_id
        || clock_nanoseconds(rustix::time::ClockId::Monotonic)?
            < record.sampled_monotonic_nanoseconds
    {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(())
}

fn clock_nanoseconds(clock: rustix::time::ClockId) -> Result<u64, AdvancedNetworkPolicyError> {
    let sample = rustix::time::clock_gettime(clock);
    let seconds =
        u64::try_from(sample.tv_sec).map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    let nanoseconds =
        u64::try_from(sample.tv_nsec).map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(AdvancedNetworkPolicyError::ProtectedStorage)
}

fn protected_snapshot(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<ProtectedJournalSnapshot, AdvancedNetworkPolicyError> {
    authority
        .snapshot()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)
}

fn current_record(
    authority: &ProtectedJournalAuthority<'_>,
    key: &[u8],
    kind: UpstreamAuthorityKindV1,
) -> Result<UpstreamAuthorityRecordV1, AdvancedNetworkPolicyError> {
    let record = authority
        .get(key)
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
        .ok_or(AdvancedNetworkPolicyError::StaleAuthority)
        .and_then(decode_upstream_record)?;
    if record.kind != kind {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    Ok(record)
}

fn validate_upstream_snapshot(
    authority: &ProtectedJournalAuthority<'_>,
    snapshot: &ProtectedJournalSnapshot,
    key: &[u8],
    expected: UpstreamAuthorityRecordV1,
) -> Result<(), AdvancedNetworkPolicyError> {
    if current_record(authority, key, expected.kind)? != expected {
        return Err(AdvancedNetworkPolicyError::StaleAuthority);
    }
    authority
        .validate_snapshot_for_effect(snapshot)
        .map_err(|_| AdvancedNetworkPolicyError::StaleAuthority)
}

fn validate_upstream_records(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(), AdvancedNetworkPolicyError> {
    for (key, value) in authority
        .records()
        .map_err(|_| AdvancedNetworkPolicyError::ProtectedStorage)?
    {
        let record = decode_upstream_record(value)?;
        if key != upstream_key(record.kind) {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
    }
    Ok(())
}

fn decode_upstream_record(
    bytes: &[u8],
) -> Result<UpstreamAuthorityRecordV1, AdvancedNetworkPolicyError> {
    if bytes.len() != RECORD_BYTES
        || bytes.get(..8) != Some(RECORD_MAGIC)
        || u16::from_be_bytes(copy_array(&bytes[8..10])?) != RECORD_VERSION
        || bytes[11] != 0
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let kind = match bytes[10] {
        5 => UpstreamAuthorityKindV1::Broker,
        1 => UpstreamAuthorityKindV1::Discovery,
        2 => UpstreamAuthorityKindV1::Capability,
        3 => UpstreamAuthorityKindV1::Ingress,
        4 => UpstreamAuthorityKindV1::Quota,
        _ => return Err(AdvancedNetworkPolicyError::NonCanonical),
    };
    let checksum: [u8; 32] = Sha256::digest(&bytes[..212]).into();
    if checksum.as_slice() != &bytes[212..244] {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let record = UpstreamAuthorityRecordV1 {
        kind,
        record_generation: u64::from_be_bytes(copy_array(&bytes[12..20])?),
        authority_generation: u64::from_be_bytes(copy_array(&bytes[20..28])?),
        subject: copy_array(&bytes[28..44])?,
        issuer: copy_array(&bytes[44..60])?,
        authority_digest: ObjectDigest::from_bytes(copy_array(&bytes[60..92])?),
        content_digest: ObjectDigest::from_bytes(copy_array(&bytes[92..124])?),
        auxiliary_digest: ObjectDigest::from_bytes(copy_array(&bytes[124..156])?),
        host_boot_id: copy_array(&bytes[156..172])?,
        sampled_monotonic_nanoseconds: u64::from_be_bytes(copy_array(&bytes[172..180])?),
        record_digest: ObjectDigest::from_bytes(copy_array(&bytes[180..212])?),
    };
    validate_record_semantics(record, bytes)
}

fn validate_record_semantics(
    record: UpstreamAuthorityRecordV1,
    bytes: &[u8],
) -> Result<UpstreamAuthorityRecordV1, AdvancedNetworkPolicyError> {
    let expected_record_digest = digest_with_domain(
        b"aos.sandbox.network.upstream-authority-record.v1\0",
        &bytes[..180],
    );
    let zero = ObjectDigest::from_bytes([0; 32]);
    if record.record_generation == 0
        || record.authority_generation == 0
        || record.subject == [0; 16]
        || record.issuer == [0; 16]
        || record.authority_digest == zero
        || record.content_digest == zero
        || record.record_digest != expected_record_digest
    {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    let auxiliary_present = record.auxiliary_digest != zero;
    let live_kernel_present =
        record.host_boot_id != [0; 16] && record.sampled_monotonic_nanoseconds != 0;
    let valid_shape = match record.kind {
        UpstreamAuthorityKindV1::Broker => auxiliary_present && live_kernel_present,
        UpstreamAuthorityKindV1::Discovery | UpstreamAuthorityKindV1::Quota => {
            !auxiliary_present && !live_kernel_present
        }
        UpstreamAuthorityKindV1::Capability => !auxiliary_present && live_kernel_present,
        UpstreamAuthorityKindV1::Ingress => auxiliary_present && !live_kernel_present,
    };
    if !valid_shape {
        return Err(AdvancedNetworkPolicyError::NonCanonical);
    }
    Ok(record)
}

const fn upstream_key(kind: UpstreamAuthorityKindV1) -> &'static [u8] {
    match kind {
        UpstreamAuthorityKindV1::Broker => BROKER_KEY,
        UpstreamAuthorityKindV1::Discovery => DISCOVERY_KEY,
        UpstreamAuthorityKindV1::Capability => CAPABILITY_KEY,
        UpstreamAuthorityKindV1::Ingress => INGRESS_KEY,
        UpstreamAuthorityKindV1::Quota => QUOTA_KEY,
    }
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AdvancedNetworkPolicyError> {
    bytes
        .try_into()
        .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
}

const fn upstream_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 16 * 1024 * 1024,
        maximum_record_bytes: 4096,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 5,
    }
}
