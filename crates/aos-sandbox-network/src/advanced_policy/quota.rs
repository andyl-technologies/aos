//! Explicit advanced Network quotas and checked replacement accounting.
//!
//! Every dimension is independently bounded. Arithmetic uses checked addition,
//! and replacement reserves the complete candidate alongside the active policy
//! before any state can describe an in-progress transition.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::identity::{
    ProtectedCurrentnessWitnessV1, ProtectedRecoveryAuthoritiesV1, ProtectedWitnessPurposeV1,
};
use super::ingress::ExternalIngressRegistryV1;
use super::{
    AdvancedNetworkPolicyError, MAXIMUM_ADVANCED_NETWORK_ENDPOINTS, MAXIMUM_ADVANCED_NETWORK_FLOWS,
};

const MAXIMUM_PROJECT_ACCOUNTS: usize = 256;
const MAXIMUM_AGGREGATE_ENDPOINTS: u32 =
    (MAXIMUM_ADVANCED_NETWORK_ENDPOINTS as u32) * (MAXIMUM_PROJECT_ACCOUNTS as u32) * 2;
const MAXIMUM_AGGREGATE_FLOWS: u32 =
    (MAXIMUM_ADVANCED_NETWORK_FLOWS as u32) * (MAXIMUM_PROJECT_ACCOUNTS as u32) * 2;
const AGGREGATE_DOMAIN: &[u8] = b"aos.sandbox.network.aggregate-quota.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.protected-transaction.v1\0";

/// Sets explicit ceilings for each advanced Network policy dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvancedNetworkQuotaV1 {
    services: u32,
    egress_destinations: u32,
    ingress_allocations: u32,
    endpoints: u32,
    flows: u32,
}

impl AdvancedNetworkQuotaV1 {
    /// Constructs one explicit set of policy ceilings.
    ///
    /// Zero is valid for any dimension and denies consumption of that resource.
    /// Values may not exceed the fixed node-wide 256 active plus 256 reserved
    /// policy aggregate bound.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::QuotaExceeded`] for a ceiling
    /// outside the fixed advanced-policy bounds.
    pub fn new(
        services: u32,
        egress_destinations: u32,
        ingress_allocations: u32,
        endpoints: u32,
        flows: u32,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if services > MAXIMUM_AGGREGATE_ENDPOINTS
            || egress_destinations > MAXIMUM_AGGREGATE_ENDPOINTS
            || ingress_allocations > MAXIMUM_AGGREGATE_ENDPOINTS
            || endpoints > MAXIMUM_AGGREGATE_ENDPOINTS
            || flows > MAXIMUM_AGGREGATE_FLOWS
        {
            return Err(AdvancedNetworkPolicyError::QuotaExceeded);
        }

        Ok(Self {
            services,
            egress_destinations,
            ingress_allocations,
            endpoints,
            flows,
        })
    }

    /// Returns the maximum distinct discovered services.
    #[must_use]
    pub const fn services(self) -> u32 {
        self.services
    }

    /// Returns the maximum mediated egress selections.
    #[must_use]
    pub const fn egress_destinations(self) -> u32 {
        self.egress_destinations
    }

    /// Returns the maximum externally allocated ingress endpoints.
    #[must_use]
    pub const fn ingress_allocations(self) -> u32 {
        self.ingress_allocations
    }

    /// Returns the maximum compiled logical endpoints.
    #[must_use]
    pub const fn endpoints(self) -> u32 {
        self.endpoints
    }

    /// Returns the maximum compiled packet flows.
    #[must_use]
    pub const fn flows(self) -> u32 {
        self.flows
    }

    /// Checks one exact usage vector against every ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::QuotaExceeded`] when any usage
    /// dimension exceeds its corresponding limit.
    pub fn admit(self, usage: NetworkPolicyUsageV1) -> Result<(), AdvancedNetworkPolicyError> {
        if usage.services > self.services
            || usage.egress_destinations > self.egress_destinations
            || usage.ingress_allocations > self.ingress_allocations
            || usage.endpoints > self.endpoints
            || usage.flows > self.flows
        {
            return Err(AdvancedNetworkPolicyError::QuotaExceeded);
        }
        Ok(())
    }
}

/// Counts the exact resources consumed by one compiled Network policy.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkPolicyUsageV1 {
    services: u32,
    egress_destinations: u32,
    ingress_allocations: u32,
    endpoints: u32,
    flows: u32,
}

impl NetworkPolicyUsageV1 {
    /// Constructs one checked usage vector.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::QuotaExceeded`] when a value is
    /// outside the packet program's fixed representable bounds.
    pub fn new(
        services: usize,
        egress_destinations: usize,
        ingress_allocations: usize,
        endpoints: usize,
        flows: usize,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if services > MAXIMUM_ADVANCED_NETWORK_ENDPOINTS
            || egress_destinations > MAXIMUM_ADVANCED_NETWORK_ENDPOINTS
            || ingress_allocations > MAXIMUM_ADVANCED_NETWORK_ENDPOINTS
            || endpoints > MAXIMUM_ADVANCED_NETWORK_ENDPOINTS
            || flows > MAXIMUM_ADVANCED_NETWORK_FLOWS
        {
            return Err(AdvancedNetworkPolicyError::QuotaExceeded);
        }

        Ok(Self {
            services: services as u32,
            egress_destinations: egress_destinations as u32,
            ingress_allocations: ingress_allocations as u32,
            endpoints: endpoints as u32,
            flows: flows as u32,
        })
    }

    /// Returns the distinct discovered-service count.
    #[must_use]
    pub const fn services(self) -> u32 {
        self.services
    }

    /// Returns the mediated-destination count.
    #[must_use]
    pub const fn egress_destinations(self) -> u32 {
        self.egress_destinations
    }

    /// Returns the external-ingress-allocation count.
    #[must_use]
    pub const fn ingress_allocations(self) -> u32 {
        self.ingress_allocations
    }

    /// Returns the compiled logical-endpoint count.
    #[must_use]
    pub const fn endpoints(self) -> u32 {
        self.endpoints
    }

    /// Returns the compiled packet-flow count.
    #[must_use]
    pub const fn flows(self) -> u32 {
        self.flows
    }

    /// Adds two usage vectors without permitting integer overflow.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::QuotaExceeded`] on overflow or
    /// when the sum exceeds the fixed two-policy replacement bounds.
    pub fn checked_add(self, other: Self) -> Result<Self, AdvancedNetworkPolicyError> {
        let services = self
            .services
            .checked_add(other.services)
            .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?;
        let egress_destinations = self
            .egress_destinations
            .checked_add(other.egress_destinations)
            .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?;
        let ingress_allocations = self
            .ingress_allocations
            .checked_add(other.ingress_allocations)
            .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?;
        let endpoints = self
            .endpoints
            .checked_add(other.endpoints)
            .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?;
        let flows = self
            .flows
            .checked_add(other.flows)
            .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?;

        if services > MAXIMUM_AGGREGATE_ENDPOINTS
            || egress_destinations > MAXIMUM_AGGREGATE_ENDPOINTS
            || ingress_allocations > MAXIMUM_AGGREGATE_ENDPOINTS
            || endpoints > MAXIMUM_AGGREGATE_ENDPOINTS
            || flows > MAXIMUM_AGGREGATE_FLOWS
        {
            return Err(AdvancedNetworkPolicyError::QuotaExceeded);
        }
        Ok(Self {
            services,
            egress_destinations,
            ingress_allocations,
            endpoints,
            flows,
        })
    }

    fn checked_sub(self, other: Self) -> Result<Self, AdvancedNetworkPolicyError> {
        Ok(Self {
            services: self
                .services
                .checked_sub(other.services)
                .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?,
            egress_destinations: self
                .egress_destinations
                .checked_sub(other.egress_destinations)
                .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?,
            ingress_allocations: self
                .ingress_allocations
                .checked_sub(other.ingress_allocations)
                .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?,
            endpoints: self
                .endpoints
                .checked_sub(other.endpoints)
                .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?,
            flows: self
                .flows
                .checked_sub(other.flows)
                .ok_or(AdvancedNetworkPolicyError::QuotaExceeded)?,
        })
    }
}

/// Tracks active and reserved usage under one explicit quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkQuotaAccountV1 {
    quota: AdvancedNetworkQuotaV1,
    active: NetworkPolicyUsageV1,
    reserved: NetworkPolicyUsageV1,
    reservation_present: bool,
}

impl NetworkQuotaAccountV1 {
    /// Constructs an account for one already-active policy.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::QuotaExceeded`] when active usage
    /// exceeds the supplied quota.
    pub fn new(
        quota: AdvancedNetworkQuotaV1,
        active: NetworkPolicyUsageV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        quota.admit(active)?;
        Ok(Self {
            quota,
            active,
            reserved: NetworkPolicyUsageV1::default(),
            reservation_present: false,
        })
    }

    /// Returns the exact governing quota.
    #[must_use]
    pub const fn quota(self) -> AdvancedNetworkQuotaV1 {
        self.quota
    }

    /// Returns the active policy's usage.
    #[must_use]
    pub const fn active(self) -> NetworkPolicyUsageV1 {
        self.active
    }

    /// Returns usage reserved for a replacement candidate.
    #[must_use]
    pub const fn reserved(self) -> NetworkPolicyUsageV1 {
        self.reserved
    }

    /// Reports whether a replacement reservation is present.
    #[must_use]
    pub const fn has_reservation(self) -> bool {
        self.reservation_present
    }

    /// Reserves a complete candidate alongside current active usage.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] if another reservation exists,
    /// addition overflows, or combined usage exceeds the quota.
    pub fn reserve(
        self,
        candidate: NetworkPolicyUsageV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if self.reservation_present {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.quota.admit(self.active.checked_add(candidate)?)?;
        Ok(Self {
            reserved: candidate,
            reservation_present: true,
            ..self
        })
    }

    /// Atomically promotes reserved usage and releases predecessor usage.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::InvalidTransition`] when no
    /// reservation is present. A present all-zero isolated-policy reservation
    /// remains distinguishable and may commit.
    pub fn commit_reserved(self) -> Result<Self, AdvancedNetworkPolicyError> {
        if !self.reservation_present {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        self.quota.admit(self.reserved)?;
        Ok(Self {
            active: self.reserved,
            reserved: NetworkPolicyUsageV1::default(),
            reservation_present: false,
            ..self
        })
    }

    /// Releases replacement reservation while preserving active usage.
    #[must_use]
    pub const fn abort_reserved(self) -> Self {
        Self {
            reserved: NetworkPolicyUsageV1 {
                services: 0,
                egress_destinations: 0,
                ingress_allocations: 0,
                endpoints: 0,
                flows: 0,
            },
            reservation_present: false,
            ..self
        }
    }
}

/// Stores one project contribution to protected node aggregate accounting.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectNetworkUsageV1 {
    project: ProjectId,
    active: NetworkPolicyUsageV1,
    reserved: NetworkPolicyUsageV1,
    reservation_present: bool,
}

impl ProjectNetworkUsageV1 {
    /// Constructs one protected aggregate accounting row.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError::Unspecified`] for a sentinel
    /// project identity.
    pub fn new(
        project: ProjectId,
        active: NetworkPolicyUsageV1,
        reserved: NetworkPolicyUsageV1,
        reservation_present: bool,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if project.as_bytes() == &[0; 16]
            || (!reservation_present && reserved != NetworkPolicyUsageV1::default())
        {
            return Err(AdvancedNetworkPolicyError::Unspecified);
        }
        Ok(Self {
            project,
            active,
            reserved,
            reservation_present,
        })
    }

    /// Returns the project identity.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns active aggregate project usage.
    #[must_use]
    pub const fn active(self) -> NetworkPolicyUsageV1 {
        self.active
    }

    /// Returns reserved aggregate project usage.
    #[must_use]
    pub const fn reserved(self) -> NetworkPolicyUsageV1 {
        self.reserved
    }

    /// Reports whether a candidate reservation exists, including all-zero use.
    #[must_use]
    pub const fn has_reservation(self) -> bool {
        self.reservation_present
    }
}

/// Carries protected project and node aggregate quota state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedNetworkQuotaV1 {
    project_limit: AdvancedNetworkQuotaV1,
    node_limit: AdvancedNetworkQuotaV1,
    projects: Vec<ProjectNetworkUsageV1>,
    digest: ObjectDigest,
    currentness: ProtectedCurrentnessWitnessV1,
}

/// Opaquely binds one registry and aggregate-quota head in a single transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedNetworkTransactionV1 {
    registry_digest: ObjectDigest,
    quota_digest: ObjectDigest,
    registry_currentness: ProtectedCurrentnessWitnessV1,
    quota_currentness: ProtectedCurrentnessWitnessV1,
    currentness: ProtectedCurrentnessWitnessV1,
}

impl ProtectedNetworkTransactionV1 {
    pub(crate) fn commitment(
        registry: &ExternalIngressRegistryV1,
        registry_currentness: ProtectedCurrentnessWitnessV1,
        quota: &ProtectedNetworkQuotaV1,
    ) -> ObjectDigest {
        transaction_digest(
            registry.digest(),
            registry_currentness,
            quota.digest(),
            quota.currentness(),
        )
    }

    pub(crate) fn mint(
        registry: &ExternalIngressRegistryV1,
        registry_currentness: ProtectedCurrentnessWitnessV1,
        quota: &ProtectedNetworkQuotaV1,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        let quota_currentness = quota.currentness();
        let commitment = Self::commitment(registry, registry_currentness, quota);
        if registry_currentness.purpose() != ProtectedWitnessPurposeV1::IngressRegistry
            || registry_currentness.record_digest() != registry.digest()
            || quota_currentness.purpose() != ProtectedWitnessPurposeV1::Quota
            || quota_currentness.namespace() != registry_currentness.namespace()
            || currentness.purpose() != ProtectedWitnessPurposeV1::CombinedTransaction
            || currentness.namespace() != registry_currentness.namespace()
            || currentness.record_digest() != commitment
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        Ok(Self {
            registry_digest: registry.digest(),
            quota_digest: quota.digest(),
            registry_currentness,
            quota_currentness,
            currentness,
        })
    }

    pub(crate) fn covers(
        self,
        registry: &ExternalIngressRegistryV1,
        registry_currentness: ProtectedCurrentnessWitnessV1,
        quota: &ProtectedNetworkQuotaV1,
    ) -> bool {
        self.registry_digest == registry.digest()
            && self.quota_digest == quota.digest()
            && self.registry_currentness == registry_currentness
            && self.quota_currentness == quota.currentness()
    }

    pub(crate) fn is_exact_successor_of(self, prior: Self) -> bool {
        self.currentness.is_exact_successor_of(prior.currentness)
    }

    pub(crate) const fn currentness(self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.currentness.current_head()
    }

    pub(crate) fn encode_recovery(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(675);
        bytes.extend_from_slice(b"AOSPTX01");
        bytes.extend_from_slice(self.registry_digest.as_bytes());
        bytes.extend_from_slice(self.quota_digest.as_bytes());
        bytes.extend_from_slice(&self.registry_currentness.encode_recovery());
        bytes.extend_from_slice(&self.quota_currentness.encode_recovery());
        bytes.extend_from_slice(&self.currentness.encode_recovery());
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        registry: &ExternalIngressRegistryV1,
        registry_currentness: ProtectedCurrentnessWitnessV1,
        quota: &ProtectedNetworkQuotaV1,
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() != 675 || bytes.get(..8) != Some(b"AOSPTX01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let registry_digest = ObjectDigest::from_bytes(
            bytes[8..40]
                .try_into()
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
        let quota_digest = ObjectDigest::from_bytes(
            bytes[40..72]
                .try_into()
                .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        );
        let stored_registry =
            ProtectedCurrentnessWitnessV1::rebind_recovery(&bytes[72..273], authorities)?;
        let stored_quota =
            ProtectedCurrentnessWitnessV1::rebind_recovery(&bytes[273..474], authorities)?;
        let currentness =
            ProtectedCurrentnessWitnessV1::rebind_recovery(&bytes[474..675], authorities)?;
        if registry_digest != registry.digest()
            || quota_digest != quota.digest()
            || stored_registry != registry_currentness
            || stored_quota != quota.currentness()
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::mint(registry, registry_currentness, quota, currentness)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }
}

impl ProtectedNetworkQuotaV1 {
    /// Computes the exact aggregate commitment a protected owner must witness.
    #[must_use]
    pub fn commitment(
        project_limit: AdvancedNetworkQuotaV1,
        node_limit: AdvancedNetworkQuotaV1,
        projects: &[ProjectNetworkUsageV1],
    ) -> ObjectDigest {
        aggregate_digest(project_limit, node_limit, projects)
    }

    /// Constructs one canonical protected aggregate quota snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for duplicate/unordered projects,
    /// aggregate overflow, limit violation, or a nonmatching currentness witness.
    pub fn new(
        project_limit: AdvancedNetworkQuotaV1,
        node_limit: AdvancedNetworkQuotaV1,
        projects: Vec<ProjectNetworkUsageV1>,
        currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if projects.len() > MAXIMUM_PROJECT_ACCOUNTS
            || projects
                .windows(2)
                .any(|pair| pair[0].project() >= pair[1].project())
        {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut node = NetworkPolicyUsageV1::default();
        for project in &projects {
            project_limit.admit(project.active.checked_add(project.reserved)?)?;
            node = node.checked_add(project.active.checked_add(project.reserved)?)?;
        }
        node_limit.admit(node)?;
        let content_digest = aggregate_digest(project_limit, node_limit, &projects);
        if currentness.purpose() != ProtectedWitnessPurposeV1::Quota
            || currentness.record_digest() != content_digest
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let digest = protected_quota_digest(content_digest, currentness);
        Ok(Self {
            project_limit,
            node_limit,
            projects,
            digest,
            currentness,
        })
    }

    /// Atomically reserves candidate usage in project and node aggregates.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for sentinel project, an existing
    /// reservation, overflow, exhaustion, or too many project accounts.
    pub fn reserve_candidate(
        &self,
        project: ProjectId,
        candidate: NetworkPolicyUsageV1,
        next_currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if project.as_bytes() == &[0; 16]
            || !next_currentness.is_exact_successor_of(self.currentness)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let mut projects = self.projects.clone();
        if projects.iter().any(|row| row.reservation_present) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        match projects.binary_search_by_key(&project, ProjectNetworkUsageV1::project) {
            Ok(index) => {
                projects[index].reserved = candidate;
                projects[index].reservation_present = true;
            }
            Err(index) => {
                if projects.len() == MAXIMUM_PROJECT_ACCOUNTS {
                    return Err(AdvancedNetworkPolicyError::QuotaExceeded);
                }
                projects.insert(
                    index,
                    ProjectNetworkUsageV1 {
                        project,
                        active: NetworkPolicyUsageV1::default(),
                        reserved: candidate,
                        reservation_present: true,
                    },
                );
            }
        }
        Self::new(
            self.project_limit,
            self.node_limit,
            projects,
            next_currentness,
        )
    }

    pub(crate) fn reserve_candidate_from_protected_owner(
        &self,
        project: ProjectId,
        candidate: NetworkPolicyUsageV1,
        mint: impl FnOnce(
            ObjectDigest,
        ) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if project.as_bytes() == &[0; 16] {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let mut projects = self.projects.clone();
        if projects.iter().any(|row| row.reservation_present) {
            return Err(AdvancedNetworkPolicyError::InvalidTransition);
        }
        match projects.binary_search_by_key(&project, ProjectNetworkUsageV1::project) {
            Ok(index) => {
                projects[index].reserved = candidate;
                projects[index].reservation_present = true;
            }
            Err(index) => {
                if projects.len() == MAXIMUM_PROJECT_ACCOUNTS {
                    return Err(AdvancedNetworkPolicyError::QuotaExceeded);
                }
                projects.insert(
                    index,
                    ProjectNetworkUsageV1 {
                        project,
                        active: NetworkPolicyUsageV1::default(),
                        reserved: candidate,
                        reservation_present: true,
                    },
                );
            }
        }
        let digest = aggregate_digest(self.project_limit, self.node_limit, &projects);
        Self::new(self.project_limit, self.node_limit, projects, mint(digest)?)
    }

    /// Returns the protected aggregate commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the per-project aggregate ceiling.
    #[must_use]
    pub const fn project_limit(&self) -> AdvancedNetworkQuotaV1 {
        self.project_limit
    }

    /// Returns the node-wide aggregate ceiling.
    #[must_use]
    pub const fn node_limit(&self) -> AdvancedNetworkQuotaV1 {
        self.node_limit
    }

    /// Returns protected quota-currentness evidence.
    #[must_use]
    pub const fn currentness(&self) -> ProtectedCurrentnessWitnessV1 {
        self.currentness
    }

    /// Returns canonical project accounting rows.
    #[must_use]
    pub fn projects(&self) -> &[ProjectNetworkUsageV1] {
        &self.projects
    }

    pub(crate) fn encode_recovery(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AOSPQT01");
        encode_quota(&mut bytes, self.project_limit);
        encode_quota(&mut bytes, self.node_limit);
        bytes.extend_from_slice(&self.currentness.encode_recovery());
        bytes.extend_from_slice(&(self.projects.len() as u16).to_be_bytes());
        for project in &self.projects {
            bytes.extend_from_slice(project.project.as_bytes());
            encode_usage(&mut bytes, project.active);
            encode_usage(&mut bytes, project.reserved);
            bytes.push(u8::from(project.reservation_present));
        }
        bytes
    }

    pub(crate) fn decode_recovery(
        bytes: &[u8],
        authorities: &ProtectedRecoveryAuthoritiesV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if bytes.len() > 32 * 1024 || bytes.get(..8) != Some(b"AOSPQT01") {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut reader = QuotaReader::new(&bytes[8..]);
        let project_limit = decode_quota(&mut reader)?;
        let node_limit = decode_quota(&mut reader)?;
        let currentness =
            ProtectedCurrentnessWitnessV1::rebind_recovery(reader.take(201)?, authorities)?;
        let count = usize::from(reader.u16()?);
        if count > MAXIMUM_PROJECT_ACCOUNTS {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let mut projects = Vec::with_capacity(count);
        for _ in 0..count {
            let project = ProjectId::from_bytes(reader.array()?);
            let active = decode_usage(&mut reader)?;
            let reserved = decode_usage(&mut reader)?;
            let present = reader.boolean()?;
            projects.push(ProjectNetworkUsageV1::new(
                project, active, reserved, present,
            )?);
        }
        if !reader.finished() {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        let value = Self::new(project_limit, node_limit, projects, currentness)?;
        if value.encode_recovery() != bytes {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(value)
    }

    /// Reports whether the exact candidate usage is protected as reserved.
    #[must_use]
    pub fn contains_reservation(
        &self,
        project: ProjectId,
        candidate: NetworkPolicyUsageV1,
    ) -> bool {
        self.projects
            .binary_search_by_key(&project, ProjectNetworkUsageV1::project)
            .ok()
            .and_then(|index| self.projects.get(index))
            .is_some_and(|account| account.reservation_present && account.reserved == candidate)
    }

    /// Reports whether any project retains an outstanding quota reservation.
    #[must_use]
    pub fn has_reservation(&self) -> bool {
        self.projects
            .iter()
            .any(|account| account.reservation_present)
    }

    /// Reports whether project aggregate active usage covers one policy.
    #[must_use]
    pub fn covers_active(&self, project: ProjectId, usage: NetworkPolicyUsageV1) -> bool {
        self.projects
            .binary_search_by_key(&project, ProjectNetworkUsageV1::project)
            .ok()
            .and_then(|index| self.projects.get(index))
            .is_some_and(|account| {
                account.active.services >= usage.services
                    && account.active.egress_destinations >= usage.egress_destinations
                    && account.active.ingress_allocations >= usage.ingress_allocations
                    && account.active.endpoints >= usage.endpoints
                    && account.active.flows >= usage.flows
            })
    }

    /// Reports whether this is the exact reservation successor of `prior`.
    #[must_use]
    pub fn is_reservation_successor_of(
        &self,
        prior: &Self,
        project: ProjectId,
        candidate: NetworkPolicyUsageV1,
    ) -> bool {
        if self.project_limit != prior.project_limit
            || self.node_limit != prior.node_limit
            || !self.currentness.is_exact_successor_of(prior.currentness)
            || prior
                .projects
                .iter()
                .any(|account| account.reservation_present)
        {
            return false;
        }
        let mut expected = prior.projects.clone();
        match expected.binary_search_by_key(&project, ProjectNetworkUsageV1::project) {
            Ok(index) if !expected[index].reservation_present => {
                expected[index].reserved = candidate;
                expected[index].reservation_present = true;
            }
            Err(index) if expected.len() < MAXIMUM_PROJECT_ACCOUNTS => {
                expected.insert(
                    index,
                    ProjectNetworkUsageV1 {
                        project,
                        active: NetworkPolicyUsageV1::default(),
                        reserved: candidate,
                        reservation_present: true,
                    },
                );
            }
            _ => return false,
        }
        self.projects == expected
    }

    /// Promotes one protected candidate reservation and releases predecessor usage.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for missing exact reservation,
    /// aggregate underflow, or stale next protected currentness.
    pub fn commit_replacement(
        &self,
        project: ProjectId,
        predecessor: NetworkPolicyUsageV1,
        candidate: NetworkPolicyUsageV1,
        next_currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !self.contains_reservation(project, candidate)
            || !next_currentness.is_exact_successor_of(self.currentness)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let mut projects = self.projects.clone();
        let index = projects
            .binary_search_by_key(&project, ProjectNetworkUsageV1::project)
            .map_err(|_| AdvancedNetworkPolicyError::QuotaExceeded)?;
        projects[index].active = projects[index]
            .active
            .checked_sub(predecessor)?
            .checked_add(candidate)?;
        projects[index].reserved = NetworkPolicyUsageV1::default();
        projects[index].reservation_present = false;
        Self::new(
            self.project_limit,
            self.node_limit,
            projects,
            next_currentness,
        )
    }

    pub(crate) fn commit_replacement_from_protected_owner(
        &self,
        project: ProjectId,
        predecessor: NetworkPolicyUsageV1,
        candidate: NetworkPolicyUsageV1,
        mint: impl FnOnce(
            ObjectDigest,
        ) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !self.contains_reservation(project, candidate) {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let mut projects = self.projects.clone();
        let index = projects
            .binary_search_by_key(&project, ProjectNetworkUsageV1::project)
            .map_err(|_| AdvancedNetworkPolicyError::QuotaExceeded)?;
        projects[index].active = projects[index]
            .active
            .checked_sub(predecessor)?
            .checked_add(candidate)?;
        projects[index].reserved = NetworkPolicyUsageV1::default();
        projects[index].reservation_present = false;
        let digest = aggregate_digest(self.project_limit, self.node_limit, &projects);
        Self::new(self.project_limit, self.node_limit, projects, mint(digest)?)
    }

    /// Releases one exact protected candidate reservation without changing active use.
    ///
    /// # Errors
    ///
    /// Returns [`AdvancedNetworkPolicyError`] for a missing exact reservation or
    /// stale next protected currentness.
    pub fn rollback_reservation(
        &self,
        project: ProjectId,
        candidate: NetworkPolicyUsageV1,
        next_currentness: ProtectedCurrentnessWitnessV1,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !self.contains_reservation(project, candidate)
            || !next_currentness.is_exact_successor_of(self.currentness)
        {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let mut projects = self.projects.clone();
        let index = projects
            .binary_search_by_key(&project, ProjectNetworkUsageV1::project)
            .map_err(|_| AdvancedNetworkPolicyError::QuotaExceeded)?;
        projects[index].reserved = NetworkPolicyUsageV1::default();
        projects[index].reservation_present = false;
        Self::new(
            self.project_limit,
            self.node_limit,
            projects,
            next_currentness,
        )
    }

    pub(crate) fn rollback_reservation_from_protected_owner(
        &self,
        project: ProjectId,
        candidate: NetworkPolicyUsageV1,
        mint: impl FnOnce(
            ObjectDigest,
        ) -> Result<ProtectedCurrentnessWitnessV1, AdvancedNetworkPolicyError>,
    ) -> Result<Self, AdvancedNetworkPolicyError> {
        if !self.contains_reservation(project, candidate) {
            return Err(AdvancedNetworkPolicyError::StaleAuthority);
        }
        let mut projects = self.projects.clone();
        let index = projects
            .binary_search_by_key(&project, ProjectNetworkUsageV1::project)
            .map_err(|_| AdvancedNetworkPolicyError::QuotaExceeded)?;
        projects[index].reserved = NetworkPolicyUsageV1::default();
        projects[index].reservation_present = false;
        let digest = aggregate_digest(self.project_limit, self.node_limit, &projects);
        Self::new(self.project_limit, self.node_limit, projects, mint(digest)?)
    }
}

fn aggregate_digest(
    project_limit: AdvancedNetworkQuotaV1,
    node_limit: AdvancedNetworkQuotaV1,
    projects: &[ProjectNetworkUsageV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(AGGREGATE_DOMAIN);
    for quota in [project_limit, node_limit] {
        digest.update(quota.services.to_be_bytes());
        digest.update(quota.egress_destinations.to_be_bytes());
        digest.update(quota.ingress_allocations.to_be_bytes());
        digest.update(quota.endpoints.to_be_bytes());
        digest.update(quota.flows.to_be_bytes());
    }
    digest.update((projects.len() as u16).to_be_bytes());
    for project in projects {
        digest.update(project.project.as_bytes());
        for usage in [project.active, project.reserved] {
            digest.update(usage.services.to_be_bytes());
            digest.update(usage.egress_destinations.to_be_bytes());
            digest.update(usage.ingress_allocations.to_be_bytes());
            digest.update(usage.endpoints.to_be_bytes());
            digest.update(usage.flows.to_be_bytes());
        }
        digest.update([u8::from(project.reservation_present)]);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn protected_quota_digest(
    content: ObjectDigest,
    witness: ProtectedCurrentnessWitnessV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.protected-aggregate-quota.v1\0");
    digest.update(content.as_bytes());
    digest.update(witness.current_head().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn transaction_digest(
    registry: ObjectDigest,
    registry_currentness: ProtectedCurrentnessWitnessV1,
    quota: ObjectDigest,
    quota_currentness: ProtectedCurrentnessWitnessV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update(registry.as_bytes());
    digest.update(registry_currentness.current_head().as_bytes());
    digest.update(quota.as_bytes());
    digest.update(quota_currentness.current_head().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

struct QuotaReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> QuotaReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], AdvancedNetworkPolicyError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AdvancedNetworkPolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
    }
    fn u16(&mut self) -> Result<u16, AdvancedNetworkPolicyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, AdvancedNetworkPolicyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn boolean(&mut self) -> Result<bool, AdvancedNetworkPolicyError> {
        match self.array::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AdvancedNetworkPolicyError::NonCanonical),
        }
    }
    fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
fn encode_quota(bytes: &mut Vec<u8>, value: AdvancedNetworkQuotaV1) {
    for field in [
        value.services,
        value.egress_destinations,
        value.ingress_allocations,
        value.endpoints,
        value.flows,
    ] {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
}
fn decode_quota(
    reader: &mut QuotaReader<'_>,
) -> Result<AdvancedNetworkQuotaV1, AdvancedNetworkPolicyError> {
    AdvancedNetworkQuotaV1::new(
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
    )
}
fn encode_usage(bytes: &mut Vec<u8>, value: NetworkPolicyUsageV1) {
    for field in [
        value.services,
        value.egress_destinations,
        value.ingress_allocations,
        value.endpoints,
        value.flows,
    ] {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
}
fn decode_usage(
    reader: &mut QuotaReader<'_>,
) -> Result<NetworkPolicyUsageV1, AdvancedNetworkPolicyError> {
    let fields = [
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
    ];
    NetworkPolicyUsageV1::new(
        usize::try_from(fields[0]).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        usize::try_from(fields[1]).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        usize::try_from(fields[2]).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        usize::try_from(fields[3]).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
        usize::try_from(fields[4]).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?,
    )
}
