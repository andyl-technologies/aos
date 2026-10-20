//! Closed backend capability vocabulary and authenticated probe snapshots.

use crate::{NodeId, ObjectDigest, Revision};

/// Names one semantic capability a runtime backend may implement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BackendCapabilityV1 {
    /// Creates a private user namespace with an immutable identity map.
    PrivateUserNamespace = 1,
    /// Accepts live descriptor-backed mount attachment.
    LiveMountAttachment = 2,
    /// Starts in a prepared private network namespace.
    PrivateNetworking = 3,
    /// Freezes and observes the complete payload cgroup.
    CgroupFreeze = 4,
    /// Coordinates a durable storage snapshot outside the backend.
    DurableStorageSnapshot = 5,
    /// Creates a cheap storage-backed fork without implying process cloning.
    CheapFork = 6,
    /// Restores portable filesystem and logical state on another compatible backend.
    PortableRestore = 7,
    /// Produces a backend-local process and device checkpoint.
    BackendLocalCheckpoint = 8,
    /// Migrates a live runtime between compatible nodes.
    CrossNodeMigration = 9,
    /// Enforces byte-exact exec argument and environment limits.
    ExactExecutionEnvelope = 10,
    /// Provides authenticated guest-agent execution handoff and observation.
    AuthenticatedGuestAgent = 11,
}

/// Stores a canonical bounded set of backend capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendCapabilitiesV1(Vec<BackendCapabilityV1>);

impl BackendCapabilitiesV1 {
    /// Validates a strict ascending capability set.
    ///
    /// # Errors
    ///
    /// Returns [`BackendCapabilityViolation`] when the set is oversized,
    /// duplicated, or not in closed discriminant order. Empty is canonical.
    pub fn new(capabilities: Vec<BackendCapabilityV1>) -> Result<Self, BackendCapabilityViolation> {
        if capabilities.len() > 32 {
            return Err(BackendCapabilityViolation::NonCanonicalSet);
        }
        if capabilities
            .windows(2)
            .any(|pair| pair[0] as u8 >= pair[1] as u8)
        {
            return Err(BackendCapabilityViolation::NonCanonicalSet);
        }
        Ok(Self(capabilities))
    }

    /// Returns capabilities in canonical closed order.
    #[must_use]
    pub fn as_slice(&self) -> &[BackendCapabilityV1] {
        &self.0
    }

    /// Reports whether the set contains one exact semantic capability.
    #[must_use]
    pub fn contains(&self, capability: BackendCapabilityV1) -> bool {
        self.0.binary_search(&capability).is_ok()
    }

    /// Validates that every required capability is present.
    ///
    /// # Errors
    ///
    /// Returns [`BackendCapabilityViolation::Missing`] for the first absent
    /// capability. A backend may never silently ignore a hard requirement.
    pub fn satisfies(
        &self,
        required: &RequiredBackendCapabilitiesV1,
    ) -> Result<(), BackendCapabilityViolation> {
        for capability in required.as_slice() {
            if !self.contains(*capability) {
                return Err(BackendCapabilityViolation::Missing(*capability));
            }
        }
        Ok(())
    }
}

/// Stores the canonical hard capability requirements of one resolved plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredBackendCapabilitiesV1(BackendCapabilitiesV1);

impl RequiredBackendCapabilitiesV1 {
    /// Validates hard requirements in closed canonical order.
    ///
    /// # Errors
    ///
    /// Returns [`BackendCapabilityViolation`] for an oversized, duplicated, or
    /// unordered set. A plan with no optional hard requirements uses empty.
    pub fn new(capabilities: Vec<BackendCapabilityV1>) -> Result<Self, BackendCapabilityViolation> {
        BackendCapabilitiesV1::new(capabilities).map(Self)
    }

    /// Returns hard requirements in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[BackendCapabilityV1] {
        self.0.as_slice()
    }
}

/// Binds a probe to one exact backend build, node, and protected probe epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendProbeCurrentnessV1 {
    node: NodeId,
    backend_build: ObjectDigest,
    probe_epoch: Revision,
    protected_context: ObjectDigest,
}

impl BackendProbeCurrentnessV1 {
    /// Constructs a non-sentinel probe-currentness claim.
    ///
    /// # Errors
    ///
    /// Returns [`BackendCapabilityViolation::Unspecified`] for any zero field.
    pub fn new(
        node: NodeId,
        backend_build: ObjectDigest,
        probe_epoch: Revision,
        protected_context: ObjectDigest,
    ) -> Result<Self, BackendCapabilityViolation> {
        if node.as_bytes() == &[0; 16]
            || backend_build.as_bytes() == &[0; 32]
            || probe_epoch.get() == 0
            || protected_context.as_bytes() == &[0; 32]
        {
            return Err(BackendCapabilityViolation::Unspecified);
        }
        Ok(Self {
            node,
            backend_build,
            probe_epoch,
            protected_context,
        })
    }

    /// Returns the exact node on which the probe ran.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the backend-build commitment.
    #[must_use]
    pub const fn backend_build(&self) -> ObjectDigest {
        self.backend_build
    }

    /// Returns the protected monotonically increasing probe epoch.
    #[must_use]
    pub const fn probe_epoch(&self) -> Revision {
        self.probe_epoch
    }

    /// Returns the commitment to protected platform inputs used by the probe.
    #[must_use]
    pub const fn protected_context(&self) -> ObjectDigest {
        self.protected_context
    }
}

/// Stores an authenticated, nonauthorizing backend capability observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendProbeReportV1 {
    currentness: BackendProbeCurrentnessV1,
    capabilities: BackendCapabilitiesV1,
    report_commitment: ObjectDigest,
}

impl BackendProbeReportV1 {
    /// Constructs a report whose commitment was verified by the protected adapter.
    ///
    /// # Errors
    ///
    /// Returns [`BackendCapabilityViolation::Unspecified`] for a zero commitment.
    pub fn new(
        currentness: BackendProbeCurrentnessV1,
        capabilities: BackendCapabilitiesV1,
        report_commitment: ObjectDigest,
    ) -> Result<Self, BackendCapabilityViolation> {
        if report_commitment.as_bytes() == &[0; 32] {
            return Err(BackendCapabilityViolation::Unspecified);
        }
        Ok(Self {
            currentness,
            capabilities,
            report_commitment,
        })
    }

    /// Returns the exact protected probe-currentness binding.
    #[must_use]
    pub const fn currentness(&self) -> &BackendProbeCurrentnessV1 {
        &self.currentness
    }

    /// Returns the observed semantic capability set.
    #[must_use]
    pub const fn capabilities(&self) -> &BackendCapabilitiesV1 {
        &self.capabilities
    }

    /// Returns the adapter-authenticated complete report commitment.
    #[must_use]
    pub const fn report_commitment(&self) -> ObjectDigest {
        self.report_commitment
    }
}

/// Reports an invalid or unsatisfied backend capability contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackendCapabilityViolation {
    /// A required identity, epoch, or digest uses its zero sentinel.
    #[error("backend capability evidence contains an unspecified field")]
    Unspecified,
    /// A capability set is oversized, duplicated, or unordered.
    #[error("backend capability set is not canonical and bounded")]
    NonCanonicalSet,
    /// The backend lacks one hard semantic requirement.
    #[error("backend does not implement required capability {0:?}")]
    Missing(BackendCapabilityV1),
}
