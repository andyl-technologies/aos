//! Durable current-namespace lifecycle transitions.
//!
//! The namespace catalog applies only exact compare-and-swap transitions over
//! a physically identified row. The transition value models an observation
//! made by the fixed privileged helper; constructing it does not inspect Linux
//! or grant effect authority. Broker admission and helper verification remain
//! separate prerequisites before this catalog boundary is called.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    NamespaceLifecycleV1, NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1,
    RECORD_FORMAT_VERSION, next_generation,
};

const TRANSITION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.namespace-lifecycle.v1\0";

/// Identifies one exact boot-scoped namespace resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespaceIdentityV1 {
    network_handle: [u8; 32],
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
}

impl NetworkNamespaceIdentityV1 {
    /// Constructs a complete non-sentinel namespace identity.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when a
    /// handle, boot ID, device, or inode uses its reserved zero value.
    pub fn new(
        network_handle: [u8; 32],
        kernel_boot_id: [u8; 16],
        namespace_device: u64,
        namespace_inode: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        if network_handle == [0; 32]
            || kernel_boot_id == [0; 16]
            || namespace_device == 0
            || namespace_inode == 0
        {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        Ok(Self {
            network_handle,
            kernel_boot_id,
            namespace_device,
            namespace_inode,
        })
    }

    /// Returns the opaque protected-catalog handle.
    #[must_use]
    pub const fn network_handle(self) -> [u8; 32] {
        self.network_handle
    }

    /// Returns the boot in which the namespace was observed.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the observed namespace device identity.
    #[must_use]
    pub const fn namespace_device(self) -> u64 {
        self.namespace_device
    }

    /// Returns the observed namespace inode identity.
    #[must_use]
    pub const fn namespace_inode(self) -> u64 {
        self.namespace_inode
    }
}

/// Names the closed kernel state reported after a lifecycle effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkNamespaceObservedStateKindV1 {
    /// The namespace is present under verified local default-drop policy.
    DefaultDrop,
    /// The namespace is present and its verified lease gate is armed.
    Armed,
    /// The namespace is present under guardian-applied fail-stop containment.
    Fenced,
    /// The namespace pin and all helper-owned kernel objects are absent.
    Absent,
}

/// Carries the closed lifecycle and lease tuple observed by the helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespaceObservedStateV1 {
    kind: NetworkNamespaceObservedStateKindV1,
    ownership_lease_digest: [u8; 32],
    lease_generation: u64,
    fail_stop_boottime_nanoseconds: u64,
}

impl NetworkNamespaceObservedStateV1 {
    /// Constructs a present verified default-drop observation.
    #[must_use]
    pub const fn default_drop() -> Self {
        Self::without_lease(NetworkNamespaceObservedStateKindV1::DefaultDrop)
    }

    /// Constructs an absent verified-destruction observation.
    #[must_use]
    pub const fn absent() -> Self {
        Self::without_lease(NetworkNamespaceObservedStateKindV1::Absent)
    }

    /// Constructs a present verified armed observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// lease digest, generation, or deadline uses its reserved zero value.
    pub fn armed(
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        Self::with_lease(
            NetworkNamespaceObservedStateKindV1::Armed,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        )
    }

    /// Constructs a present verified fail-stop observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// retained lease digest, generation, or deadline is zero.
    pub fn fenced(
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        Self::with_lease(
            NetworkNamespaceObservedStateKindV1::Fenced,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        )
    }

    /// Returns the closed observed lifecycle state.
    #[must_use]
    pub const fn kind(self) -> NetworkNamespaceObservedStateKindV1 {
        self.kind
    }

    /// Returns the observed lease tuple for Armed or Fenced state.
    #[must_use]
    pub const fn lease(self) -> Option<(ObjectDigest, u64, u64)> {
        if matches!(
            self.kind,
            NetworkNamespaceObservedStateKindV1::Armed
                | NetworkNamespaceObservedStateKindV1::Fenced
        ) {
            Some((
                ObjectDigest::from_bytes(self.ownership_lease_digest),
                self.lease_generation,
                self.fail_stop_boottime_nanoseconds,
            ))
        } else {
            None
        }
    }

    const fn without_lease(kind: NetworkNamespaceObservedStateKindV1) -> Self {
        Self {
            kind,
            ownership_lease_digest: [0; 32],
            lease_generation: 0,
            fail_stop_boottime_nanoseconds: 0,
        }
    }

    fn with_lease(
        kind: NetworkNamespaceObservedStateKindV1,
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        if ownership_lease_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || fail_stop_boottime_nanoseconds == 0
        {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        Ok(Self {
            kind,
            ownership_lease_digest: *ownership_lease_digest.as_bytes(),
            lease_generation,
            fail_stop_boottime_nanoseconds,
        })
    }
}

/// Carries one helper-observed lifecycle result and its prior-state CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespaceLifecycleObservationV1 {
    request_id: [u8; 16],
    prior_resource_digest: ObjectDigest,
    namespace: NetworkNamespaceIdentityV1,
    observed_state: NetworkNamespaceObservedStateV1,
    observation_digest: ObjectDigest,
}

impl NetworkNamespaceLifecycleObservationV1 {
    /// Constructs a mechanically bound lifecycle observation.
    ///
    /// This constructor checks shape only. A privileged helper must derive the
    /// observation digest after verifying the complete kernel postcondition.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] for a zero
    /// request, prior-resource digest, or observation digest.
    pub fn new(
        request_id: [u8; 16],
        prior_resource_digest: ObjectDigest,
        namespace: NetworkNamespaceIdentityV1,
        observed_state: NetworkNamespaceObservedStateV1,
        observation_digest: ObjectDigest,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        if request_id == [0; 16]
            || prior_resource_digest.as_bytes() == &[0; 32]
            || observation_digest.as_bytes() == &[0; 32]
        {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        Ok(Self {
            request_id,
            prior_resource_digest,
            namespace,
            observed_state,
            observation_digest,
        })
    }

    /// Returns the request that owns this transition attempt.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the resource digest that must still be current.
    #[must_use]
    pub const fn prior_resource_digest(self) -> ObjectDigest {
        self.prior_resource_digest
    }

    /// Returns the exact physical namespace identity.
    #[must_use]
    pub const fn namespace(self) -> NetworkNamespaceIdentityV1 {
        self.namespace
    }

    /// Returns the helper's closed observed lifecycle and lease state.
    #[must_use]
    pub const fn observed_state(self) -> NetworkNamespaceObservedStateV1 {
        self.observed_state
    }

    /// Returns the helper's complete postcondition commitment.
    #[must_use]
    pub const fn observation_digest(self) -> ObjectDigest {
        self.observation_digest
    }
}

/// Names the closed current-resource lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkNamespaceLifecycleActionV1 {
    /// Raises an existing default-drop namespace under a new ownership lease.
    Arm,
    /// Advances the fail-stop gate for the currently armed owner.
    Renew,
    /// Restores local default-drop under current cleanup authority.
    Disarm,
    /// Records guardian-applied fail-stop containment without new authority.
    Fence,
    /// Permanently retires a namespace after its fixed pin is absent.
    Destroy,
}

/// Carries one validated closed transition for the namespace catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkNamespaceLifecycleTransitionV1 {
    observation: NetworkNamespaceLifecycleObservationV1,
    action: NetworkNamespaceLifecycleActionV1,
    ownership_lease_digest: [u8; 32],
    lease_generation: u64,
    fail_stop_boottime_nanoseconds: u64,
    digest: [u8; 32],
}

impl NetworkNamespaceLifecycleTransitionV1 {
    /// Constructs a transition that arms a new lease generation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// observation does not report Armed with the exact nonzero lease tuple or
    /// the derived transition digest uses its reserved zero value.
    pub fn arm(
        observation: NetworkNamespaceLifecycleObservationV1,
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        Self::lease_transition(
            observation,
            NetworkNamespaceLifecycleActionV1::Arm,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        )
    }

    /// Constructs a transition that renews the currently armed lease.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// observation does not report Armed with the exact nonzero lease tuple or
    /// the derived transition digest uses its reserved zero value.
    pub fn renew(
        observation: NetworkNamespaceLifecycleObservationV1,
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        Self::lease_transition(
            observation,
            NetworkNamespaceLifecycleActionV1::Renew,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        )
    }

    /// Constructs a verified default-drop transition.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// observation does not report DefaultDrop or the derived transition
    /// digest uses its reserved zero value.
    pub fn disarm(
        observation: NetworkNamespaceLifecycleObservationV1,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        require_observed_state(
            observation,
            NetworkNamespaceObservedStateKindV1::DefaultDrop,
        )?;
        Self::without_lease(observation, NetworkNamespaceLifecycleActionV1::Disarm)
    }

    /// Constructs a guardian fail-stop transition.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// observation does not report Fenced or the derived transition digest
    /// uses its reserved zero value.
    pub fn fence(
        observation: NetworkNamespaceLifecycleObservationV1,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        require_observed_state(observation, NetworkNamespaceObservedStateKindV1::Fenced)?;
        Self::without_lease(observation, NetworkNamespaceLifecycleActionV1::Fence)
    }

    /// Constructs a verified-absence retirement transition.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError::InvalidCandidate`] when the
    /// observation does not report Absent or the derived transition digest
    /// uses its reserved zero value.
    pub fn destroy(
        observation: NetworkNamespaceLifecycleObservationV1,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        require_observed_state(observation, NetworkNamespaceObservedStateKindV1::Absent)?;
        Self::without_lease(observation, NetworkNamespaceLifecycleActionV1::Destroy)
    }

    /// Returns the selected closed action.
    #[must_use]
    pub const fn action(self) -> NetworkNamespaceLifecycleActionV1 {
        self.action
    }

    /// Returns the helper-bound observation.
    #[must_use]
    pub const fn observation(self) -> NetworkNamespaceLifecycleObservationV1 {
        self.observation
    }

    /// Returns lease generation and fail-stop deadline for arm or renew.
    #[must_use]
    pub const fn lease(self) -> Option<(ObjectDigest, u64, u64)> {
        if matches!(
            self.action,
            NetworkNamespaceLifecycleActionV1::Arm | NetworkNamespaceLifecycleActionV1::Renew
        ) {
            Some((
                ObjectDigest::from_bytes(self.ownership_lease_digest),
                self.lease_generation,
                self.fail_stop_boottime_nanoseconds,
            ))
        } else {
            None
        }
    }

    fn lease_transition(
        observation: NetworkNamespaceLifecycleObservationV1,
        action: NetworkNamespaceLifecycleActionV1,
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        if ownership_lease_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || fail_stop_boottime_nanoseconds == 0
        {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }
        if !matches!(
            action,
            NetworkNamespaceLifecycleActionV1::Arm | NetworkNamespaceLifecycleActionV1::Renew
        ) {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }
        require_observed_state(observation, NetworkNamespaceObservedStateKindV1::Armed)?;
        if observation.observed_state.lease()
            != Some((
                ownership_lease_digest,
                lease_generation,
                fail_stop_boottime_nanoseconds,
            ))
        {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        Self::new(
            observation,
            action,
            *ownership_lease_digest.as_bytes(),
            lease_generation,
            fail_stop_boottime_nanoseconds,
        )
    }

    fn without_lease(
        observation: NetworkNamespaceLifecycleObservationV1,
        action: NetworkNamespaceLifecycleActionV1,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        Self::new(observation, action, [0; 32], 0, 0)
    }

    fn new(
        observation: NetworkNamespaceLifecycleObservationV1,
        action: NetworkNamespaceLifecycleActionV1,
        ownership_lease_digest: [u8; 32],
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
    ) -> Result<Self, NetworkNamespaceCatalogError> {
        let mut transition = Self {
            observation,
            action,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            digest: [0; 32],
        };
        transition.digest = transition.compute_digest();
        if transition.digest == [0; 32] {
            return Err(NetworkNamespaceCatalogError::InvalidCandidate);
        }

        Ok(transition)
    }

    fn compute_digest(self) -> [u8; 32] {
        let namespace = self.observation.namespace;
        Sha256::new()
            .chain_update(TRANSITION_DIGEST_DOMAIN)
            .chain_update([action_code(self.action)])
            .chain_update(self.observation.request_id)
            .chain_update(self.observation.prior_resource_digest.as_bytes())
            .chain_update(namespace.network_handle)
            .chain_update(namespace.kernel_boot_id)
            .chain_update(namespace.namespace_device.to_be_bytes())
            .chain_update(namespace.namespace_inode.to_be_bytes())
            .chain_update([observed_state_code(self.observation.observed_state.kind)])
            .chain_update(self.observation.observed_state.ownership_lease_digest)
            .chain_update(
                self.observation
                    .observed_state
                    .lease_generation
                    .to_be_bytes(),
            )
            .chain_update(
                self.observation
                    .observed_state
                    .fail_stop_boottime_nanoseconds
                    .to_be_bytes(),
            )
            .chain_update(self.ownership_lease_digest)
            .chain_update(self.lease_generation.to_be_bytes())
            .chain_update(self.fail_stop_boottime_nanoseconds.to_be_bytes())
            .chain_update(self.observation.observation_digest.as_bytes())
            .finalize()
            .into()
    }
}

/// Classifies one exact durable lifecycle compare-and-swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkNamespaceLifecycleOutcomeV1 {
    /// The observed state became the new durable catalog head.
    Applied,
    /// The exact most recent transition was already durable.
    Replay,
}

impl NetworkNamespaceCatalogV1 {
    /// Applies one physically verified lifecycle transition to an exact row.
    ///
    /// Arm and renew advance the retained lease-generation high-water mark.
    /// Disarm and retirement clear active lease state without erasing that
    /// fence. Guardian fencing retains the expired lease tuple as containment
    /// evidence. Retirement requires the fixed pin to be absent and can never
    /// be reversed into a live row.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceCatalogError`] for stale resource evidence,
    /// illegal lifecycle order, lease rollback/equivocation, request reuse,
    /// changed physical identity, pin mismatch, or durable commit failure.
    pub fn apply_lifecycle_transition(
        &mut self,
        transition: NetworkNamespaceLifecycleTransitionV1,
    ) -> Result<NetworkNamespaceLifecycleOutcomeV1, NetworkNamespaceCatalogError> {
        let observation = transition.observation;
        let identity = observation.namespace;
        let current = self
            .records
            .get(&identity.network_handle)
            .ok_or(NetworkNamespaceCatalogError::LifecycleConflict)?;

        if current.last_transition_request_id == observation.request_id {
            if current.last_transition_digest != transition.digest {
                return Err(NetworkNamespaceCatalogError::IdentityConflict);
            }
            self.validate_transition_pin(current, transition.action)?;
            return Ok(NetworkNamespaceLifecycleOutcomeV1::Replay);
        }
        if self.records.values().any(|record| {
            record.request_id == observation.request_id
                || record.last_transition_request_id == observation.request_id
        }) {
            return Err(NetworkNamespaceCatalogError::IdentityConflict);
        }
        if current.resource_digest != *observation.prior_resource_digest.as_bytes()
            || current.kernel_boot_id != identity.kernel_boot_id
            || current.namespace_device != identity.namespace_device
            || current.namespace_inode != identity.namespace_inode
        {
            return Err(NetworkNamespaceCatalogError::LifecycleConflict);
        }
        self.validate_transition_pin(current, transition.action)?;

        let mut next = current.clone();
        match transition.action {
            NetworkNamespaceLifecycleActionV1::Arm => {
                require_lifecycle(&next, NamespaceLifecycleV1::DefaultDrop)?;
                next.accept_lease(transition)?;
                next.lifecycle = NamespaceLifecycleV1::Armed;
            }
            NetworkNamespaceLifecycleActionV1::Renew => {
                require_lifecycle(&next, NamespaceLifecycleV1::Armed)?;
                next.accept_lease(transition)?;
            }
            NetworkNamespaceLifecycleActionV1::Disarm => {
                if !matches!(
                    next.lifecycle,
                    NamespaceLifecycleV1::Armed | NamespaceLifecycleV1::Fenced
                ) {
                    return Err(NetworkNamespaceCatalogError::LifecycleConflict);
                }
                next.lifecycle = NamespaceLifecycleV1::DefaultDrop;
                next.clear_active_lease();
            }
            NetworkNamespaceLifecycleActionV1::Fence => {
                require_lifecycle(&next, NamespaceLifecycleV1::Armed)?;
                if observation.observed_state.lease()
                    != Some((
                        ObjectDigest::from_bytes(next.highest_lease_digest),
                        next.lease_generation,
                        next.fail_stop_boottime_nanoseconds,
                    ))
                {
                    return Err(NetworkNamespaceCatalogError::LifecycleConflict);
                }
                next.lifecycle = NamespaceLifecycleV1::Fenced;
            }
            NetworkNamespaceLifecycleActionV1::Destroy => {
                let same_boot = next.kernel_boot_id == self.kernel_boot_id;
                if matches!(next.lifecycle, NamespaceLifecycleV1::Retired)
                    || (same_boot
                        && !matches!(
                            next.lifecycle,
                            NamespaceLifecycleV1::DefaultDrop | NamespaceLifecycleV1::Fenced
                        ))
                {
                    return Err(NetworkNamespaceCatalogError::LifecycleConflict);
                }
                next.lifecycle = NamespaceLifecycleV1::Retired;
                next.clear_active_lease();
            }
        }

        next.format_version = RECORD_FORMAT_VERSION;
        next.catalog_generation = next_generation(self.generation)?;
        next.current_observation_digest = *observation.observation_digest.as_bytes();
        next.last_transition_request_id = observation.request_id;
        next.last_transition_digest = transition.digest;
        next.refresh_digest()?;
        next.validate()?;
        self.commit(next)?;

        Ok(NetworkNamespaceLifecycleOutcomeV1::Applied)
    }

    fn validate_transition_pin(
        &self,
        record: &super::NamespaceRecordV2,
        action: NetworkNamespaceLifecycleActionV1,
    ) -> Result<(), NetworkNamespaceCatalogError> {
        if action == NetworkNamespaceLifecycleActionV1::Destroy {
            self.pin_root.ensure_absent(&record.network_handle)
        } else if record.kernel_boot_id != self.kernel_boot_id
            || matches!(record.lifecycle, NamespaceLifecycleV1::Retired)
        {
            Err(NetworkNamespaceCatalogError::LifecycleConflict)
        } else {
            self.pin_root.verify_record(record)
        }
    }
}

impl super::NamespaceRecordV2 {
    fn accept_lease(
        &mut self,
        transition: NetworkNamespaceLifecycleTransitionV1,
    ) -> Result<(), NetworkNamespaceCatalogError> {
        if transition.lease_generation <= self.highest_lease_generation
            || transition.ownership_lease_digest == [0; 32]
            || transition.fail_stop_boottime_nanoseconds == 0
        {
            return Err(NetworkNamespaceCatalogError::LifecycleConflict);
        }

        self.lease_generation = transition.lease_generation;
        self.fail_stop_boottime_nanoseconds = transition.fail_stop_boottime_nanoseconds;
        self.highest_lease_generation = transition.lease_generation;
        self.highest_lease_digest = transition.ownership_lease_digest;
        Ok(())
    }

    fn clear_active_lease(&mut self) {
        self.lease_generation = 0;
        self.fail_stop_boottime_nanoseconds = 0;
    }
}

fn require_lifecycle(
    record: &super::NamespaceRecordV2,
    expected: NamespaceLifecycleV1,
) -> Result<(), NetworkNamespaceCatalogError> {
    if record.lifecycle == expected {
        Ok(())
    } else {
        Err(NetworkNamespaceCatalogError::LifecycleConflict)
    }
}

fn require_observed_state(
    observation: NetworkNamespaceLifecycleObservationV1,
    expected: NetworkNamespaceObservedStateKindV1,
) -> Result<(), NetworkNamespaceCatalogError> {
    if observation.observed_state.kind == expected {
        Ok(())
    } else {
        Err(NetworkNamespaceCatalogError::InvalidCandidate)
    }
}

const fn observed_state_code(state: NetworkNamespaceObservedStateKindV1) -> u8 {
    match state {
        NetworkNamespaceObservedStateKindV1::DefaultDrop => 1,
        NetworkNamespaceObservedStateKindV1::Armed => 2,
        NetworkNamespaceObservedStateKindV1::Fenced => 3,
        NetworkNamespaceObservedStateKindV1::Absent => 4,
    }
}

const fn action_code(action: NetworkNamespaceLifecycleActionV1) -> u8 {
    match action {
        NetworkNamespaceLifecycleActionV1::Arm => 1,
        NetworkNamespaceLifecycleActionV1::Renew => 2,
        NetworkNamespaceLifecycleActionV1::Disarm => 3,
        NetworkNamespaceLifecycleActionV1::Fence => 4,
        NetworkNamespaceLifecycleActionV1::Destroy => 5,
    }
}
