//! Session-owned debugger lifecycle, access roles, and controller leases.
//!
//! The coordinator serializes operations that can move or mutate a live
//! scenario while allowing any number of explicitly registered read-only
//! observers. It contains no transport or QEMU implementation details.

use super::*;

/// Stable identity assigned to one authenticated debugger client.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugClientId(String);

impl DebugClientId {
    /// Builds a client identity from an authenticated principal name.
    ///
    /// # Errors
    ///
    /// Returns [`DebugCoordinatorError::InvalidClientId`] when `value` is
    /// empty or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, DebugCoordinatorError> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(DebugCoordinatorError::InvalidClientId);
        }
        Ok(Self(value))
    }

    /// Returns the authenticated principal name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authorization capabilities understood by the debugger control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DebugCapability {
    /// Reads session state and debugger observations.
    Observe,
    /// Owns the exclusive debugger controller lease.
    Control,
    /// Forks and mutates a non-canonical scenario.
    Mutate,
    /// Opens guest exec, PTY, or SSH-compatible channels.
    Shell,
    /// Changes debugger policy and authorization configuration.
    Admin,
}

/// Named role resolved from daemon authorization policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRole {
    capabilities: BTreeSet<DebugCapability>,
}

impl DebugRole {
    /// Builds a role from an explicit capability set.
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = DebugCapability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    /// Builds the least-privileged read-only role.
    #[must_use]
    pub fn observer() -> Self {
        Self::new([DebugCapability::Observe])
    }

    /// Returns whether the role grants `capability`.
    #[must_use]
    pub fn allows(&self, capability: DebugCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Exclusive controller lease issued by one session coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DebugControllerLease {
    /// Client that owns the lease.
    pub client: DebugClientId,
    /// Monotonic lease generation preventing stale release requests.
    pub generation: u64,
}

/// Stable debugger lifecycle state owned by the session actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugCoordinatorState {
    /// No debugger runtime is attached.
    Detached,
    /// Runtime and gateway attachment is in progress.
    Attaching,
    /// Attached runtime is paused on canonical recorded history.
    CanonicalReadOnly {
        /// Current canonical configuration.
        configuration: ContentHash,
    },
    /// A candidate runtime is being restored and replayed.
    Repositioning {
        /// Canonical configuration expected after replacement.
        target: ContentHash,
    },
    /// Runtime belongs to an explicitly forked non-canonical scenario.
    NonCanonical {
        /// Current non-canonical configuration.
        configuration: ContentHash,
    },
    /// Gateway and runtime teardown is in progress.
    Detaching,
    /// An unrecoverable debugger lifecycle operation failed.
    Failed {
        /// Stable diagnostic safe to return to clients.
        reason: String,
    },
}

/// Coordinates debugger ownership independently of transport connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugCoordinator {
    state: DebugCoordinatorState,
    controller: Option<DebugControllerLease>,
    observers: BTreeSet<DebugClientId>,
    next_generation: u64,
}

impl Default for DebugCoordinator {
    fn default() -> Self {
        Self {
            state: DebugCoordinatorState::Detached,
            controller: None,
            observers: BTreeSet::new(),
            next_generation: 0,
        }
    }
}

impl DebugCoordinator {
    /// Builds a detached coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current debugger lifecycle state.
    #[must_use]
    pub const fn state(&self) -> &DebugCoordinatorState {
        &self.state
    }

    /// Returns the active controller lease, when one exists.
    #[must_use]
    pub const fn controller(&self) -> Option<&DebugControllerLease> {
        self.controller.as_ref()
    }

    /// Returns the number of registered read-only observers.
    #[must_use]
    pub fn observer_count(&self) -> usize {
        self.observers.len()
    }

    /// Registers a read-only observer after checking its role.
    ///
    /// # Errors
    ///
    /// Returns [`DebugCoordinatorError::CapabilityDenied`] when `role` does
    /// not grant [`DebugCapability::Observe`].
    pub fn add_observer(
        &mut self,
        client: DebugClientId,
        role: &DebugRole,
    ) -> Result<(), DebugCoordinatorError> {
        require_capability(role, DebugCapability::Observe)?;
        self.observers.insert(client);
        Ok(())
    }

    /// Removes a read-only observer connection.
    pub fn remove_observer(&mut self, client: &DebugClientId) {
        self.observers.remove(client);
    }

    /// Acquires the single controller lease after checking the client's role.
    ///
    /// Reacquiring by the current owner returns the existing lease. This makes
    /// connection retries idempotent without permitting a second controller.
    ///
    /// # Errors
    ///
    /// Returns [`DebugCoordinatorError::CapabilityDenied`] when `role` lacks
    /// control access, or [`DebugCoordinatorError::ControllerBusy`] when a
    /// different client owns the lease.
    pub fn acquire_controller(
        &mut self,
        client: DebugClientId,
        role: &DebugRole,
    ) -> Result<DebugControllerLease, DebugCoordinatorError> {
        require_capability(role, DebugCapability::Control)?;
        if let Some(lease) = &self.controller {
            if lease.client == client {
                return Ok(lease.clone());
            }
            return Err(DebugCoordinatorError::ControllerBusy {
                owner: lease.client.clone(),
            });
        }
        self.next_generation = self.next_generation.saturating_add(1);
        let lease = DebugControllerLease {
            client,
            generation: self.next_generation,
        };
        self.controller = Some(lease.clone());
        Ok(lease)
    }

    /// Releases the controller lease when the complete token matches.
    ///
    /// # Errors
    ///
    /// Returns [`DebugCoordinatorError::StaleControllerLease`] when `lease`
    /// is not the currently active token.
    pub fn release_controller(
        &mut self,
        lease: &DebugControllerLease,
    ) -> Result<(), DebugCoordinatorError> {
        if self.controller.as_ref() != Some(lease) {
            return Err(DebugCoordinatorError::StaleControllerLease);
        }
        self.controller = None;
        Ok(())
    }

    /// Requires the active controller token and one additional capability.
    ///
    /// # Errors
    ///
    /// Returns an authorization or stale-lease error when the operation is not
    /// permitted.
    pub fn authorize_controller_operation(
        &self,
        lease: &DebugControllerLease,
        role: &DebugRole,
        capability: DebugCapability,
    ) -> Result<(), DebugCoordinatorError> {
        require_capability(role, capability)?;
        if self.controller.as_ref() != Some(lease) {
            return Err(DebugCoordinatorError::StaleControllerLease);
        }
        Ok(())
    }

    /// Records successful attachment at a canonical configuration.
    pub fn attached_canonical(&mut self, configuration: ContentHash) {
        self.state = DebugCoordinatorState::CanonicalReadOnly { configuration };
    }

    /// Records the start of an atomic runtime reposition transaction.
    pub fn begin_reposition(&mut self, target: ContentHash) {
        self.state = DebugCoordinatorState::Repositioning { target };
    }

    /// Records successful canonical runtime replacement.
    pub fn repositioned_canonical(&mut self, configuration: ContentHash) {
        self.state = DebugCoordinatorState::CanonicalReadOnly { configuration };
    }

    /// Records entry into an explicitly forked non-canonical scenario.
    pub fn forked_non_canonical(&mut self, configuration: ContentHash) {
        self.state = DebugCoordinatorState::NonCanonical { configuration };
    }

    pub(super) fn restore_state(&mut self, state: DebugCoordinatorState) {
        self.state = state;
    }

    pub(super) fn failed(&mut self, reason: String) {
        self.state = DebugCoordinatorState::Failed { reason };
    }

    pub(super) fn detached(&mut self) {
        self.state = DebugCoordinatorState::Detached;
        self.controller = None;
        self.observers.clear();
        self.next_generation = self.next_generation.saturating_add(1);
    }
}

/// Errors returned by debugger coordination and lease authorization.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugCoordinatorError {
    /// A client identity was empty or unsafe for logs and protocol messages.
    #[error("debug client identity is invalid")]
    InvalidClientId,
    /// A role did not grant a required capability.
    #[error("debug capability {capability:?} is denied")]
    CapabilityDenied {
        /// Capability required by the attempted operation.
        capability: DebugCapability,
    },
    /// Another client already owns the exclusive controller lease.
    #[error("debug controller lease is owned by {owner:?}")]
    ControllerBusy {
        /// Current controller identity.
        owner: DebugClientId,
    },
    /// A release or operation supplied an expired or foreign lease token.
    #[error("debug controller lease is stale or foreign")]
    StaleControllerLease,
}

fn require_capability(
    role: &DebugRole,
    capability: DebugCapability,
) -> Result<(), DebugCoordinatorError> {
    if !role.allows(capability) {
        return Err(DebugCoordinatorError::CapabilityDenied { capability });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(value: &str) -> DebugClientId {
        DebugClientId::new(value).unwrap_or_else(|error| panic!("valid client id: {error}"))
    }

    #[test]
    fn one_controller_and_multiple_observers_are_enforced() {
        let controller_role = DebugRole::new([
            DebugCapability::Observe,
            DebugCapability::Control,
            DebugCapability::Mutate,
        ]);
        let observer_role = DebugRole::observer();
        let mut coordinator = DebugCoordinator::new();
        coordinator
            .add_observer(client("observer-a"), &observer_role)
            .unwrap_or_else(|error| panic!("observer should register: {error}"));
        coordinator
            .add_observer(client("observer-b"), &observer_role)
            .unwrap_or_else(|error| panic!("observer should register: {error}"));
        let lease = coordinator
            .acquire_controller(client("controller-a"), &controller_role)
            .unwrap_or_else(|error| panic!("controller should acquire: {error}"));
        assert_eq!(coordinator.observer_count(), 2);
        assert!(matches!(
            coordinator.acquire_controller(client("controller-b"), &controller_role),
            Err(DebugCoordinatorError::ControllerBusy { .. })
        ));
        coordinator
            .authorize_controller_operation(&lease, &controller_role, DebugCapability::Mutate)
            .unwrap_or_else(|error| panic!("owner should mutate: {error}"));
        coordinator
            .release_controller(&lease)
            .unwrap_or_else(|error| panic!("owner should release: {error}"));
        assert!(matches!(
            coordinator.release_controller(&lease),
            Err(DebugCoordinatorError::StaleControllerLease)
        ));
    }

    #[test]
    fn observer_role_cannot_control_or_shell() {
        let role = DebugRole::observer();
        let mut coordinator = DebugCoordinator::new();
        assert!(matches!(
            coordinator.acquire_controller(client("observer"), &role),
            Err(DebugCoordinatorError::CapabilityDenied {
                capability: DebugCapability::Control
            })
        ));
    }

    #[test]
    fn detach_clears_connections_and_invalidates_controller_lease() {
        let role = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
        let mut coordinator = DebugCoordinator::new();
        coordinator
            .add_observer(client("observer"), &role)
            .unwrap_or_else(|error| panic!("observer should register: {error}"));
        let stale = coordinator
            .acquire_controller(client("controller"), &role)
            .unwrap_or_else(|error| panic!("controller should acquire: {error}"));
        coordinator.detached();

        assert_eq!(coordinator.observer_count(), 0);
        assert!(coordinator.controller().is_none());
        assert!(matches!(
            coordinator.release_controller(&stale),
            Err(DebugCoordinatorError::StaleControllerLease)
        ));
        let renewed = coordinator
            .acquire_controller(client("controller"), &role)
            .unwrap_or_else(|error| panic!("controller should reacquire: {error}"));
        assert!(renewed.generation > stale.generation);
    }
}
