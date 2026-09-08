//! Restart-retained custody for prepared Network namespace descriptors.
//!
//! systemd's file-descriptor store is an ordered transport, not an
//! acknowledgement protocol. In systemd 259.8, `FDSTORE=1` can be processed
//! and rejected because the configured store is full or an internal operation
//! fails; `BARRIER=1` reports only that earlier notifications were processed.
//! This module therefore requires an independent, complete
//! `DumpUnitFileDescriptorStore` readback after every add or removal before it
//! changes its local authoritative inventory.
//!
//! Socket activation returns retained namespaces with names of the form:
//!
//! ```text
//! aos-network-netns-v1-<64 lowercase hexadecimal digits>
//! ```
//!
//! Every returned descriptor is retyped through [`NamespaceFd`], which checks
//! both `nsfs` and `NS_GET_NSTYPE == CLONE_NEWNET`. Replay additionally binds
//! the complete returned set to caller-supplied protected current-boot
//! requirements. This module never reconstructs custody from a path or durable
//! bytes and does not publish Network Apply.

mod format;
mod systemd;

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};

use self::format::StoreSnapshot;
#[cfg(test)]
use self::format::{parse_activation_names, parse_systemd_snapshot};
use self::systemd::SystemdStoreBackend;

pub use self::format::{
    ActivatedNetworkDescriptors, MAXIMUM_RETAINED_NETWORK_NAMESPACES,
    NetworkNamespaceCustodyRequirementV1, NetworkNamespaceStoreName, RetainedNetworkNamespace,
    adopt_systemd_activation, validate_activation_replay,
};

/// Reports invalid activation, divergent custody, or an unconfirmed manager mutation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkNamespaceStoreError {
    /// A descriptor-store name is outside the closed versioned language.
    #[error("Network namespace descriptor-store name is invalid")]
    InvalidName,
    /// Socket-activation metadata or a returned descriptor is invalid.
    #[error("Network namespace descriptor activation is invalid: {0}")]
    InvalidActivation(&'static str),
    /// A protected replay requirement or returned descriptor set conflicts.
    #[error("Network namespace descriptor replay conflicts with protected state")]
    ReplayConflict,
    /// The configured descriptor-store capacity is already exhausted.
    #[error("Network namespace descriptor store is full")]
    Capacity,
    /// systemd processed the mutation but the complete readback proves it absent.
    #[error("systemd did not retain the requested Network namespace descriptor mutation")]
    Rejected,
    /// A mutation may have changed manager state without a conclusive readback.
    #[error("Network namespace descriptor-store outcome is ambiguous: {0}")]
    Ambiguous(String),
    /// A prior ambiguous mutation requires process restart and activation replay.
    #[error("Network namespace descriptor store is poisoned until process restart")]
    Poisoned,
    /// systemd notification or D-Bus observation failed before a mutation.
    #[error("systemd Network namespace descriptor-store operation failed: {0}")]
    Systemd(String),
}

/// Reports the exact confirmed effect of one descriptor-store request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkNamespaceStoreOutcome {
    /// A new name and namespace identity were retained.
    Stored,
    /// The exact name and identity were already retained.
    Replay,
    /// The addressed name was removed.
    Removed,
    /// The addressed name was already absent.
    Absent,
}

/// Retains Network namespace descriptors across `aos-netd` process restarts.
///
/// Each successful mutation includes a systemd processing barrier followed by
/// an exact whole-store D-Bus readback. Any inconclusive or divergent result
/// poisons the instance so no later mutation can be reported as authoritative.
pub struct SystemdNetworkNamespaceStore {
    core: StoreCore<SystemdStoreBackend>,
}

impl SystemdNetworkNamespaceStore {
    /// Connects to systemd and verifies the complete activation inventory.
    ///
    /// Call this only after [`adopt_systemd_activation`] has adopted every
    /// startup descriptor and before serving mutation requests.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceStoreError`] when `NOTIFY_SOCKET` or the
    /// system bus is unavailable, configured capacity differs from activation,
    /// or the manager's complete readback differs from the activated set.
    pub fn from_environment(
        activation: &ActivatedNetworkDescriptors,
    ) -> Result<Self, NetworkNamespaceStoreError> {
        let backend = SystemdStoreBackend::from_environment()?;
        let core = StoreCore::new(
            backend,
            activation.identities(),
            activation.maximum_entries,
            activation.host_network_identity,
        )?;
        Ok(Self { core })
    }

    /// Returns the retained identity for `name`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error after an ambiguous mutation poisons this instance.
    pub fn retained_identity(
        &self,
        name: &NetworkNamespaceStoreName,
    ) -> Result<Option<NamespaceIdentity>, NetworkNamespaceStoreError> {
        self.core.retained_identity(name)
    }

    /// Stores one typed namespace and proves exact manager acceptance.
    ///
    /// The caller retains its descriptor. Success means the complete systemd
    /// readback exactly equals the prior set plus `name` and this namespace's
    /// physical identity.
    ///
    /// # Errors
    ///
    /// Returns an error for capacity exhaustion, name or identity conflict,
    /// explicit manager rejection, failed transport/readback, or ambiguity.
    pub fn store(
        &self,
        name: &NetworkNamespaceStoreName,
        namespace: &NamespaceFd,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreError> {
        self.core.store(name, namespace)
    }

    /// Removes one name and proves its absence from complete manager readback.
    ///
    /// # Errors
    ///
    /// Returns an error when systemd retains the name, transport or readback
    /// fails, or any unrelated inventory delta makes the result ambiguous.
    pub fn remove(
        &self,
        name: &NetworkNamespaceStoreName,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreError> {
        self.core.remove(name)
    }
}

enum BackendMutationError {
    NotSent(String),
    Ambiguous(String),
}

trait StoreBackend {
    fn snapshot(&self) -> Result<StoreSnapshot, String>;

    fn store(
        &self,
        name: &NetworkNamespaceStoreName,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), BackendMutationError>;

    fn remove(&self, name: &NetworkNamespaceStoreName) -> Result<(), BackendMutationError>;
}

struct StoreCore<B> {
    backend: B,
    state: Mutex<BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>>,
    maximum_entries: usize,
    host_network_identity: NamespaceIdentity,
    poisoned: AtomicBool,
}

impl<B: StoreBackend> StoreCore<B> {
    fn new(
        backend: B,
        initial: BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
        maximum_entries: usize,
        host_network_identity: NamespaceIdentity,
    ) -> Result<Self, NetworkNamespaceStoreError> {
        if maximum_entries == 0
            || maximum_entries > MAXIMUM_RETAINED_NETWORK_NAMESPACES
            || initial.len() > maximum_entries
        {
            return Err(NetworkNamespaceStoreError::Capacity);
        }
        if host_network_identity.device == 0 || host_network_identity.inode == 0 {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }
        if initial
            .values()
            .any(|identity| *identity == host_network_identity)
        {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }
        let snapshot = backend
            .snapshot()
            .map_err(NetworkNamespaceStoreError::Systemd)?;
        validate_snapshot(&snapshot, &initial, maximum_entries)?;

        Ok(Self {
            backend,
            state: Mutex::new(initial),
            maximum_entries,
            host_network_identity,
            poisoned: AtomicBool::new(false),
        })
    }

    fn retained_identity(
        &self,
        name: &NetworkNamespaceStoreName,
    ) -> Result<Option<NamespaceIdentity>, NetworkNamespaceStoreError> {
        self.ensure_reconcilable()?;
        let state = self.lock_state()?;
        self.ensure_reconcilable()?;
        Ok(state.get(name).copied())
    }

    fn store(
        &self,
        name: &NetworkNamespaceStoreName,
        namespace: &NamespaceFd,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreError> {
        self.ensure_reconcilable()?;
        if namespace.kind() != NamespaceKind::Network {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }
        let mut state = self.lock_state()?;
        self.ensure_reconcilable()?;
        self.verify_current(&state)?;

        let identity = namespace.identity();
        if identity == self.host_network_identity {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }
        if let Some(existing) = state.get(name) {
            return if *existing == identity {
                Ok(NetworkNamespaceStoreOutcome::Replay)
            } else {
                Err(NetworkNamespaceStoreError::ReplayConflict)
            };
        }
        if state.values().any(|existing| *existing == identity) {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }
        if state.len() >= self.maximum_entries {
            return Err(NetworkNamespaceStoreError::Capacity);
        }

        self.backend
            .store(name, namespace.as_fd())
            .map_err(|error| self.backend_error(error))?;
        let mut expected = state.clone();
        expected.insert(name.clone(), identity);
        match self.post_mutation_snapshot(&state, &expected)? {
            MutationReadback::Accepted => {
                *state = expected;
                Ok(NetworkNamespaceStoreOutcome::Stored)
            }
            MutationReadback::Rejected => Err(NetworkNamespaceStoreError::Rejected),
        }
    }

    fn remove(
        &self,
        name: &NetworkNamespaceStoreName,
    ) -> Result<NetworkNamespaceStoreOutcome, NetworkNamespaceStoreError> {
        self.ensure_reconcilable()?;
        let mut state = self.lock_state()?;
        self.ensure_reconcilable()?;
        self.verify_current(&state)?;
        if !state.contains_key(name) {
            return Ok(NetworkNamespaceStoreOutcome::Absent);
        }

        self.backend
            .remove(name)
            .map_err(|error| self.backend_error(error))?;
        let mut expected = state.clone();
        expected.remove(name);
        match self.post_mutation_snapshot(&state, &expected)? {
            MutationReadback::Accepted => {
                *state = expected;
                Ok(NetworkNamespaceStoreOutcome::Removed)
            }
            MutationReadback::Rejected => Err(NetworkNamespaceStoreError::Rejected),
        }
    }

    fn verify_current(
        &self,
        current: &BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
    ) -> Result<(), NetworkNamespaceStoreError> {
        let snapshot = self
            .backend
            .snapshot()
            .map_err(NetworkNamespaceStoreError::Systemd)?;
        validate_snapshot(&snapshot, current, self.maximum_entries)
    }

    fn post_mutation_snapshot(
        &self,
        previous: &BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
        expected: &BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
    ) -> Result<MutationReadback, NetworkNamespaceStoreError> {
        let snapshot = self
            .backend
            .snapshot()
            .map_err(|error| self.ambiguous(error))?;
        if snapshot.maximum_entries != self.maximum_entries
            || snapshot.reported_entries != snapshot.entries.len()
        {
            return Err(
                self.ambiguous("manager capacity or count changed during mutation".to_owned())
            );
        }
        if snapshot.entries == *expected {
            return Ok(MutationReadback::Accepted);
        }
        if snapshot.entries == *previous {
            return Ok(MutationReadback::Rejected);
        }
        Err(self.ambiguous("manager inventory changed unexpectedly".to_owned()))
    }

    fn backend_error(&self, error: BackendMutationError) -> NetworkNamespaceStoreError {
        match error {
            BackendMutationError::NotSent(message) => NetworkNamespaceStoreError::Systemd(message),
            BackendMutationError::Ambiguous(message) => self.ambiguous(message),
        }
    }

    fn ambiguous(&self, message: String) -> NetworkNamespaceStoreError {
        self.poisoned.store(true, Ordering::Release);
        NetworkNamespaceStoreError::Ambiguous(message)
    }

    fn ensure_reconcilable(&self) -> Result<(), NetworkNamespaceStoreError> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(NetworkNamespaceStoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn lock_state(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>>,
        NetworkNamespaceStoreError,
    > {
        self.state.lock().map_err(|_| {
            self.ambiguous("local descriptor-store inventory lock is poisoned".to_owned())
        })
    }
}

enum MutationReadback {
    Accepted,
    Rejected,
}

fn validate_snapshot(
    snapshot: &StoreSnapshot,
    expected: &BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
    maximum_entries: usize,
) -> Result<(), NetworkNamespaceStoreError> {
    if snapshot.maximum_entries != maximum_entries
        || snapshot.reported_entries != snapshot.entries.len()
        || snapshot.entries != *expected
    {
        return Err(NetworkNamespaceStoreError::Systemd(
            "complete manager descriptor-store readback disagrees with local inventory".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
