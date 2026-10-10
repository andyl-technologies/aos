//! Binds original native generations to fresh nodes and their monitor operation.
//!
//! The witness enters the actual fresh factory before node exposure. A later
//! observation borrows that same host, generation and actor decoder; no PID,
//! caller-supplied flag, raw contract getter or replacement account grants it.

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use super::{
    LinuxQemuAttemptHostOwner, OriginalActorAccountError, OriginalActorDecodeOwner,
    OriginalNativeNodeBinding,
};
use crate::qmp::readonly_backing_stream::{BackingEvent, QmpReadOnlyBackingReceipt};
use crate::qmp::readonly_backing_transport::{
    BackingCaptureFailure, capture_with_verified_contract,
};
use crate::qmp::{QmpClient, QmpTimeoutStream};
use crate::supervision::{
    QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError,
    QemuProductionFreshLaunchAdmission,
};
use crate::{QemuNode, QemuPreparedRunDirectory, QemuVmRealizationError};

#[derive(Debug, thiserror::Error)]
enum FreshLaunchCause {
    #[error("original native node binding refused: {0}")]
    Binding(#[source] OriginalActorAccountError),
    #[error("original native process contract refused: {0}")]
    Contract(#[source] QemuVmRealizationError),
    #[error("original native fresh launch refused: {0}")]
    Launch(#[source] QemuLiveNodeStepGateError),
    #[error("original device-digest workspace refused: {0}")]
    Workspace(#[source] crate::spawn::DeviceDigestWorkspaceIssueError),
}

/// Retains a fresh launch's first refusal and its independent original postcut.
///
/// A successfully created node stays inside this failure on a late refusal.
/// Dropping that uncertainty retains the actual node and its generation witness;
/// it cannot release the external native credit or authorize slot reuse.
#[must_use = "retain uncertain fresh launch custody through physical containment"]
pub struct OriginalNativeFreshLaunchError {
    primary: OnceLock<FreshLaunchCause>,
    original_after: OnceLock<HostSupervisionError>,
    node: Mutex<Option<QemuNode>>,
    workspace: Mutex<Option<crate::spawn::OriginalDeviceDigestWorkspace>>,
}

impl OriginalNativeFreshLaunchError {
    fn prepare() -> Arc<Self> {
        Arc::new(Self {
            primary: OnceLock::new(),
            original_after: OnceLock::new(),
            node: Mutex::new(None),
            workspace: Mutex::new(None),
        })
    }

    fn record(
        &self,
        primary: FreshLaunchCause,
        original_after: Option<HostSupervisionError>,
        node: Option<QemuNode>,
    ) {
        // This one precharged control is private until the initiating cut has
        // completed. Publication never allocates another failure owner.
        let _ = self.primary.set(primary);
        if let Some(after) = original_after {
            let _ = self.original_after.set(after);
        }
        *self
            .node
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = node;
    }

    /// Borrows the independent same-original refusal after the initiating cut.
    #[must_use]
    pub fn original_after(&self) -> Option<&HostSupervisionError> {
        self.original_after.get()
    }
}

impl std::fmt::Debug for OriginalNativeFreshLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalNativeFreshLaunchError")
            .field("primary", &self.primary)
            .field("original_after", &self.original_after)
            .field(
                "retains_node",
                &self.node.try_lock().map_or(true, |node| node.is_some()),
            )
            .finish()
    }
}

impl std::fmt::Display for OriginalNativeFreshLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?}; original: {:?}",
            self.primary.get(),
            self.original_after.get()
        )
    }
}

impl std::error::Error for OriginalNativeFreshLaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let primary = self.primary.get()?;
        Some(primary)
    }
}

impl Drop for OriginalNativeFreshLaunchError {
    fn drop(&mut self) {
        let node = self
            .node
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(node) = node.take() {
            // This is terminal containment, not resumable cleanup. The host's
            // physical owner remains responsible for the child; the outstanding
            // witness deliberately prevents vector/control credit reuse.
            std::mem::forget(node);
        }
    }
}

pub(super) struct OriginalNativeFreshPreparation {
    // Physical failure storage closes before the final in-flight lease.
    failure: Arc<OriginalNativeFreshLaunchError>,
    original: Arc<HostOperationGuard>,
    lease: FreshLaunchLease,
}

impl OriginalNativeFreshPreparation {
    pub(super) fn retain(
        original: &Arc<HostOperationGuard>,
        attempt: super::NativeAccountAttempt,
    ) -> Self {
        Self {
            failure: OriginalNativeFreshLaunchError::prepare(),
            original: Arc::clone(original),
            lease: FreshLaunchLease {
                attempt,
                entered: false,
                completed: false,
            },
        }
    }

    fn enter(&mut self) {
        self.lease.entered = true;
    }

    #[cfg(test)]
    pub(super) fn enter_mechanism(&mut self) {
        self.enter();
    }

    #[cfg(test)]
    pub(super) fn mechanism_refusal(
        &mut self,
        source: OriginalActorAccountError,
        after: HostSupervisionError,
    ) -> Arc<OriginalNativeFreshLaunchError> {
        self.failure
            .record(FreshLaunchCause::Binding(source), Some(after), None);
        Arc::clone(&self.failure)
    }

    pub(super) fn launch(
        &mut self,
        host: &LinuxQemuAttemptHostOwner,
        config: &QemuLiveNodeStepGateConfig,
        admission: QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<QemuNode, Arc<OriginalNativeFreshLaunchError>> {
        self.enter();
        let (directory, identity) = admission.original_node_basis();
        let failure = Arc::clone(&self.failure);
        let launch =
            host.launch_original_fresh_node(config, directory, identity, &self.original, failure);
        if launch.is_ok() {
            self.lease.completed = true;
        }
        launch
    }
}

struct FreshLaunchLease {
    attempt: super::NativeAccountAttempt,
    entered: bool,
    completed: bool,
}

impl Drop for FreshLaunchLease {
    fn drop(&mut self) {
        self.attempt
            .finish_fresh_launch(self.entered, self.completed);
    }
}

/// Preserves the typed bound-host or transport refusal during an observation.
#[derive(Debug, thiserror::Error)]
pub enum OriginalBackingObservationError<'owner> {
    /// The same roster, live generation, decoder or preparation identity refused.
    #[error("original backing binding refused: {0}")]
    Binding(#[source] OriginalActorAccountError),
    /// The actual host contract refused before a separate original postcut.
    #[error("original backing contract refused: {source}; original: {original_after:?}")]
    Contract {
        /// The actual initiating contract refusal.
        #[source]
        source: QemuVmRealizationError,
        /// The independent retained-original refusal after that cut.
        original_after: Option<HostSupervisionError>,
    },
    /// The same-client transport retained its initiating failure and actor loans.
    #[error(transparent)]
    Capture(BackingCaptureFailure<'owner>),
}

/// Borrows an authenticated host generation and its external actor keeper.
///
/// Only the retained host can construct this opaque observation. It exposes
/// no process contract, guard or account and grants no replacement authority.
pub struct OriginalBoundBackingObservation<'host, 'owner> {
    host: &'host LinuxQemuAttemptHostOwner,
    binding: &'host OriginalNativeNodeBinding,
    decoder: &'owner OriginalActorDecodeOwner,
    original: &'owner Arc<HostOperationGuard>,
}

impl LinuxQemuAttemptHostOwner {
    /// Launches through this owner's original route when it has original custody.
    ///
    /// Ordinary owners use the unchanged prepared fresh-launch function. An
    /// original owner prepays its fixed error/control purpose within the same
    /// external TOTAL pair, then retains any typed terminal refusal in its slot.
    ///
    /// # Errors
    /// Returns actual admission or launch errors. Original refusals retain the
    /// same physical ownership, first cause, postcut and generation credit.
    pub fn launch_fresh_node(
        &self,
        config: &QemuLiveNodeStepGateConfig,
        admission: QemuProductionFreshLaunchAdmission<'_>,
    ) -> Result<QemuNode, QemuLiveNodeStepGateError> {
        let Some(attempt) = self.original_account.as_ref() else {
            return crate::supervision::launch_qemu_production_fresh_node(config, admission);
        };
        let mut preparation = attempt
            .prepare_fresh_launch()
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
        match preparation.launch(self, config, admission) {
            Ok(node) => Ok(node),
            Err(error) => {
                let source = attempt.retain_launch_refusal(error);
                Err(QemuLiveNodeStepGateError::OriginalNativeLaunch { source })
            }
        }
    }

    /// Launches a fresh node with this owner's one admitted generation witness.
    ///
    /// The actual process contract comes from this host. The private completed
    /// factory consumes the witness before exposing the node; ordinary launch
    /// APIs do not acquire or install it. This path does not issue Source or
    /// native initialization permission.
    ///
    /// # Errors
    /// Refuses a missing or terminal original host, a different preparation,
    /// an exhausted active/staged node census, invalid fresh artifacts, or actual launch failure.
    /// A late original refusal retains a successfully created node.
    fn launch_original_fresh_node(
        &self,
        config: &QemuLiveNodeStepGateConfig,
        run_directory: &QemuPreparedRunDirectory,
        identity: QemuLiveNodeIdentity<'_>,
        original: &Arc<HostOperationGuard>,
        failure: Arc<OriginalNativeFreshLaunchError>,
    ) -> Result<QemuNode, Arc<OriginalNativeFreshLaunchError>> {
        let launch = (|| {
            if self.terminal {
                return Err(FreshLaunchCause::Binding(
                    OriginalActorAccountError::Unavailable,
                ));
            }
            let attempt = self
                .original_account
                .as_ref()
                .ok_or(FreshLaunchCause::Binding(
                    OriginalActorAccountError::Unavailable,
                ))?;
            let binding = attempt
                .prepare_node_binding(original)
                .map_err(FreshLaunchCause::Binding)?;
            // The source-qualified admission precedes even a per-spawn
            // contract duplicate. Absence cannot become an enabled None path.
            let workspace_purpose = config
                .requires_device_digest_workspace()
                .then(|| {
                    attempt.prepare_device_digest_workspace(
                        original,
                        config.original_process_generation(),
                    )
                })
                .transpose()
                .map_err(FreshLaunchCause::Binding)?;
            let contract = self
                .process_contract()
                .map_err(FreshLaunchCause::Contract)?;
            let admission = QemuProductionFreshLaunchAdmission::admit(
                config,
                run_directory,
                contract,
                identity,
            )
            .map_err(FreshLaunchCause::Launch)?;
            if let Some(purpose) = workspace_purpose {
                let mut held = failure
                    .workspace
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // The already-precreated failure body owns the holder before
                // its first Arc or FD effect. A refusal retains this same slot.
                *held = Some(crate::spawn::OriginalDeviceDigestWorkspace::new(purpose));
                held.as_mut()
                    .ok_or(FreshLaunchCause::Workspace(
                        crate::spawn::DeviceDigestWorkspaceIssueError::Unavailable,
                    ))?
                    .create()
                    .map_err(FreshLaunchCause::Workspace)?;
            }
            let workspace = failure
                .workspace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            crate::supervision::launch_qemu_original_fresh_node(
                config, admission, binding, workspace,
            )
            .map_err(FreshLaunchCause::Launch)
        })();
        let original_after = original.wait_slice().err();
        match (launch, original_after) {
            (Ok(node), None) => Ok(node),
            (Ok(node), Some(after)) => {
                failure.record(
                    FreshLaunchCause::Binding(OriginalActorAccountError::Supervision(after)),
                    None,
                    Some(node),
                );
                Err(failure)
            }
            (Err(primary), original_after) => {
                failure.record(primary, original_after, None);
                Err(failure)
            }
        }
    }

    pub(crate) fn verify_original_park_binding(
        &self,
        binding: &OriginalNativeNodeBinding,
        decoder: &crate::OriginalActorParkCaller,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), crate::OriginalActorAccountError> {
        if self.terminal {
            return Err(crate::OriginalActorAccountError::Unavailable);
        }
        let attempt = self
            .original_account
            .as_ref()
            .ok_or(crate::OriginalActorAccountError::Unavailable)?;
        binding.verify_against(attempt, original)?;
        decoder.verify_original(original)
    }

    pub(crate) fn enter_original_park_quiescence(
        &self,
        binding: &OriginalNativeNodeBinding,
        decoder: &crate::OriginalActorParkCaller,
        original: &Arc<HostOperationGuard>,
    ) -> Result<crate::OriginalActorParkQuiescence, crate::OriginalActorParkQuiescenceError> {
        use crate::OriginalActorParkQuiescenceError;

        self.verify_original_park_binding(binding, decoder, original)
            .map_err(|first| OriginalActorParkQuiescenceError::Binding {
                first,
                original_after: original.wait_slice().err(),
            })?;
        let contract = self.process_contract().map_err(|first| {
            OriginalActorParkQuiescenceError::Contract {
                first,
                original_after: original.wait_slice().err(),
            }
        })?;
        decoder.enter_park_quiescence(original, contract)
    }

    pub(crate) fn bind_readonly_backing_observation<'host, 'owner>(
        &'host self,
        binding: &'host OriginalNativeNodeBinding,
        decoder: &'owner OriginalActorDecodeOwner,
        original: &'owner Arc<HostOperationGuard>,
    ) -> Result<OriginalBoundBackingObservation<'host, 'owner>, OriginalActorAccountError> {
        if self.terminal {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let attempt = self
            .original_account
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        binding.verify_against(attempt, original)?;
        // This closed decoder entry checks the same private preparation Arc;
        // actual FD, parser and transport extents are admitted by capture.
        drop(decoder.prepare_readonly_backing_purpose(original)?);
        Ok(OriginalBoundBackingObservation {
            host: self,
            binding,
            decoder,
            original,
        })
    }
}

impl<'host, 'owner> OriginalBoundBackingObservation<'host, 'owner> {
    pub(crate) fn capture<S: QmpTimeoutStream>(
        self,
        client: &mut QmpClient<S>,
        visitor: &mut dyn for<'event> FnMut(BackingEvent<'event>) -> io::Result<()>,
    ) -> Result<QmpReadOnlyBackingReceipt, OriginalBackingObservationError<'owner>> {
        let attempt =
            self.host
                .original_account
                .as_ref()
                .ok_or(OriginalBackingObservationError::Binding(
                    OriginalActorAccountError::Unavailable,
                ))?;
        if self.host.terminal {
            return Err(OriginalBackingObservationError::Binding(
                OriginalActorAccountError::Unavailable,
            ));
        }
        self.binding
            .verify_against(attempt, self.original)
            .map_err(OriginalBackingObservationError::Binding)?;
        let purpose = self
            .decoder
            .prepare_readonly_backing_failure_owner(self.original)
            .map_err(OriginalBackingObservationError::Capture)?;
        let contract = self.host.process_contract().map_err(|source| {
            OriginalBackingObservationError::Contract {
                source,
                original_after: self.original.wait_slice().err(),
            }
        })?;
        capture_with_verified_contract(client, contract, purpose, visitor)
            .map_err(OriginalBackingObservationError::Capture)
    }
}
