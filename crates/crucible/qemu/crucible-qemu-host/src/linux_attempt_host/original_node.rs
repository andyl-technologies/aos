//! Binds original native generations to fresh nodes and their monitor operation.
//!
//! The witness enters the actual fresh factory before node exposure. A later
//! observation borrows that same host, generation and actor decoder; no PID,
//! caller-supplied flag, raw contract getter or replacement account grants it.

#[cfg(feature = "private-measurement-domain")]
use std::io;

mod helper_receiver;
pub use helper_receiver::QemuIssuedHelperHistory;
pub(super) mod retained_error;
pub use retained_error::RetainedNativeFreshLaunchError;
mod issuer;
pub use issuer::InstalledNodeLaunchIssuer;
use std::sync::{Arc, Mutex, OnceLock};

use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};

#[cfg(feature = "private-measurement-domain")]
use super::OriginalActorDecodeOwner;
use super::{LinuxQemuAttemptHostOwner, OriginalActorAccountError, OriginalNativeNodeBinding};
#[cfg(feature = "private-measurement-domain")]
use crate::qmp::readonly_backing_stream::{BackingEvent, QmpReadOnlyBackingReceipt};
#[cfg(feature = "private-measurement-domain")]
use crate::qmp::readonly_backing_transport::{
    BackingCaptureFailure, capture_with_verified_contract,
};
#[cfg(feature = "private-measurement-domain")]
use crate::qmp::{QmpClient, QmpTimeoutStream};
use crate::supervision::{
    QemuLiveNodeStepGateConfig, QemuLiveNodeStepGateError, QemuProductionFreshLaunchAdmission,
};
use crate::{QemuNode, QemuVmRealizationError};

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
    #[error("installed launch artifact refused: {0}")]
    Artifact(#[source] crate::artifact_identity::ControlledInstallerIdentityError),
    #[error("installed process purpose refused: {0}")]
    Purpose(#[source] super::InstalledProcessPurposeError),
}

/// Retains a fresh launch's first refusal and its independent original postcut.
///
/// A successfully created node stays inside this failure on a late refusal.
/// Dropping that uncertainty retains the actual node and its generation witness;
/// it cannot release the external native credit or authorize slot reuse.
#[must_use = "retain uncertain fresh launch custody through physical containment"]
pub struct OriginalNativeFreshLaunchError {
    origin: Arc<HostOperationGuard>,
    cleanup: OnceLock<Result<Arc<HostOperationGuard>, HostSupervisionError>>,
    primary: OnceLock<FreshLaunchCause>,
    original_after: OnceLock<HostSupervisionError>,
    node: Mutex<RetainedLaunch>,
    child_borrowed: std::sync::atomic::AtomicBool,
    helper: Mutex<helper_receiver::HelperDebt>,
    source_host: Option<retained_error::LaunchControllerFunding>,
    helper_first: OnceLock<crucible_engine::SharedOperationalCause<crate::QemuSpawnError>>,
    exact_launch: Mutex<Option<crate::QemuProductionExactRestoreLaunch>>,
    workspace: Mutex<Option<crate::spawn::OriginalDeviceDigestWorkspace>>,
}

#[derive(Default)]
struct RetainedLaunch {
    owner: Option<crate::QemuFailedLaunchOwner>,
    first_cleanup: Option<crate::QemuNodeError>,
    latest_cleanup: Option<crate::QemuNodeError>,
}

impl OriginalNativeFreshLaunchError {
    pub(super) fn prepare(
        origin: &Arc<HostOperationGuard>,
        funding: retained_error::LaunchControllerFunding,
    ) -> RetainedNativeFreshLaunchError {
        Self::prepare_body(origin, Some(funding))
    }

    #[cfg(test)]
    pub(super) fn prepare_unissued(
        origin: &Arc<HostOperationGuard>,
    ) -> RetainedNativeFreshLaunchError {
        Self::prepare_body(origin, None)
    }

    fn prepare_body(
        origin: &Arc<HostOperationGuard>,
        funding: Option<retained_error::LaunchControllerFunding>,
    ) -> RetainedNativeFreshLaunchError {
        RetainedNativeFreshLaunchError::new(Self {
            origin: Arc::clone(origin),
            cleanup: OnceLock::new(),
            primary: OnceLock::new(),
            original_after: OnceLock::new(),
            node: Mutex::new(RetainedLaunch::default()),
            child_borrowed: std::sync::atomic::AtomicBool::new(false),
            helper: Mutex::new(helper_receiver::HelperDebt::default()),
            source_host: funding,
            helper_first: OnceLock::new(),
            exact_launch: Mutex::new(None),
            workspace: Mutex::new(None),
        })
    }

    /// Borrows the same prepaid Main Source purpose for later native startup.
    ///
    /// # Errors
    /// Refuses absent genuine Main custody without creating a replacement payer.
    pub(super) fn retained_source_host(
        &self,
    ) -> Result<
        &crucible_host_resources::host_services::process_birth::AuthenticatedSourceHostPurpose,
        OriginalActorAccountError,
    > {
        self.source_host
            .as_ref()
            .map(|funding| &funding.host)
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(crate) fn reserve_child_owner(
        &self,
        lender: super::SourceCleanupLender,
        supervisor: crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Result<crate::node::SourceLaunchReservation, OriginalActorAccountError> {
        let current = lender.controller()?;
        if !std::ptr::eq(self, current.as_ref()) || self.primary.get().is_some() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let retained = self
            .node
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        if retained.owner.is_some()
            || self
                .child_borrowed
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        drop(retained);
        Ok(crate::node::SourceLaunchReservation::new(
            current, lender, supervisor,
        ))
    }

    pub(crate) fn launch_original(&self) -> Arc<HostOperationGuard> {
        Arc::clone(&self.origin)
    }

    pub(crate) fn finish_child_borrow(&self) {
        self.child_borrowed
            .store(false, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn return_issued_owner(&self, owner: crate::QemuFailedLaunchOwner) {
        // The unique prebirth reservation excludes any other owner publisher.
        // Only this pure move runs under the short recipient metadata lock.
        let mut retained = match self.node.lock() {
            Ok(retained) => retained,
            Err(poisoned) => poisoned.into_inner(),
        };
        retained.owner = Some(owner);
        self.finish_child_borrow();
    }

    pub(super) fn retained_cleanup(
        &self,
    ) -> Result<Arc<HostOperationGuard>, OriginalActorAccountError> {
        self.cleanup
            .get_or_init(|| self.origin.begin_original_cleanup_control().map(Arc::new))
            .as_ref()
            .map(Arc::clone)
            .map_err(|first| (*first).into())
    }

    pub(super) fn cleanup_matches(&self, original: &Arc<HostOperationGuard>) -> bool {
        self.cleanup
            .get()
            .and_then(|saved| saved.as_ref().ok())
            .is_some_and(|saved| Arc::ptr_eq(saved, original))
    }

    fn record(&self, primary: FreshLaunchCause, original_after: Option<HostSupervisionError>) {
        // Save the actual body before shared diagnostics expose the refusal.
        let mut primary = primary;
        let owner = match &mut primary {
            FreshLaunchCause::Launch(first) => first.take_retained_owner(),
            _ => None,
        };
        if let Some(owner) = owner {
            self.return_issued_owner(owner);
        }
        let _ = self.primary.set(primary);
        if let Some(after) = original_after {
            let _ = self.original_after.set(after);
        }
    }

    /// Continues the same held launch without replacing its saved Cleanup.
    ///
    /// Physical return is separate from this error's permanent primary/post
    /// health. Contention and poison keep the actual owner in its same field.
    #[must_use]
    pub fn retry_physical_cleanup(&self) -> bool {
        if !self.retry_retained_helper() {
            return false;
        }
        if self
            .child_borrowed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Ok(mut retained) = self.node.try_lock() else {
            return false;
        };
        let Some(owner) = retained.owner.as_mut() else {
            return true;
        };
        match owner.retry_cleanup() {
            Ok(()) => {
                let returned = retained.owner.take();
                drop(retained);
                drop(returned);
                true
            }
            Err(first) => {
                if retained.first_cleanup.is_none() {
                    retained.first_cleanup = Some(first);
                } else if retained.latest_cleanup.as_ref() != Some(&first) {
                    retained.latest_cleanup = Some(first);
                }
                false
            }
        }
    }

    pub(super) fn physical_owners_returned(&self) -> bool {
        if self
            .child_borrowed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Ok(helper) = self.helper.try_lock() else {
            return false;
        };
        if helper.child.is_some() {
            return false;
        }
        let Ok(retained) = self.node.try_lock() else {
            return false;
        };
        retained.owner.is_none()
    }

    /// Retains the exact node, its directory and root relation on a late refusal.
    pub(crate) fn retain_exact_launch(
        &self,
        launch: crate::QemuProductionExactRestoreLaunch,
        after: HostSupervisionError,
    ) {
        let _ = self.primary.set(FreshLaunchCause::Binding(
            OriginalActorAccountError::Supervision(after),
        ));
        let _ = self.original_after.set(after);
        *self
            .exact_launch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(launch);
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
            .field("helper_first", &self.helper_first)
            .field("original_after", &self.original_after)
            .field(
                "retains_node",
                &self
                    .node
                    .try_lock()
                    .map_or(true, |node| node.owner.is_some()),
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
        )?;
        if let Some(first) = self.helper_first.get() {
            write!(formatter, "; helper first: {}", first.source_ref())?;
        }
        match self.helper.try_lock() {
            Ok(held) => write!(
                formatter,
                "; helper before: {:?}; helper after: {:?}; helper cleanup first: {:?}; helper cleanup latest: {:?}",
                held.history().before,
                held.history().after,
                held.history().first_cleanup,
                held.history().latest_cleanup
            )?,
            Err(_) => formatter.write_str("; helper history retained behind unavailable access")?,
        }
        match self.node.try_lock() {
            Ok(held) => write!(
                formatter,
                "; cleanup first: {:?}; cleanup latest: {:?}",
                held.first_cleanup, held.latest_cleanup
            ),
            Err(_) => formatter.write_str("; cleanup history retained behind unavailable access"),
        }
    }
}

impl std::error::Error for OriginalNativeFreshLaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(primary) = self.primary.get() {
            return Some(primary);
        }

        match self.helper_first.get() {
            Some(first) => Some(first.source_ref()),
            None => None,
        }
    }
}

impl Drop for OriginalNativeFreshLaunchError {
    fn drop(&mut self) {
        let node = self
            .node
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(node) = node.owner.take() {
            // This is terminal containment, not resumable cleanup. The host's
            // physical owner remains responsible for the child; the outstanding
            // witness deliberately prevents vector/control credit reuse.
            std::mem::forget(node);
        }
        if let Some(launch) = self
            .exact_launch
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            std::mem::forget(launch);
        }
    }
}

pub(super) struct OriginalNativeFreshPreparation {
    // Physical failure storage closes before the final in-flight lease.
    failure: RetainedNativeFreshLaunchError,
    original: Arc<HostOperationGuard>,
    lease: FreshLaunchLease,
}

impl OriginalNativeFreshPreparation {
    pub(super) fn retain(
        original: &Arc<HostOperationGuard>,
        attempt: super::NativeAccountAttempt,
        controller: RetainedNativeFreshLaunchError,
    ) -> Self {
        Self {
            failure: controller,
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
    ) -> RetainedNativeFreshLaunchError {
        self.failure
            .record(FreshLaunchCause::Binding(source), Some(after));
        self.failure.clone()
    }

    pub(super) fn launch<'a, T>(
        &mut self,
        host: &'a LinuxQemuAttemptHostOwner,
        config: &'a QemuLiveNodeStepGateConfig,
        admission: QemuProductionFreshLaunchAdmission<'a>,
        complete: impl FnOnce(
            &'a QemuLiveNodeStepGateConfig,
            QemuProductionFreshLaunchAdmission<'a>,
            OriginalNativeNodeBinding,
            Option<crate::spawn::OriginalDeviceDigestWorkspace>,
        ) -> Result<T, QemuLiveNodeStepGateError>,
        retain_refusal: impl FnOnce(T, &OriginalNativeFreshLaunchError, HostSupervisionError),
    ) -> Result<T, RetainedNativeFreshLaunchError> {
        let (directory, identity) = admission.original_node_basis();
        self.launch_bound(
            host,
            config,
            |binding, workspace, contract| {
                let admission = QemuProductionFreshLaunchAdmission::admit(
                    config, directory, contract, identity,
                )?;
                complete(config, admission, binding, workspace)
            },
            retain_refusal,
        )
    }

    fn launch_bound<'a, T>(
        &mut self,
        host: &'a LinuxQemuAttemptHostOwner,
        config: &'a QemuLiveNodeStepGateConfig,
        complete: impl FnOnce(
            OriginalNativeNodeBinding,
            Option<crate::spawn::OriginalDeviceDigestWorkspace>,
            &'a crate::QemuChildProcessContract,
        ) -> Result<T, QemuLiveNodeStepGateError>,
        retain_refusal: impl FnOnce(T, &OriginalNativeFreshLaunchError, HostSupervisionError),
    ) -> Result<T, RetainedNativeFreshLaunchError> {
        self.enter();
        let failure = self.failure.clone();
        let launch =
            host.launch_original_node(config, &self.original, failure, complete, retain_refusal);
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
#[cfg(feature = "private-measurement-domain")]
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
#[cfg(feature = "private-measurement-domain")]
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
        match preparation.launch(
            self,
            config,
            admission,
            crate::supervision::launch_qemu_original_fresh_node,
            |node, failure, after| {
                let mut owner = crate::QemuFailedLaunchOwner::node(node);
                owner.require_source_cleanup(attempt.bound_source_cleanup_lender(failure));
                failure.return_issued_owner(owner);
                failure.record(
                    FreshLaunchCause::Binding(OriginalActorAccountError::Supervision(after)),
                    None,
                );
            },
        ) {
            Ok(node) => Ok(node),
            Err(error) => {
                let source = attempt.retain_launch_refusal(error);
                Err(QemuLiveNodeStepGateError::OriginalNativeLaunch { source })
            }
        }
    }

    /// Retains an admitted stopped child before the first guest resume.
    ///
    /// This uses the ordinary original issuer and stopped launch stage. The
    /// caller must retain this host while using the stage, and then physically
    /// reap the child. No raw PID, copied contract or replacement account can
    /// construct the returned owner.
    ///
    /// # Errors
    /// Refuses absent original custody, exhausted incarnation shares, actual
    /// launch failure or the independent original postcut. A late refusal reaps
    /// the actual child and retains unreaped custody in the typed failure.
    #[cfg(feature = "private-measurement-domain")]
    pub fn launch_paused_fresh_node<'a>(
        &'a self,
        config: &'a QemuLiveNodeStepGateConfig,
        admission: QemuProductionFreshLaunchAdmission<'a>,
    ) -> Result<crate::supervision::PausedLiveNodeLaunch<'a>, QemuLiveNodeStepGateError> {
        let attempt = self.original_account.as_ref().ok_or(
            QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: OriginalActorAccountError::Unavailable,
            },
        )?;
        let mut preparation = attempt
            .prepare_fresh_launch()
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
        match preparation.launch(
            self,
            config,
            admission,
            crate::supervision::prepare_qemu_original_fresh_node,
            |stage, failure, after| {
                let primary =
                    stage.reap_refused(QemuLiveNodeStepGateError::OriginalNativeAccount {
                        source: OriginalActorAccountError::Supervision(after),
                    });
                failure.record(FreshLaunchCause::Launch(primary), Some(after));
            },
        ) {
            Ok(stage) => Ok(stage),
            Err(error) => {
                let source = attempt.retain_launch_refusal(error);
                Err(QemuLiveNodeStepGateError::OriginalNativeLaunch { source })
            }
        }
    }

    /// Restores an exact node through this same retained installed issuer.
    ///
    /// # Errors
    /// Preserves actual materialization, issuer, launch and independent original
    /// refusals with the exact node, directory and repository relation retained.
    pub fn launch_exact_node(
        &self,
        request: crate::QemuProductionExactRestoreRequest,
    ) -> Result<crate::QemuProductionExactRestoreLaunch, QemuLiveNodeStepGateError> {
        self.lend_installed_node_issuer()?
            .launch_exact_node(request)
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
    fn launch_original_node<'a, T>(
        &'a self,
        config: &'a QemuLiveNodeStepGateConfig,
        original: &Arc<HostOperationGuard>,
        failure: RetainedNativeFreshLaunchError,
        complete: impl FnOnce(
            OriginalNativeNodeBinding,
            Option<crate::spawn::OriginalDeviceDigestWorkspace>,
            &'a crate::QemuChildProcessContract,
        ) -> Result<T, QemuLiveNodeStepGateError>,
        retain_refusal: impl FnOnce(T, &OriginalNativeFreshLaunchError, HostSupervisionError),
    ) -> Result<T, RetainedNativeFreshLaunchError> {
        let issuer = match self.lend_installed_node_issuer() {
            Ok(issuer) => issuer,
            Err(source) => {
                failure.record(
                    FreshLaunchCause::Launch(source),
                    original.wait_slice().err(),
                );
                return Err(failure);
            }
        };
        let contract = match self.process_contract() {
            Ok(contract) => contract,
            Err(source) => {
                failure.record(
                    FreshLaunchCause::Contract(source),
                    original.wait_slice().err(),
                );
                return Err(failure);
            }
        };
        issuer.launch_original_node(
            config,
            contract,
            original,
            failure,
            complete,
            retain_refusal,
        )
    }

    #[cfg(feature = "private-measurement-domain")]
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

    #[cfg(feature = "private-measurement-domain")]
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

    #[cfg(feature = "private-measurement-domain")]
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

#[cfg(feature = "private-measurement-domain")]
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
