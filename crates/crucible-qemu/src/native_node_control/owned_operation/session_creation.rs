//! Preserves the actual process owner across initial file-creation refusal.
//!
//! A live child never disappears behind a filesystem `?` path. The failure
//! capsule owns its endpoint, vacant archive, complete Applied receipt and
//! intended file path before create/fsync, including an uncertain partial file.

// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

use crucible_protocol::node_control::{NativeInitializationReceipt, NativePrefixPreparation};

use crate::native_node_control::NativeAdministrationTransport;
use crate::{QemuNodeChild, QemuShutdownTargetError};

use super::{
    Archive, ArchiveError, InitialEvidenceBudget, InitialEvidenceStore, NativeOwnedPrefixSession,
    TurnoverState,
};

/// Retains the live original owners when initial durable storage cannot be created.
///
/// The original path stays reserved by any existing or partial bytes. Disposal
/// only contains the child; it never removes that file or reports NoEffects.
pub struct NativeSessionCreateFailure {
    child: QemuNodeChild,
    endpoint: NativeAdministrationTransport,
    archive: Archive,
    path: PathBuf,
    initialization: NativeInitializationReceipt,
    budget: InitialEvidenceBudget,
    error: Option<ArchiveError>,
}

impl NativeSessionCreateFailure {
    /// Returns the actual retained child identifier.
    pub fn process_id(&self) -> u32 {
        self.child.process_id()
    }

    /// Reports only an actual observed child reap.
    pub fn reaped(&self) -> bool {
        self.child.reaped()
    }

    /// Borrows the original filesystem or correlation refusal.
    pub fn error(&self) -> Option<&ArchiveError> {
        self.error.as_ref()
    }

    /// Borrows the unchanged source preparation, if the endpoint has one.
    pub fn preparation(&self) -> Option<&NativePrefixPreparation> {
        self.endpoint.prefix_preparation()
    }

    /// Borrows the independently retained complete Applied receipt.
    pub fn initialization(&self) -> &NativeInitializationReceipt {
        &self.initialization
    }

    /// Borrows the intended original path, including an existing or uncertain file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the declared lifetime evidence allowance.
    pub fn budget(&self) -> InitialEvidenceBudget {
        self.budget
    }

    /// Returns the unchanged command archive fence.
    pub fn archive_state(&self) -> TurnoverState {
        self.archive.state()
    }

    /// Force-kills and boundedly reaps the same child while retaining all original evidence.
    ///
    /// # Errors
    /// Retains the unique wait authority on kernel failure or deadline exhaustion.
    /// This failure capsule has no send, execution or storage cleanup method.
    pub fn dispose(&mut self, timeout: Duration) -> Result<(), QemuShutdownTargetError> {
        self.child.force_kill_and_reap_failed_helper(timeout)
    }

    /// Polls actual containment without blocking the owning supervisor.
    ///
    /// # Errors
    /// Preserves this complete failure capsule on kernel failure. A false result
    /// requires another actor poll; it cannot release the original wait owner.
    pub fn poll_disposal(&mut self) -> Result<bool, QemuShutdownTargetError> {
        self.child.poll_force_kill_and_reap_failed_helper()
    }
}

impl NativeOwnedPrefixSession {
    /// Retains the live child before creating or fsyncing initial evidence.
    ///
    /// The constructor stores complete original companions before any Query.
    /// An already existing file stays unchanged. Returned sessions still require
    /// authentic source facts and consumed ACK before command reservation.
    ///
    /// # Errors
    /// Returns the complete child, endpoint, archive, receipt and intended path
    /// on missing preparation, invalid correlation, storage exhaustion, collision
    /// or create/fsync failure. Uncertain partial files remain at the same path.
    pub fn create(
        child: Child,
        endpoint: NativeAdministrationTransport,
        archive: Archive,
        path: impl AsRef<Path>,
        initialization: NativeInitializationReceipt,
        budget: InitialEvidenceBudget,
    ) -> Result<Self, Box<NativeSessionCreateFailure>> {
        Self::create_owned(
            QemuNodeChild::new(child),
            endpoint,
            archive,
            path.as_ref().to_path_buf(),
            initialization,
            budget,
        )
    }

    // Keeps the already attached unique wait owner across durable-store setup.
    pub(crate) fn create_owned(
        child: QemuNodeChild,
        endpoint: NativeAdministrationTransport,
        archive: Archive,
        path: PathBuf,
        initialization: NativeInitializationReceipt,
        budget: InitialEvidenceBudget,
    ) -> Result<Self, Box<NativeSessionCreateFailure>> {
        let mut failure = Box::new(NativeSessionCreateFailure {
            child,
            endpoint,
            archive,
            path,
            initialization,
            budget,
            error: None,
        });
        let Some(preparation) = failure.endpoint.prefix_preparation().cloned() else {
            failure.error = Some(ArchiveError::Conflict);
            return Err(failure);
        };
        let initial = match InitialEvidenceStore::create(
            &failure.path,
            preparation,
            failure.initialization.clone(),
            failure.budget,
        ) {
            Ok(initial) => initial,
            Err(error) => {
                failure.error = Some(error);
                return Err(failure);
            }
        };
        let NativeSessionCreateFailure {
            child,
            endpoint,
            archive,
            ..
        } = *failure;
        Ok(Self::retain_owned(child, endpoint, archive, initial))
    }
}
