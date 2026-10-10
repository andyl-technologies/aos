//! Retains actual Root world custody until both supervisors prove reclamation.
//!
//! The namespace pin comes from the original installed preparation, never a
//! caller path. A completed request or closed channel supplies no reclamation
//! evidence. Poll failures preserve the same owner and all original obligations.

use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    task::{Context, Poll},
};

use crucible::node_contract::{ActivationRecord, QuarantinedRuntime, RuntimeCustodyQueue};

use super::{custody::RootCustodyQueue, factory::RootNativeFactory, installed::RootColdPlan};
use crate::node_observed_executor::{NodeObservedError, factory::refused};

pub(super) struct RootRetirementScope {
    pub(super) target: ActivationRecord,
    native: RootCustodyQueue,
    runtime: RuntimeCustodyQueue,
    namespace: PinnedNamespace,
}

impl RootRetirementScope {
    pub(super) fn new(
        target: ActivationRecord,
        namespace: &Path,
        native: RootCustodyQueue,
        runtime: RuntimeCustodyQueue,
    ) -> Result<Self, NodeObservedError> {
        native.publication_knowledge(&target)?;
        Ok(Self {
            target,
            native,
            runtime,
            namespace: PinnedNamespace::new(namespace)?,
        })
    }

    pub(super) fn cleanup_status(
        &self,
    ) -> Result<super::InstalledRootCleanupStatus, NodeObservedError> {
        self.native.cleanup_status(&self.target)
    }

    pub(super) fn namespace(&self) -> &Path {
        &self.namespace.path
    }

    pub(super) fn begin_unstarted(
        self,
        factory: Rc<RootNativeFactory>,
        original: RootColdPlan,
    ) -> InstalledRootRetirement {
        InstalledRootRetirement {
            scope: self,
            _factory: factory,
            quarantine: None,
            unstarted: Some(original),
            reclaimed: false,
        }
    }

    pub(super) fn begin(
        self,
        factory: Rc<RootNativeFactory>,
        quarantine: Option<QuarantinedRuntime>,
    ) -> InstalledRootRetirement {
        InstalledRootRetirement {
            scope: self,
            _factory: factory,
            quarantine,
            unstarted: None,
            reclaimed: false,
        }
    }
}

/// Owns original Root containment and the exact pinned private namespace.
///
/// It exposes no execution or native capture interface. The actor retains this
/// value and its original request/GC roots while polling the authentic queues.
/// An unstarted restore retains the original unused lease instead of asserting
/// that an absent child was reclaimed. Runtime supervision remains mandatory.
/// The actor-local runtime queue must be completely reclaimed before namespace
/// removal; another live world conservatively keeps this operation pending.
pub struct InstalledRootRetirement {
    scope: RootRetirementScope,
    _factory: Rc<RootNativeFactory>,
    quarantine: Option<QuarantinedRuntime>,
    unstarted: Option<RootColdPlan>,
    reclaimed: bool,
}

impl InstalledRootRetirement {
    /// Reads this retained target's native cleanup state without advancing it.
    ///
    /// The snapshot grants no reclamation or namespace-release authority. It
    /// neither probes a caller PID nor polls, commands, or reaps the native peer.
    ///
    /// # Errors
    /// Refuses an absent original queue entry; the same owning handle is retained.
    pub fn cleanup_status(&self) -> Result<super::InstalledRootCleanupStatus, NodeObservedError> {
        self.scope.cleanup_status()
    }

    /// Polls original runtime and exact-target native reclamation without execution.
    ///
    /// # Errors
    /// Returns native cleanup, foreign reservation or supervisor evidence errors.
    /// Every error retains the same complete custody and pinned namespace.
    pub fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), NodeObservedError>> {
        if self.reclaimed {
            return Poll::Ready(Ok(()));
        }
        if let Some(quarantine) = &mut self.quarantine {
            match quarantine.poll_reclamation(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(refused(&error.to_string())));
                }
                Poll::Ready(Ok(())) => {
                    // Drop transfers the same released world and original ledger
                    // into its pre-reserved actor-local mailbox before native Drop.
                    drop(self.quarantine.take());
                }
            }
        }
        match self.scope.runtime.poll_reclamation(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(refused(&error.to_string()))),
            Poll::Ready(Ok(())) => {}
        }
        if let Some(original) = &self.unstarted {
            let Some(owner) = original
                .target
                .owners
                .iter()
                .find(|owner| owner.owner.as_str() == "owner/root")
            else {
                return Poll::Ready(Err(refused("Root original unused owner absent")));
            };
            // This owned plan can exist here only after the factory consumed
            // its still-unused cold lease. A missing native entry or world is
            // never substituted for that explicit original reservation proof.
            if let Err(error) =
                self.scope
                    .native
                    .verify_reserved(&self.scope.target, owner, &original.archive)
            {
                return Poll::Ready(Err(error));
            }
            self.reclaimed = true;
            return Poll::Ready(Ok(()));
        }
        match self
            .scope
            .native
            .original_group_reclaimed(&self.scope.target)
        {
            Ok(true) => {
                self.reclaimed = true;
                Poll::Ready(Ok(()))
            }
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    /// Removes only the original namespace after authentic complete reclamation.
    ///
    /// # Errors
    /// Returns the same owning handle if cleanup is incomplete, the original
    /// directory identity changed, or removal fails. No other path is accepted.
    pub fn release_namespace(self) -> Result<(), Box<RootNamespaceReleaseFailure>> {
        if !self.reclaimed {
            return Err(Box::new(RootNamespaceReleaseFailure {
                error: refused("Root namespace still has original reclamation obligations"),
                retirement: self,
            }));
        }
        if let Err(error) = self.scope.namespace.remove() {
            return Err(Box::new(RootNamespaceReleaseFailure {
                error,
                retirement: self,
            }));
        }
        Ok(())
    }
}

/// Retains original containment when its namespace cannot be released safely.
pub struct RootNamespaceReleaseFailure {
    /// Describes the unmet original reclamation or namespace precondition.
    pub error: NodeObservedError,
    /// Owns the same supervisors, original factory and namespace pin.
    pub retirement: InstalledRootRetirement,
}

pub(super) struct PinnedNamespace {
    path: PathBuf,
    directory: File,
}

impl PinnedNamespace {
    pub(super) fn new(path: &Path) -> Result<Self, NodeObservedError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(path)
            .map_err(|error| refused(&error.to_string()))?;
        let pinned = Self {
            path: path.to_owned(),
            directory,
        };
        pinned.authenticate()?;
        Ok(pinned)
    }

    fn authenticate(&self) -> Result<(), NodeObservedError> {
        let current =
            std::fs::symlink_metadata(&self.path).map_err(|error| refused(&error.to_string()))?;
        let pinned = self
            .directory
            .metadata()
            .map_err(|error| refused(&error.to_string()))?;
        if !current.is_dir()
            || !pinned.is_dir()
            || current.dev() != pinned.dev()
            || current.ino() != pinned.ino()
            || current.uid() != rustix::process::getuid().as_raw()
            || current.mode() & 0o077 != 0
            || self.path.canonicalize().ok().as_ref() != Some(&self.path)
        {
            return Err(refused(
                "Root namespace differs from its original private directory",
            ));
        }
        Ok(())
    }

    pub(super) fn remove(&self) -> Result<(), NodeObservedError> {
        self.authenticate()?;
        std::fs::remove_dir_all(&self.path).map_err(|error| refused(&error.to_string()))
    }
}

impl std::fmt::Debug for InstalledRootRetirement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledRootRetirement")
            .field("target", &self.scope.target.activation_id)
            .field("reclaimed", &self.reclaimed)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RootNamespaceReleaseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootNamespaceReleaseFailure")
            .field("error", &self.error)
            .field("retirement", &self.retirement)
            .finish_non_exhaustive()
    }
}
