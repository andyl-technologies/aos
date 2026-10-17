//! Attaches the unique child before endpoint or durable archive setup can fail.

// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, process::Child};

use crucible::node_contract::OperationFailure;
use crucible_protocol::node_control::NativeInitializationReceipt;

use crate::{
    QemuNodeChild,
    native_node_control::{
        NativeAdministrationTransport,
        owned_operation::{
            Archive, ArchiveBudget, ArchiveError, InitialEvidenceBudget, NativeOwnedPrefixSession,
        },
    },
};

use super::{
    custody::{ArchiveCreationOffer, BareChild, Resources, SessionSetup},
    guard::{Guard, QemuInitialPreparation, QemuInitialPreparationFailure, QemuInitialReservation},
};

/// Supervises the original spawned child throughout fallible factory setup.
///
/// Dropping this owner transfers its child and any retained archive into the
/// same reserved common slot. It cannot expose a raw child, execute a command,
/// or issue readiness. Setup refusal permanently fences Session conversion.
pub struct QemuInitialLaunching(pub(super) Guard);

impl QemuInitialReservation {
    /// Attaches the actual child immediately after the factory spawns it.
    ///
    /// Call this before endpoint, archive or initial-evidence setup. This move
    /// performs no native admission or filesystem operation. Typestate prevents
    /// a second child from replacing the unique wait owner.
    pub fn attach_spawned_child(self, child: Child) -> QemuInitialLaunching {
        self.0.custody.borrow_mut().resources = Resources::Bare(Box::new(BareChild {
            child: QemuNodeChild::new(child),
            archive: None,
            archive_offer: None,
            setup_failure: None,
            session_setup: None,
        }));
        QemuInitialLaunching(self.0)
    }
}

impl QemuInitialLaunching {
    /// Returns the actual child identifier while factory setup remains incomplete.
    pub fn process_id(&self) -> Option<u32> {
        match &self.0.custody.borrow().resources {
            Resources::Bare(original) => Some(original.child.process_id()),
            _ => None,
        }
    }

    /// Copies the intended archive path, including uncertain partial storage.
    pub fn archive_path(&self) -> Option<PathBuf> {
        match &self.0.custody.borrow().resources {
            Resources::Bare(original) => original
                .archive_offer
                .as_ref()
                .map(|offer| offer.path.clone()),
            _ => None,
        }
    }

    /// Copies the first retained setup refusal without releasing child custody.
    pub fn setup_failure(&self) -> Option<OperationFailure> {
        match &self.0.custody.borrow().resources {
            Resources::Bare(original) => original.setup_failure.clone(),
            _ => None,
        }
    }

    /// Creates and retains the exclusive command archive beneath child custody.
    ///
    /// The intended path, complete scope, preparation and budget are retained
    /// before create or fsync. An existing or
    /// partial file is never removed. Success retains the archive in this guard,
    /// so later endpoint setup failure cannot discard its original evidence.
    ///
    /// # Errors
    /// Returns storage or budget refusal while keeping the original child and
    /// path. Any refusal fences later creation; repeated setup cannot replace
    /// an archive or reuse an uncertain original path.
    pub fn create_archive(
        &mut self,
        path: PathBuf,
        scope: [u8; 32],
        preparation: [u8; 32],
        budget: ArchiveBudget,
    ) -> Result<(), ArchiveError> {
        let mut custody = self.0.custody.borrow_mut();
        let Resources::Bare(original) = &mut custody.resources else {
            return Err(ArchiveError::Failed);
        };
        if original.archive_offer.is_some()
            || original.archive.is_some()
            || original.setup_failure.is_some()
        {
            return Err(ArchiveError::Failed);
        }
        original.archive_offer = Some(ArchiveCreationOffer {
            path,
            scope,
            preparation,
            budget,
        });
        let offer = original
            .archive_offer
            .as_ref()
            .ok_or(ArchiveError::Failed)?;
        let result = Archive::create(&offer.path, offer.scope, offer.preparation, offer.budget);
        match result {
            Ok(archive) => {
                original.archive = Some(archive);
                Ok(())
            }
            Err(error) => {
                original.setup_failure = Some(super::uncertain(error.to_string()));
                Err(error)
            }
        }
    }

    /// Fences failed endpoint setup while preserving the original child and files.
    pub fn refuse_setup(self, reason: impl Into<String>) -> Box<QemuInitialPreparationFailure> {
        let error = super::uncertain(reason);
        if let Resources::Bare(original) = &mut self.0.custody.borrow_mut().resources
            && original.setup_failure.is_none()
        {
            original.setup_failure = Some(error.clone());
        }
        Box::new(QemuInitialPreparationFailure {
            error,
            preparation: QemuInitialPreparation(self.0),
        })
    }

    /// Consumes the same attached child and retained archive into initial Session custody.
    ///
    /// All supplied endpoint and receipt owners move into the Session creation
    /// capsule before initial file effects. Setup refusals leave the Bare child
    /// supervised; successful setup never extracts or replaces its wait owner.
    ///
    /// # Errors
    /// Retains the original child and files under the same slot on earlier setup,
    /// missing archive, initial-store failure or changed constructor identity.
    pub fn create_session(
        self,
        endpoint: NativeAdministrationTransport,
        path: PathBuf,
        initialization: NativeInitializationReceipt,
        budget: InitialEvidenceBudget,
    ) -> Result<QemuInitialPreparation, Box<QemuInitialPreparationFailure>> {
        let ready = {
            let mut custody = self.0.custody.borrow_mut();
            match &mut custody.resources {
                Resources::Bare(original) => {
                    original.session_setup = Some(SessionSetup {
                        endpoint,
                        path,
                        initialization,
                        budget,
                    });
                    original.setup_failure.is_none() && original.archive.is_some()
                }
                _ => false,
            }
        };
        if !ready {
            return Err(self.refuse_setup("QEMU original factory setup is incomplete or refused"));
        }

        let resources = std::mem::replace(
            &mut self.0.custody.borrow_mut().resources,
            Resources::Unspawned,
        );
        let Resources::Bare(mut original) = resources else {
            return Err(self.refuse_setup("QEMU original child custody is absent"));
        };
        let Some(setup) = original.session_setup.take() else {
            self.0.custody.borrow_mut().resources = Resources::Bare(original);
            return Err(self.refuse_setup("QEMU original endpoint setup custody is absent"));
        };
        let Some(archive) = original.archive.take() else {
            original.session_setup = Some(setup);
            self.0.custody.borrow_mut().resources = Resources::Bare(original);
            return Err(self.refuse_setup("QEMU original archive custody is absent"));
        };
        let original = *original;

        match NativeOwnedPrefixSession::create_owned(
            original.child,
            setup.endpoint,
            archive,
            setup.path,
            setup.initialization,
            setup.budget,
        ) {
            Ok(session) => QemuInitialReservation(self.0).attach(session),
            Err(original) => {
                self.0.custody.borrow_mut().resources = Resources::CreateFailure(original);
                Err(Box::new(QemuInitialPreparationFailure {
                    error: super::uncertain("QEMU original Session create/fsync refused"),
                    preparation: QemuInitialPreparation(self.0),
                }))
            }
        }
    }
}
