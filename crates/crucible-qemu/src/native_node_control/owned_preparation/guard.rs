//! Reserves and transfers original initial custody without a placeholder node.

// SPDX-License-Identifier: Apache-2.0

use std::{cell::RefCell, path::PathBuf, process::Child, rc::Rc};

use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, NodeRoute, OperationFailure, PreparedNativeResources, RuntimeCustodySlot,
        RuntimeLimits, WholeRuntimeCustody,
    },
};
use crucible_node_contract::{HashRef, Id, NodeBinding, NodeDescriptor};
use crucible_protocol::node_control::{
    NativeInitializationReceipt, NativePrefixPreparation, NativePrefixPreparationFacts,
};

use crate::native_node_control::{
    NativeAdministrationTransport,
    owned_operation::{
        Archive, ArchiveError, InitialEvidenceBudget, NativeOwnedPrefixSession,
        OriginalPreparationProgress,
    },
};

use super::{
    QemuInitialInstallationQualification, binding,
    custody::{Custody, PreparedCapsule, Resources},
};

pub(super) struct Guard {
    pub(super) custody: Rc<RefCell<Custody>>,
    pub(super) whole: Option<WholeRuntimeCustody>,
    pub(super) slot: Option<Box<dyn RuntimeCustodySlot>>,
    pub(super) target: ActivationRecord,
    pub(super) limits: RuntimeLimits,
    pub(super) binding: Option<binding::Binding>,
}

/// Reserves the original common world slot before native child or file effects.
///
/// This type can attach one unique child or Session exactly once. It cannot launch a
/// child, publish readiness or issue a command. Dropping an unused reservation
/// releases only its empty slot; attached resources always transfer to supervision.
pub struct QemuInitialReservation(pub(super) Guard);

/// Retains the complete unused reservation on installation or binding refusal.
pub struct QemuInitialReservationFailure {
    /// Explains the conversion refusal before native allocation.
    pub error: OperationFailure,
    /// Owns the original slot and empty preallocated capsule.
    pub reservation: QemuInitialReservation,
}

/// Retains actual native initial resources while full common qualification is pending.
///
/// Facts and consumed initial ACK are original protocol evidence. They never
/// create a common token or substitute for the missing complete source issuer.
pub struct QemuInitialPreparation(pub(super) Guard);

/// Retains the actual attached Session under the same common supervision slot.
pub struct QemuInitialPreparationFailure {
    /// Explains the attached constructor or current process mismatch.
    pub error: OperationFailure,
    /// Owns the actual Child, endpoint, archive and complete initial journal.
    pub preparation: QemuInitialPreparation,
}

impl QemuInitialReservation {
    /// Matches the complete graph and installed tuple before native allocation.
    ///
    /// The caller reserves `slot` before constructing any child or initial file.
    /// This constructor allocates the owning capsule and validates that same
    /// slot, complete indivisible owner and original constructor preparation.
    ///
    /// # Errors
    /// Returns the unchanged unused reservation on foreign world/limits,
    /// incompatible graph scope or missing measured installation qualification.
    pub fn reserve(
        graph: &AdmittedGraph,
        node: &Id,
        target: ActivationRecord,
        limits: RuntimeLimits,
        slot: Box<dyn RuntimeCustodySlot>,
        preparation: NativePrefixPreparation,
        installation: &dyn QemuInitialInstallationQualification,
    ) -> Result<Self, Box<QemuInitialReservationFailure>> {
        let custody = Rc::new(RefCell::new(Custody {
            resources: Resources::Unspawned,
            target: target.clone(),
            publication: None,
            foreign_quarantine: false,
            cleanup_failure: None,
        }));
        let whole = WholeRuntimeCustody::from_prepared_resources(
            Box::new(PreparedCapsule(Rc::clone(&custody))),
            target.clone(),
            None,
            limits,
        );
        let mut failure = Box::new(QemuInitialReservationFailure {
            error: super::refusal("QEMU initial reservation has not been validated"),
            reservation: Self(Guard {
                custody,
                whole: Some(whole),
                slot: Some(slot),
                target,
                limits,
                binding: None,
            }),
        });
        let guard = &mut failure.reservation.0;
        let result = (|| {
            let slot = guard
                .slot
                .as_ref()
                .ok_or_else(|| super::refusal("QEMU original slot is absent"))?;
            slot.validate_world(&guard.target, guard.limits)
                .map_err(|error| super::refusal(error.to_string()))?;
            binding::validate(graph, node, &guard.target, &preparation, installation)
        })();
        match result {
            Ok(binding) => {
                guard.binding = Some(binding);
                Ok(failure.reservation)
            }
            Err(error) => {
                failure.error = error;
                Err(failure)
            }
        }
    }

    /// Installs the same actual Session before any attached validation can fail.
    ///
    /// Typestate prevents replacing an already attached child. A foreign or
    /// failed Session remains inside the original reserved custody capsule.
    ///
    /// # Errors
    /// Returns the complete attached preparation for changed constructor bytes,
    /// missing accepted process identity or an earlier supervision refusal.
    pub fn attach(
        self,
        session: NativeOwnedPrefixSession,
    ) -> Result<QemuInitialPreparation, Box<QemuInitialPreparationFailure>> {
        let mut failure = Box::new(QemuInitialPreparationFailure {
            error: super::uncertain("QEMU attached preparation has not been validated"),
            preparation: QemuInitialPreparation(self.0),
        });
        let guard = &mut failure.preparation.0;
        let mut custody = guard.custody.borrow_mut();
        custody.resources = Resources::Session(Box::new(session));
        let Resources::Session(session) = &custody.resources else {
            drop(custody);
            return Err(failure);
        };
        let Some(binding) = guard.binding.as_ref() else {
            if let Resources::Session(session) = &mut custody.resources {
                session.quarantine();
            }
            drop(custody);
            return Err(failure);
        };
        if session.preparation() != Some(&binding.preparation)
            || session.supervision_refusal().is_some()
            || session.preparation_failure().is_some()
            || session.reaped()
        {
            failure.error =
                super::uncertain("QEMU attached original process or constructor differs");
            if let Resources::Session(session) = &mut custody.resources {
                session.quarantine();
            }
            drop(custody);
            return Err(failure);
        }
        drop(custody);
        Ok(failure.preparation)
    }

    /// Creates the initial Session beneath the already reserved common capsule.
    ///
    /// The factory obtains this reservation before spawning `child`. The failure
    /// owner is allocated before initial file effects; create/fsync refusal then
    /// stays under the same world slot with the actual Child and every original
    /// endpoint, archive, receipt and uncertain path.
    ///
    /// # Errors
    /// Returns the complete supervised preparation on Session storage or attached
    /// identity failure. No native admission, readiness or command is granted.
    pub fn create_session(
        self,
        child: Child,
        endpoint: NativeAdministrationTransport,
        archive: Archive,
        path: PathBuf,
        initialization: NativeInitializationReceipt,
        budget: InitialEvidenceBudget,
    ) -> Result<QemuInitialPreparation, Box<QemuInitialPreparationFailure>> {
        let launching = self.attach_spawned_child(child);
        if let Resources::Bare(original) = &mut launching.0.custody.borrow_mut().resources {
            original.archive = Some(archive);
        }
        launching.create_session(endpoint, path, initialization, budget)
    }
}

impl QemuInitialPreparation {
    /// Borrows the exact admitted immutable descriptor retained before native allocation.
    pub fn descriptor(&self) -> Option<&NodeDescriptor> {
        self.0.binding.as_ref().map(|binding| &binding.descriptor)
    }

    /// Borrows the exact full admitted binding without issuing native permission.
    pub fn binding(&self) -> Option<&NodeBinding> {
        self.0.binding.as_ref().map(|binding| &binding.node)
    }

    /// Borrows the indivisible original participant/owner route.
    pub fn route(&self) -> Option<&NodeRoute> {
        self.0.binding.as_ref().map(|binding| &binding.route)
    }

    /// Borrows the complete original world identity, without readiness publication.
    pub fn world_binding_hash(&self) -> Option<&HashRef> {
        self.0.binding.as_ref().map(|binding| &binding.world)
    }

    /// Copies only the original observed initial facts, without Ready promotion.
    pub fn facts(&self) -> Option<NativePrefixPreparationFacts> {
        let custody = self.0.custody.borrow();
        match &custody.resources {
            Resources::Session(session) => session.facts().cloned(),
            _ => None,
        }
    }

    /// Advances the original initial protocol while retaining common supervision.
    ///
    /// # Errors
    /// Retains every owner on process, storage or original protocol failure.
    /// No Compute, common grant, callback or readiness is exposed by this method.
    pub fn poll_initial(&mut self) -> Result<OriginalPreparationProgress, ArchiveError> {
        match &mut self.0.custody.borrow_mut().resources {
            Resources::Session(session) => session.poll(),
            _ => Err(ArchiveError::Failed),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let empty = {
            let custody = self.custody.borrow();
            matches!(custody.resources, Resources::Unspawned)
        };
        if empty {
            // No child was ever attached: only unused host reservation capacity
            // is released, without claiming a native reclamation receipt.
            return;
        }
        PreparedCapsule(Rc::clone(&self.custody)).quarantine_resources(&self.target, None);
        if let (Some(slot), Some(whole)) = (self.slot.take(), self.whole.take()) {
            // The complete capsule and runtime wrapper predate native allocation.
            // Transfer consumes those exact objects without allocating on Drop.
            slot.retain(whole);
        }
    }
}
