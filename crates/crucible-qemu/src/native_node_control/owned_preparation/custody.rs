//! Reclaims the same actual initial Child without discarding original evidence.

// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    task::{Context, Poll},
};

use crucible::node_contract::{
    ActivationRecord, OperationFailure, PreparedNativeResources, PublicationStatus,
};

use crate::native_node_control::owned_operation::{
    NativeOwnedPrefixSession, NativeSessionCreateFailure,
};

pub(super) struct SessionSetup {
    pub(super) endpoint: crate::native_node_control::NativeAdministrationTransport,
    pub(super) path: PathBuf,
    pub(super) initialization: crucible_protocol::node_control::NativeInitializationReceipt,
    pub(super) budget: super::super::owned_operation::InitialEvidenceBudget,
}

// Retains the complete original archive offer even when creation leaves no Archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArchiveCreationOffer {
    pub(super) path: PathBuf,
    pub(super) scope: [u8; 32],
    pub(super) preparation: [u8; 32],
    pub(super) budget: super::super::owned_operation::ArchiveBudget,
}

pub(super) struct BareChild {
    pub(super) child: crate::QemuNodeChild,
    pub(super) archive: Option<super::super::owned_operation::Archive>,
    pub(super) archive_offer: Option<ArchiveCreationOffer>,
    pub(super) setup_failure: Option<OperationFailure>,
    pub(super) session_setup: Option<SessionSetup>,
}

pub(super) enum Resources {
    Unspawned,
    Bare(Box<BareChild>),
    Session(Box<NativeOwnedPrefixSession>),
    CreateFailure(Box<NativeSessionCreateFailure>),
}

pub(super) struct Custody {
    pub(super) resources: Resources,
    pub(super) target: ActivationRecord,
    pub(super) publication: Option<PublicationStatus>,
    pub(super) foreign_quarantine: bool,
    pub(super) cleanup_failure: Option<OperationFailure>,
}

pub(super) struct PreparedCapsule(pub(super) Rc<RefCell<Custody>>);

impl PreparedNativeResources for PreparedCapsule {
    fn quarantine_resources(
        &mut self,
        activation: &ActivationRecord,
        publication: Option<PublicationStatus>,
    ) {
        let mut custody = self.0.borrow_mut();
        if activation != &custody.target {
            custody.foreign_quarantine = true;
        } else {
            custody.publication = publication;
        }
        if let Resources::Session(session) = &mut custody.resources {
            session.quarantine();
        }
    }

    fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), OperationFailure>> {
        let mut custody = self.0.borrow_mut();
        let result = match &mut custody.resources {
            Resources::Bare(original) => original.child.poll_force_kill_and_reap_failed_helper(),
            Resources::Session(session) => session.poll_disposal(),
            Resources::CreateFailure(failure) => failure.poll_disposal(),
            Resources::Unspawned => return retained_cleanup_result(&mut custody),
        };
        match result {
            Ok(true) => retained_cleanup_result(&mut custody),
            Ok(false) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => {
                let failure = super::uncertain(error.to_string());
                if custody.cleanup_failure.is_none() {
                    custody.cleanup_failure = Some(failure.clone());
                }
                Poll::Ready(Err(failure))
            }
        }
    }
}

fn retained_cleanup_result(custody: &mut Custody) -> Poll<Result<(), OperationFailure>> {
    if custody.foreign_quarantine {
        let failure = custody.cleanup_failure.get_or_insert_with(|| {
            super::uncertain("QEMU initial quarantine target differs from original custody")
        });
        return Poll::Ready(Err(failure.clone()));
    }
    Poll::Ready(Ok(()))
}
