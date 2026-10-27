//! Retains the real checkpoint original with its actual process-status owner.
//!
//! The registered node lends its existing supervisor, service account and
//! process-contract cancellation alias. Quiescence begins once, before capture
//! effects, and remains held across retries. The actual receiver joins through
//! the registered client and QMP begin; fixed bytes alone never authorize capture.
//!
//! ```text
//! retained body: entered Quiescence + original 80-byte basis + registered target
//! external lease: actual body/control bytes; subscriber: same event + own lease
//! release boundary: matched native final disposition or observed child reap
//! ```

use std::alloc::Layout;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use crucible_host_resources::host_services::{HostServiceError, HostServiceLease};
use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_host_resources::ram_policy::HostRamTarget;
use crucible_qemu_protocol::ram_control::{RamControlDisposition, RamControlError};

use crate::ram_control::CheckpointArmReceipt;

/// Names the typed refusal at checkpoint original admission or receiving.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointOriginalCause {
    /// The actual node lacks its registered supervisor, account or event owner.
    #[error("registered checkpoint original owner is absent")]
    MissingOwner,
    /// The borrowing node cannot lend its genuine current installed Source.
    #[error("checkpoint original installed Source binding is unavailable")]
    SourceBindingUnavailable,
    /// This registration has no genuine held native checkpoint request receiver.
    #[error("checkpoint original native receiving transaction is unavailable")]
    NativeReceiverUnavailable,
    /// Same-account body or subscriber admission refused before descriptor birth.
    #[error("checkpoint original service admission refused: {0}")]
    Account(#[source] HostServiceError),
    /// The entered original expired, canceled or refused its immutable basis.
    #[error("checkpoint original supervision refused: {0}")]
    Original(#[source] HostSupervisionError),
    /// Duplicating the same retained kernel event failed.
    #[error("checkpoint original cancellation alias failed: {0}")]
    Kernel(#[source] rustix::io::Errno),
    /// The actual descriptor-bound ARM transport refused its retained request.
    #[error("checkpoint ARM transport refused: {0}")]
    Transport(#[source] CheckpointTransportCause),
    /// Native receipt preserves its initiating status and independent postcut.
    #[error(
        "checkpoint ARM native receipt refused: {disposition:?}, first {first_status}, post {post_status}"
    )]
    NativeReceipt {
        /// Actual observed receiver disposition.
        disposition: RamControlDisposition,
        /// Raw initiating native status.
        first_status: i32,
        /// Independent raw native postcut status.
        post_status: i32,
    },
    /// Checked fixed control extent could not be represented.
    #[error("checkpoint original control extent is unrepresentable")]
    Geometry,
}

/// Retains a bounded typed ARM transport cause without allocating diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointTransportCause {
    /// Canonical record syntax failed.
    #[error("invalid frame")]
    InvalidFrame,
    /// A different immediate-cutover protocol was observed.
    #[error("unsupported schema {0}")]
    UnsupportedVersion(u32),
    /// Actual session, target, sequence, or request binding failed.
    #[error("authority mismatch")]
    AuthorityMismatch,
    /// A record exceeded its fixed bound.
    #[error("oversized frame")]
    TooLarge,
    /// The actual kernel transport returned this error kind and optional errno.
    #[error("I/O {kind:?}, errno {errno:?}")]
    Io {
        /// Actual I/O category.
        kind: std::io::ErrorKind,
        /// Actual raw kernel errno when supplied.
        errno: Option<i32>,
    },
}

impl From<RamControlError> for CheckpointTransportCause {
    fn from(error: RamControlError) -> Self {
        match error {
            RamControlError::InvalidFrame => Self::InvalidFrame,
            RamControlError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            RamControlError::AuthorityMismatch => Self::AuthorityMismatch,
            RamControlError::TooLarge => Self::TooLarge,
            RamControlError::Io(error) => Self::Io {
                kind: error.kind(),
                errno: error.raw_os_error(),
            },
        }
    }
}

/// Preserves the first checkpoint refusal and its separate original postcut.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{source}; original postcut: {original_after:?}")]
pub struct CheckpointOriginalError {
    /// First actual typed refusal without an allocating diagnostic conversion.
    #[source]
    pub source: CheckpointOriginalCause,
    /// Independent typed original refusal after the attempted operation.
    pub original_after: Option<HostSupervisionError>,
}

impl CheckpointOriginalError {
    pub(crate) const fn before(source: CheckpointOriginalCause) -> Self {
        Self {
            source,
            original_after: None,
        }
    }
}

// The descriptor is destroyed before its external same-account credit.
#[derive(Debug)]
struct NativeTransfer {
    cancellation: OwnedFd,
    _credit: HostServiceLease,
}

/// Shares the already entered original with transport and retained spool owners.
///
/// The private owner admits this allocation in the same service account before
/// operation birth. Cloning the loan neither enters nor renews an operation.
/// The final loan frees the shared allocation before returning its original
/// service credit. Raw strong and weak references never leave this owner.
#[derive(Clone, Debug)]
pub struct CheckpointOriginalLoan {
    body: Option<Arc<LoanBody>>,
}

#[derive(Debug)]
struct LoanBody {
    original: HostOperationGuard,
    _credit: HostServiceLease,
}

impl CheckpointOriginalLoan {
    pub(crate) fn guard(&self) -> &HostOperationGuard {
        &self.shared().original
    }

    /// Rechecks the entered original and its retained cancellation subscriber.
    ///
    /// # Errors
    /// Refuses the same original's cancellation, deadline or policy boundary.
    pub(crate) fn check(&self) -> Result<(), HostSupervisionError> {
        self.guard().check_original_quiescence_cancellation()?;
        self.guard().wait_slice()?;
        self.guard().check_original_quiescence_cancellation()
    }

    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.shared(), other.shared())
    }

    fn shared(&self) -> &Arc<LoanBody> {
        match &self.body {
            Some(body) => body,
            None => unreachable!("a live checkpoint loan retains its original allocation"),
        }
    }

    fn allocation_bytes() -> Result<u64, CheckpointOriginalError> {
        let (layout, _) = Layout::new::<(AtomicUsize, AtomicUsize)>()
            .extend(Layout::new::<LoanBody>())
            .map_err(|_| CheckpointOriginalError::before(CheckpointOriginalCause::Geometry))?;
        u64::try_from(layout.pad_to_align().size())
            .ok()
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes()))
            .ok_or_else(|| CheckpointOriginalError::before(CheckpointOriginalCause::Geometry))
    }
}

impl Drop for CheckpointOriginalLoan {
    fn drop(&mut self) {
        if let Some(body) = self.body.take() {
            // All aliases use this closed owner. Even concurrent final drops
            // extract exactly one body after the actual Arc header is freed.
            drop(Arc::into_inner(body));
        }
    }
}

/// Lends one retained checkpoint original to its registered RAM control client.
///
/// Only the actual child original constructs this non-cloneable loan. Its fixed
/// basis, cancellation alias, supervisor, and account remain retained in that
/// child through native final disposition or actual reap. This loan cannot be
/// constructed from an operator target, request bytes, or a copied generation.
pub struct CheckpointArmLoan<'a> {
    original: &'a CheckpointOriginalLoan,
    basis: &'a [u8; 80],
    cancellation: &'a OwnedFd,
    target: HostRamTarget,
    supervisor: &'a HostOperationSupervisor,
    account: &'a crucible_host_resources::host_services::HostServiceAllocator,
    receipt: &'a mut Option<CheckpointArmReceipt>,
}

impl CheckpointArmLoan<'_> {
    /// Returns the actual original's registered target.
    #[must_use]
    pub fn target(&self) -> HostRamTarget {
        self.target
    }

    /// Checks identity with the actual retained supervisor allocation.
    #[must_use]
    pub fn matches_supervisor(&self, supervisor: &HostOperationSupervisor) -> bool {
        self.supervisor == supervisor
    }

    /// Returns a bounded wait slice from the existing original and subscriber.
    ///
    /// # Errors
    /// Refuses the same original's cancellation, deadline, or live policy.
    pub fn wait_slice(&self) -> Result<Duration, CheckpointOriginalError> {
        self.original.check().map_err(|source| {
            CheckpointOriginalError::before(CheckpointOriginalCause::Original(source))
        })?;
        self.original.guard().wait_slice().map_err(|source| {
            CheckpointOriginalError::before(CheckpointOriginalCause::Original(source))
        })
    }

    pub(crate) fn original(&self) -> &CheckpointOriginalLoan {
        self.original
    }

    pub(crate) fn basis(&self) -> &[u8; 80] {
        self.basis
    }

    pub(crate) fn cancellation(&self) -> &OwnedFd {
        self.cancellation
    }

    pub(crate) fn account(&self) -> &crucible_host_resources::host_services::HostServiceAllocator {
        self.account
    }

    pub(crate) fn record_receipt(&mut self, receipt: CheckpointArmReceipt) {
        *self.receipt = Some(receipt);
    }
}

#[derive(Debug)]
struct OriginalBody {
    native_transfer: Option<NativeTransfer>,
    arm_receipt: Option<CheckpointArmReceipt>,
    original: Option<CheckpointOriginalLoan>,
    basis: Option<[u8; 80]>,
    target: HostRamTarget,
    supervisor: HostOperationSupervisor,
    account: crucible_host_resources::host_services::HostServiceAllocator,
    first_refusal: Option<CheckpointOriginalError>,
}

// Receiving means local original/event custody has entered the native handoff,
// even if capability or purpose admission refuses before a transport write.
// It never certifies that a native receiver accepted this transaction.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum ReceiverCustody {
    #[default]
    Local,
    Receiving,
    Reaped,
}

/// Keeps concrete original body allocation before its external same-account loan.
#[derive(Debug)]
pub(crate) struct CheckpointOriginal {
    body: Option<Box<OriginalBody>>,
    receiver_custody: ReceiverCustody,
    control: Option<HostServiceLease>,
}

impl CheckpointOriginal {
    /// Admits the exact registered node's owner before entering Quiescence.
    ///
    /// The caller installs this owner in the actual Child before calling
    /// `enter`. Cloning the retained supervisor and account creates aliases of
    /// their existing controls, rather than a replacement issuer or bank.
    ///
    /// # Errors
    /// Refuses unrepresentable fixed geometry or same-account body admission.
    pub(crate) fn allocate(
        supervisor: &HostOperationSupervisor,
        registration: &crate::ram_control::RamControlRegistration,
    ) -> Result<Self, CheckpointOriginalError> {
        Self::allocate_registered_owner(
            supervisor,
            &registration.host_services,
            registration.target,
        )
    }

    fn allocate_registered_owner(
        supervisor: &HostOperationSupervisor,
        account: &crucible_host_resources::host_services::HostServiceAllocator,
        target: HostRamTarget,
    ) -> Result<Self, CheckpointOriginalError> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<OriginalBody>())
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes() as usize))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| CheckpointOriginalError::before(CheckpointOriginalCause::Geometry))?;
        let control = account.reserve_resources(0, 0, bytes).map_err(|source| {
            CheckpointOriginalError::before(CheckpointOriginalCause::Account(source))
        })?;
        Ok(Self {
            body: Some(Box::new(OriginalBody {
                native_transfer: None,
                arm_receipt: None,
                original: None,
                basis: None,
                target,
                supervisor: supervisor.clone(),
                account: account.clone(),
                first_refusal: None,
            })),
            receiver_custody: ReceiverCustody::Local,
            control: Some(control),
        })
    }

    /// Enters once and retains the same original on every preparation refusal.
    ///
    /// # Errors
    /// Refuses absent custody, the actual original, subscriber admission or
    /// event duplication. An earlier refusal remains primary on every retry.
    pub(crate) fn enter(&mut self, cancellation: &OwnedFd) -> Result<(), CheckpointOriginalError> {
        let body = self.body.as_mut().ok_or_else(|| {
            CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
        })?;
        if let Some(first) = body.first_refusal {
            return Err(Self::retained_refusal(body, first));
        }
        if body.basis.is_some() {
            return Ok(());
        }
        let result = Self::enter_body(body, cancellation);
        if let Err(first) = result {
            body.first_refusal = Some(first);
        }
        result
    }

    fn enter_body(
        body: &mut OriginalBody,
        cancellation: &OwnedFd,
    ) -> Result<(), CheckpointOriginalError> {
        // The owning body is already installed in Child. Save the entered guard
        // before subscriber, descriptor, basis or postcut can refuse.
        let credit = body
            .account
            .reserve_resources(0, 0, CheckpointOriginalLoan::allocation_bytes()?)
            .map_err(|source| {
                CheckpointOriginalError::before(CheckpointOriginalCause::Account(source))
            })?;
        let original = body
            .supervisor
            .begin(HostOperationClass::Quiescence)
            .map_err(|source| {
                CheckpointOriginalError::before(CheckpointOriginalCause::Original(source))
            })?;
        body.original = Some(CheckpointOriginalLoan {
            body: Some(Arc::new(LoanBody {
                original,
                _credit: credit,
            })),
        });
        let original = body.original.as_ref().ok_or_else(|| {
            CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
        })?;
        let original = original.guard();
        let work = (|| {
            original
                .wait_slice()
                .map_err(CheckpointOriginalCause::Original)?;
            let subscriber = body
                .account
                .reserve_resources(
                    0,
                    1,
                    HostOperationGuard::original_quiescence_cancellation_bytes(),
                )
                .map_err(CheckpointOriginalCause::Account)?;
            let alias = rustix::io::fcntl_dupfd_cloexec(cancellation, 0)
                .map_err(CheckpointOriginalCause::Kernel)?;
            original
                .retain_original_quiescence_cancellation(alias, subscriber)
                .map_err(CheckpointOriginalCause::Original)?;
            let basis = original
                .serialize_original_quiescence_basis()
                .map_err(CheckpointOriginalCause::Original)?;
            let credit = body
                .account
                .reserve_resources(0, 1, HostServiceLease::metadata_bytes())
                .map_err(CheckpointOriginalCause::Account)?;
            let native_alias = rustix::io::fcntl_dupfd_cloexec(cancellation, 0)
                .map_err(CheckpointOriginalCause::Kernel)?;
            // Both aliases are born from the same actual borrowed event in the
            // sole entry call. A later caller cannot substitute another event.
            // Save the transfer alias before the fallible original postcut.
            body.native_transfer = Some(NativeTransfer {
                cancellation: native_alias,
                _credit: credit,
            });
            Ok(basis)
        })();
        let original_after = original.wait_slice().err();
        body.basis = Some(match (work, original_after) {
            (Err(source), original_after) => {
                return Err(CheckpointOriginalError {
                    source,
                    original_after,
                });
            }
            (Ok(_), Some(source)) => {
                return Err(CheckpointOriginalError::before(
                    CheckpointOriginalCause::Original(source),
                ));
            }
            (Ok(basis), None) => basis,
        });
        Ok(())
    }

    /// Lends the same paid original to used capture transport and page readers.
    ///
    /// # Errors
    /// Refuses absent custody, a changed target or a retained original failure.
    pub(crate) fn loan(
        &self,
        target: HostRamTarget,
    ) -> Result<CheckpointOriginalLoan, CheckpointOriginalError> {
        self.check(target)?;
        self.body
            .as_ref()
            .and_then(|body| body.original.as_ref())
            .cloned()
            .ok_or_else(|| self.refusal(CheckpointOriginalCause::MissingOwner))
    }

    /// Lends the original once to the exact registered native request receiver.
    ///
    /// Receiving custody precedes service admission, locking, and transport.
    /// The receipt is saved before any native or host postcut can refuse, and
    /// retries never send the descriptor or replace the entered operation.
    ///
    /// # Errors
    /// Refuses the registered target, original, service admission, transport, or
    /// native receipt. The initiating cause remains retained through child reap.
    pub(crate) fn prepare_receiving(
        &mut self,
        registration: &crate::ram_control::RamControlRegistration,
    ) -> Result<CheckpointArmReceipt, CheckpointOriginalError> {
        self.check(registration.target)?;
        let body = self.body.as_mut().ok_or_else(|| {
            CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
        })?;
        if body.account != registration.host_services {
            return Err(CheckpointOriginalError::before(
                CheckpointOriginalCause::MissingOwner,
            ));
        }
        if let Some(receipt) = body.arm_receipt {
            return Ok(receipt);
        }
        self.receiver_custody = ReceiverCustody::Receiving;
        let work = (|| {
            let loan = CheckpointArmLoan {
                original: body.original.as_ref().ok_or_else(|| {
                    CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
                })?,
                basis: body.basis.as_ref().ok_or_else(|| {
                    CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
                })?,
                cancellation: &body
                    .native_transfer
                    .as_ref()
                    .ok_or_else(|| {
                        CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
                    })?
                    .cancellation,
                target: body.target,
                supervisor: &body.supervisor,
                account: &body.account,
                receipt: &mut body.arm_receipt,
            };
            registration.registrar.checkpoint_arm(loan)
        })();
        let original_after = body
            .original
            .as_ref()
            .and_then(|original| original.check().err());
        let first = match (work, original_after) {
            (Ok(receipt), None) => return Ok(receipt),
            (Err(mut first), original_after) => {
                first.original_after = first.original_after.or(original_after);
                first
            }
            (Ok(_), Some(source)) => CheckpointOriginalError {
                source: CheckpointOriginalCause::Original(source),
                original_after: Some(source),
            },
        };
        body.first_refusal = Some(first);
        Err(first)
    }

    fn retained_refusal(
        body: &OriginalBody,
        first: CheckpointOriginalError,
    ) -> CheckpointOriginalError {
        // Preserve the saved initiating postcut in the body. A retry can report
        // a later raw refusal without replacing either the first cause or guard.
        CheckpointOriginalError {
            source: first.source,
            original_after: body
                .original
                .as_ref()
                .and_then(|original| original.check().err())
                .or(first.original_after),
        }
    }

    /// Rechecks the same original and retained cancellation without renewal.
    ///
    /// # Errors
    /// Refuses absent custody, cancellation, expiration or changed original basis.
    pub(crate) fn check(&self, target: HostRamTarget) -> Result<(), CheckpointOriginalError> {
        let body = self.body.as_ref().ok_or_else(|| {
            CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
        })?;
        if let Some(first) = body.first_refusal {
            return Err(Self::retained_refusal(body, first));
        }
        let original = body.original.as_ref().ok_or_else(|| {
            CheckpointOriginalError::before(CheckpointOriginalCause::MissingOwner)
        })?;
        let original = original.guard();
        let work = if body.target != target || body.basis.is_none() {
            Err(HostSupervisionError::InvalidBudget)
        } else {
            original.check_original_quiescence_cancellation()
        };
        let original_after = original.wait_slice().err();
        match (work, original_after) {
            (Err(source), after) => Err(CheckpointOriginalError {
                source: CheckpointOriginalCause::Original(source),
                original_after: after,
            }),
            (Ok(()), Some(source)) => Err(CheckpointOriginalError::before(
                CheckpointOriginalCause::Original(source),
            )),
            (Ok(()), None) => Ok(()),
        }
    }

    /// Preserves an ingress refusal before separately checking the same original.
    pub(crate) fn refusal(&self, source: CheckpointOriginalCause) -> CheckpointOriginalError {
        CheckpointOriginalError {
            source,
            original_after: self
                .body
                .as_ref()
                .and_then(|body| body.original.as_ref())
                .and_then(|original| original.guard().wait_slice().err()),
        }
    }

    /// Releases held borrowers after the actual direct parent observed terminal status.
    pub(crate) fn retire_after_reap(&mut self) {
        self.receiver_custody = ReceiverCustody::Reaped;
        drop(self.body.take());
        drop(self.control.take());
    }
}

impl Drop for CheckpointOriginal {
    fn drop(&mut self) {
        if self.receiver_custody == ReceiverCustody::Receiving {
            // Receiving custody cannot be discharged by Drop, including a
            // refused or uncertain handoff. The actual parent-observed reap is the
            // physical release boundary until native disposition is joined.
            if let Some(body) = self.body.take() {
                std::mem::forget(body);
            }
            if let Some(control) = self.control.take() {
                std::mem::forget(control);
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn loan_fixture() -> (
    CheckpointOriginal,
    CheckpointOriginalLoan,
    HostOperationSupervisor,
    OwnedFd,
    crucible_host_resources::host_services::HostServiceAllocator,
) {
    let supervisor = HostOperationSupervisor::new(
        crucible_host_resources::host_supervision::HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(2)),
    )
    .unwrap();
    let account =
        crucible_host_resources::host_services::HostServiceAllocator::new(1, 2, 16384).unwrap();
    let event = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .unwrap();
    let target = HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    let mut owner =
        CheckpointOriginal::allocate_registered_owner(&supervisor, &account, target).unwrap();
    owner.enter(&event).unwrap();
    let loan = owner.loan(target).unwrap();
    (owner, loan, supervisor, event, account)
}
