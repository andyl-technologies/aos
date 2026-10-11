//! Reserves original singleton packet process, private journal and runtime custody.
//!
//! Retention moves whole incoming bodies into preallocated Cells without user
//! callbacks or allocation. The common runtime queue handles authentic full-world
//! cleanup. Direct native containment checks only the original Child/group; its
//! success never discards journals or grants semantic rollback or qualification.

use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    task::{Context, Poll},
};

use crucible::{
    node_adapters::cnp::{CnpSemanticProcessCustody, CnpSemanticProcessSlot},
    node_contract::{
        ActivationRecord, RuntimeCustodyQueue, RuntimeCustodySlot, RuntimeCustodySupervisor,
        RuntimeLimits, RuntimePollFailure,
    },
};
use crucible_node_contract::U64;
use crucible_node_provider::ProviderError;

use super::{PacketPeerJournalCustody, PacketPeerJournalSlot, QualificationError};

struct Mailbox {
    reserved: Cell<bool>,
    expected: Cell<bool>,
    returned: Cell<bool>,
    reaped: Cell<bool>,
    journal_retained: Cell<bool>,
    polling: Cell<bool>,
    invalid: Cell<bool>,
    native: Cell<Option<CnpSemanticProcessCustody>>,
    journal: Cell<Option<PacketPeerJournalCustody>>,
    keepalive: Cell<Option<Rc<Mailbox>>>,
}

/// Retains three actual reservations made before Child, without admission authority.
pub struct PacketOriginalReservations {
    /// Retains the actual native Child/controller returned by guard Drop.
    pub native: Box<dyn CnpSemanticProcessSlot>,
    /// Retains complete original private launch and Hello data on capsule Drop.
    pub journal: Box<dyn PacketPeerJournalSlot>,
    /// Retains complete original world custody on native/runtime transfer failure.
    pub runtime: Box<dyn RuntimeCustodySlot>,
}

/// Reports original retention and kernel cleanup without permission or rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketSupervisionObservation {
    /// Records whether the actual guard still owes native custody.
    pub native_expected: bool,
    /// Records transfer of that same custody to its reserved mailbox.
    pub native_returned: bool,
    /// Records actual original reaping and empty private process-group proof.
    pub kernel_reclaimed: bool,
    /// Records retention of the complete private journal sidecar.
    pub journal_retained: bool,
    /// Counts original whole-world cleanup obligations still reserved.
    pub runtime_worlds: usize,
    /// Records invalid duplicate transfer without successful reclamation.
    pub containment_fault: bool,
}

/// Separates authentic cleanup errors from successful kernel containment.
pub enum PacketSupervisionFailure {
    /// Retains a whole runtime's original cleanup failure.
    Runtime(RuntimePollFailure),
    /// Retains actual original Child/group containment failure.
    Native(ProviderError),
    /// Retains the same original owner after a callback unwinds.
    Unwind,
    /// Refuses successful reclamation after invalid duplicate transfer.
    Duplicate,
}

/// Owns one finite original native/journal mailbox and the common runtime queue.
///
/// The reservation is never recycled. Returned originals retain the mailbox
/// independently even if this owner is dropped. Private bodies remain retained
/// after kernel cleanup; the fixture owner must keep supervision for audit.
/// There is no data extraction, decoded constructor or replacement owner API.
pub struct PacketHostSupervisor {
    mailbox: Rc<Mailbox>,
    runtime: RuntimeCustodyQueue,
}

impl PacketHostSupervisor {
    /// Preallocates the singleton fixture's original cleanup inventory before Child.
    ///
    /// # Errors
    /// Refuses unavailable common mailbox allocation. Rc/Box allocator exhaustion
    /// follows Rust's process-level contract, outside callback containment.
    pub fn new() -> Result<Self, QualificationError> {
        let runtime = RuntimeCustodyQueue::new(1)
            .map_err(|_| QualificationError::Refused("packet runtime supervisor allocation"))?;
        Ok(Self {
            mailbox: Rc::new(Mailbox {
                reserved: Cell::new(false),
                expected: Cell::new(false),
                returned: Cell::new(false),
                reaped: Cell::new(false),
                journal_retained: Cell::new(false),
                polling: Cell::new(false),
                invalid: Cell::new(false),
                native: Cell::new(None),
                journal: Cell::new(None),
                keepalive: Cell::new(None),
            }),
            runtime,
        })
    }

    /// Reserves all three original slots once under the complete activation proposal.
    ///
    /// The proposal is data only; source/runtime admission independently validates
    /// it. Every mailbox and owning slot is allocated before peer creation.
    ///
    /// # Errors
    /// Refuses a second reservation or unavailable common runtime capacity.
    pub fn reserve_original(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<PacketOriginalReservations, QualificationError> {
        if self.mailbox.reserved.get() {
            return Err(QualificationError::Refused(
                "packet original supervision already reserved",
            ));
        }
        let runtime = self
            .runtime
            .reserve_world(activation, limits)
            .map_err(|_| QualificationError::Refused("packet original runtime reservation"))?;
        let native = Box::new(NativeSlot {
            mailbox: self.mailbox.clone(),
            transferred: false,
        });
        let journal = Box::new(JournalSlot {
            mailbox: self.mailbox.clone(),
            transferred: false,
        });
        self.mailbox.reserved.set(true);
        self.mailbox.expected.set(true);
        Ok(PacketOriginalReservations {
            native,
            journal,
            runtime,
        })
    }

    /// Reports data-only retention counts without exposing private original bodies.
    pub fn observation(&self) -> PacketSupervisionObservation {
        PacketSupervisionObservation {
            native_expected: self.mailbox.expected.get(),
            native_returned: self.mailbox.returned.get(),
            kernel_reclaimed: self.mailbox.reaped.get(),
            journal_retained: self.mailbox.journal_retained.get(),
            runtime_worlds: self.runtime.reserved_worlds(),
            containment_fault: self.mailbox.invalid.get(),
        }
    }

    /// Polls genuine original cleanup while retaining all returned private bodies.
    ///
    /// No custody Cell is borrowed across callbacks. Runtime failures retain the
    /// common queue capsule; native failure/unwind reinserts the same actual
    /// custody. Kernel containment never retires report/journal evidence.
    ///
    /// # Errors
    /// Preserves runtime/native failure, callback unwind and duplicate transfer.
    /// Pending means a live owner or authentic cleanup obligation remains.
    pub fn poll_reclamation(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<PacketSupervisionObservation, PacketSupervisionFailure>> {
        if self.mailbox.invalid.get() {
            return Poll::Ready(Err(PacketSupervisionFailure::Duplicate));
        }
        if self.mailbox.polling.replace(true) {
            return Poll::Pending;
        }
        match catch_unwind(AssertUnwindSafe(|| self.runtime.poll_reclamation(context))) {
            Ok(Poll::Ready(Err(error))) => {
                self.mailbox.polling.set(false);
                return Poll::Ready(Err(PacketSupervisionFailure::Runtime(error)));
            }
            Err(_) => {
                self.mailbox.polling.set(false);
                return Poll::Ready(Err(PacketSupervisionFailure::Unwind));
            }
            _ => {}
        }
        if let Some(mut original) = self.mailbox.native.take() {
            let result = catch_unwind(AssertUnwindSafe(|| original.poll_reclamation()));
            self.mailbox.native.set(Some(original));
            match result {
                Ok(Ok(true)) => self.mailbox.reaped.set(true),
                Ok(Ok(false)) => {}
                Ok(Err(error)) => {
                    self.mailbox.polling.set(false);
                    return Poll::Ready(Err(PacketSupervisionFailure::Native(error)));
                }
                Err(_) => {
                    self.mailbox.polling.set(false);
                    return Poll::Ready(Err(PacketSupervisionFailure::Unwind));
                }
            }
        }
        self.mailbox.polling.set(false);
        let state = self.observation();
        if state.runtime_worlds == 0 && (!state.native_expected || state.kernel_reclaimed) {
            Poll::Ready(Ok(state))
        } else {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct NativeSlot {
    mailbox: Rc<Mailbox>,
    transferred: bool,
}

impl CnpSemanticProcessSlot for NativeSlot {
    fn identity(&self) -> U64 {
        U64::new(1)
    }

    fn retain(&mut self, original: CnpSemanticProcessCustody) {
        if self.transferred || self.mailbox.returned.replace(true) {
            // A nonclone once-only slot cannot normally receive two originals.
            // Defensive containment retains the extra allocation permanently;
            // invalid transfer cannot recycle capacity or report reclamation.
            self.mailbox.invalid.set(true);
            std::mem::forget(original);
            return;
        }
        self.transferred = true;
        self.mailbox.native.set(Some(original));
        self.mailbox.keepalive.set(Some(self.mailbox.clone()));
    }
}

impl Drop for NativeSlot {
    fn drop(&mut self) {
        if !self.transferred {
            self.mailbox.expected.set(false);
        }
    }
}

struct JournalSlot {
    mailbox: Rc<Mailbox>,
    transferred: bool,
}

impl PacketPeerJournalSlot for JournalSlot {
    fn retain(&mut self, original: PacketPeerJournalCustody) {
        if self.transferred || self.mailbox.journal_retained.replace(true) {
            self.mailbox.invalid.set(true);
            std::mem::forget(original);
            return;
        }
        self.transferred = true;
        self.mailbox.journal.set(Some(original));
        self.mailbox.keepalive.set(Some(self.mailbox.clone()));
    }
}
