//! Holds three original peer mailboxes beneath one whole-world runtime reservation.
//!
//! Native and private-journal retention is per original peer, while the runtime
//! queue owns one complete activation and all participants. Returned custody is
//! reinserted before interpreting cleanup errors or unwind. Kernel reaping never
//! discards evidence, renews capacity or establishes qualification.

use super::{
    Cell, Context, JournalSlot, Mailbox, NativeSlot, PacketSupervisionFailure,
    PacketSupervisionObservation, Poll, Rc, RuntimeCustodyQueue, RuntimeCustodySupervisor,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

mod connected;

use crucible::{
    node_adapters::cnp::{CnpSemanticProcessCustody, CnpSemanticProcessSlot},
    node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeLimits},
};
use crucible_node_contract::U64;

use super::QualificationError;
use crate::node_qualification::packet_collection::PacketPeerJournalSlot;

/// Retains three peer reservations and exactly one whole-world runtime slot.
pub struct PacketWorldOriginalReservations {
    /// Holds the three actual native slots in authenticated full-world order.
    pub native: [Box<dyn CnpSemanticProcessSlot>; 3],
    /// Holds the three original private-journal return mailboxes in the same order.
    pub journal: [Box<dyn PacketPeerJournalSlot>; 3],
    /// Holds the single original complete-world reservation made before Child.
    pub runtime: Box<dyn RuntimeCustodySlot>,
}

/// Reports each original peer and the one global cleanup obligation as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketWorldSupervisionObservation {
    /// Reports the complete ordered native/private-journal original roster.
    pub peers: [PacketSupervisionObservation; 3],
    /// Counts complete original worlds still held in the common runtime queue.
    pub runtime_worlds: usize,
}

/// Owns three finite original peer mailboxes and one complete runtime queue.
///
/// The original reservation is never recycled. Retained native/journal bodies
/// keep their mailbox alive after this handle drops; the independent fixture
/// owner must retain this supervisor to drive cleanup and preserve its audit.
/// No node, runtime or private native body can be extracted through this API.
pub struct PacketWorldHostSupervisor {
    mailboxes: [Rc<Mailbox>; 3],
    runtime: RuntimeCustodyQueue,
    complete_wake: Option<crucible::node_contract::RuntimeCustodyWakeReader>,
    complete_origin: Option<(u32, std::thread::ThreadId)>,
}

impl PacketWorldHostSupervisor {
    /// Allocates the complete fixed peer inventory and one world queue before Child.
    ///
    /// # Errors
    /// Refuses unavailable finite runtime queue capacity. Rc/Box allocator failure
    /// follows the separate Rust process-level contract, outside callback custody.
    pub fn new() -> Result<Self, QualificationError> {
        let runtime = RuntimeCustodyQueue::new(1)
            .map_err(|_| QualificationError::Refused("packet world runtime allocation"))?;
        Ok(Self::with_runtime(runtime, None))
    }

    /// Preallocates the selected four-owner cleanup queue before native birth.
    ///
    /// This fixes a bounded notification owner and does not create an activation,
    /// Arm or Ready receipt. Keep this supervisor through cancellation and unwind.
    ///
    /// # Errors
    /// Refuses unavailable finite queue, descriptor or host allocation resources.
    pub fn new_complete_original() -> Result<Self, QualificationError> {
        let (runtime, wake) = RuntimeCustodyQueue::new_with_bounded_wake(1).map_err(|_| {
            QualificationError::Refused("complete original notification reservation")
        })?;
        Ok(Self::with_runtime(runtime, Some(wake)))
    }

    fn with_runtime(
        runtime: RuntimeCustodyQueue,
        complete_wake: Option<crucible::node_contract::RuntimeCustodyWakeReader>,
    ) -> Self {
        let mailboxes = std::array::from_fn(|_| {
            Rc::new(Mailbox {
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
            })
        });
        let complete_origin = complete_wake
            .as_ref()
            .map(|_| (std::process::id(), std::thread::current().id()));
        Self {
            mailboxes,
            runtime,
            complete_wake,
            complete_origin,
        }
    }

    /// Reserves all three original peers beneath one complete activation proposal.
    ///
    /// The proposal is data, not Ready authority. Full-world admission separately
    /// authenticates its exact owners, source and current plan before effects.
    /// The runtime slot is reserved once, never once per peer.
    ///
    /// # Errors
    /// Refuses an incomplete or repeated reservation or exhausted queue capacity.
    pub fn reserve_original(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<PacketWorldOriginalReservations, QualificationError> {
        self.authenticate_selected_origin()?;
        let expected_owners = if self.complete_wake.is_some() { 4 } else { 3 };
        if activation.owners.len() != expected_owners
            || self.mailboxes.iter().any(|m| m.reserved.get())
        {
            return Err(QualificationError::Refused(
                "packet world supervision roster",
            ));
        }
        let native: [Box<dyn CnpSemanticProcessSlot>; 3] = std::array::from_fn(|member| {
            Box::new(WorldNativeSlot {
                original: NativeSlot {
                    mailbox: self.mailboxes[member].clone(),
                    transferred: false,
                },
                identity: U64::new((member as u64) + 1),
            }) as Box<dyn CnpSemanticProcessSlot>
        });
        let journal: [Box<dyn PacketPeerJournalSlot>; 3] = std::array::from_fn(|member| {
            Box::new(JournalSlot {
                mailbox: self.mailboxes[member].clone(),
                transferred: false,
            }) as Box<dyn PacketPeerJournalSlot>
        });
        let runtime = self
            .runtime
            .reserve_world(activation, limits)
            .map_err(|_| QualificationError::Refused("packet whole-world reservation"))?;
        for mailbox in &self.mailboxes {
            mailbox.reserved.set(true);
            mailbox.expected.set(true);
        }
        Ok(PacketWorldOriginalReservations {
            native,
            journal,
            runtime,
        })
    }

    /// Reads complete original retention status without granting reclamation.
    pub fn observation(&self) -> PacketWorldSupervisionObservation {
        let runtime_worlds = self.runtime.reserved_worlds();
        PacketWorldSupervisionObservation {
            peers: std::array::from_fn(|member| {
                let mailbox = &self.mailboxes[member];
                PacketSupervisionObservation {
                    native_expected: mailbox.expected.get(),
                    native_returned: mailbox.returned.get(),
                    kernel_reclaimed: mailbox.reaped.get(),
                    journal_retained: mailbox.journal_retained.get(),
                    runtime_worlds,
                    containment_fault: mailbox.invalid.get(),
                }
            }),
            runtime_worlds,
        }
    }

    fn authenticate_selected_origin(&self) -> Result<(), QualificationError> {
        match (&self.complete_wake, self.complete_origin) {
            (None, None) => Ok(()),
            (Some(wake), Some((process, thread)))
                if process == std::process::id() && thread == std::thread::current().id() =>
            {
                wake.original_cleanup_waker()
                    .map(|_| ())
                    .map_err(|_| QualificationError::Refused("complete original supervisor origin"))
            }
            _ => Err(QualificationError::Refused(
                "complete original supervisor origin",
            )),
        }
    }

    /// Checks actual runtime custody against this same selected original queue.
    ///
    /// # Errors
    /// Refuses an unselected supervisor, foreign creator or another actual queue.
    pub fn authenticate_complete_original_runtime(
        &self,
        runtime: &mut crucible::node_contract::ConformanceRuntime,
    ) -> Result<(), QualificationError> {
        self.authenticate_selected_origin()?;
        self.complete_wake
            .as_ref()
            .ok_or(QualificationError::Refused(
                "complete original notification selection",
            ))?
            .original_cleanup_waker()
            .map_err(|_| QualificationError::Refused("complete original notification origin"))?;
        runtime
            .authenticate_original_custody_queue(&self.runtime)
            .map_err(|_| QualificationError::Refused("complete original runtime queue identity"))
    }

    /// Drives bounded cleanup passes on this same selected four-owner supervisor.
    ///
    /// Every pending pass waits for a concrete notification or a five millisecond
    /// operational fallback. No simulation coordinate is advanced. An exhausted
    /// pass budget returns Pending and retains the same custody for another call.
    /// Ordinary three-owner caller-context polling remains unchanged.
    ///
    /// # Errors
    /// Refuses an unselected/foreign notifier, zero/excessive pass count or sticky
    /// transport fault. No error releases or replaces original native custody.
    pub fn drive_complete_original_reclamation(
        &self,
        maximum_passes: usize,
    ) -> Result<
        Poll<Result<PacketWorldSupervisionObservation, PacketSupervisionFailure>>,
        QualificationError,
    > {
        self.authenticate_selected_origin()?;
        let wake = self
            .complete_wake
            .as_ref()
            .ok_or(QualificationError::Refused(
                "complete original notification selection",
            ))?;
        if maximum_passes == 0 || maximum_passes > 64 {
            return Err(QualificationError::Refused("complete cleanup pass bound"));
        }
        let waker = wake
            .original_cleanup_waker()
            .map_err(|_| QualificationError::Refused("complete original notification origin"))?;
        for _ in 0..maximum_passes {
            let mut context = Context::from_waker(&waker);
            let observed = self.poll_reclamation(&mut context);
            if observed.is_ready() {
                return Ok(observed);
            }
            let notification = wake
                .wait(std::time::Duration::from_millis(5))
                .map_err(|_| QualificationError::Refused("complete original notification wait"))?;
            if matches!(
                notification,
                crucible::node_contract::RuntimeCustodyWakeWait::Fault(_)
            ) {
                return Err(QualificationError::Refused(
                    "complete cleanup notification fault; original custody retained",
                ));
            }
        }
        Ok(Poll::Pending)
    }

    /// Reports backing of this actual selected supervisor, excluding its inline root.
    ///
    /// Shared queue/mailbox/notifier allocations may conservatively repeat another
    /// retained view. Returned or busy native custody and arbitrary wake backing
    /// remain unknown. Kernel descriptors and allocator residency are separate.
    ///
    /// # Errors
    /// Refuses incomplete original backing observations or exhausted requested credit.
    pub fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, QualificationError> {
        self.authenticate_selected_origin()?;
        let wake = self
            .complete_wake
            .as_ref()
            .ok_or(QualificationError::Refused(
                "complete original notification selection",
            ))?;
        let waker = wake
            .original_cleanup_waker()
            .map_err(|_| QualificationError::Refused("complete original notification origin"))?;
        drop(waker);
        let mut counter = super::super::complete::retained::Counter::new(maximum);
        for mailbox in &self.mailboxes {
            let bytes = super::requested_storage::retained_mailbox_storage_data(mailbox, maximum)
                .map_err(|error| QualificationError::Evidence(error.reason))?
                .ok_or(QualificationError::Refused(
                    "complete original mailbox backing unknown",
                ))?;
            counter.add(bytes)?;
        }
        counter.add(
            self.runtime
                .retained_requested_storage_data(maximum)
                .map_err(|_| QualificationError::Refused("complete runtime queue backing"))?
                .ok_or(QualificationError::Refused(
                    "complete runtime queue backing unknown",
                ))?,
        )?;
        counter
            .add(wake.retained_requested_storage_data(maximum).map_err(|_| {
                QualificationError::Refused("complete original notifier backing")
            })?)?;
        Ok(counter.bytes())
    }

    /// Drives authentic complete-world and per-peer cleanup without dropping originals.
    ///
    /// Native custody is moved back into its original mailbox before the cleanup
    /// result is interpreted. All private journals survive kernel reclamation.
    ///
    /// # Errors
    /// Preserves native/runtime failure, callback unwind and duplicate transfer.
    /// Pending means an actual original owner or world obligation remains live.
    pub fn poll_reclamation(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<PacketWorldSupervisionObservation, PacketSupervisionFailure>> {
        if self.authenticate_selected_origin().is_err() {
            return Poll::Ready(Err(PacketSupervisionFailure::Runtime(
                crucible::node_contract::RuntimePollFailure::Admission(
                    crucible::node_contract::RuntimeError::ForeignAuthority,
                ),
            )));
        }
        if self.mailboxes.iter().any(|m| m.invalid.get()) {
            return Poll::Ready(Err(PacketSupervisionFailure::Duplicate));
        }
        // Mark every mailbox together before callbacks, so reentrant polling
        // cannot remove a second original while this complete pass owns it.
        if self.mailboxes.iter().any(|m| m.polling.get()) {
            return Poll::Pending;
        }
        for mailbox in &self.mailboxes {
            mailbox.polling.set(true);
        }
        let result = catch_unwind(AssertUnwindSafe(|| self.runtime.poll_reclamation(context)));
        let mut failure = match result {
            Ok(Poll::Ready(Err(error))) => Some(PacketSupervisionFailure::Runtime(error)),
            Err(_) => Some(PacketSupervisionFailure::Unwind),
            _ => None,
        };
        if failure.is_none() {
            for mailbox in &self.mailboxes {
                if let Some(mut original) = mailbox.native.take() {
                    let result = catch_unwind(AssertUnwindSafe(|| original.poll_reclamation()));
                    mailbox.native.set(Some(original));
                    match result {
                        Ok(Ok(true)) => mailbox.reaped.set(true),
                        Ok(Ok(false)) => {}
                        Ok(Err(error)) => failure = Some(PacketSupervisionFailure::Native(error)),
                        Err(_) => failure = Some(PacketSupervisionFailure::Unwind),
                    }
                    if failure.is_some() {
                        break;
                    }
                }
            }
        }
        for mailbox in &self.mailboxes {
            mailbox.polling.set(false);
        }
        if let Some(error) = failure {
            return Poll::Ready(Err(error));
        }
        let state = self.observation();
        if state.runtime_worlds == 0
            && state
                .peers
                .iter()
                .all(|p| !p.native_expected || p.kernel_reclaimed)
        {
            Poll::Ready(Ok(state))
        } else {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct WorldNativeSlot {
    original: NativeSlot,
    identity: U64,
}

impl CnpSemanticProcessSlot for WorldNativeSlot {
    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible::node_contract::OperationFailure> {
        self.original.retained_requested_storage_data(maximum)
    }

    fn identity(&self) -> U64 {
        self.identity
    }

    fn retain(&mut self, original: CnpSemanticProcessCustody) {
        self.original.retain(original);
    }
}

#[cfg(test)]
#[path = "world_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "world/bounded_wake_tests.rs"]
mod bounded_wake_tests;
