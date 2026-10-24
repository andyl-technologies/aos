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

use crucible_engine::{
    node_adapters::cnp::{CnpSemanticProcessCustody, CnpSemanticProcessSlot},
    node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeLimits},
};
use crucible_node_format::U64;

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
    complete_wake: Option<crucible_engine::node_contract::RuntimeCustodyWakeReader>,
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
        complete_wake: Option<crucible_engine::node_contract::RuntimeCustodyWakeReader>,
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
                    process: std::process::id(),
                    thread: std::thread::current().id(),
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
        runtime: &mut crucible_engine::node_contract::ConformanceRuntime,
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
                crucible_engine::node_contract::RuntimeCustodyWakeWait::Fault(_)
            ) {
                return Err(QualificationError::Refused(
                    "complete cleanup notification fault; original custody retained",
                ));
            }
        }
        Ok(Poll::Pending)
    }

    /// Counts actual local mailbox, queue and result observation headers.
    ///
    /// The caller admits this fixed window before walking the same supervisor.
    /// It excludes this owner's inline root, allocator residency, compiler
    /// frames and kernel descriptors.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn retained_requested_storage_counter_scratch_data()
    -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        let queue = RuntimeCustodyQueue::retained_requested_storage_counter_scratch_data()?;
        std::mem::size_of::<super::super::complete::retained::Counter>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(queue))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    Result<Option<usize>, crucible_engine::node_contract::RuntimeError>,
                >())
            })
            .ok_or(crucible_engine::node_contract::RuntimeError::ResourceLimit)
    }

    /// Observes the same selected supervisor before credit without owned diagnostics.
    ///
    /// Native slots whose original guard remains held outside the mailbox are
    /// supported. Returned custody, busy mailboxes and unknown wake or runtime
    /// backing refuse. Queue/notifier aliases are conservatively counted per
    /// view; this method neither polls cleanup nor releases reservations.
    ///
    /// # Errors
    /// Refuses unselected or foreign origin, conflicting loans, returned or
    /// unsupported custody, checked overflow or a requested-storage excess.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        let Some((process, thread)) = self.complete_origin else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        let wake = self
            .complete_wake
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let mut counter = super::super::complete::retained::Counter::new(maximum);
        for mailbox in &self.mailboxes {
            let bytes = super::requested_storage::retained_mailbox_storage_precredit_data(
                mailbox,
                counter.remaining(),
            )?
            .ok_or(RuntimeError::UnsupportedFacet)?;
            counter
                .add(bytes)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .add(
                self.runtime
                    .retained_requested_storage_data(counter.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(wake.retained_requested_storage_data(counter.remaining())?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(counter.bytes())
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
                crucible_engine::node_contract::RuntimePollFailure::Admission(
                    crucible_engine::node_contract::RuntimeError::ForeignAuthority,
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
    fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        if self.original.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.original.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if self.original.transferred {
            return Err(RuntimeError::UnsupportedFacet);
        }
        original_mailbox_descriptor_count_data(&self.original.mailbox).map(Some)
    }

    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
        self.original
            .retained_requested_storage_precredit_data(maximum)
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible_engine::node_contract::OperationFailure> {
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

impl PacketWorldHostSupervisor {
    /// Counts the genuine fresh selected supervisor before its one reservation.
    ///
    /// Each actual mailbox must still be wholly unreserved and unentered. This
    /// does not reinterpret a returned or busy reserved owner as an empty bank.
    /// The real queue and notifier are walked through their raw typed observers;
    /// the caller admits their fixed scratch before entering. The inline root,
    /// kernel descriptors and allocator physical overhead remain separate.
    ///
    /// # Errors
    /// Refuses generic or foreign supervisors, entered mailboxes, unknown actual
    /// queue backing or requested storage above the supplied ceiling.
    pub fn unreserved_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        match self.complete_origin {
            Some((process, _)) if process != std::process::id() => {
                return Err(RuntimeError::ForeignAuthority);
            }
            Some((_, thread)) if thread != std::thread::current().id() => {
                return Err(RuntimeError::ThreadAffinity);
            }
            None => return Err(RuntimeError::UnsupportedFacet),
            Some(_) => {}
        }
        let wake = self
            .complete_wake
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let mut counter = super::super::complete::retained::Counter::new(maximum);
        for mailbox in &self.mailboxes {
            if mailbox.reserved.get()
                || mailbox.expected.get()
                || mailbox.returned.get()
                || mailbox.reaped.get()
                || mailbox.journal_retained.get()
                || mailbox.polling.get()
                || mailbox.invalid.get()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            counter
                .rc(mailbox)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .add(
                self.runtime
                    .retained_requested_storage_data(counter.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(wake.retained_requested_storage_data(counter.remaining())?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(counter.bytes())
    }

    /// Quotes the fixed three-peer and one-world reservation before allocation.
    ///
    /// Only the real concrete WorldNativeSlot, JournalSlot and Core QueueSlot
    /// constructors contribute. Rc clones create no new backing. The original
    /// supervisor and proposal remain independently counted current owners.
    /// Forthcoming native-slot observers conservatively repeat their mailbox
    /// backing; the quote explicitly includes those same retained views.
    /// This is a data quote, with no native or runtime execution permission.
    ///
    /// # Errors
    /// Refuses foreign creator custody, overflow or a row above maximum.
    pub fn quote_original_scene_reservation_requested_storage_data(
        &self,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        // The selected queue's raw quote authenticates the same creator before
        // walking activation capacities. No closure or virtual callback runs.
        let runtime = self
            .runtime
            .quote_original_reservation_requested_storage_data(activation, maximum)?;
        let mut repeated = super::super::complete::retained::Counter::new(maximum);
        for mailbox in &self.mailboxes {
            repeated
                .rc(mailbox)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        std::mem::size_of::<WorldNativeSlot>()
            .checked_add(std::mem::size_of::<JournalSlot>())
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| bytes.checked_add(runtime))
            .and_then(|bytes| bytes.checked_add(repeated.bytes()))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

fn original_mailbox_descriptor_count_data(
    mailbox: &Mailbox,
) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
    use crucible_engine::node_contract::RuntimeError;
    // Only retain()/journal retain can populate the private Cell owners; they
    // set the corresponding flags before custody enters those original banks.
    // Do not take or temporarily remove a non-Copy owner merely to observe it.
    if mailbox.returned.get()
        || mailbox.journal_retained.get()
        || mailbox.polling.get()
        || mailbox.invalid.get()
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(0)
}

impl PacketWorldHostSupervisor {
    /// Counts actual selected supervision descriptors without cleanup effects.
    ///
    /// The same bounded runtime queue and wake reader own exactly their
    /// eventfd/dup pair. Empty native/journal mailboxes own no descriptors;
    /// returned custody remains unknown until its actual typed census exists.
    ///
    /// # Errors
    /// Refuses foreign/unselected origin, retained unknown custody or conflicting
    /// original loans. Revocation never discards a retained descriptor owner.
    pub fn retained_descriptor_count_data(
        &self,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        match self.complete_origin {
            Some((process, thread))
                if process == std::process::id() && thread == std::thread::current().id() => {}
            Some(_) => return Err(RuntimeError::ForeignAuthority),
            None => return Err(RuntimeError::UnsupportedFacet),
        }
        let wake = self
            .complete_wake
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let mut total = self
            .runtime
            .retained_descriptor_count_with_original_reader_data(wake)?;
        for mailbox in &self.mailboxes {
            total = total
                .checked_add(original_mailbox_descriptor_count_data(mailbox)?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }
}

impl PacketWorldHostSupervisor {
    /// Checks the original reserved queue/slot and its untouched peer mailboxes.
    ///
    /// This is readonly custody correspondence for the selected staged caller.
    /// The slot must be the actual reservation retained by that same caller;
    /// the trait method is not a general purity promise for arbitrary callbacks.
    /// No source, activation, native or allocation authority follows from this data.
    ///
    /// # Errors
    /// Refuses generic/foreign creators, changed proposal/limits, a distinct or
    /// transferred queue slot, or returned/entered original native custody.
    pub(crate) fn authenticate_original_reserved_slot_data(
        &self,
        proposal: &ActivationRecord,
        limits: RuntimeLimits,
        slot: &dyn RuntimeCustodySlot,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        match self.complete_origin {
            Some((process, _)) if process != std::process::id() => {
                return Err(RuntimeError::ForeignAuthority);
            }
            Some((_, thread)) if thread != std::thread::current().id() => {
                return Err(RuntimeError::ThreadAffinity);
            }
            None => return Err(RuntimeError::UnsupportedFacet),
            Some(_) => {}
        }
        if self.complete_wake.is_none() || self.runtime.reserved_worlds() != 1 {
            return Err(RuntimeError::OutstandingObligations);
        }
        for mailbox in &self.mailboxes {
            if !mailbox.reserved.get()
                || !mailbox.expected.get()
                || mailbox.returned.get()
                || mailbox.reaped.get()
                || mailbox.journal_retained.get()
                || mailbox.polling.get()
                || mailbox.invalid.get()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        self.runtime.authenticate_original_slot(slot)?;
        slot.validate_world(proposal, limits)
    }
}
