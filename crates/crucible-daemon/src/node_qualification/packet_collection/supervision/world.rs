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
        Ok(Self { mailboxes, runtime })
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
        if activation.owners.len() != 3 || self.mailboxes.iter().any(|m| m.reserved.get()) {
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
