//! Preowned vendor slots and callback-safe original process reclamation.

use super::{InstalledVendorPeerCleanup, VendorCnpCustody, refused, unknown};
use crate::node_contract::OperationFailure;
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    task::{Context, Poll},
};

struct Entry {
    reserved: Cell<bool>,
    transferred: Cell<bool>,
    original: Cell<Option<Box<VendorCnpCustody>>>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            // Dropping a supervisor cannot prove native release. Preserve the
            // entire unresolved capsule even if its last external owner vanishes.
            // Operators should keep servicing the queue to reclaim it normally.
            let _ = Box::leak(original);
        }
    }
}

/// Owns finite original native capsules independently of adapter drop.
///
/// Slots are reserved before process birth. A transferred slot remains charged
/// while its original is polled, even when its storage cell is temporarily empty.
/// Every external callback is caught with the whole original outside the catch.
#[derive(Clone)]
pub struct VendorCnpCustodyQueue {
    entries: Rc<[Rc<Entry>]>,
    cleanup: Rc<dyn InstalledVendorPeerCleanup>,
}

impl VendorCnpCustodyQueue {
    /// Creates a bounded empty owner-thread queue without launching a provider.
    ///
    /// # Errors
    /// Refuses zero capacity or more than 256 original native peers.
    pub fn new(
        maximum_peers: usize,
        cleanup: Rc<dyn InstalledVendorPeerCleanup>,
    ) -> Result<Self, OperationFailure> {
        if maximum_peers == 0 || maximum_peers > 256 {
            return Err(refused("invalid vendor custody capacity"));
        }
        let entries: Vec<_> = (0..maximum_peers)
            .map(|_| {
                Rc::new(Entry {
                    reserved: Cell::new(false),
                    transferred: Cell::new(false),
                    original: Cell::new(None),
                })
            })
            .collect();
        Ok(Self {
            entries: entries.into(),
            cleanup,
        })
    }

    /// Reserves a distinct original slot before Child allocation or negotiation.
    ///
    /// # Errors
    /// Refuses full capacity. Empty storage never releases an attempted original.
    pub fn reserve(&self) -> Result<VendorCnpCustodySlot, OperationFailure> {
        let entry = self
            .entries
            .iter()
            .find(|entry| !entry.reserved.get())
            .ok_or_else(|| refused("vendor native custody capacity exhausted"))?;
        entry.reserved.set(true);
        entry.transferred.set(false);
        Ok(VendorCnpCustodySlot {
            entry: Rc::clone(entry),
            cleanup: Rc::clone(&self.cleanup),
        })
    }

    /// Counts all reserved originals, including active polling and uncertainty.
    pub fn reserved_peers(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.reserved.get())
            .count()
    }

    /// Polls each complete original under independent whole-group reclamation.
    ///
    /// Actual child wait alone grants no group release. Every original requires
    /// independent native birth, group and resource release authentication. An
    /// adopted node additionally requires every original owner's codec receipt
    /// and validator; a rejected unadopted launch has no codec obligation. A
    /// callback error or unwind stores the same original before returning the diagnostic.
    ///
    /// # Errors
    /// Returns unresolved native cleanup or a caught callback failure, keeping
    /// every affected slot charged and its entire original capsule owned.
    pub fn poll(&self, context: &mut Context<'_>) -> Result<usize, OperationFailure> {
        let mut reclaimed = 0;
        for entry in self.entries.iter() {
            let Some(mut original) = entry.original.take() else {
                continue;
            };
            let result = catch_unwind(AssertUnwindSafe(|| {
                original.poll_complete_reclamation(context)
            }));
            match result {
                Ok(Poll::Ready(Ok(()))) => {
                    // Authentic validation precedes both original drop and credit reuse.
                    drop(original);
                    entry.reserved.set(false);
                    reclaimed += 1;
                }
                Ok(Poll::Pending) => entry.original.set(Some(original)),
                Ok(Poll::Ready(Err(error))) => {
                    entry.original.set(Some(original));
                    return Err(error);
                }
                Err(_) => {
                    entry.original.set(Some(original));
                    return Err(unknown(
                        "vendor cleanup callback unwound with original custody retained",
                    ));
                }
            }
        }
        Ok(reclaimed)
    }
}

/// Reserves once-only storage for one complete original native capsule.
///
/// This slot has no public constructor, Clone or user callback. Adapter drop
/// transfers the complete original directly into its preowned storage cell.
pub struct VendorCnpCustodySlot {
    entry: Rc<Entry>,
    pub(super) cleanup: Rc<dyn InstalledVendorPeerCleanup>,
}

impl VendorCnpCustodySlot {
    pub(super) fn retain(self, original: Box<VendorCnpCustody>) {
        self.entry.original.set(Some(original));
        self.entry.transferred.set(true);
    }
}

impl Drop for VendorCnpCustodySlot {
    fn drop(&mut self) {
        if !self.entry.transferred.get() {
            // Before launch adoption the caller still owns any birth failure.
            // Only an unused reservation can return its capacity here.
            self.entry.reserved.set(false);
        }
    }
}

impl VendorCnpCustody {
    fn poll_complete_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), OperationFailure>> {
        if !self.quarantined {
            self.quarantined = true;
            self.uncertain = true;
            self.peer.session.close();
            if let Err(error) = self.cleanup.request_containment(&mut self.peer) {
                self.containment_error = Some(error);
            }
        }
        if self.peer.reaped.is_none() {
            match self.peer.child.try_wait() {
                Ok(Some(wait)) => self.peer.reaped = Some(wait),
                Ok(None) => {
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(unknown(&error.to_string()))),
            }
        }
        if self.host_release.is_none() {
            let receipt = match self.cleanup.poll_release(&self.peer, context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(unknown(&error.reason))),
                Poll::Ready(Ok(receipt)) => receipt,
            };
            self.host_release = Some(receipt);
        }
        let Some(receipt) = &self.host_release else {
            return Poll::Ready(Err(unknown("original host release proof disappeared")));
        };
        if let Err(error) = self.cleanup.validate_release(&self.peer, receipt) {
            return Poll::Ready(Err(unknown(&error.reason)));
        }
        if !self.adopted {
            return Poll::Ready(Ok(()));
        }
        let (Some(identity), Some(codec)) = (&self.identity, &self.codec) else {
            // Before codec adoption there are no admitted node operations. Only
            // the independent original native host proof can release this birth.
            return Poll::Ready(Err(unknown("adopted original source identity disappeared")));
        };
        for (index, owner) in identity.route.owners.iter().enumerate() {
            if self.reclamation.len() == index {
                let receipt = match codec.poll_reclamation(identity, owner, &self.peer, context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(receipt)) => receipt,
                };
                // Store each actual returned proof before the next callback.
                // An invalid proof remains original evidence; it cannot be replaced.
                self.reclamation.push(receipt);
            }
            let receipt = &self.reclamation[index];
            if receipt.owner != *owner {
                return Poll::Ready(Err(unknown(
                    "vendor reclamation changed the original owner",
                )));
            }
            if let Err(error) = codec.validate_reclamation(identity, &self.peer, receipt) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnqualifiedCleanup;
    impl InstalledVendorPeerCleanup for UnqualifiedCleanup {
        fn authenticate_original(
            &self,
            _: &super::super::VendorCnpPeer,
        ) -> Result<(), OperationFailure> {
            Err(refused("no native birth in this inert control"))
        }
        fn request_containment(
            &self,
            _: &mut super::super::VendorCnpPeer,
        ) -> Result<(), OperationFailure> {
            Err(unknown("no native birth in this inert control"))
        }
        fn poll_release(
            &self,
            _: &super::super::VendorCnpPeer,
            _: &mut Context<'_>,
        ) -> Poll<Result<crucible_node_contract::ContentRef, OperationFailure>> {
            Poll::Ready(Err(unknown("no native release in this inert control")))
        }
        fn validate_release(
            &self,
            _: &super::super::VendorCnpPeer,
            _: &crucible_node_contract::ContentRef,
        ) -> Result<(), OperationFailure> {
            Err(unknown("no native release in this inert control"))
        }
    }

    #[test]
    fn reservations_remain_charged_without_transferred_originals() -> Result<(), OperationFailure> {
        let queue = VendorCnpCustodyQueue::new(1, Rc::new(UnqualifiedCleanup))?;
        let slot = queue.reserve()?;
        assert_eq!(queue.reserved_peers(), 1);
        assert!(queue.reserve().is_err());
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert_eq!(queue.poll(&mut context)?, 0);
        assert_eq!(queue.reserved_peers(), 1);
        drop(slot);
        assert_eq!(queue.reserved_peers(), 0);
        Ok(())
    }
}
