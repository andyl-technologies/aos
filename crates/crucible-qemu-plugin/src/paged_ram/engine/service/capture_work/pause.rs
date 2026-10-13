//! Holds fault-consumption admission through an actual actor-boundary pause.
//!
//! The checkpoint callback's genuine retained context remains the issuer. This
//! private state only orders the fault worker's existing run loop: an in-flight
//! request completes or stays retained, and unread UFFD messages remain owned by
//! the existing Registration. A request never acknowledges itself or proves that
//! the kernel queue is empty. The native context/loan join is not installed here.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ram_error::RamError;

/// Orders requests and actor acknowledgement within one retained transaction.
#[derive(Default)]
pub(super) struct FaultPause {
    admission_cut: AtomicBool,
    requested: AtomicU64,
    acknowledged: AtomicU64,
    issued: AtomicU64,
    ordinary_requested: AtomicU64,
    ordinary_acknowledged: AtomicU64,
    ordinary_issued: AtomicU64,
}

struct PauseAdmission<'a>(&'a AtomicBool);

impl Drop for PauseAdmission<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl FaultPause {
    fn admission(&self) -> Result<PauseAdmission<'_>, RamError> {
        self.admission_cut
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("fault pause admission is busy"))?;
        Ok(PauseAdmission(&self.admission_cut))
    }

    /// Closes admission for one new native-issued checkpoint transaction.
    ///
    /// # Errors
    /// Refuses zero/reused epochs, another held epoch or a competing request.
    pub(super) fn request(&self, epoch: u64) -> Result<(), RamError> {
        let _admission = self.admission()?;
        if epoch == 0 {
            return Err(RamError::Invariant("capture pause epoch is zero"));
        }
        if self.ordinary_requested.load(Ordering::Acquire) != 0 {
            return Err(RamError::Invariant(
                "ordinary capture retains fault admission",
            ));
        }
        let current = self.requested.load(Ordering::Acquire);
        if current == epoch {
            return Ok(());
        }
        if current != 0 {
            return Err(RamError::Invariant("another capture pause remains held"));
        }
        // An uncertain competing request never recycles its generation. Only
        // the genuine native transaction issuer can provide a later epoch.
        let issued = self.issued.load(Ordering::Acquire);
        if epoch <= issued {
            return Err(RamError::Invariant("capture pause epoch was reused"));
        }
        // The callback never retries a competing issuer. Burning this epoch
        // before the admission CAS prevents uncertain requests from reusing it.
        self.issued
            .compare_exchange(issued, epoch, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("capture pause issuance raced"))?;
        self.requested
            .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("capture pause admission raced"))?;
        Ok(())
    }

    /// Records the actual actor's settled request boundary.
    ///
    /// # Errors
    /// Refuses unresolved consumed-event custody instead of acknowledging it.
    pub(super) fn boundary(&self, unresolved: bool) -> Result<bool, RamError> {
        let ordinary = self.ordinary_requested.load(Ordering::Acquire);
        if ordinary != 0 {
            if unresolved {
                return Err(RamError::Invariant(
                    "ordinary pause has unresolved fault custody",
                ));
            }
            self.ordinary_acknowledged
                .store(ordinary, Ordering::Release);
            return Ok(true);
        }
        let epoch = self.requested.load(Ordering::Acquire);
        if epoch == 0 {
            return Ok(false);
        }
        if unresolved {
            return Err(RamError::Invariant(
                "capture pause has unresolved fault custody",
            ));
        }
        self.acknowledged.store(epoch, Ordering::Release);
        Ok(true)
    }

    /// Observes this gate under the caller's retained native transaction.
    pub(super) fn acknowledged(&self, epoch: u64) -> bool {
        epoch != 0
            && self.requested.load(Ordering::Acquire) == epoch
            && self.acknowledged.load(Ordering::Acquire) == epoch
    }

    /// Reopens consumption after exact native epoch disposition.
    ///
    /// # Errors
    /// Refuses unmatched epochs, unacknowledged boundaries or a raced release.
    pub(super) fn release(&self, epoch: u64) -> Result<(), RamError> {
        if !self.acknowledged(epoch) {
            return Err(RamError::Invariant(
                "capture pause has no matching boundary",
            ));
        }
        self.requested
            .compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("capture pause disposition raced"))?;
        // A stale acknowledgement cannot authenticate a later, unique epoch.
        // Leaving it until the next boundary avoids clearing a concurrent new
        // acknowledgement after reopening the actual consumption gate.
        Ok(())
    }

    /// Requests a new real ordinary holder without admitting stale acknowledgments.
    ///
    /// # Errors
    /// Refuses reused holders, a held checkpoint or concurrent ordinary custody.
    pub(super) fn request_ordinary(&self, identity: u64) -> Result<(), RamError> {
        let _admission = self.admission()?;
        if identity == 0 || self.requested.load(Ordering::Acquire) != 0 {
            return Err(RamError::Invariant(
                "ordinary fault pause conflicts with checkpoint",
            ));
        }
        let current = self.ordinary_requested.load(Ordering::Acquire);
        if current == identity {
            return Ok(());
        }
        if current != 0 || identity <= self.ordinary_issued.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "ordinary fault pause is occupied or stale",
            ));
        }
        self.ordinary_issued.store(identity, Ordering::Release);
        self.ordinary_requested.store(identity, Ordering::Release);
        Ok(())
    }

    pub(super) fn ordinary_acknowledged(&self, identity: u64) -> bool {
        identity != 0
            && self.ordinary_requested.load(Ordering::Acquire) == identity
            && self.ordinary_acknowledged.load(Ordering::Acquire) == identity
    }

    pub(super) fn return_ordinary(&self, identity: u64) -> Result<(), RamError> {
        self.ordinary_requested
            .compare_exchange(identity, 0, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("ordinary fault pause return changed"))?;
        Ok(())
    }

    /// Reports whether the allocation must retain its capture custody.
    pub(super) fn held(&self) -> bool {
        self.requested.load(Ordering::Acquire) != 0
            || self.ordinary_requested.load(Ordering::Acquire) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cannot_acknowledge_unfinished_work() {
        let pause = FaultPause::default();
        pause.request(1).unwrap();
        assert!(!pause.acknowledged(1));
        assert!(pause.boundary(true).is_err());
        assert!(!pause.acknowledged(1));
        assert!(pause.release(1).is_err());
        assert!(pause.held());
    }

    #[test]
    fn held_boundary_only_reopens_for_matching_disposition() {
        let pause = FaultPause::default();
        pause.request(2).unwrap();
        assert!(pause.boundary(false).unwrap());
        assert!(pause.acknowledged(2));
        assert!(pause.release(1).is_err());
        assert!(pause.held());
        pause.release(2).unwrap();
        assert!(!pause.held());
        assert!(!pause.boundary(false).unwrap());
    }

    #[test]
    fn stale_epoch_and_acknowledgement_cannot_authorize_next_capture() {
        let pause = FaultPause::default();
        pause.request(3).unwrap();
        pause.boundary(false).unwrap();
        pause.release(3).unwrap();
        assert!(pause.request(3).is_err());
        pause.request(4).unwrap();
        assert!(!pause.acknowledged(4));
        assert!(pause.release(3).is_err());
        pause.boundary(false).unwrap();
        assert!(pause.acknowledged(4));
    }

    #[test]
    fn concurrent_requests_cannot_replace_one_retained_epoch() {
        let pause = std::sync::Arc::new(FaultPause::default());
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for epoch in [1, 2] {
            let pause = pause.clone();
            let start = start.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                (epoch, pause.request(epoch).is_ok())
            }));
        }

        start.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|(_, accepted)| *accepted).count(), 1);
        let epoch = results.iter().find(|(_, accepted)| *accepted).unwrap().0;
        let other = if epoch == 1 { 2 } else { 1 };

        assert!(!pause.acknowledged(epoch));
        assert!(pause.release(epoch).is_err());
        pause.boundary(false).unwrap();
        assert!(pause.acknowledged(epoch));
        assert!(!pause.acknowledged(other));
        assert!(pause.release(other).is_err());
        assert!(pause.held());
    }
    #[test]
    fn ordinary_and_checkpoint_holders_cannot_share_worker_admission() {
        let pause = FaultPause::default();
        pause.request_ordinary(1).unwrap();
        assert!(pause.request(1).is_err());
        assert!(!pause.ordinary_acknowledged(1));
        assert!(pause.boundary(true).is_err());
        assert!(!pause.ordinary_acknowledged(1));

        pause.boundary(false).unwrap();
        assert!(pause.ordinary_acknowledged(1));
        assert!(pause.return_ordinary(2).is_err());
        assert!(pause.held());
        pause.return_ordinary(1).unwrap();
        pause.request(1).unwrap();
        assert!(pause.request_ordinary(2).is_err());
    }

    #[test]
    fn stale_ordinary_acknowledgment_cannot_admit_a_new_capture() {
        let pause = FaultPause::default();
        pause.request_ordinary(1).unwrap();
        pause.boundary(false).unwrap();
        pause.return_ordinary(1).unwrap();

        assert!(pause.request_ordinary(1).is_err());
        pause.request_ordinary(2).unwrap();
        assert!(!pause.ordinary_acknowledged(2));
        assert!(pause.return_ordinary(1).is_err());
        pause.boundary(false).unwrap();
        assert!(pause.ordinary_acknowledged(2));
    }
}
