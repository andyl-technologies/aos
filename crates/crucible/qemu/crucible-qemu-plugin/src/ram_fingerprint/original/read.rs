//! Retains nested backing-read loans beneath the already borrowed Root view.
//!
//! The inline ledger blocks Root view return and physical retirement while a
//! synchronous backing exchange exists. Its checked serial is local identity,
//! never an Original or a clock. Every read still queries the existing Source
//! Original; physical loan release queries neither a deadline nor a dead parent.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    serial: u64,
    selector: usize,
}

/// Belongs to the complete paid Runtime, independently of any read stack frame.
#[derive(Default)]
pub(super) struct Custody {
    serial: u64,
    retained: Option<Identity>,
}

impl Custody {
    pub(super) fn is_retained(&self) -> bool {
        self.retained.is_some()
    }
}

/// Owns one physical child of the Module's existing Root view.
struct Loan<'a> {
    state: &'a Mutex<State>,
    identity: Identity,
}

impl<'a> Loan<'a> {
    fn retain(state: &'a Mutex<State>, selector: usize) -> Result<Self, ObservationOperationError> {
        let mut current = state
            .try_lock()
            .map_err(|_| refusal("Root read loan busy"))?;
        if selector == 0
            || current.selector.load(Ordering::Acquire) as usize != selector
            || current.reads.is_retained()
        {
            return Err(refusal("Root read parent is absent or already lent"));
        }
        let serial = current
            .reads
            .serial
            .checked_add(1)
            .ok_or_else(|| refusal("Root read loan serial exhausted"))?;
        let identity = Identity { serial, selector };
        current.reads.serial = serial;
        current.reads.retained = Some(identity);
        Ok(Self { state, identity })
    }

    fn current(&self) -> Result<(), ObservationOperationError> {
        let current = self
            .state
            .try_lock()
            .map_err(|_| refusal("Root read observation busy"))?;
        if current.reads.retained != Some(self.identity)
            || current.selector.load(Ordering::Acquire) as usize != self.identity.selector
        {
            return Err(refusal("Root read loan changed"));
        }
        Ok(())
    }
}

impl Drop for Loan<'_> {
    fn drop(&mut self) {
        // The synchronous closure cannot retain the borrowed operation. Release
        // its real local loan even after expiry or unwinding; neither event
        // ends the Source Original. Changed identity leaves durable parent debt.
        let Ok(mut current) = self.state.try_lock() else {
            // Contention or poison leaves the prepaid parent's real debt. The
            // caller cannot treat a best-effort destructor as consumed custody.
            return;
        };
        if current.reads.retained == Some(self.identity)
            && current.selector.load(Ordering::Acquire) as usize == self.identity.selector
        {
            current.reads.retained = None;
        }
    }
}

/// Completes backing work without claiming native output or progress publication.
struct ReadExchange<'a> {
    owner: &'a Owner,
    loan: Loan<'a>,
    completed: AtomicBool,
}

impl SourceOperation for ReadExchange<'_> {
    fn wait_slice(&self) -> std::io::Result<Duration> {
        self.wait_slice_for_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        if self.completed.load(Ordering::Acquire) {
            return Err(refusal(
                "native Original backing exchange already completed",
            ));
        }
        self.loan.current()?;
        self.owner
            .sample()
            .map(|evidence| Duration::from_nanos(evidence.bounded_ns))
    }

    fn complete(&self) -> std::io::Result<()> {
        self.complete_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.wait_slice_for_observation()?;
        self.completed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| refusal("native Original backing exchange completed twice"))?;
        // Native mints its witness only after this backing exchange and its
        // output/range publication succeed. Completion retains the physical
        // child until the synchronous callback has actually returned.
        Ok(())
    }
}

/// Lends the existing Root Original and retains its parent through the exchange.
///
/// # Errors
/// Refuses an absent Root view, another retained read, exhausted local identity,
/// or busy ownership before invoking the supplied exchange. No clock is issued.
pub(crate) fn with_read_exchange<T>(
    exchange: impl FnOnce(&dyn SourceOperation) -> T,
) -> Result<T, ObservationOperationError> {
    let owner = OBSERVER
        .get()
        .and_then(|observer| observer.original)
        .ok_or_else(|| refusal("RAM observation lacks an active native Original"))?
        .owner();
    let selector = owner.selector()?;
    let loan = Loan::retain(&owner.state, selector)?;
    let operation = ReadExchange {
        owner,
        loan,
        completed: AtomicBool::new(false),
    };
    Ok(exchange(&operation))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures exercise the real Module loan ledger and Rust scope only.
    // The opaque address is never dereferenced or accepted by a Source issuer.
    fn state() -> Mutex<State> {
        Mutex::new(State {
            selector: AtomicPtr::new(std::ptr::dangling_mut()),
            ..State::default()
        })
    }

    fn selector(state: &Mutex<State>) -> usize {
        state.lock().unwrap().selector.load(Ordering::Acquire) as usize
    }

    #[test]
    fn backing_read_scope_keeps_parent_debt_through_result_construction_and_unwind() {
        for unwind in [false, true] {
            let state = state();
            let selector = selector(&state);
            let result = std::panic::catch_unwind(|| {
                let loan = Loan::retain(&state, selector).unwrap();
                assert!(loan.current().is_ok());
                assert!(state.lock().unwrap().reads.is_retained());
                assert!(Loan::retain(&state, selector).is_err());
                if unwind {
                    panic!("backing exchange unwinds with its parent retained");
                }
                // Producing a completed result cannot release the scope loan.
                let result = 7_u32;
                assert!(state.lock().unwrap().reads.is_retained());
                result
            });

            assert_eq!(result.is_err(), unwind);
            assert!(!state.lock().unwrap().reads.is_retained());
            assert_eq!(self::selector(&state), selector);
        }
    }

    #[test]
    fn changed_parent_cannot_release_retained_read_debt() {
        let state = state();
        let selector = selector(&state);
        let loan = Loan::retain(&state, selector).unwrap();
        state
            .lock()
            .unwrap()
            .selector
            .store(std::ptr::null_mut(), Ordering::Release);
        assert!(loan.current().is_err());

        drop(loan);

        assert!(state.lock().unwrap().reads.is_retained());
        assert!(Loan::retain(&state, selector).is_err());
    }

    #[test]
    fn contended_read_release_retains_parent_without_waiting() {
        let state = state();
        let selector = selector(&state);
        let loan = Loan::retain(&state, selector).unwrap();
        let current = state.lock().unwrap();

        drop(loan);

        assert!(current.reads.is_retained());
        assert_eq!(current.selector.load(Ordering::Acquire) as usize, selector);
    }

    #[test]
    fn exhausted_read_identity_refuses_before_exchange_and_preserves_parent() {
        let state = state();
        let selector = selector(&state);
        state.lock().unwrap().reads.serial = u64::MAX;

        assert!(Loan::retain(&state, selector).is_err());

        let current = state.lock().unwrap();
        assert!(!current.reads.is_retained());
        assert_eq!(current.reads.serial, u64::MAX);
        assert_eq!(current.selector.load(Ordering::Acquire) as usize, selector);
    }
}
