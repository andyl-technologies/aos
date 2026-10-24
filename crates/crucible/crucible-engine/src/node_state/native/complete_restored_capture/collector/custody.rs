//! Releases private collection bank loans before full-observation callbacks.
//!
//! The separate once fence keeps a temporarily empty bank from looking unused.
//! Actual partial caches return to that same bank on ordinary failure or unwind.
//! This is pure terminal-verifier custody; no modeled operation is reconstructed.

use super::*;
use std::cell::{Cell, RefCell};

/// Preserves the actual terminal collection once state while its bank is lent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum CollectorPhase17 {
    /// No collection attempt has begun.
    Pending,
    /// A local staging guard owns the actual output during callbacks.
    Running,
    /// The same output returned after successful origin and constructor guards.
    Finished,
    /// Refusal or unwind spent the attempt and preserved its partial custody.
    Failed,
}

struct StagedCollection17<'a, T> {
    bank: &'a RefCell<Option<T>>,
    phase: &'a Cell<CollectorPhase17>,
    value: Option<T>,
    restored: bool,
}

impl<'a, T> StagedCollection17<'a, T> {
    fn begin_data(
        bank: &'a RefCell<Option<T>>,
        phase: &'a Cell<CollectorPhase17>,
    ) -> Result<Self, StateError> {
        if phase.get() != CollectorPhase17::Pending {
            return Err(refused("settled17 terminal collection is busy or spent"));
        }
        let mut output = bank
            .try_borrow_mut()
            .map_err(|_| refused("settled17 terminal collection bank is busy"))?;
        if output.is_some() {
            return Err(refused(
                "settled17 terminal collection already has an owner",
            ));
        }
        phase.set(CollectorPhase17::Running);
        let value = output.take();
        drop(output);
        Ok(Self {
            bank,
            phase,
            value,
            restored: false,
        })
    }

    fn restore_data(&mut self, completed: bool) -> Result<(), StateError> {
        let mut output = match self.bank.try_borrow_mut() {
            Ok(output) => output,
            Err(_) => {
                self.phase.set(CollectorPhase17::Failed);
                return Err(refused("settled17 terminal collection return bank is busy"));
            }
        };
        if output.is_some() || self.phase.get() != CollectorPhase17::Running {
            self.phase.set(CollectorPhase17::Failed);
            return Err(refused(
                "settled17 terminal collection return custody differs",
            ));
        }
        *output = self.value.take();
        self.restored = true;
        self.phase.set(if completed {
            CollectorPhase17::Finished
        } else {
            CollectorPhase17::Failed
        });
        Ok(())
    }
}

impl<T> Drop for StagedCollection17<'_, T> {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        // No public method lends a private collection Ref across a callback.
        // If that invariant is violated internally, keep the fence failed and
        // preserve an existing bank owner; a pure local cache may then drop.
        self.phase.set(CollectorPhase17::Failed);
        if let Ok(mut output) = self.bank.try_borrow_mut() {
            if output.is_none() {
                *output = self.value.take();
            }
        }
    }
}

/// Collects in local custody while no private bank loan crosses an observer.
///
/// # Errors
/// Refuses foreign origin, reused/busy custody, any defining decoder failure,
/// or failure to return the actual partial output to its original bank.
pub(in super::super) fn collect_terminal_into_data(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    additional: usize,
) -> Result<(), StateError> {
    scope.validation_origin.authenticate(scope.archive)?;
    let mut staged = StagedCollection17::begin_data(scope.collection, scope.collection_phase)?;
    let result =
        RetainedCold17Collection::collect_current_into(scope, additional, &mut staged.value);
    let current = scope.validation_origin.authenticate(scope.archive);
    let completed = result.is_ok() && current.is_ok();
    let restored = staged.restore_data(completed);
    // Recheck the exact archive even when a constructor refused. Neither an
    // earlier typed output nor a restored cache slot supplies currentness.
    current?;
    restored?;
    result
}

/// Names the actual staging guard, once state and both-outcome result headers.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<StagedCollection17<'static, RetainedCold17Collection>>()
        + size_of::<CollectorPhase17>()
        + size_of::<Result<(), StateError>>() * 3
        + size_of::<Result<StagedCollection17<'static, RetainedCold17Collection>, StateError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbacks_can_borrow_the_bank_but_cannot_restart_the_once_owner() {
        let bank = RefCell::new(None::<u8>);
        let phase = Cell::new(CollectorPhase17::Pending);
        let mut staged = StagedCollection17::begin_data(&bank, &phase).unwrap();
        staged.value = Some(7);

        assert!(bank.try_borrow_mut().is_ok());
        assert!(StagedCollection17::begin_data(&bank, &phase).is_err());
        assert_eq!(phase.get(), CollectorPhase17::Running);

        staged.restore_data(true).unwrap();
        assert_eq!(*bank.borrow(), Some(7));
        assert_eq!(phase.get(), CollectorPhase17::Finished);
        assert!(StagedCollection17::begin_data(&bank, &phase).is_err());
    }

    #[test]
    fn refusal_and_early_return_guard_return_actual_partial_custody() {
        for early_return in [false, true] {
            let bank = RefCell::new(None::<Vec<u8>>);
            let phase = Cell::new(CollectorPhase17::Pending);
            {
                let mut staged = StagedCollection17::begin_data(&bank, &phase).unwrap();
                let mut partial = Vec::with_capacity(31);
                partial.extend_from_slice(b"partial");
                staged.value = Some(partial);
                if !early_return {
                    staged.restore_data(false).unwrap();
                }
            }
            assert_eq!(phase.get(), CollectorPhase17::Failed);
            assert_eq!(bank.borrow().as_ref().unwrap().as_slice(), b"partial");
            assert!(bank.borrow().as_ref().unwrap().capacity() >= 31);
            assert!(StagedCollection17::begin_data(&bank, &phase).is_err());
        }
    }

    #[test]
    fn unwinding_restores_the_partial_and_poisons_the_once_fence() {
        let bank = RefCell::new(None::<u8>);
        let phase = Cell::new(CollectorPhase17::Pending);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut staged = StagedCollection17::begin_data(&bank, &phase).unwrap();
            staged.value = Some(19);
            panic!("terminal callback unwound");
        }));

        assert!(result.is_err());
        assert_eq!(*bank.borrow(), Some(19));
        assert_eq!(phase.get(), CollectorPhase17::Failed);
        assert!(StagedCollection17::begin_data(&bank, &phase).is_err());
    }
}
