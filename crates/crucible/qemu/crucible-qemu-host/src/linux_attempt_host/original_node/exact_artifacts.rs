//! Retains exact-restore artifacts until their actual destruction completes.
//!
//! The fixed cell belongs to the prebirth controller. It runs no destructor
//! under its metadata mutex. Unwind or duplicate delivery preserves uncertainty
//! permanently; neither an empty slot nor a returned Node proves file closure.

use std::sync::Mutex;

pub(super) struct ExactArtifactCell<T> {
    state: Mutex<ArtifactState<T>>,
}

enum ArtifactState<T> {
    Vacant,
    Held(T),
    Issued,
    Closing,
    Uncertain(Option<T>),
}

impl<T> Default for ExactArtifactCell<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(ArtifactState::Vacant),
        }
    }
}

impl<T> ExactArtifactCell<T> {
    /// Reserves the existing cell while the launch still owns its artifacts.
    pub(super) fn reserve_transfer(&self) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if !matches!(*state, ArtifactState::Vacant) {
            return false;
        }
        *state = ArtifactState::Issued;
        true
    }

    /// Transfers the actual artifacts to their next successful external owner.
    pub(super) fn finish_transfer(&self) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if !matches!(*state, ArtifactState::Issued) {
            return false;
        }
        *state = ArtifactState::Vacant;
        true
    }

    /// Receives the unique actual artifacts without creating another owner.
    ///
    /// # Errors
    /// Returns a duplicate delivery to its sender and quarantines the cell.
    pub(super) fn retain(&self, artifacts: T) -> Result<(), T> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, ArtifactState::Vacant | ArtifactState::Issued) {
            *state = ArtifactState::Held(artifacts);
            return Ok(());
        }

        // A duplicate violates the unique launch reservation. Keep the first
        // body and permanently prevent closure; losing a handle cannot certify
        // physical return. The extra body remains in terminal containment.
        let previous = std::mem::replace(&mut *state, ArtifactState::Closing);
        *state = match previous {
            ArtifactState::Held(first) => ArtifactState::Uncertain(Some(first)),
            ArtifactState::Uncertain(first) => ArtifactState::Uncertain(first),
            ArtifactState::Closing | ArtifactState::Vacant | ArtifactState::Issued => {
                ArtifactState::Uncertain(None)
            }
        };
        drop(state);
        Err(artifacts)
    }

    /// Destroys actual artifacts outside the mutex and latches only completion.
    pub(super) fn close(&self) -> bool {
        let artifacts = {
            let Ok(mut state) = self.state.try_lock() else {
                return false;
            };
            match &*state {
                ArtifactState::Vacant => return true,
                ArtifactState::Issued | ArtifactState::Closing | ArtifactState::Uncertain(_) => {
                    return false;
                }
                ArtifactState::Held(_) => {}
            }
            match std::mem::replace(&mut *state, ArtifactState::Closing) {
                ArtifactState::Held(artifacts) => artifacts,
                _ => return false,
            }
        };

        drop(artifacts);

        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if !matches!(*state, ArtifactState::Closing) {
            return false;
        }
        *state = ArtifactState::Vacant;
        true
    }

    /// Reports only a vacant cell after successful handoff or destruction.
    pub(super) fn returned(&self) -> bool {
        self.state
            .try_lock()
            .is_ok_and(|state| matches!(*state, ArtifactState::Vacant))
    }
}

impl<T> Drop for ExactArtifactCell<T> {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::mem::replace(state, ArtifactState::Closing) {
            ArtifactState::Held(artifacts) | ArtifactState::Uncertain(Some(artifacts)) => {
                std::mem::forget(artifacts);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "exact_artifacts/tests.rs"]
mod tests;
