//! Owns the Module counterpart of Source's registered RAM read children.
//!
//! Each child retains a real subloan of the existing Root view. Protected
//! journals and completed receipts stay inline in the paid pinned Runtime;
//! Source reads them only after the corresponding Module callback returns.
//! No callback or factual return creates an Original or replaces its clock.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use std::sync::atomic::AtomicU64;

mod abi;
mod api;
mod callbacks;

use abi::{CompletedReceipt, Completion, Journal, SourceChild, SourceOwner};
use api::Api;

/// Retains the actual nominal loan until explicit known physical consumption.
struct Child {
    source: usize,
    epoch: u64,
    loan: Option<read::Loan<'static>>,
}

#[derive(Default)]
struct ReaderState {
    attempted: bool,
    enrollment_status: Option<c_int>,
    owner_epoch: u64,
    journal: Journal,
    receipt: CompletedReceipt,
    prior_completion: Option<Completion>,
    child: Option<Child>,
    completion_pending: bool,
    close_attempted: bool,
    close_status: Option<c_int>,
    closed: bool,
    return_attempted: bool,
    returned: bool,
    return_first: Option<c_int>,
    return_post: Option<c_int>,
    return_observation: Option<abi::RegistrationReturn>,
    first_error: Option<ObservationOperationError>,
    post_error: Option<ObservationOperationError>,
    return_error: Option<ObservationOperationError>,
    source_post_status: Option<c_int>,
    acknowledgement_status: Option<c_int>,
}

/// Belongs to the actual Runtime allocation priced before any callback birth.
pub(super) struct Reader {
    api: Option<Api>,
    holder: AtomicPtr<SourceOwner>,
    epoch: AtomicU64,
    state: Mutex<ReaderState>,
}

impl Reader {
    /// Initializes inline custody before the containing Runtime is exposed.
    ///
    /// # Errors
    /// Refuses a selected reader without the complete matching Native SDK.
    pub(super) fn prepare(placement: FingerprintPlacement) -> Result<Self, RamError> {
        let api = match placement {
            FingerprintPlacement::Paging => Some(Api::resolve()?),
            FingerprintPlacement::Resident => None,
        };
        Ok(Self {
            api,
            holder: AtomicPtr::new(std::ptr::null_mut()),
            epoch: AtomicU64::new(0),
            state: Mutex::new(ReaderState::default()),
        })
    }

    /// Enrolls only after the real callback child and registration owner exist.
    ///
    /// # Errors
    /// Retains born outputs on Source refusal, contention or failed enrollment.
    pub(super) fn enroll(
        &'static self,
        owner: &'static Owner,
        runtime: *mut crate::startup_source::runtime_purpose::RuntimePurpose,
    ) -> Result<(), RamError> {
        let Some(api) = self.api else {
            return Ok(());
        };
        let mut state = self.state.try_lock().map_err(|_| busy())?;
        if state.attempted || runtime.is_null() {
            return Err(RamError::Invariant(
                "RAM reader registration already attempted or absent",
            ));
        }
        state.attempted = true;
        let journal = std::ptr::from_mut(&mut state.journal);
        let receipt = std::ptr::from_mut(&mut state.receipt);
        drop(state);

        // These are stable, disjoint fields of the genuinely retained Runtime.
        // Source alone writes the canonical fields, before callback admission
        // or during physical registration return. No Rust reference aliases
        // those writes and its registry synchronizes later observations.
        let status = (api.register)(
            owner.plugin_id,
            runtime,
            &callbacks::CALLBACKS,
            journal,
            receipt,
            self.holder.as_ptr(),
            self.epoch.as_ptr(),
        );
        let epoch = self.epoch.load(Ordering::Acquire);
        let mut state = self.state.try_lock().map_err(|_| busy())?;
        state.owner_epoch = epoch;
        state.enrollment_status = Some(status);
        drop(state);
        native(status, "register retained RAM readers")?;
        if self.holder.load(Ordering::Acquire).is_null() || epoch == 0 {
            return Err(RamError::Invariant(
                "RAM reader registration has no born owner",
            ));
        }
        Ok(())
    }

    /// Checks the saved successful enrollment and its actual canonical fields.
    ///
    /// # Errors
    /// Refuses an absent, changed, failed or physically closing registration.
    pub(super) fn require_enrolled(&self) -> Result<(), RamError> {
        let state = self.state.try_lock().map_err(|_| busy())?;
        if self.api.is_none()
            || state.enrollment_status != Some(0)
            || state.close_attempted
            || state.return_attempted
            || state.owner_epoch == 0
            || self.epoch.load(Ordering::Acquire) != state.owner_epoch
            || self.holder.load(Ordering::Acquire).is_null()
        {
            return Err(RamError::Invariant("paid RAM reader registration absent"));
        }
        Ok(())
    }

    /// Borrows the already retained child during the actual Source read phase.
    ///
    /// # Errors
    /// Refuses missing selected custody, changed identity or a failed current
    /// observation. Resident mode has no nominal Source reader registration.
    pub(super) fn borrow_backing(
        &self,
    ) -> Result<Option<read::Borrow<'static>>, ObservationOperationError> {
        let Some(api) = self.api else {
            return Ok(None);
        };
        let selected = {
            let state = self
                .state
                .try_lock()
                .map_err(|_| refusal("RAM read child busy"))?;
            state
                .child
                .as_ref()
                .and_then(|child| child.loan.as_ref().map(|_| (child.source, child.epoch)))
        };
        let (source, epoch) = selected.ok_or_else(|| refusal("selected RAM read child absent"))?;
        let status = (api.child_current)(source as *mut SourceChild, epoch);
        if status != 0 {
            return Err(ObservationOperationError::Io(
                std::io::Error::from_raw_os_error(if status < 0 {
                    status.saturating_neg()
                } else {
                    libc::EPROTO
                }),
            ));
        }
        let state = self
            .state
            .try_lock()
            .map_err(|_| refusal("RAM read child busy"))?;
        let child = state
            .child
            .as_ref()
            .ok_or_else(|| refusal("RAM read child absent"))?;
        if child.source != source || child.epoch != epoch || !state.completion_pending {
            return Err(refusal("RAM read child changed"));
        }
        let loan = child
            .loan
            .as_ref()
            .ok_or_else(|| refusal("RAM read child returned"))?;
        loan.current()?;
        // This borrow refers only to the same process-retained Original ledger.
        // Its current check rejects physical consumption; Source separately
        // authenticated the actual entered child above. It creates no owner.
        Ok(Some(loan.borrow()))
    }

    /// Saves the prior delivery's final Source facts before receipt replacement.
    ///
    /// # Errors
    /// Refuses failed observations, changed receipts or retained delivery debt.
    pub(super) fn corroborate_completion(&self, plugin_id: u64) -> Result<(), RamError> {
        let Some(api) = self.api else {
            return Ok(());
        };
        let (owner_epoch, saved) = {
            let state = self.state.try_lock().map_err(|_| busy())?;
            (state.owner_epoch, state.receipt)
        };
        if saved.source.source_epoch == 0 {
            return Ok(());
        }
        let mut final_source = Completion::default();
        let status = (api.observe_completion)(
            plugin_id,
            self.holder.as_ptr(),
            self.epoch.as_ptr(),
            owner_epoch,
            saved.source.source_epoch,
            &mut final_source,
        );
        native(status, "observe RAM read completion")?;
        if final_source.read != saved.source
            || final_source.delivery_entered != 1
            || final_source.delivery_returned != 1
            || final_source.acknowledgement_attempted != 1
            || final_source.acknowledged != 1
            || final_source.post_recorded != 1
            || final_source.retained != 0
            || final_source.uncertain != 0
            || final_source.reserved != 0
            || final_source.callback_status != 0
            || final_source.post_status != 0
            || final_source.first_status != 0
            || final_source.acknowledgement_status != 0
        {
            return Err(RamError::Invariant(
                "RAM read completion retains delivery debt",
            ));
        }
        let mut state = self.state.try_lock().map_err(|_| busy())?;
        if state.receipt != saved {
            return Err(RamError::Invariant(
                "RAM read receipt changed during observation",
            ));
        }
        state.prior_completion = Some(final_source);
        state.completion_pending = false;
        Ok(())
    }

    /// Closes, drains and returns registration before its containing owner.
    ///
    /// # Errors
    /// Preserves active children, uncertain returns and independent negative
    /// statuses. Known physical consumption is recorded before error projection.
    pub(super) fn return_registration(&self, plugin_id: u64) -> Result<(), RamError> {
        {
            let state = self.state.try_lock().map_err(|_| busy())?;
            if state.returned {
                return returned_result(&state);
            }
            if !state.attempted {
                return Ok(());
            }
        }
        let Some(api) = self.api else {
            return Ok(());
        };
        self.corroborate_completion(plugin_id)?;
        let (attempted, returned, closed, return_attempted, epoch) = {
            let state = self.state.try_lock().map_err(|_| busy())?;
            if state.completion_pending
                || state
                    .child
                    .as_ref()
                    .is_some_and(|child| child.loan.is_some())
            {
                return Err(RamError::Invariant("RAM reader still retains a child"));
            }
            (
                state.attempted,
                state.returned,
                state.closed,
                state.return_attempted,
                state.owner_epoch,
            )
        };
        if !attempted || returned {
            let state = self.state.try_lock().map_err(|_| busy())?;
            return if returned {
                returned_result(&state)
            } else {
                Ok(())
            };
        }
        if return_attempted {
            return Err(RamError::Invariant(
                "RAM reader registration return is uncertain",
            ));
        }
        if !closed {
            self.state.try_lock().map_err(|_| busy())?.close_attempted = true;
            let status = (api.close)(plugin_id, self.holder.load(Ordering::Acquire), epoch);
            let mut state = self.state.try_lock().map_err(|_| busy())?;
            state.close_status.get_or_insert(status);
            drop(state);
            native(status, "close RAM reader admission")?;
            self.state.try_lock().map_err(|_| busy())?.closed = true;
        }
        self.state.try_lock().map_err(|_| busy())?.return_attempted = true;
        let first = (api.return_owner)(plugin_id, self.holder.as_ptr(), self.epoch.as_ptr());
        self.state.try_lock().map_err(|_| busy())?.return_first = Some(first);
        let mut observation = abi::RegistrationReturn::default();
        let post = (api.observe_return)(
            plugin_id,
            self.holder.as_ptr(),
            self.epoch.as_ptr(),
            epoch,
            &mut observation,
        );
        let mut state = self.state.try_lock().map_err(|_| busy())?;
        state.return_post = Some(post);
        state.return_observation = Some(observation);
        if post == 0
            && observation.owner_epoch == epoch
            && observation.attempted == 1
            && observation.returned == 1
            && observation.consumed == 1
            && observation.uncertain == 0
            && self.holder.load(Ordering::Acquire).is_null()
            && self.epoch.load(Ordering::Acquire) == 0
        {
            state.returned = true;
        }
        if !state.returned {
            native(first, "return RAM reader registration")?;
            native(post, "observe RAM reader registration return")?;
            return Err(RamError::Invariant(
                "RAM reader registration is not consumed",
            ));
        }
        returned_result(&state)
    }
}

/// Projects saved history only; known consumption forbids another Source call.
fn returned_result(state: &ReaderState) -> Result<(), RamError> {
    let (Some(first), Some(post), Some(observation)) = (
        state.return_first,
        state.return_post,
        state.return_observation,
    ) else {
        return Err(RamError::Invariant(
            "RAM reader registration return history absent",
        ));
    };
    // Physical cleanup can finish after an earlier close refusal. Preserve
    // that first failure without retrying the already consumed registration.
    let close = state.close_status.ok_or(RamError::Invariant(
        "RAM reader registration close history absent",
    ))?;
    native(close, "close RAM reader admission")?;
    native(first, "return RAM reader registration")?;
    native(post, "observe RAM reader registration return")?;
    native(
        observation.first_status,
        "RAM reader registration return first",
    )?;
    native(
        observation.post_status,
        "RAM reader registration return post",
    )
}

fn busy() -> RamError {
    RamError::Invariant("RAM reader owner is busy or poisoned")
}

fn native(status: c_int, operation: &'static str) -> Result<(), RamError> {
    if status == 0 {
        Ok(())
    } else {
        Err(RamError::Native { operation, status })
    }
}

pub(super) fn active_owner() -> Option<&'static Owner> {
    OBSERVER.get()?.original.map(OwnerRef::owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumed_registration_replays_close_refusal_without_source_calls() {
        // This local journal supplies no Source owner or Native return. The
        // absent API proves replay cannot call another destructor or observer.
        let reader = Reader {
            api: None,
            holder: AtomicPtr::new(std::ptr::null_mut()),
            epoch: AtomicU64::new(0),
            state: Mutex::new(ReaderState {
                attempted: true,
                close_attempted: true,
                close_status: Some(-libc::EBUSY),
                closed: true,
                return_attempted: true,
                returned: true,
                return_first: Some(0),
                return_post: Some(0),
                return_observation: Some(abi::RegistrationReturn {
                    owner_epoch: 7,
                    attempted: 1,
                    returned: 1,
                    consumed: 1,
                    ..abi::RegistrationReturn::default()
                }),
                ..ReaderState::default()
            }),
        };

        for _ in 0..2 {
            let error = reader.return_registration(23).unwrap_err();
            assert!(matches!(
                error,
                RamError::Native {
                    operation: "close RAM reader admission",
                    status,
                } if status == -libc::EBUSY
            ));
        }

        let state = reader.state.try_lock().unwrap();
        assert!(state.returned);
        assert_eq!(state.close_status, Some(-libc::EBUSY));
        assert_eq!(state.return_first, Some(0));
        assert_eq!(state.return_post, Some(0));
        assert_eq!(state.return_observation.unwrap().consumed, 1);
        assert!(reader.holder.load(Ordering::Acquire).is_null());
        assert_eq!(reader.epoch.load(Ordering::Acquire), 0);
    }
}
