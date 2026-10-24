//! Returns exact World accounting under its once-entered saved Cleanup.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::sync::MutexGuard;

use super::{
    AuthenticatedNativeWorldClaim, AuthenticatedNativeWorldCleanupLoan, HostOperationGuard,
    NativeWorldReturn, PoolState, ServiceBirthError, ledger,
};
use crate::host_supervision::HostOperationClass;

/// Preserves a native return refusal and its independent saved-Cleanup postcut.
///
/// The containing journal records actual irreversible return separately. These
/// moved errors contain no replacement guard, account, clock or return grant.
#[derive(Debug)]
pub struct NativePoolReturnError {
    first: Option<ServiceBirthError>,
    post: Option<crate::host_supervision::HostSupervisionError>,
}

impl NativePoolReturnError {
    /// Borrows the actual structural, accounting or kernel refusal.
    #[must_use]
    pub fn first_error(&self) -> Option<&ServiceBirthError> {
        self.first.as_ref()
    }

    /// Borrows the same saved Cleanup's independent post-refusal.
    #[must_use]
    pub fn post_error(&self) -> Option<&crate::host_supervision::HostSupervisionError> {
        self.post.as_ref()
    }

    pub(super) fn finish<T>(
        result: Result<T, ServiceBirthError>,
        post: Result<(), crate::host_supervision::HostSupervisionError>,
    ) -> Result<T, Self> {
        match (result, post) {
            (Ok(value), Ok(())) => Ok(value),
            (result, post) => Err(Self {
                first: result.err(),
                post: post.err(),
            }),
        }
    }
}

impl From<ServiceBirthError> for NativePoolReturnError {
    fn from(first: ServiceBirthError) -> Self {
        Self {
            first: Some(first),
            post: None,
        }
    }
}

impl std::fmt::Display for NativePoolReturnError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native return refused: first={:?}; Cleanup post={:?}",
            self.first, self.post
        )
    }
}

impl std::error::Error for NativePoolReturnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(first) = &self.first {
            return Some(first);
        }
        match &self.post {
            Some(post) => Some(post),
            None => None,
        }
    }
}

impl AuthenticatedNativeWorldClaim {
    /// Returns this World only after its actual members and body have closed.
    ///
    /// # Errors
    /// Retains live body/member debt, saved Cleanup refusal, and independent post.
    pub fn finish_after_members_returned(&mut self) -> Result<(), NativePoolReturnError> {
        match self.try_finish_after_members_returned()? {
            NativeWorldReturn::Returned => Ok(()),
            NativeWorldReturn::PendingBody => Err(ServiceBirthError::policy(
                "native World still retains containing-body custody",
            )
            .into()),
        }
    }

    /// Observes actual return, including return driven by this World's loan.
    ///
    /// An uncertain ledger remains unreturned. The cached local fact stays true
    /// after irreversible return, independently of any historical post-refusal.
    #[must_use]
    pub fn is_physically_returned(&mut self) -> bool {
        if self.returned {
            return true;
        }
        let Some(held) = self.held.as_ref() else {
            return false;
        };
        observe_claim_returned(&held.ledger, self.epoch, &mut self.returned)
    }

    /// Returns exact accounting or observes its still-retained containing body.
    ///
    /// Pending validates the complete ledger without entering Cleanup or changing
    /// debt. Physical return uses the same World original and cached Cleanup;
    /// parent expiry cannot become a new work admission or replacement clock.
    ///
    /// # Errors
    /// Retains typed structural/kernel refusal and independent Cleanup post.
    /// A post-refusal can coexist with actual return; callers must observe that
    /// fact before reporting the error and must never subtract a second time.
    pub fn try_finish_after_members_returned(
        &mut self,
    ) -> Result<NativeWorldReturn, NativePoolReturnError> {
        if self.returned {
            return Ok(NativeWorldReturn::Returned);
        }
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native World return custody is absent"))?;
        try_return_world(held, self.epoch, Some(&self.original), &mut self.returned)
    }
}

impl AuthenticatedNativeWorldCleanupLoan {
    /// Returns only this genuinely borrowed World's closed assignment.
    ///
    /// The original and cached Cleanup come from this loan's actual retained
    /// pool and epoch. A pending body enters no Cleanup. Actual descriptor and
    /// ledger consumption is recorded before reporting work or post-refusal.
    ///
    /// # Errors
    /// Retains uncertain/stale custody, live members, structural/kernel failure
    /// and the same Cleanup's independent post. An error may follow actual
    /// return; use [`Self::observe_physically_returned`] before retrying effects.
    pub fn try_finish_after_members_returned(
        &self,
    ) -> Result<NativeWorldReturn, NativePoolReturnError> {
        let mut returned = false;
        try_return_world(&self.held, self.epoch, None, &mut returned)
    }

    /// Observes this exact issued epoch's physical return without new work.
    ///
    /// The loan's private pool identity and monotonic epoch survive canonical
    /// row reuse. This neither enters Cleanup nor erases earlier return errors.
    ///
    /// # Errors
    /// Refuses an unissued epoch or an unavailable/uncertain ledger. Absence
    /// proves return only at the existing irreversible journal-removal cut.
    pub fn observe_physically_returned(&self) -> Result<bool, ServiceBirthError> {
        observe_returned(&self.held.ledger, self.epoch)
    }
}

impl Drop for AuthenticatedNativeWorldClaim {
    fn drop(&mut self) {
        let returned = self.is_physically_returned();
        if let Some(held) = self.held.take() {
            if returned {
                drop(held);
            } else {
                // Losing an uncertain facade still proves no physical return.
                std::mem::forget(held);
            }
        }
    }
}

fn observe_returned(
    ledger: &Mutex<ledger::PoolLedger>,
    epoch: u64,
) -> Result<bool, ServiceBirthError> {
    ledger
        .try_lock()
        .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?
        .observe_world_returned(epoch)
}

/// Keeps the same World open until its existing pool alias has been retained.
#[cfg(test)]
pub(super) fn borrow_unreturned_world(
    ledger: &Mutex<ledger::PoolLedger>,
    epoch: u64,
) -> Result<MutexGuard<'_, ledger::PoolLedger>, ServiceBirthError> {
    let ledger = ledger
        .try_lock()
        .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?;
    if ledger.observe_world_returned(epoch)? {
        return Err(ServiceBirthError::policy("native World already returned"));
    }
    Ok(ledger)
}

/// A factual observation remains true even if a later Drop cannot borrow the ledger.
fn observe_claim_returned(
    ledger: &Mutex<ledger::PoolLedger>,
    epoch: u64,
    returned: &mut bool,
) -> bool {
    if *returned {
        return true;
    }
    let observed = ledger
        .try_lock()
        .is_ok_and(|ledger| ledger.world_return_fact(epoch) == Ok(true));
    if observed {
        *returned = true;
    }
    observed
}

enum ReturnStart {
    Observed(NativeWorldReturn),
    Ready {
        original: Arc<HostOperationGuard>,
        cleanup: Arc<HostOperationGuard>,
    },
}

/// Holds the same ledger lock while authenticating and preparing first effects.
fn prepare_return(
    ledger: &ledger::PoolLedger,
    epoch: u64,
    expected_original: Option<&Arc<HostOperationGuard>>,
) -> Result<ReturnStart, ServiceBirthError> {
    if ledger.observe_world_returned(epoch)? {
        return Ok(ReturnStart::Observed(NativeWorldReturn::Returned));
    }
    if let Some(original) = expected_original {
        ledger.verify_world_original(epoch, original)?;
    }
    if matches!(
        ledger.prepare_world_return(epoch)?,
        ledger::WorldReturnPreparation::PendingBody
    ) {
        return Ok(ReturnStart::Observed(NativeWorldReturn::PendingBody));
    }
    let original = Arc::clone(ledger.world_original(epoch)?);
    // Only the ready physical cut enters Cleanup. Every retry reads the same
    // saved admission result; no caller supplies a replacement original.
    let cleanup = ledger.enter_cleanup(epoch)?;
    Ok(ReturnStart::Ready { original, cleanup })
}

fn try_return_world(
    held: &PoolState,
    epoch: u64,
    expected_original: Option<&Arc<HostOperationGuard>>,
    returned: &mut bool,
) -> Result<NativeWorldReturn, NativePoolReturnError> {
    let start = {
        let ledger = held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?;
        prepare_return(&ledger, epoch, expected_original)?
    };
    let (original, cleanup) = match start {
        ReturnStart::Observed(observed) => {
            if observed == NativeWorldReturn::Returned {
                *returned = true;
            }
            return Ok(observed);
        }
        ReturnStart::Ready { original, cleanup } => (original, cleanup),
    };
    let result = (|| {
        held.verify_return_custody(&cleanup)?;
        let mut ledger = held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?;
        if ledger.observe_world_returned(epoch)? {
            *returned = true;
            return Ok(NativeWorldReturn::Returned);
        }
        ledger.verify_world_original(epoch, &original)?;
        ledger.verify_cleanup(epoch, &cleanup)?;
        let (index, used, peak, tables) = match ledger.prepare_world_return(epoch)? {
            ledger::WorldReturnPreparation::PendingBody => {
                return Ok(NativeWorldReturn::PendingBody);
            }
            ledger::WorldReturnPreparation::Ready {
                index,
                used,
                peak,
                tables,
            } => (index, used, peak, tables),
        };
        let (work, consumed) = held
            .root
            .owner
            .host_descriptors
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("Main descriptor owner is uncertain"))?
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
            .close_pool_assignment(peak, tables);
        record_return(&mut ledger, epoch, index, used, consumed, returned);
        drop(ledger);
        work?;
        Ok(NativeWorldReturn::Returned)
    })();
    finish_return(result, &cleanup, *returned)
}

/// Latches the actual consumption before either its work result or postcut.
fn record_return(
    ledger: &mut ledger::PoolLedger,
    epoch: u64,
    index: usize,
    used: super::HostResourceVector,
    consumed: bool,
    returned: &mut bool,
) {
    if consumed {
        ledger.commit_world_return(index, epoch, used);
        *returned = true;
    }
}

fn finish_return(
    result: Result<NativeWorldReturn, ServiceBirthError>,
    cleanup: &HostOperationGuard,
    returned: bool,
) -> Result<NativeWorldReturn, NativePoolReturnError> {
    let post = cleanup
        .verify_operation_class(HostOperationClass::Cleanup)
        .and_then(|()| {
            if returned {
                cleanup.complete().map(|_| ())
            } else {
                Ok(())
            }
        });
    NativePoolReturnError::finish(result, post)
}

#[cfg(test)]
pub(super) mod tests;
