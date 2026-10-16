//! Returns exact World accounting under its once-entered saved Cleanup.
// SPDX-License-Identifier: Apache-2.0

use super::{AuthenticatedNativeWorldClaim, NativeWorldReturn, ServiceBirthError, ledger};

/// Preserves a native return refusal and its independent saved-Cleanup postcut.
///
/// The containing claim records actual irreversible return separately. These
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
        self.first
            .as_ref()
            .map(|error| error as &dyn std::error::Error)
            .or_else(|| {
                self.post
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
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

    /// Observes actual assignment return separately from any historical post-refusal.
    #[must_use]
    pub fn is_physically_returned(&self) -> bool {
        self.returned
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
        let held =
            self.held.as_ref().cloned().ok_or_else(|| {
                ServiceBirthError::policy("native World return custody is absent")
            })?;
        let cleanup = {
            let ledger = held
                .ledger
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?;
            ledger.verify_world_original(self.epoch, &self.original)?;
            if matches!(
                ledger.prepare_world_return(self.epoch)?,
                ledger::WorldReturnPreparation::PendingBody
            ) {
                return Ok(NativeWorldReturn::PendingBody);
            }
            // Actual retirement begins here. Verification below only reads
            // this once-latched result and cannot initialize another operation.
            ledger.enter_cleanup(self.epoch)?
        };
        let result = (|| {
            held.verify_return_custody(&cleanup)?;
            let mut ledger = held
                .ledger
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?;
            ledger.verify_world_original(self.epoch, &self.original)?;
            ledger.verify_cleanup(self.epoch, &cleanup)?;
            let (index, used, peak, tables) = match ledger.prepare_world_return(self.epoch)? {
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
            if consumed {
                ledger.commit_world_return(index, self.epoch, used);
            }
            drop(ledger);
            if consumed {
                self.returned = true;
            }
            work?;
            Ok(NativeWorldReturn::Returned)
        })();
        let post = cleanup
            .verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)
            .and_then(|()| {
                if self.is_physically_returned() {
                    cleanup.complete().map(|_| ())
                } else {
                    Ok(())
                }
            });
        NativePoolReturnError::finish(result, post)
    }
}
