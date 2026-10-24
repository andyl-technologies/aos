//! Keeps one failed debugger candidate through its original terminal handback.
//!
//! Body cleanup alone cannot dispose a candidate's native loan or typed report.
//! The existing lifecycle slot retains the original failure, then its exact
//! canonical receipt, then completed history until the containing carrier takes
//! it. This state creates no receiver, allocation, Original or replay authority.

use std::fmt;

use super::{LifecycleApiError, ProductionVmConstructionFailure};
use crate::SourceCleanupHistory;
use crate::{ProductionVmConstructionCleanupError, ProductionVmConstructionPostBody};

#[cfg(target_os = "linux")]
use super::custody::FailureStorage;

type CleanupReceipt = Box<
    dyn crucible_control_api::ProductionVmCleanupHandoff<
            Failure = ProductionVmConstructionCleanupError,
            PostBody = ProductionVmConstructionPostBody,
        >,
>;

type CleanupError = ProductionVmConstructionCleanupError;

/// Keeps the existing inline slot occupied through publication and reporting.
pub(in crate::vm_lifecycle) enum RetainedDebugConstruction {
    /// Retains the complete failure until its original receiver accepts custody.
    Unpublished(Option<ProductionVmConstructionFailure>),
    /// Retains the original receipt and report through terminal observation.
    Published(ConstructorReturn),
    /// Holds completed history until the containing body accepts the move.
    History(Option<SourceCleanupHistory>),
}

/// Retains a published candidate's original receipt and typed constructor report.
pub(in crate::vm_lifecycle) struct ConstructorReturn {
    shell: Option<ProductionVmConstructionFailure>,
    first: Option<LifecycleApiError>,
    receipt: Option<CleanupReceipt>,
}

impl RetainedDebugConstruction {
    /// Retains the owning failure before its caller formats the diagnostic.
    pub(in crate::vm_lifecycle) fn new(failure: ProductionVmConstructionFailure) -> Self {
        Self::Unpublished(Some(failure))
    }

    /// Advances only this candidate's original reserved cleanup operation.
    ///
    /// # Errors
    /// Keeps the original owner or receipt on refused publication, incomplete
    /// cleanup, unavailable terminal custody or an unconverted error shell.
    pub(in crate::vm_lifecycle) fn retry(&mut self) -> Result<(), CleanupError> {
        if let Self::History(history) = self {
            return if history.is_some() {
                Ok(())
            } else {
                Err(CleanupError::Retained(
                    "construction terminal history has already moved",
                ))
            };
        }
        self.publish()?;
        let Self::Published(returned) = self else {
            return Err(CleanupError::Retained(
                "construction has no published original receipt",
            ));
        };
        let history = returned.retry()?;
        *self = Self::History(Some(history));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn publish(&mut self) -> Result<(), CleanupError> {
        let Self::Unpublished(slot) = self else {
            return Ok(());
        };
        let failure = slot.as_mut().ok_or(CleanupError::Retained(
            "construction owning failure is absent",
        ))?;
        if failure.additional.is_some() {
            return Err(CleanupError::Retained(
                "construction retains an independent original cause",
            ));
        }
        if matches!(failure.storage, FailureStorage::Rejected { .. }) {
            let receipt = failure
                .retry_reserved_publication()
                .map_err(CleanupError::Retained)?
                .ok_or(CleanupError::Retained(
                    "construction publication has no saved original receipt",
                ))?;
            // The returned shell still owns its typed first. Save the same
            // receipt before any shell conversion or native cleanup can fail.
            *self = Self::Published(ConstructorReturn {
                shell: slot.take(),
                first: None,
                receipt: Some(receipt),
            });
            return Ok(());
        }

        let failure = slot.take().ok_or(CleanupError::Retained(
            "construction owning failure is absent",
        ))?;
        match failure.retain_in_reserved_cleanup() {
            Ok((first, receipt)) => {
                *self = Self::Published(ConstructorReturn {
                    shell: None,
                    first: Some(first),
                    receipt: Some(receipt),
                });
                Ok(())
            }
            Err(failure) => {
                *slot = Some(failure);
                Err(CleanupError::Retained(
                    "construction remains outside its original reserved receiver",
                ))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn publish(&mut self) -> Result<(), CleanupError> {
        // No canonical handback producer exists on this platform. Preserve the
        // complete original failure rather than treating body cleanup as return.
        Err(CleanupError::Retained(
            "construction canonical handback is unavailable on this platform",
        ))
    }

    /// Moves history through the containing PostBody's existing paid slot.
    ///
    /// # Errors
    /// Retains history until completion and restores it if the containing
    /// destination already owns independent history.
    pub(in crate::vm_lifecycle) fn transfer_history(
        &mut self,
        destination: &mut Option<ProductionVmConstructionPostBody>,
    ) -> Result<(), CleanupError> {
        let Self::History(slot) = self else {
            return Err(CleanupError::Retained(
                "construction terminal history has not completed",
            ));
        };
        let history = slot.take().ok_or(CleanupError::Retained(
            "construction terminal history has already moved",
        ))?;
        let body = destination.get_or_insert_with(ProductionVmConstructionPostBody::history_only);
        match body.retain_source_history(history) {
            Ok(()) => Ok(()),
            Err(history) => {
                *slot = Some(history);
                Err(CleanupError::Retained(
                    "containing body retains independent construction history",
                ))
            }
        }
    }
}

impl ConstructorReturn {
    fn retry(&mut self) -> Result<SourceCleanupHistory, CleanupError> {
        #[cfg(target_os = "linux")]
        if self.first.is_none() {
            let shell = self.shell.take().ok_or(CleanupError::Retained(
                "construction return lost its original error shell",
            ))?;
            match shell.into_published_error() {
                Ok(first) => self.first = Some(first),
                Err(shell) => {
                    self.shell = Some(shell);
                    return Err(CleanupError::Retained(
                        "construction return retains its original error shell",
                    ));
                }
            }
        }
        if self.shell.is_some() {
            return Err(CleanupError::Retained(
                "construction return retains independent unpublished custody",
            ));
        }
        let receipt = self.receipt.as_mut().ok_or(CleanupError::Retained(
            "construction return lost its original cleanup receipt",
        ))?;
        // The canonical driver retains its raw first/post journals. Independently
        // observe stage below: this report alone never certifies physical return.
        let _attempt = receipt.retry();
        SourceCleanupHistory::take_returned_constructor(&mut self.first, &mut self.receipt)
            .map_err(CleanupError::Retained)
    }
}

impl fmt::Display for RetainedDebugConstruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unpublished(Some(failure)) => fmt::Display::fmt(failure, formatter),
            Self::Published(returned) => {
                if let Some(shell) = &returned.shell {
                    fmt::Display::fmt(shell, formatter)
                } else if let Some(first) = &returned.first {
                    fmt::Display::fmt(first, formatter)
                } else {
                    formatter.write_str("construction retains its original cleanup receipt")
                }
            }
            Self::History(Some(history)) => fmt::Display::fmt(history, formatter),
            Self::Unpublished(None) | Self::History(None) => {
                formatter.write_str("construction owning value is being transferred")
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
