//! Retains guarded preparation causes and their exact issued recipient identities.
//!
//! Local construction errors carry no issued recipient. Issued failures share
//! the existing prepaid first-cause receipt; fixed custody refusals retain only
//! their nominal recipient. No variant allocates a new diagnostic carrier or
//! turns an unavailable recipient into a physical-return observation.

use super::QemuSpawnError;
#[cfg(target_os = "linux")]
use super::{QemuIssuedHelperFailure, QemuIssuedHelperReceiver};

/// Reports guarded preparation while its issued recipient retains every child.
///
/// The error never owns a process. The constructor-bound Source keeps any
/// unsettled helper in its original preborn slot through later cleanup.
#[derive(Debug)]
pub struct QemuGuardedImagePreparationError {
    detail: PreparationFailure,
}

#[derive(Debug)]
enum PreparationFailure {
    Local(QemuSpawnError),
    #[cfg(target_os = "linux")]
    Issued {
        first: QemuIssuedHelperFailure,
        receiver: QemuIssuedHelperReceiver,
    },
    #[cfg(target_os = "linux")]
    Custody {
        receiver: QemuIssuedHelperReceiver,
    },
}

#[cfg(target_os = "linux")]
static CUSTODY_REFUSAL: QemuSpawnError = QemuSpawnError::HelperCustodyUnavailable;

impl QemuGuardedImagePreparationError {
    pub(crate) fn local(source: QemuSpawnError) -> Self {
        Self {
            detail: PreparationFailure::Local(source),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn issued(
        first: QemuIssuedHelperFailure,
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
    ) -> Self {
        Self {
            detail: PreparationFailure::Issued {
                first,
                receiver: QemuIssuedHelperReceiver::from_lender(receiver.clone()),
            },
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn issued_custody_refusal(
        receiver: &crate::linux_attempt_host::SourceCleanupLender,
    ) -> Self {
        Self {
            detail: PreparationFailure::Custody {
                receiver: QemuIssuedHelperReceiver::from_lender(receiver.clone()),
            },
        }
    }

    /// Borrows the actual first helper failure without replacing its type.
    #[must_use]
    pub fn first_cause(&self) -> &QemuSpawnError {
        match &self.detail {
            PreparationFailure::Local(QemuSpawnError::HelperFailure { first }) => {
                first.source_ref()
            }
            PreparationFailure::Local(source) => source,
            #[cfg(target_os = "linux")]
            PreparationFailure::Issued { first, .. } => first.source_ref(),
            #[cfg(target_os = "linux")]
            PreparationFailure::Custody { .. } => &CUSTODY_REFUSAL,
        }
    }

    /// Clones the saved nominal recipient without inferring current custody.
    ///
    /// An unavailable Source remains a retained cleanup obligation. Callers
    /// must resolve this identity before attempting any recipient operation.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn retained_receiver_identity(&self) -> Option<QemuIssuedHelperReceiver> {
        self.receiver().cloned()
    }

    /// Returns the existing issued recipient that retains helper disposition.
    ///
    /// This observer creates neither a process nor an operation or return loan.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn retained_receiver(
        &self,
    ) -> Option<crate::linux_attempt_host::RetainedNativeFreshLaunchError> {
        self.receiver().and_then(QemuIssuedHelperReceiver::upgrade)
    }

    /// Projects the original helper's independent first, post and cleanup causes.
    ///
    /// # Errors
    /// Refuses absent, expired, contended or poisoned issued helper custody.
    ///
    /// # Panics
    /// Propagates a projection panic while retaining the original journal;
    /// subsequent access refuses its poisoned mutex.
    #[cfg(target_os = "linux")]
    pub fn with_retained_history<T>(
        &self,
        apply: impl for<'a> FnOnce(crate::linux_attempt_host::QemuIssuedHelperHistory<'a>) -> T,
    ) -> Result<T, crate::linux_attempt_host::OriginalActorAccountError> {
        let receiver = self
            .retained_receiver()
            .ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable)?;
        receiver.with_helper_history(apply)
    }

    /// Observes known helper return without inferring absence from contention.
    ///
    /// # Errors
    /// Refuses unavailable access to the original issued recipient.
    #[cfg(target_os = "linux")]
    pub fn retained_helper_process(
        &self,
    ) -> Result<Option<u32>, crate::linux_attempt_host::OriginalActorAccountError> {
        match self.receiver() {
            Some(receiver) => receiver
                .upgrade()
                .ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable)?
                .retained_helper_process(),
            None => Ok(None),
        }
    }

    #[cfg(target_os = "linux")]
    fn receiver(&self) -> Option<&QemuIssuedHelperReceiver> {
        match &self.detail {
            PreparationFailure::Local(_) => None,
            PreparationFailure::Issued { receiver, .. }
            | PreparationFailure::Custody { receiver } => Some(receiver),
        }
    }
}

impl std::fmt::Display for QemuGuardedImagePreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            PreparationFailure::Local(source) => source.fmt(formatter),
            #[cfg(target_os = "linux")]
            PreparationFailure::Issued { first, .. } => {
                write!(formatter, "issued helper failed: {first:?}")
            }
            #[cfg(target_os = "linux")]
            PreparationFailure::Custody { .. } => CUSTODY_REFUSAL.fmt(formatter),
        }
    }
}

impl std::error::Error for QemuGuardedImagePreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.detail {
            PreparationFailure::Local(source) => Some(source),
            #[cfg(target_os = "linux")]
            PreparationFailure::Issued { first, .. } => Some(first),
            #[cfg(target_os = "linux")]
            PreparationFailure::Custody { .. } => Some(&CUSTODY_REFUSAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::test_support::TestAllocationObserver;
    use std::error::Error;

    #[test]
    fn local_preparation_moves_the_original_io_payload_without_allocating() {
        let source = std::io::Error::new(
            std::io::ErrorKind::Other,
            std::io::Error::from_raw_os_error(libc::EIO),
        );
        let payload = source.get_ref().unwrap() as *const _;
        let first = QemuSpawnError::Io {
            operation: "observe guarded preparation",
            source,
        };

        let (report, counts) =
            TestAllocationObserver::count(|| QemuGuardedImagePreparationError::local(first));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let QemuSpawnError::Io { operation, source } = report.first_cause() else {
            panic!("the concrete initiating I/O error must remain available");
        };
        assert_eq!(*operation, "observe guarded preparation");
        assert!(std::ptr::eq(source.get_ref().unwrap(), payload));
        assert_eq!(
            source
                .get_ref()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EIO),
        );
        assert!(std::ptr::eq(
            report
                .source()
                .unwrap()
                .downcast_ref::<QemuSpawnError>()
                .unwrap(),
            report.first_cause(),
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unissued_custody_refusal_does_not_acquire_a_recipient() {
        let (report, counts) = TestAllocationObserver::count(|| {
            QemuGuardedImagePreparationError::local(QemuSpawnError::HelperCustodyUnavailable)
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert!(matches!(
            report.first_cause(),
            QemuSpawnError::HelperCustodyUnavailable
        ));
        assert!(report.retained_receiver_identity().is_none());
        assert!(report.retained_receiver().is_none());
        assert_eq!(report.retained_helper_process().unwrap(), None);
    }
}
