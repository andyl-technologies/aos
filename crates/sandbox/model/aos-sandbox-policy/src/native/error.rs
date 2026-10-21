//! Preserves lower mechanical originals separately from Policy role acceptance.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_broker::receiving::{RootJournalFinancialOriginalV1, RootWriterErrorV1};

/// Preserves an actual native, mechanical or same-original financial refusal.
///
/// The mechanical variant retains the existing complete 23-class taxonomy.
/// Selected replay/append originals stay in their owner; this error never
/// flattens or disposes a selected failed native prefix.
#[derive(Debug, thiserror::Error)]
pub enum PolicyNativeJournalErrorV1 {
    /// Marks a failed Q04 readback retained by the same native journal.
    #[error(transparent)]
    Q04Current(super::journal::Q04ReadbackFailureV1),
    /// Preserves the existing canonical mechanical cause without rebuilding it.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Preserves the actual fixed Root native or invocation cause.
    #[error(transparent)]
    Root(#[from] RootWriterErrorV1),
    /// Keeps the same negative append prefix in its original native sink.
    #[error(transparent)]
    RootAppend(#[from] aos_sandbox_broker::receiving::RootAppendFailureOriginalV1),
    /// Marks a failed name observation retained by the actual target.
    #[error(transparent)]
    TargetCurrent(super::target::PolicyTargetCurrentFailureV1),
    /// Retains the primary append and independently owed post together.
    #[error(transparent)]
    NativePost(super::journal::PolicyNativePostFailureOriginalV1),
    /// Retains the actual lower financial allocation and its stable first cause.
    #[error(transparent)]
    Financial(RootJournalFinancialOriginalV1),
}

impl PolicyNativeJournalErrorV1 {
    pub(super) fn boundary() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)
    }

    pub(super) fn geometry() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::LimitExceeded(
            "fixed Policy journal construction",
        ))
    }
}

impl From<std::io::Error> for PolicyNativeJournalErrorV1 {
    fn from(cause: std::io::Error) -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::Io(cause))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::io;

    use super::*;

    #[derive(Debug)]
    struct OriginalCause;

    impl fmt::Display for OriginalCause {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("original owned IO cause")
        }
    }

    impl std::error::Error for OriginalCause {}

    #[test]
    fn mechanical_wrapper_moves_the_same_io_cause() {
        let original = io::Error::new(io::ErrorKind::PermissionDenied, OriginalCause);
        let address = original.get_ref().unwrap() as *const _;

        let wrapped = ErrorV1::from(CanonicalJournalMechanicalErrorV1::Io(original));
        let ErrorV1::Mechanical(CanonicalJournalMechanicalErrorV1::Io(retained)) = wrapped else {
            panic!("mechanical IO classification changed");
        };

        assert_eq!(retained.kind(), io::ErrorKind::PermissionDenied);
        assert!(std::ptr::addr_eq(
            retained.get_ref().unwrap() as *const _,
            address
        ));
        assert!(retained.get_ref().unwrap().is::<OriginalCause>());
    }

    #[test]
    fn root_wrapper_moves_the_same_native_io_cause() {
        let original = io::Error::other(OriginalCause);
        let address = original.get_ref().unwrap() as *const _;
        let native = aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1::Io(original);

        let wrapped = ErrorV1::from(RootWriterErrorV1::Native(native));
        let ErrorV1::Root(RootWriterErrorV1::Native(
            aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1::Io(retained),
        )) = wrapped
        else {
            panic!("Root native IO classification changed");
        };

        assert!(std::ptr::addr_eq(
            retained.get_ref().unwrap() as *const _,
            address
        ));
        assert!(retained.get_ref().unwrap().is::<OriginalCause>());
    }

    type ErrorV1 = PolicyNativeJournalErrorV1;
}
