//! Moves actual Policy-owned failures into their historical upper categories.
//!
//! The projectors move concrete causes without observing, rebuilding or
//! disposing their native owners. A phase's unit refusal remains with the
//! same Work and is selected by its caller before independently owed posts.

use aos_sandbox_policy::native::{
    PolicyCompilerJournalErrorV1, PolicyNativeJournalErrorV1, RootAuthorityErrorV1,
    RootPolicyPublicationErrorV1,
};
use aos_sandbox_policy::parentless_input::ParentlessPolicyInputDataErrorV1;
use aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::{
    Q04OriginalRowsDataErrorV1, Q04OriginalRowsHashDataErrorV1,
};

use super::{CreateQ04ErrorV1, authority_error::map_root_authority_error_v1};
use crate::journal::JournalError;
use crate::policy_compiler::CurrentCreateCompilerInputErrorV1;
use crate::reconciler::ReconcilerError;

/// Moves one actual owning Work failure into the existing Q04 error boundary.
pub(crate) fn project_root_policy_error_v1(
    cause: RootPolicyPublicationErrorV1,
) -> CreateQ04ErrorV1 {
    use RootPolicyPublicationErrorV1 as Work;

    match cause {
        Work::Authority(cause) => map_root_authority_error_v1(cause),
        Work::Journal(cause) => project_root_native_journal_error_v1(cause),
        Work::Origin(cause) => map_root_authority_error_v1(RootAuthorityErrorV1::Origin(cause)),
        Work::OriginBorrow(cause) => {
            map_root_authority_error_v1(RootAuthorityErrorV1::OriginBorrow(cause))
        }
        Work::Data(cause) => CreateQ04ErrorV1::from(cause),
        Work::OriginalRows(cause) => match cause {
            Q04OriginalRowsDataErrorV1::CorruptLedger(reason) => {
                CreateQ04ErrorV1::Reconciler(ReconcilerError::CorruptLedger(reason))
            }
            Q04OriginalRowsDataErrorV1::Operation(cause) => {
                CreateQ04ErrorV1::Reconciler(ReconcilerError::from(cause))
            }
            Q04OriginalRowsDataErrorV1::Effect(cause) => {
                CreateQ04ErrorV1::Reconciler(ReconcilerError::from(cause))
            }
            Q04OriginalRowsDataErrorV1::Projection(cause) => CreateQ04ErrorV1::Projection(cause),
            Q04OriginalRowsDataErrorV1::Hash(cause) => match cause {
                Q04OriginalRowsHashDataErrorV1::ProtectedBoundary => {
                    CreateQ04ErrorV1::Journal(JournalError::ProtectedBoundary)
                }
                Q04OriginalRowsHashDataErrorV1::Transaction(cause) => CreateQ04ErrorV1::from(cause),
            },
        },
        Work::Publication(cause) => CreateQ04ErrorV1::PolicyCompiler(cause),
        Work::Model(cause) => {
            CreateQ04ErrorV1::PolicyCompiler(PolicyCompilerJournalErrorV1::Model(cause))
        }
        Work::Input(cause) => CreateQ04ErrorV1::Input(match cause {
            ParentlessPolicyInputDataErrorV1::Model(cause) => {
                CurrentCreateCompilerInputErrorV1::Model(cause)
            }
            ParentlessPolicyInputDataErrorV1::Resources(cause) => {
                CurrentCreateCompilerInputErrorV1::Resources(cause)
            }
        }),
        Work::SignedInput(cause) => CreateQ04ErrorV1::Deployment(cause.into()),
        Work::Compilation(cause) => CreateQ04ErrorV1::Compilation(cause),
        Work::Cache(cause) => CreateQ04ErrorV1::from(cause),
        Work::ChangedCut => CreateQ04ErrorV1::ChangedCut,
        Work::Expired => CreateQ04ErrorV1::Expired,
        Work::Bounds => CreateQ04ErrorV1::Bounds,
    }
}

/// Moves the same native journal cause without wrapping it in Authority again.
pub(crate) fn project_root_native_journal_error_v1(
    cause: PolicyNativeJournalErrorV1,
) -> CreateQ04ErrorV1 {
    use PolicyNativeJournalErrorV1 as Native;

    match cause {
        Native::Mechanical(cause) => CreateQ04ErrorV1::Journal(JournalError::from(cause)),
        Native::Root(cause) => CreateQ04ErrorV1::Journal(JournalError::RootNative(cause)),
        Native::Financial(cause) => CreateQ04ErrorV1::Journal(JournalError::RootFinancial(cause)),
        original @ (Native::Q04Current(_)
        | Native::TargetCurrent(_)
        | Native::RootAppend(_)
        | Native::NativePost(_)) => CreateQ04ErrorV1::PolicyNativeJournal(original),
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, io};

    use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
    use aos_sandbox_policy::PolicyModelError;

    use super::*;

    #[derive(Debug)]
    struct OriginalIoCause;

    impl fmt::Display for OriginalIoCause {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("original Policy IO cause")
        }
    }

    impl std::error::Error for OriginalIoCause {}

    #[test]
    fn native_mechanical_projection_moves_the_same_owned_io_cause() {
        let original = io::Error::new(io::ErrorKind::PermissionDenied, OriginalIoCause);
        let address = original.get_ref().unwrap() as *const _;
        let native = PolicyNativeJournalErrorV1::Mechanical(
            CanonicalJournalMechanicalErrorV1::Io(original),
        );

        let projected = project_root_native_journal_error_v1(native);

        let CreateQ04ErrorV1::Journal(JournalError::Io(retained)) = projected else {
            panic!("native mechanical IO category changed");
        };
        assert_eq!(retained.kind(), io::ErrorKind::PermissionDenied);
        assert!(retained.get_ref().unwrap().is::<OriginalIoCause>());
        assert!(std::ptr::addr_eq(retained.get_ref().unwrap() as *const _, address));
    }

    #[test]
    fn input_and_publication_model_failures_keep_distinct_original_categories() {
        let input = RootPolicyPublicationErrorV1::Input(
            ParentlessPolicyInputDataErrorV1::Model(PolicyModelError::AmbiguousIdentity),
        );
        let publication = RootPolicyPublicationErrorV1::Model(PolicyModelError::CanonicalEncoding);

        let input = project_root_policy_error_v1(input);
        let publication = project_root_policy_error_v1(publication);

        assert!(matches!(input, CreateQ04ErrorV1::Input(
            CurrentCreateCompilerInputErrorV1::Model(PolicyModelError::AmbiguousIdentity),
        )));
        assert!(matches!(publication, CreateQ04ErrorV1::PolicyCompiler(
            PolicyCompilerJournalErrorV1::Model(PolicyModelError::CanonicalEncoding),
        )));
    }

    #[test]
    fn original_row_hash_refusal_keeps_the_journal_boundary_category() {
        let cause = RootPolicyPublicationErrorV1::OriginalRows(
            Q04OriginalRowsDataErrorV1::Hash(Q04OriginalRowsHashDataErrorV1::ProtectedBoundary),
        );

        let projected = project_root_policy_error_v1(cause);

        assert!(matches!(projected, CreateQ04ErrorV1::Journal(JournalError::ProtectedBoundary)));
    }
}
