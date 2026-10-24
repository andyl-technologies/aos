//! Preserves existing fixed credential categories and exact native causes.

use super::super::RootStartupJournalErrorV1;
use crate::native::PolicyNativeJournalErrorV1;
use crate::signed_inputs::SignedPolicyInputDataErrorV1;
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;

/// Reports one fixed startup credential admission refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootStartupCredentialErrorV1 {
    /// The deployment head or signer generations are malformed.
    #[error("invalid deployment policy head")]
    InvalidHead,
    /// The exact deployment packet signature failed.
    #[error("deployment policy head signature is invalid")]
    InvalidSignature,
    /// The head, signer pins, or protected hold is no longer current.
    #[error("deployment policy head generation is not current")]
    StaleHead,
    /// An owner pin is malformed or reuses another role's key.
    #[error("invalid or reused owner signer pin")]
    InvalidPin,
    /// A protected pin is missing, changed, held, removed, or rotated.
    #[error("owner signer pin is not current")]
    StalePin,
    /// Owns the actual ordinary fixed-opening refusal and every reached original.
    #[error("{original}")]
    Opening {
        /// Keeps the exact returned opening error before diagnostic ownership moves.
        returned: RootStartupJournalErrorV1,
        /// Retains the same whole opening, including native partial failure prefixes.
        #[source]
        original: Box<super::super::RootStartupJournalFailureOriginalV1>,
    },
    /// Owns the original native, financial, or append refusal.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
    /// Retains the same startup owner's opening or names failure marker.
    #[error(transparent)]
    Startup(#[from] RootStartupJournalErrorV1),
}

impl From<SignedPolicyInputDataErrorV1> for RootStartupCredentialErrorV1 {
    fn from(error: SignedPolicyInputDataErrorV1) -> Self {
        match error {
            SignedPolicyInputDataErrorV1::InvalidHead => Self::InvalidHead,
            SignedPolicyInputDataErrorV1::InvalidSignature => Self::InvalidSignature,
            SignedPolicyInputDataErrorV1::StaleHead => Self::StaleHead,
        }
    }
}

impl From<JournalTransactionDataError> for RootStartupCredentialErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        Self::Native(PolicyNativeJournalErrorV1::from(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from(error),
        ))
    }
}
