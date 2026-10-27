//! Preserves existing native error lanes for moved historical DATA codecs.

use crate::journal::JournalError;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;

#[cfg(target_os = "linux")]
impl From<CanonicalJournalMechanicalErrorV1>
    for crate::policy_compiler::create_q04::CreateQ04ErrorV1
{
    fn from(cause: CanonicalJournalMechanicalErrorV1) -> Self {
        Self::from(JournalError::from(cause))
    }
}

impl From<CanonicalJournalMechanicalErrorV1>
    for crate::policy_compiler::ControllerHoldReadbackErrorV1
{
    fn from(cause: CanonicalJournalMechanicalErrorV1) -> Self {
        Self::from(JournalError::from(cause))
    }
}

impl From<CanonicalJournalMechanicalErrorV1>
    for crate::policy_compiler::ControllerEffectAckReadbackErrorV1
{
    fn from(cause: CanonicalJournalMechanicalErrorV1) -> Self {
        Self::from(JournalError::from(cause))
    }
}

impl From<CanonicalJournalMechanicalErrorV1>
    for crate::policy_compiler::PolicyCompilerJournalErrorV1
{
    fn from(cause: CanonicalJournalMechanicalErrorV1) -> Self {
        Self::from(JournalError::from(cause))
    }
}

impl From<CanonicalJournalMechanicalErrorV1> for crate::policy_compiler::RootV8EffectAckErrorV1 {
    fn from(cause: CanonicalJournalMechanicalErrorV1) -> Self {
        Self::from(JournalError::from(cause))
    }
}
