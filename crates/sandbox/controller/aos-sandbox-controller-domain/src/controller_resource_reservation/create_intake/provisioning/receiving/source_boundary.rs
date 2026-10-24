//! Selects a closed Create or fresh Start Source append on the same engine.
//!
//! Both variants borrow genuine owning native stages. The input model, key
//! and canonical recipe remain independently exact. A variant supplies no
//! writer, financial account, callback or general mutation exception.

use super::source::SourceAdmissionAuthorizationV1;
use super::start_entry::source_origin::StartSourceAdmissionAuthorizationV1;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::LifecycleProtectedJournalKeyV1;
use crate::policy_compiler::create_q04::Q04CutIdentityV1;
use crate::JournalError;

#[derive(Clone, Copy)]
pub(crate) enum SourceAppendBoundaryV1<'turn> {
    Create(&'turn SourceAdmissionAuthorizationV1<'turn>),
    Start(&'turn StartSourceAdmissionAuthorizationV1<'turn>),
}

impl SourceAppendBoundaryV1<'_> {
    pub(crate) fn require_current_v1(&self) -> Result<(), JournalError> {
        match self {
            Self::Create(original) => original.require_current_v1(),
            Self::Start(original) => original.require_current_v1(),
        }
    }

    pub(crate) fn final_native_cut_v2(&self) -> Result<(), JournalError> {
        match self {
            Self::Create(_) => Ok(()),
            Self::Start(original) => original.final_native_cut_v2(),
        }
    }

    pub(crate) fn source_identity_v1(&self) -> &SourceProvisioningIdentityV1 {
        match self {
            Self::Create(original) => original.source_identity_v1(),
            Self::Start(original) => original.source_identity_v1(),
        }
    }

    pub(crate) fn expected_key_v1(&self) -> Result<LifecycleProtectedJournalKeyV1, JournalError> {
        match self {
            Self::Create(original) => original.expected_key_v1(),
            Self::Start(original) => original.expected_key_v1(),
        }
    }

    pub(crate) fn transaction_id_v1(&self) -> Result<[u8; 16], JournalError> {
        match self {
            Self::Create(original) => original.transaction_id_v1(),
            Self::Start(original) => original.transaction_id_v1(),
        }
    }

    pub(crate) fn q04_v1(&self) -> &Q04CutIdentityV1 {
        match self {
            Self::Create(original) => original.q04_v1(),
            Self::Start(original) => original.q04_v1(),
        }
    }
}
