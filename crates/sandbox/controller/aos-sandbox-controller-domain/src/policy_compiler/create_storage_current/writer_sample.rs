//! Retains both held Root writer names and their independent location posts.

use std::error::Error as StdError;

use crate::journal::{Journal, JournalError, ProtectedJournalNamesV1};

use super::root_open::{RootCurrentOpenStateV1, require_authority, require_policy};

#[derive(Default)]
pub(super) struct RootCurrentWriterSampleV1 {
    authority_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    policy_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    binding: Option<Result<(), JournalError>>,
    authority: Option<Result<(), JournalError>>,
    policy: Option<Result<(), JournalError>>,
}

impl RootCurrentWriterSampleV1 {
    pub(super) fn capture_once(
        &mut self,
        authority: &Journal,
        policy: &Journal,
        root_open: &RootCurrentOpenStateV1,
    ) {
        self.authority_names = Some(authority.protected_writer_physical_names_v1());
        self.policy_names = Some(policy.protected_writer_physical_names_v1());
        self.binding = Some((|| {
            let body = root_open.completed_body().map_err(|_| JournalError::ProtectedBoundary)?;
            let authority = self.authority_names.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let policy = self.policy_names.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            if *authority != body.authority_names || *policy != body.policy_names {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        // Both actual locations are posted independently even after a changed
        // physical-name result; later IO cannot replace that earlier mismatch.
        self.authority = Some(require_authority(authority));
        self.policy = Some(require_policy(policy));
    }

    pub(super) fn require_positive(&self) -> Result<(), JournalError> {
        if self.failure().is_none()
            && matches!(self.binding, Some(Ok(())))
            && matches!(self.authority, Some(Ok(())))
            && matches!(self.policy, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.authority_names)
            .or_else(|| cause!(self.policy_names))
            .or_else(|| cause!(self.binding))
            .or_else(|| cause!(self.authority))
            .or_else(|| cause!(self.policy))
    }
}
