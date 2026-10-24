//! Retains a bounded positional read of the already-held local trust bootstrap.
//!
//! This is subordinate to the genuine same-R namespace/profile interval. The
//! original descriptor remains in its namespace owner; only the Linux reader's
//! own duplicate is used, so active Ownership's stream offsets cannot change.

use super::*;
use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use aos_sandbox_ownership_protocol::{
    local_bootstrap::{
        LocalOwnershipBootstrapDataErrorV1, decode_local_ownership_bootstrap_data_v1,
    },
    trusted_policy::{
        OwnershipTrustConfigurationCaptureV1, OwnershipTrustConfigurationClosedV1,
        verifier_from_protected_policy_retaining_v1,
    },
};
use aos_sandbox_protocol::domain_ledger::delete_root::planning::{
    DeleteRootPlanningDataErrorV3, DeleteRootPlanningTrustDataV2,
};

#[derive(Clone, Copy)]
enum First {
    Read,
    Frame,
    Trust,
    Post,
    Projection,
}

pub(super) struct BootstrapTrustOriginalV2 {
    read: FixedRoleCredentialReadV1,
    framing: Option<Result<(), LocalOwnershipBootstrapDataErrorV1>>,
    trust: OwnershipTrustConfigurationCaptureV1,
    validation: Option<Result<(), OwnershipTrustConfigurationClosedV1>>,
    post: Option<rustix::io::Result<Stat>>,
    binding: Option<Result<(), JournalError>>,
    public: Option<Result<DeleteRootPlanningTrustDataV2, DeleteRootPlanningDataErrorV3>>,
    entered: bool,
    first: Option<First>,
}

impl Default for BootstrapTrustOriginalV2 {
    fn default() -> Self {
        Self {
            read: FixedRoleCredentialReadV1::prearmed(),
            framing: None,
            trust: OwnershipTrustConfigurationCaptureV1::new(),
            validation: None,
            post: None,
            binding: None,
            public: None,
            entered: false,
            first: None,
        }
    }
}

impl BootstrapTrustOriginalV2 {
    pub(super) fn entered_v2(&self) -> bool {
        self.entered
    }

    pub(super) fn demand_v2(before: &Stat) -> Result<ResourceVector, JournalError> {
        let length =
            usize::try_from(before.st_size).map_err(|_| JournalError::ProtectedBoundary)?;
        if !(1..=128 * 1024).contains(&length) {
            return Err(JournalError::ProtectedBoundary);
        }
        let memory = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(length)
            .and_then(|bytes| bytes.checked_add(length.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        // The sole positional reader retains one duplicate on an incomplete read.
        // Inline read/parser/results are already included in the namespace Self.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, 1))
    }

    pub(super) fn read_once_v2(&mut self, file: &File, before: &Stat) -> Result<(), JournalError> {
        if self.entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        let length =
            usize::try_from(before.st_size).map_err(|_| JournalError::ProtectedBoundary)?;
        self.read.read_exact_at_once(file.as_fd(), length);
        let Some(Ok(Some(bytes))) = self.read.outcome() else {
            self.first = Some(First::Read);
            return Err(JournalError::ProtectedBoundary);
        };
        let decoded = decode_local_ownership_bootstrap_data_v1(bytes);
        match decoded {
            Err(cause) => {
                self.framing = Some(Err(cause));
                self.first = Some(First::Frame);
            }
            Ok((policy, public_key)) => {
                self.framing = Some(Ok(()));
                self.validation = Some(verifier_from_protected_policy_retaining_v1(
                    policy,
                    public_key,
                    aos_sandbox_model::DecodeLimits::default(),
                    &mut self.trust,
                ));
                if !matches!(self.validation, Some(Ok(()))) {
                    self.first = Some(First::Trust);
                }
            }
        }
        if self.first.is_some() {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        }
    }

    pub(super) fn finish_if_owed_v2(
        &mut self,
        file: &File,
        before: &Stat,
    ) -> Result<(), JournalError> {
        if !self.entered {
            return Ok(());
        }
        if self.post.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        // This is independently owed even if read, framing or trust failed.
        self.post = Some(fstat(file));
        self.binding = Some((|| {
            let after = positive(&self.post)?;
            if !same_bootstrap_stat(before, after) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if !matches!(self.binding, Some(Ok(()))) {
            self.first.get_or_insert(First::Post);
        }
        if self.first.is_none() {
            self.public = Some(match self.trust.verifier() {
                Some(verifier) => DeleteRootPlanningTrustDataV2::from_verifier_comparison_v2(verifier),
                None => Err(DeleteRootPlanningDataErrorV3::Wire(
                    aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2::Association)),
            });
            if !matches!(self.public, Some(Ok(_))) {
                self.first = Some(First::Projection);
            }
        }
        if self.first.is_some() {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        }
    }

    pub(super) fn public_v2(&self) -> Result<DeleteRootPlanningTrustDataV2, JournalError> {
        if !self.entered || self.first.is_some() || !matches!(self.binding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.public
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Read => self.read.failure(),
            First::Frame => cause(&self.framing),
            First::Trust => self.trust.failure().or_else(|| cause(&self.validation)),
            First::Post => cause(&self.post).or_else(|| cause(&self.binding)),
            First::Projection => cause(&self.public),
        }
    }
}

// Active journals keep their separate append-compatible identity rule. This
// exact predicate belongs only to the immutable public bootstrap read.
pub(super) fn same_bootstrap_stat(before: &Stat, after: &Stat) -> bool {
    physical(before) == physical(after)
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek as _, Write as _};

    #[test]
    fn invalid_framing_keeps_first_cause_and_still_observes_changed_metadata() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&[0; 80]).unwrap();
        let before = fstat(&file).unwrap();
        let original_offset = file.stream_position().unwrap();
        assert!(BootstrapTrustOriginalV2::demand_v2(&before).is_ok());
        let mut owner = BootstrapTrustOriginalV2::default();

        assert!(owner.read_once_v2(&file, &before).is_err());
        let first = owner.failure().unwrap() as *const dyn Error as *const ();
        assert_eq!(file.stream_position().unwrap(), original_offset);
        file.write_all(b"changed").unwrap();
        assert!(owner.finish_if_owed_v2(&file, &before).is_err());

        assert!(matches!(owner.post, Some(Ok(_))));
        assert!(matches!(owner.binding, Some(Err(_))));
        assert!(owner.public_v2().is_err());
        assert_eq!(
            first,
            owner.failure().unwrap() as *const dyn Error as *const ()
        );
        assert!(owner.read_once_v2(&file, &before).is_err());
        assert_eq!(
            first,
            owner.failure().unwrap() as *const dyn Error as *const ()
        );
    }
}
