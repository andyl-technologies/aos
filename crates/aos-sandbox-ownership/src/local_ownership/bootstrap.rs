//! Retains the fixed local trust bootstrap and its original protected files.
//!
//! The shared Linux bounded reader owns allocation/read custody. This closed
//! role adds the original root directory, exact bootstrap codec and trust-key
//! joins; request bytes never choose a path, key, policy or native descriptor.

use std::fs::File;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_core::model::KeyReference;
use aos_sandbox_core::{ObjectDescriptor, TrustScopeId};
use aos_sandbox_linux::credential::{CredentialOwnerPolicyV1, FixedRoleCredentialReadV1};
use rustix::fs::{FileType, Mode, OFlags, Stat, fstat, open};

use super::*;

#[derive(Debug, thiserror::Error)]
enum BootstrapError {
    #[error("local ownership bootstrap framing is invalid")]
    Framing(#[source] ProtectedLeaseAuthorityErrorV1),
    #[error(transparent)]
    Canonical(#[from] aos_sandbox_core::CanonicalCborError),
    #[error(transparent)]
    Registry(#[from] aos_sandbox_core::RegistryError),
    #[error(transparent)]
    Trust(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
    #[error("local ownership bootstrap role is invalid")]
    Binding,
}

struct BootstrapBinding {
    verifier: Option<OwnershipAuthorityVerifier>,
    public_key: [u8; 32],
    authority: KeyReference,
    scope: TrustScopeId,
    policy: ObjectDescriptor,
}

pub(super) struct LocalBootstrapOriginalV1 {
    directory: Result<File, rustix::io::Errno>,
    before: Option<Result<Stat, rustix::io::Errno>>,
    directory_binding: Option<Result<(), signing::LocalSigningUnavailable>>,
    read: FixedRoleCredentialReadV1,
    file_after: Option<std::io::Result<std::fs::Metadata>>,
    file_binding: Option<Result<(), signing::LocalSigningUnavailable>>,
    after: Option<Result<Stat, rustix::io::Errno>>,
    bookend: Option<Result<(), signing::LocalSigningUnavailable>>,
    decoded: Option<Result<BootstrapBinding, BootstrapError>>,
}

impl LocalBootstrapOriginalV1 {
    pub(super) fn capture() -> Self {
        let mut original = Self {
            directory: open(PROTECTED_MULTI_NODE_DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty()).map(File::from),
            before: None,
            directory_binding: None,
            read: FixedRoleCredentialReadV1::prearmed(),
            file_after: None,
            file_binding: None,
            after: None,
            bookend: None,
            decoded: None,
        };
        if let Ok(directory) = &original.directory {
            original.before = Some(fstat(directory));
            original.directory_binding = Some(if original.before.as_ref()
                .and_then(|result| result.as_ref().ok()).is_some_and(protected_directory)
            { Ok(()) } else { Err(signing::LocalSigningUnavailable) });
            if matches!(original.directory_binding, Some(Ok(()))) {
                original.read.read_at_once(directory.as_fd(), PROTECTED_LEASE_BOOTSTRAP,
                    1, MAXIMUM_BOOTSTRAP_BYTES, true, CredentialOwnerPolicyV1::Root);
            }
            if let Some(Ok(file)) = original.read.view().open {
                original.file_after = Some(file.metadata());
            }
            original.file_binding = Some(if original.read.view().metadata
                .and_then(|result| result.as_ref().ok())
                .zip(original.file_after.as_ref().and_then(|result| result.as_ref().ok()))
                .is_some_and(|(before, after)| before.mode() & 0o7777 == 0o600
                    && before.dev() == after.dev() && before.ino() == after.ino()
                    && before.uid() == after.uid() && before.gid() == after.gid()
                    && before.mode() == after.mode() && before.len() == after.len()
                    && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
                    && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec())
            { Ok(()) } else { Err(signing::LocalSigningUnavailable) });
            original.after = Some(fstat(directory));
        }
        original.bookend = Some(if original.before.as_ref().and_then(|result| result.as_ref().ok())
            .zip(original.after.as_ref().and_then(|result| result.as_ref().ok()))
            .is_some_and(|(before, after)| protected_directory(after)
                && before.st_dev == after.st_dev && before.st_ino == after.st_ino
                && before.st_uid == after.st_uid && before.st_gid == after.st_gid
                && before.st_mode == after.st_mode)
        { Ok(()) } else { Err(signing::LocalSigningUnavailable) });
        if matches!(original.file_binding, Some(Ok(())))
            && matches!(original.bookend, Some(Ok(()))) {
            if let Some(Ok(Some(bytes))) = original.read.outcome() {
                original.decoded = Some(authenticate(bytes));
            }
        }
        original
    }

    pub(super) fn take_binding(
        &mut self,
    ) -> Option<(OwnershipAuthorityVerifier, LocalOwnershipSigningOriginalV1)> {
        let binding = match self.decoded.as_mut()? {
            Ok(binding) => binding,
            Err(_) => return None,
        };
        let issuer = LocalOwnershipSigningOriginalV1::capture(binding.public_key,
            binding.authority.clone(), binding.scope, binding.policy.clone());
        // The positive verifier moves once; original canonical bytes, parsed
        // associations, native reads and files remain in this same owner.
        Some((binding.verifier.take()?, issuer))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.directory.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.directory_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.read.failure())
            .or_else(|| self.file_after.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.file_binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.bookend.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.decoded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

fn protected_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0 && stat.st_mode & 0o022 == 0
}

fn authenticate(bytes: &[u8]) -> Result<BootstrapBinding, BootstrapError> {
    let (policy_bytes, public_key) = decode_bootstrap(bytes).map_err(BootstrapError::Framing)?;
    use aos_sandbox_ownership_protocol::trusted_policy::{
        OwnershipTrustConfigurationErrorV1 as TrustError, verifier_from_protected_policy_v1,
    };
    let verifier = verifier_from_protected_policy_v1(policy_bytes, public_key, DecodeLimits::default())
        .map_err(|cause| match cause {
            TrustError::Canonical(cause) => BootstrapError::Canonical(cause),
            TrustError::Features(cause) => BootstrapError::Registry(cause),
            TrustError::Trust(cause) => BootstrapError::Trust(cause),
            TrustError::MediaType(_) | TrustError::Binding => BootstrapError::Binding,
        })?;
    let view = verifier.trust_anchor_comparison_v1();
    let authority = view.authority().clone();
    let scope = view.trust_scope();
    let descriptor = view.policy_descriptor().clone();
    Ok(BootstrapBinding {
        verifier: Some(verifier),
        public_key, authority, scope, policy: descriptor,
    })
}
