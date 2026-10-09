//! Pinned bounded streaming authentication for candidate installation artifacts.

use std::{
    fs::File,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

use super::{KvmCandidateArtifactPolicy, KvmCandidateArtifactRole, KvmCandidateError};

#[derive(Debug)]
pub(super) struct PinnedArtifact {
    pub(super) policy: KvmCandidateArtifactPolicy,
    descriptor: File,
}

impl PinnedArtifact {
    pub(super) fn open(policy: KvmCandidateArtifactPolicy) -> Result<Self, KvmCandidateError> {
        let descriptor = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&policy.path)
            .map_err(|source| KvmCandidateError::ArtifactIo {
                role: policy.role,
                source,
            })?;
        let pinned = Self { policy, descriptor };
        pinned.verify()?;
        Ok(pinned)
    }

    pub(super) fn verify(&self) -> Result<(), KvmCandidateError> {
        let io_error = |source| KvmCandidateError::ArtifactIo {
            role: self.policy.role,
            source,
        };
        let before = self.descriptor.metadata().map_err(io_error)?;
        if !before.is_file()
            || before.len() != self.policy.expected.length.get()
            || (self.policy.role == KvmCandidateArtifactRole::Qemu
                && before.permissions().mode() & 0o111 == 0)
        {
            return Err(KvmCandidateError::ArtifactIdentity {
                role: self.policy.role,
            });
        }

        let domain = b"cnp.blob.v1";
        let domain_length = u32::try_from(domain.len()).map_err(|_| KvmCandidateError::Policy {
            reason: "candidate content domain length is unrepresentable",
        })?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CNP/1\0");
        hasher.update(&domain_length.to_be_bytes());
        hasher.update(domain);
        hasher.update(&before.len().to_be_bytes());
        let mut offset = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        while offset < before.len() {
            let remaining = before.len() - offset;
            let allowed = usize::try_from(remaining.min(64 * 1024)).map_err(|_| {
                KvmCandidateError::Policy {
                    reason: "candidate streaming allowance is unrepresentable",
                }
            })?;
            let count = std::os::unix::fs::FileExt::read_at(
                &self.descriptor,
                &mut buffer[..allowed],
                offset,
            )
            .map_err(io_error)?;
            if count == 0 {
                return Err(KvmCandidateError::ArtifactIdentity {
                    role: self.policy.role,
                });
            }
            hasher.update(&buffer[..count]);
            let count = u64::try_from(count).map_err(|_| KvmCandidateError::Policy {
                reason: "candidate streaming read size is unrepresentable",
            })?;
            offset = offset.checked_add(count).ok_or(KvmCandidateError::Policy {
                reason: "candidate streaming offset overflows",
            })?;
        }
        let after = self.descriptor.metadata().map_err(io_error)?;
        if after.len() != before.len()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || after.ctime() != before.ctime()
            || after.ctime_nsec() != before.ctime_nsec()
            || hasher.finalize().to_hex().as_str() != self.policy.expected.hash.digest
        {
            return Err(KvmCandidateError::ArtifactIdentity {
                role: self.policy.role,
            });
        }
        Ok(())
    }
}
