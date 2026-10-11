//! Exclusive ownership of a profile's prepare, activation, and publication cycle.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, ensure};
use rustix::fs::{FlockOperation, Mode, OFlags};

use super::Profile;

/// Holds exclusive ownership of mutations to one profile.
///
/// The guard spans reads of the prior generation, pure preparation, and durable
/// publication. A transaction journal lock alone cannot prevent two callers
/// from preparing different changes against the same earlier generation.
pub struct ProfileMutationGuard {
    file: File,
}

impl Profile {
    /// Acquires exclusive mutation ownership before reading or preparing state.
    ///
    /// The lock is nonblocking. Callers retain the guard through recovery,
    /// generation allocation, activation, and publication.
    ///
    /// # Errors
    /// Returns an error for contention, inaccessible directories, or an
    /// insecure lock file, including symbolic links and another owner's file.
    pub fn lock_mutation(&self) -> Result<ProfileMutationGuard> {
        std::fs::create_dir_all(&self.path).context("creating profile lock directory")?;
        let path = self.path.join("mutation.lock");
        let descriptor = rustix::fs::open(
            &path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .context("opening profile mutation lock")?;
        let file = File::from(descriptor);
        rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive).with_context(|| {
            format!(
                "profile mutation is already active: {}",
                self.path.display()
            )
        })?;
        let guard = ProfileMutationGuard { file };
        let metadata = guard.file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "profile mutation lock must be a private regular file owned by the caller"
        );
        Ok(guard)
    }
}

impl Drop for ProfileMutationGuard {
    fn drop(&mut self) {
        // Explicit unlock ends ownership even if a concurrently forked child
        // still holds the open file description before its close-on-exec step.
        let _ = rustix::fs::flock(&self.file, FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProfileScope;

    #[test]
    fn profile_mutation_ownership_blocks_other_writers_and_releases_inherited_descriptors() {
        let directory = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(directory.path().into(), ProfileScope::User).unwrap();
        let guard = profile.lock_mutation().unwrap();
        let inherited = guard.file.try_clone().unwrap();

        assert!(profile.lock_mutation().is_err());
        drop(guard);
        let next = profile.lock_mutation().unwrap();
        drop(inherited);
        drop(next);
    }

    #[test]
    fn profile_mutation_lock_rejects_symbolic_links() {
        let directory = tempfile::tempdir().unwrap();
        let profile = Profile::open_at(directory.path().into(), ProfileScope::User).unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"preserved").unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join("mutation.lock")).unwrap();

        assert!(profile.lock_mutation().is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"preserved");
    }
}
