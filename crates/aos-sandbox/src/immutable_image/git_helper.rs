//! Build-selected G/H image custody for private helper mechanics.
//!
//! Complete build content SHA256 selects bytes; the separately observed kernel
//! fs-verity SHA256 is checked on the same retained inode and used in E0 plans.
//! Neither comparison creates execution delegation, loader currentness, a Git
//! task role or repository rights. Missing installed labels/backing deny here.

use std::fmt;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::immutable_file::{FsVerityBacking, FsVerityDigest, ImmutableFileError};
use aos_sandbox_linux::startup_fd_table::{
    StartupExecutableObservationV1, observe_provisioned_startup_executable,
};

use super::{ImmutableImageErrorV1, RetainedImmutableFileV1};

mod selected {
    include!(env!("AOS_GIT_HELPER_SELECTION_HEADER"));
}

const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const HELPER_CONTEXT: &str = "system_u:object_r:aos_sandbox_git_helper_exec_t";
const GIT_CONTEXT: &str = "system_u:object_r:aos_sandbox_git_program_exec_t";

/// Retains only the two exact package-selected executable originals.
pub(crate) struct FixedGitHelperImagesV1 {
    helper: PinnedImage,
    git: PinnedImage,
}

impl FixedGitHelperImagesV1 {
    /// Opens the fixed build selection without accepting caller paths or hashes.
    ///
    /// # Errors
    /// Rejects changed content/names, unsafe mounts or unavailable enforcing
    /// labels, build identity and native fs-verity. These are real prerequisites.
    pub(crate) fn open_fixed() -> Result<Self, GitHelperImageErrorV1> {
        let helper = PinnedImage::open(
            selected::HELPER_PATH,
            selected::HELPER_CONTENT_SHA256,
            HELPER_CONTEXT,
        )?;
        let git = PinnedImage::open(
            selected::GIT_PATH,
            selected::GIT_CONTENT_SHA256,
            GIT_CONTEXT,
        )?;

        let images = Self { helper, git };
        images.recheck()?;
        Ok(images)
    }

    /// Rechecks both actual originals without converting observations to authority.
    ///
    /// # Errors
    /// Rejects missing or changed names, content, metadata, labels or backing.
    pub(crate) fn recheck(&self) -> Result<(), GitHelperImageErrorV1> {
        self.helper.recheck()?;
        self.git.recheck()
    }

    /// Borrows the selected helper argv0 without adding a path override.
    pub(crate) fn helper_path(&self) -> &Path {
        self.helper.original.path()
    }

    /// Returns the kernel measurement bound to the retained helper original.
    pub(crate) fn helper_verity(&self) -> [u8; 32] {
        self.helper.observation.fs_verity_sha256
    }

    /// Returns the kernel measurement bound to the retained Git original.
    pub(crate) fn git_verity(&self) -> [u8; 32] {
        self.git.observation.fs_verity_sha256
    }

    /// Duplicates only the retained helper for the existing executable slot.
    ///
    /// # Errors
    /// Returns the concrete OS descriptor-duplication failure.
    pub(crate) fn duplicate_helper(&self) -> Result<OwnedFd, GitHelperImageErrorV1> {
        self.helper.backing.as_fd().try_clone_to_owned()
            .map_err(GitHelperImageErrorV1::Duplicate)
    }

    /// Duplicates only the retained Git image for fixed role5.
    ///
    /// # Errors
    /// Returns the concrete OS descriptor-duplication failure.
    pub(crate) fn duplicate_git(&self) -> Result<OwnedFd, GitHelperImageErrorV1> {
        self.git.backing.as_fd().try_clone_to_owned()
            .map_err(GitHelperImageErrorV1::Duplicate)
    }
}

struct PinnedImage {
    original: RetainedImmutableFileV1,
    backing: FsVerityBacking,
    observation: StartupExecutableObservationV1,
    context: &'static str,
}

impl PinnedImage {
    fn open(
        path: &'static str,
        content_sha256: [u8; 32],
        context: &'static str,
    ) -> Result<Self, GitHelperImageErrorV1> {
        let original = RetainedImmutableFileV1::open_with_profile(
            path.into(),
            Some(content_sha256),
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )
        .map_err(GitHelperImageErrorV1::Content)?;
        let observation = observe_provisioned_startup_executable(original.path(), context)
            .map_err(GitHelperImageErrorV1::Kernel)?;
        require_same_inode(&original, observation)?;

        // The preflight digest is observational, not authenticated publication
        // data. Comparing it on this original FD establishes mechanical custody
        // only; the caller has received no protected execution permission.
        let duplicate = original.file.as_fd().try_clone_to_owned()
            .map_err(GitHelperImageErrorV1::Duplicate)?;
        let backing = FsVerityBacking::from_received(
            duplicate,
            FsVerityDigest::Sha256(observation.fs_verity_sha256),
            observation.size,
            MAXIMUM_EXECUTABLE_BYTES,
        )
        .map_err(GitHelperImageErrorV1::Backing)?;

        let pinned = Self {
            original,
            backing,
            observation,
            context,
        };
        pinned.recheck()?;
        Ok(pinned)
    }

    fn recheck(&self) -> Result<(), GitHelperImageErrorV1> {
        self.original.revalidate().map_err(GitHelperImageErrorV1::Content)?;
        let named = observe_provisioned_startup_executable(self.original.path(), self.context)
            .map_err(GitHelperImageErrorV1::Kernel)?;
        if named != self.observation {
            return Err(GitHelperImageErrorV1::Changed);
        }
        require_same_inode(&self.original, named)?;

        let duplicate = self.backing.as_fd().try_clone_to_owned()
            .map_err(GitHelperImageErrorV1::Duplicate)?;
        let checked = FsVerityBacking::from_received(
            duplicate,
            FsVerityDigest::Sha256(named.fs_verity_sha256),
            named.size,
            MAXIMUM_EXECUTABLE_BYTES,
        )
        .map_err(GitHelperImageErrorV1::Backing)?;
        let identity = checked.identity();
        let backing_identity = (identity.device(), identity.inode(), identity.bytes());
        if backing_identity != self.original.physical_identity() {
            return Err(GitHelperImageErrorV1::Changed);
        }

        self.original.revalidate().map_err(GitHelperImageErrorV1::Content)
    }
}

fn require_same_inode(
    original: &RetainedImmutableFileV1,
    observation: StartupExecutableObservationV1,
) -> Result<(), GitHelperImageErrorV1> {
    let observed_identity = (observation.device, observation.inode, observation.size);
    if original.physical_identity() != observed_identity {
        return Err(GitHelperImageErrorV1::Changed);
    }
    Ok(())
}

/// Retains available typed causes without printing paths or descriptor values.
#[derive(thiserror::Error)]
pub(crate) enum GitHelperImageErrorV1 {
    #[error("Git helper content custody failed")]
    Content(#[source] ImmutableImageErrorV1),
    #[error("Git helper kernel observation failed")]
    Kernel(#[source] aos_sandbox_linux::Error),
    #[error("Git helper backing custody failed")]
    Backing(#[source] ImmutableFileError),
    #[error("Git helper descriptor duplication failed")]
    Duplicate(#[source] std::io::Error),
    #[error("Git helper original image changed")]
    Changed,
}

impl fmt::Debug for GitHelperImageErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_selection_has_two_distinct_absolute_images() {
        assert!(Path::new(selected::HELPER_PATH).starts_with("/nix/store"));
        assert!(Path::new(selected::GIT_PATH).starts_with("/nix/store"));
        assert_ne!(selected::HELPER_PATH, selected::GIT_PATH);
        assert_ne!(selected::HELPER_CONTENT_SHA256, [0; 32]);
        assert_ne!(selected::GIT_CONTENT_SHA256, [0; 32]);
        // Content identities cannot supply either kernel measurement or a
        // protected positive fixture. No image opener executes in this test.
    }

    #[test]
    fn image_diagnostics_redact_nested_os_details() {
        let error = GitHelperImageErrorV1::Duplicate(std::io::Error::other("private image detail"));

        assert!(!format!("{error:?}").contains("private image detail"));
        assert!(!format!("{error}").contains("private image detail"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
