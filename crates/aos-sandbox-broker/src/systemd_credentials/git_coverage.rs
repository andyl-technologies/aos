//! Retains fixed Git coverage inputs for the existing service recipes.
//!
//! This owner shares the sole native read and named-readback engines. It
//! supplies DATA custody only; purpose, payment, and issuer authority stay upper.

use super::*;

/// Reports the original shared credential engine's retained first failure.
#[derive(Debug)]
pub struct GitCoverageCredentialErrorV1(ControllerNixPublicCredentialErrorV1);

impl std::fmt::Display for GitCoverageCredentialErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Git coverage credential capture failed: {}", self.0)
    }
}

impl std::error::Error for GitCoverageCredentialErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<ControllerNixPublicCredentialErrorV1> for GitCoverageCredentialErrorV1 {
    fn from(cause: ControllerNixPublicCredentialErrorV1) -> Self {
        Self(cause)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum GitCoverageCredentialRoleV1 {
    Controller,
    Mount,
    Storage,
    Root,
}

impl GitCoverageCredentialRoleV1 {
    pub(super) fn directory(self) -> &'static str {
        match self {
            Self::Controller => "/run/credentials/aos-sandboxd.service",
            Self::Mount => "/run/credentials/aos-sandbox-mountd.service",
            Self::Storage => "/run/credentials/aos-storaged.service",
            Self::Root => "/run/credentials/aos-sandbox-policy-authorityd.service",
        }
    }

    pub(super) fn count(self) -> usize {
        match self {
            Self::Root => 6,
            _ => 4,
        }
    }
}

pub(super) const GIT_COVERAGE_CREDENTIAL_NAMES_V1: [&str; 6] = [
    "git-upload-coverage-enrollment-v1",
    "git-upload-owner-catalog-v1",
    "project-public-key",
    "deployment-public-key",
    "git-upload-mount-session-manifest-v1",
    "git-upload-storage-session-manifest-v1",
];

/// Owns fixed public enrollment inputs through the existing credential engine.
///
/// Construction allocates only empty storage. Capture derives the process UID,
/// opens the one fixed role directory and parks each actual original before
/// checks. No caller path, descriptor, key, UID or authority input is accepted.
/// The owning caller must remain prearmed on failure or uncaught unwind.
pub struct GitCoverageCredentialCustodyV1 {
    role: GitCoverageCredentialRoleV1,
    custody: CredentialRosterCustodyV1<6, GitCoverageCredentialErrorV1>,
}

impl GitCoverageCredentialCustodyV1 {
    /// Prepares empty storage for the fixed Controller's public inputs.
    #[must_use]
    pub fn controller() -> Self {
        Self::new(GitCoverageCredentialRoleV1::Controller)
    }

    /// Prepares empty storage for the fixed Mount service's public inputs.
    #[must_use]
    pub fn mount() -> Self {
        Self::new(GitCoverageCredentialRoleV1::Mount)
    }

    // This only selects a monotone denial in the same fixed Journal. It is
    // never used as a successful credential, census or allocation proof.
    /// Rechecks this fixed native recipe and retains its original refusal.
    pub fn retains_mount_recipe_v1(&self) -> bool {
        self.role == GitCoverageCredentialRoleV1::Mount
    }

    /// Prepares empty storage for the fixed Storage service's public inputs.
    #[must_use]
    pub fn storage() -> Self {
        Self::new(GitCoverageCredentialRoleV1::Storage)
    }

    /// Prepares empty storage for Root's public inputs and two fixed manifests.
    #[must_use]
    pub fn root() -> Self {
        Self::new(GitCoverageCredentialRoleV1::Root)
    }

    // The Cache initializer consumes only the actual fixed Controller inputs.
    // A public DATA view from another role cannot select this recipe.
    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck_controller_inputs_v1(
        &mut self,
    ) -> Result<(), &GitCoverageCredentialErrorV1> {
        self.recheck_role(GitCoverageCredentialRoleV1::Controller)
    }

    /// Rechecks only the fixed Mount service's original public inputs.
    ///
    /// # Errors
    /// Permanently refuses another credential role or changed original files.
    /// This lends DATA, not peer, signature, writer or allocation authority.
    pub fn recheck_mount_inputs_v1(&mut self) -> Result<(), &GitCoverageCredentialErrorV1> {
        self.recheck_role(GitCoverageCredentialRoleV1::Mount)
    }

    /// Rechecks only the fixed Storage service's original public inputs.
    ///
    /// # Errors
    /// Permanently refuses another credential role or changed original files.
    /// The same ancestry, leaf-reader and named-readback engines are reused.
    pub fn recheck_storage_inputs_v1(&mut self) -> Result<(), &GitCoverageCredentialErrorV1> {
        self.recheck_role(GitCoverageCredentialRoleV1::Storage)
    }

    /// Rechecks Root's original public inputs and two fixed session manifests.
    ///
    /// # Errors
    /// Permanently refuses another credential role or changed original files.
    /// Current Root deployment and held-writer joins remain independently required.
    pub fn recheck_root_inputs_v1(&mut self) -> Result<(), &GitCoverageCredentialErrorV1> {
        self.recheck_role(GitCoverageCredentialRoleV1::Root)
    }

    fn recheck_role(
        &mut self,
        expected: GitCoverageCredentialRoleV1,
    ) -> Result<(), &GitCoverageCredentialErrorV1> {
        if self.role != expected {
            self.custody.fence();
            return self.custody.finish(Err(credential_state_rejected()));
        }
        self.recheck()
    }

    fn new(role: GitCoverageCredentialRoleV1) -> Self {
        Self {
            role,
            custody: CredentialRosterCustodyV1::new(CredentialRosterKindV1::GitCoverage(role)),
        }
    }

    /// Captures exactly the fixed selected profile once, with resident failures.
    ///
    /// # Errors
    /// Permanently closes on reentry, absent/unsafe originals, shape bounds or
    /// changed names; returns a borrow of the actual retained first cause.
    pub fn capture(&mut self) -> Result<(), &GitCoverageCredentialErrorV1> {
        self.custody.capture()
    }

    /// Rechecks all same originals and named readbacks under their fixed bounds.
    ///
    /// # Errors
    /// Closes before fallible work and never retries a failed capture/readback.
    /// Old partials, original files and the first typed cause remain resident.
    pub fn recheck(&mut self) -> Result<(), &GitCoverageCredentialErrorV1> {
        self.custody.recheck()
    }

    /// Lends original public DATA only while the local profile remains ready.
    #[must_use]
    pub fn ready(&self) -> Option<GitCoverageCredentialDataV1<'_>> {
        Some(GitCoverageCredentialDataV1 {
            enrollment: self.custody.public(0)?.bytes(),
            catalog: self.custody.public(1)?.bytes(),
            project_pin: self.custody.public(2)?.bytes(),
            deployment_pin: self.custody.public(3)?.bytes(),
            manifests: match self.role {
                GitCoverageCredentialRoleV1::Root => Some([
                    self.custody.public(4)?.bytes(),
                    self.custody.public(5)?.bytes(),
                ]),
                _ => None,
            },
        })
    }

    /// Borrows the first owning credential failure without extracting files.
    #[must_use]
    pub fn failure(&self) -> Option<&GitCoverageCredentialErrorV1> {
        self.custody.failure()
    }

    /// Irreversibly closes borrowed observation; this is not physical disposal.
    pub fn fence(&mut self) {
        self.custody.fence();
    }
}

/// Lends fixed public preimages; signature/current owner verification is separate.
pub struct GitCoverageCredentialDataV1<'a> {
    enrollment: &'a [u8],
    catalog: &'a [u8],
    project_pin: &'a [u8],
    deployment_pin: &'a [u8],
    manifests: Option<[&'a [u8]; 2]>,
}

impl<'a> GitCoverageCredentialDataV1<'a> {
    /// Borrows the complete original signed enrollment.
    #[must_use]
    pub fn enrollment(&self) -> &'a [u8] {
        self.enrollment
    }

    /// Borrows the complete original provisioned catalog.
    #[must_use]
    pub fn catalog(&self) -> &'a [u8] {
        self.catalog
    }

    /// Borrows both existing independently provisioned public role pin carriers.
    #[must_use]
    pub fn role_pins(&self) -> (&'a [u8], &'a [u8]) {
        (self.project_pin, self.deployment_pin)
    }

    /// Borrows Root's two complete fixed manifests, never request-provided keys.
    #[must_use]
    pub fn root_session_manifests(&self) -> Option<[&'a [u8]; 2]> {
        self.manifests
    }
}

pub(super) fn git_coverage_read_profile(index: usize) -> CredentialReadProfile {
    let maximum = match index {
        0 => aos_sandbox_core::format::git_upload_enrollment::MAXIMUM_ENROLLMENT_BYTES_V1,
        1 => aos_sandbox_core::format::git_upload_enrollment::MAXIMUM_OWNER_CATALOG_BYTES_V1,
        2 | 3 => 80,
        _ => 920,
    };
    CredentialReadProfile::Ordinary(maximum as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn role_refusal_preserves_the_original_wrapped_io_cause() {
        let mut owner = GitCoverageCredentialCustodyV1::controller();
        let original = ControllerNixPublicCredentialErrorV1::io(
            CredentialFailureClass::Configuration,
            CredentialOperation::FileRead,
            std::io::Error::from_raw_os_error(5),
        );
        assert!(owner.custody.finish(Err(original)).is_err());
        let first = owner.failure().unwrap() as *const _;

        assert!(owner.recheck_mount_inputs_v1().is_err());
        assert!(owner.capture().is_err());

        let retained = owner.failure().unwrap();
        assert_eq!(first, retained as *const _);
        assert_eq!(retained.0.source().unwrap().downcast_ref::<std::io::Error>()
            .unwrap().raw_os_error(), Some(5));
        assert!(owner.ready().is_none());
    }
}
