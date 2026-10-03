//! Role-local protected configuration, key, process, and nonce custody.

use std::path::Path;

use aos_sandbox_source_provider_protocol::{
    ProtectedRootMountPeerV1, ProtectedSourceProviderRouteV1, SourceProviderCurrentAuthorityV1,
    SourceProviderPeerRole, SourceProviderTrustSetV1,
};

use crate::SourceProviderSecurityError;
use crate::entropy::ProcessNonceSourceV1;
use crate::execution::RetainedSelfExecutionV1;
use crate::manifest::{SourceProviderSecurityManifestV1, SourceProviderSecurityRoleV1};
use crate::protected_files::{ProtectedSourceProviderFiles, RetainedSecret};

pub(crate) const FIXED_ROOT_MOUNT_SOURCE_PROVIDER_CUSTODY: &str =
    "/var/lib/aos/sandbox-mount/source-provider-authority";
pub(crate) const FIXED_PROVIDER_SOURCE_PROVIDER_CUSTODY: &str =
    "/var/lib/aos/source-provider/authority";

/// Validates the externally provisioned RootMount role files before service activation.
///
/// This opens only RootMount's fixed tree and immediately drops its custody.
/// The live owner repeats every check when it opens the authenticated carrier.
/// No session, journal, source effect, or signing capability is returned.
///
/// # Errors
///
/// Rejects absent or changed files, unsafe metadata, wrong role or key
/// material, inactive trust, process drift, or invalid protected time.
pub fn validate_fixed_root_mount_authority_v1() -> Result<(), SourceProviderSecurityError> {
    let mut custody =
        ProtectedRootMountCustodyV1::load(Path::new(FIXED_ROOT_MOUNT_SOURCE_PROVIDER_CUSTODY))?;
    crate::RevalidatedProviderConfigurationV1::capture_root_mount(
        &mut custody,
        current_unix_seconds()?,
    )?;
    Ok(())
}

/// Validates the externally provisioned Provider role files before service activation.
///
/// This opens only Provider's fixed tree and immediately drops its custody.
/// The live owner repeats every check after accepting a connected carrier.
/// No session, journal, source effect, or signing capability is returned.
///
/// # Errors
///
/// Rejects absent or changed files, unsafe metadata, wrong role or key
/// material, inactive trust, process drift, or invalid protected time.
pub fn validate_fixed_provider_authority_v1() -> Result<(), SourceProviderSecurityError> {
    let mut custody =
        ProtectedProviderCustodyV1::load(Path::new(FIXED_PROVIDER_SOURCE_PROVIDER_CUSTODY))?;
    crate::RevalidatedProviderConfigurationV1::capture(&mut custody, current_unix_seconds()?)?;
    Ok(())
}

/// Validates selected RootMount custody through its genuine retained self role.
///
/// This preactivation check opens only the fixed RootMount tree. Its temporary
/// custody is intentionally released on return; it is not a live session or a
/// substitute for the selected carrier owner's resident opening reservoir.
///
/// # Errors
///
/// Rejects a non-enforcing or wrong selected task role, changed self execution,
/// unsafe protected files, inactive keys or authority, or an invalid clock.
pub fn validate_fixed_selected_root_mount_authority_v1(
) -> Result<(), SourceProviderSecurityError> {
    let mut opening = ProtectedRootMountCustodyV1::begin_fixed_selected_mount_source();
    opening.open_inner()?;
    let mut custody = opening
        .take_root_mount_custody()
        .ok_or(SourceProviderSecurityError::Poisoned)?;

    crate::RevalidatedProviderConfigurationV1::capture_root_mount(
        &mut custody,
        current_unix_seconds()?,
    )?;
    Ok(())
}

/// Validates selected Provider custody through its genuine retained self role.
///
/// This preactivation check opens only the fixed Provider tree. Its temporary
/// custody is intentionally released on return; it grants no session, journal,
/// source effect or signing capability. A live selected owner must repeat the
/// same opening under its original-carrier shutdown reservoir.
///
/// # Errors
///
/// Rejects a non-enforcing or wrong selected task role, changed self execution,
/// unsafe protected files, inactive keys or authority, or an invalid clock.
pub fn validate_fixed_selected_provider_authority_v1(
) -> Result<(), SourceProviderSecurityError> {
    let mut opening = ProtectedProviderCustodyV1::begin_fixed_selected_mount_source();
    opening.open_inner()?;
    let mut custody = opening
        .take_provider_custody()
        .ok_or(SourceProviderSecurityError::Poisoned)?;

    crate::RevalidatedProviderConfigurationV1::capture(&mut custody, current_unix_seconds()?)?;
    Ok(())
}

fn current_unix_seconds() -> Result<i64, SourceProviderSecurityError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if now < 0 {
        return Err(SourceProviderSecurityError::ExecutionChanged);
    }
    Ok(now)
}

pub(crate) struct ProtectedCustodyV1 {
    files: ProtectedSourceProviderFiles,
    execution: RetainedSelfExecutionV1,
    nonces: ProcessNonceSourceV1,
    root_authority: SourceProviderCurrentAuthorityV1,
    provider_authority: SourceProviderCurrentAuthorityV1,
    poisoned: bool,
}

impl core::fmt::Debug for ProtectedCustodyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedCustodyV1([redacted])")
    }
}

/// Owns protected Root Mount SourceProvider configuration and role-local keys.
///
/// No public loader exists in this production-inert tranche.
pub struct ProtectedRootMountCustodyV1 {
    inner: ProtectedCustodyV1,
}

impl core::fmt::Debug for ProtectedRootMountCustodyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedRootMountCustodyV1([redacted])")
    }
}

/// Owns protected provider configuration and role-local keys.
///
/// Construction is retained inside the fixed dormant provider owner. It
/// performs complete FD-relative protected-directory checks and activates no
/// service.
pub struct ProtectedProviderCustodyV1 {
    inner: ProtectedCustodyV1,
}

impl core::fmt::Debug for ProtectedProviderCustodyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedProviderCustodyV1([redacted])")
    }
}

impl ProtectedRootMountCustodyV1 {
    /// Creates an empty opening for the fixed selected RootMount custody.
    ///
    /// The caller parks this value under its original-carrier shutdown guard
    /// before invoking [`SelectedSourceProviderCustodyOpeningV1::open_once`].
    /// Creation performs no observation and grants no protected authority.
    pub fn begin_fixed_selected_mount_source() -> SelectedSourceProviderCustodyOpeningV1 {
        SelectedSourceProviderCustodyOpeningV1::new(SourceProviderSecurityRoleV1::RootMount)
    }

    pub(crate) fn load(path: &Path) -> Result<Self, SourceProviderSecurityError> {
        Ok(Self {
            inner: ProtectedCustodyV1::load(path, SourceProviderSecurityRoleV1::RootMount)?,
        })
    }

    pub(crate) fn draw_nonce_at(
        &mut self,
        now_seconds: i64,
    ) -> Result<[u8; 32], SourceProviderSecurityError> {
        self.inner.draw_nonce_at(now_seconds)
    }

    pub(crate) const fn inner(&self) -> &ProtectedCustodyV1 {
        &self.inner
    }

    pub(crate) fn inner_mut(&mut self) -> &mut ProtectedCustodyV1 {
        &mut self.inner
    }
}

impl ProtectedProviderCustodyV1 {
    /// Creates an empty opening for the fixed selected Provider custody.
    ///
    /// The caller parks this value under its original-carrier shutdown guard
    /// before invoking [`SelectedSourceProviderCustodyOpeningV1::open_once`].
    /// Creation performs no observation and grants no protected authority.
    pub fn begin_fixed_selected_mount_source() -> SelectedSourceProviderCustodyOpeningV1 {
        SelectedSourceProviderCustodyOpeningV1::new(SourceProviderSecurityRoleV1::Provider)
    }

    /// Produces a current non-secret projection after complete revalidation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] for custody drift, process
    /// replacement, poison, or an inactive current authority or signer.
    pub fn revalidated_configuration(
        &mut self,
    ) -> Result<crate::RevalidatedProviderConfigurationV1, SourceProviderSecurityError> {
        let now_seconds = crate::handshake::current_unix_seconds()?;
        crate::RevalidatedProviderConfigurationV1::capture(self, now_seconds)
    }

    /// Irreversibly closes custody after an ambiguous durable owner transition.
    ///
    /// This operation releases no key material or authority. It exists so an
    /// owner that cannot prove whether a protected commit completed can fail
    /// closed without reusing the same custody in a second transition.
    pub fn close_after_ambiguous_durable_transition(&mut self) {
        self.inner.poison();
    }

    pub(crate) fn load(path: &Path) -> Result<Self, SourceProviderSecurityError> {
        Ok(Self {
            inner: ProtectedCustodyV1::load(path, SourceProviderSecurityRoleV1::Provider)?,
        })
    }

    pub(crate) fn draw_nonce_at(
        &mut self,
        now_seconds: i64,
    ) -> Result<[u8; 32], SourceProviderSecurityError> {
        self.inner.draw_nonce_at(now_seconds)
    }

    pub(crate) const fn inner(&self) -> &ProtectedCustodyV1 {
        &self.inner
    }

    pub(crate) fn inner_mut(&mut self) -> &mut ProtectedCustodyV1 {
        &mut self.inner
    }
}

/// Retains returned prefixes while opening one fixed selected role's custody.
///
/// Only the two purpose-specific custody entry points construct this value.
/// The selected self owner is parked before protected files are opened. Each
/// returned files, nonce and authority owner remains resident before the next
/// fallible crossing. The first actual error is terminal and borrowed, never
/// copied into a replacement owner. Lower openers' unreturned partial resources
/// and allocation funding are not closed by this reservoir.
///
/// This value does not own a transport. Its installed caller must retain it
/// inside the whole original-carrier shutdown owner throughout opening and
/// failure, so shutdown precedes dropping these nested fields.
#[must_use = "retain selected opening custody through success or terminal failure"]
pub struct SelectedSourceProviderCustodyOpeningV1 {
    role: SourceProviderSecurityRoleV1,
    attempted: bool,
    first_failure: Option<SourceProviderSecurityError>,
    execution: Option<RetainedSelfExecutionV1>,
    files: Option<ProtectedSourceProviderFiles>,
    nonces: Option<ProcessNonceSourceV1>,
    root_authority: Option<SourceProviderCurrentAuthorityV1>,
    provider_authority: Option<SourceProviderCurrentAuthorityV1>,
    admitted: Option<ProtectedCustodyV1>,
}

impl core::fmt::Debug for SelectedSourceProviderCustodyOpeningV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SelectedSourceProviderCustodyOpeningV1([retained opening])")
    }
}

impl SelectedSourceProviderCustodyOpeningV1 {
    fn new(role: SourceProviderSecurityRoleV1) -> Self {
        Self {
            role,
            attempted: false,
            first_failure: None,
            execution: None,
            files: None,
            nonces: None,
            root_authority: None,
            provider_authority: None,
            admitted: None,
        }
    }

    /// Opens the one fixed role exactly once, retaining every returned prefix.
    ///
    /// # Errors
    ///
    /// Lends the first actual selected-subject, protected-file, nonce or
    /// authority failure. A second invocation is refused without observation;
    /// no failed opening can be retried or changed into another role.
    pub fn open_once(&mut self) -> Result<(), &SourceProviderSecurityError> {
        if self.attempted {
            if self.first_failure.is_none() {
                self.first_failure = Some(SourceProviderSecurityError::Poisoned);
            }
        } else {
            self.attempted = true;
            if let Err(error) = self.open_inner() {
                self.first_failure = Some(error);
            }
        }

        match self.first_failure.as_ref() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Lends the actual terminal failure without observing or reopening files.
    pub const fn failure(&self) -> Option<&SourceProviderSecurityError> {
        self.first_failure.as_ref()
    }

    pub(crate) fn admitted_execution(&self) -> Option<&RetainedSelfExecutionV1> {
        self.admitted.as_ref().map(ProtectedCustodyV1::execution)
    }

    /// Moves successful Provider custody once, without further observation.
    ///
    /// Returns `None` for RootMount, failure, incomplete or already moved state.
    pub fn take_provider_custody(&mut self) -> Option<ProtectedProviderCustodyV1> {
        if self.role != SourceProviderSecurityRoleV1::Provider || self.first_failure.is_some() {
            return None;
        }
        self.admitted
            .take()
            .map(|inner| ProtectedProviderCustodyV1 { inner })
    }

    /// Moves successful RootMount custody once, without further observation.
    ///
    /// Returns `None` for Provider, failure, incomplete or already moved state.
    pub fn take_root_mount_custody(&mut self) -> Option<ProtectedRootMountCustodyV1> {
        if self.role != SourceProviderSecurityRoleV1::RootMount || self.first_failure.is_some() {
            return None;
        }
        self.admitted
            .take()
            .map(|inner| ProtectedRootMountCustodyV1 { inner })
    }

    fn open_inner(&mut self) -> Result<(), SourceProviderSecurityError> {
        let path = match self.role {
            SourceProviderSecurityRoleV1::RootMount => {
                RetainedSelfExecutionV1::capture_selected_root_mount(&mut self.execution)?;
                Path::new(FIXED_ROOT_MOUNT_SOURCE_PROVIDER_CUSTODY)
            }
            SourceProviderSecurityRoleV1::Provider => {
                RetainedSelfExecutionV1::capture_selected_provider(&mut self.execution)?;
                Path::new(FIXED_PROVIDER_SOURCE_PROVIDER_CUSTODY)
            }
        };
        self.files = Some(ProtectedSourceProviderFiles::load(path, self.role)?);

        let execution = self
            .execution
            .as_ref()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        let files = self
            .files
            .as_ref()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        self.nonces = Some(ProcessNonceSourceV1::create(self.role, execution, files)?);
        self.root_authority = Some(current_authority(files, SourceProviderPeerRole::RootMount)?);
        self.provider_authority = Some(current_authority(files, SourceProviderPeerRole::Provider)?);
        execution.revalidate()?;

        // Validate all slot associations before taking any original. The
        // completed assembly is infallible; an invariant failure restores the
        // same tuple rather than dropping a partially taken prefix.
        if self.files.is_none()
            || self.execution.is_none()
            || self.nonces.is_none()
            || self.root_authority.is_none()
            || self.provider_authority.is_none()
            || self.admitted.is_some()
        {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        let parts = (
            self.files.take(),
            self.execution.take(),
            self.nonces.take(),
            self.root_authority.take(),
            self.provider_authority.take(),
        );
        match parts {
            (
                Some(files),
                Some(execution),
                Some(nonces),
                Some(root_authority),
                Some(provider_authority),
            ) => {
                self.admitted = Some(ProtectedCustodyV1 {
                    files,
                    execution,
                    nonces,
                    root_authority,
                    provider_authority,
                    poisoned: false,
                });
                Ok(())
            }
            (files, execution, nonces, root_authority, provider_authority) => {
                self.files = files;
                self.execution = execution;
                self.nonces = nonces;
                self.root_authority = root_authority;
                self.provider_authority = provider_authority;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }?;

        // The whole final custody stays resident across its ordinary final
        // file/process/authority bookend. Failure cannot take it out again.
        let now = current_unix_seconds()?;
        self.admitted
            .as_mut()
            .ok_or(SourceProviderSecurityError::Poisoned)?
            .revalidate_at(now)
    }
}

impl ProtectedCustodyV1 {
    fn load(
        path: &Path,
        role: SourceProviderSecurityRoleV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        let files = ProtectedSourceProviderFiles::load(path, role)?;
        let execution = RetainedSelfExecutionV1::capture()?;
        let nonces = ProcessNonceSourceV1::create(role, &execution, &files)?;
        let root_authority = current_authority(&files, SourceProviderPeerRole::RootMount)?;
        let provider_authority = current_authority(&files, SourceProviderPeerRole::Provider)?;
        Ok(Self {
            files,
            execution,
            nonces,
            root_authority,
            provider_authority,
            poisoned: false,
        })
    }

    pub(crate) fn revalidate_at(
        &mut self,
        now_seconds: i64,
    ) -> Result<(), SourceProviderSecurityError> {
        if self.poisoned {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        if let Err(error) = self
            .files
            .revalidate()
            .and_then(|_| self.execution.revalidate())
            .and_then(|_| {
                self.root_authority
                    .validate_at(now_seconds)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
            })
            .and_then(|_| {
                self.provider_authority
                    .validate_at(now_seconds)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
            })
        {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    fn draw_nonce_at(&mut self, now_seconds: i64) -> Result<[u8; 32], SourceProviderSecurityError> {
        self.revalidate_at(now_seconds)?;
        let result = self.nonces.draw(&self.execution, &self.files);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) const fn manifest(&self) -> &SourceProviderSecurityManifestV1 {
        self.files.manifest()
    }

    pub(crate) fn public_archive_capture(
        &mut self,
        now_seconds: i64,
    ) -> Result<crate::protected_files::PublicConfigurationCaptureV5, SourceProviderSecurityError> {
        self.revalidate_at(now_seconds)?;
        let capture = self.files.public_archive_capture()?;
        self.revalidate_at(now_seconds)?;
        Ok(capture)
    }

    pub(crate) const fn trust(&self) -> &SourceProviderTrustSetV1 {
        self.files.trust().trust_set()
    }

    pub(crate) fn trust_history(&self) -> &[crate::trust_file::ProtectedTrustHeadLinkV2] {
        self.files.trust().history()
    }

    pub(crate) fn trust_key_issuance(
        &self,
        signer: &aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    ) -> Option<(
        (
            u64,
            aos_sandbox_core::ObjectDigest,
            u64,
            aos_sandbox_core::ObjectDigest,
        ),
        (
            u64,
            aos_sandbox_core::ObjectDigest,
            u64,
            aos_sandbox_core::ObjectDigest,
        ),
    )> {
        self.files.trust().key_history(signer)
    }

    pub(crate) fn trust_authority_state_head(
        &self,
        authority: &aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    ) -> Option<(
        u64,
        aos_sandbox_core::ObjectDigest,
        u64,
        aos_sandbox_core::ObjectDigest,
    )> {
        self.files.trust().authority_state_head(authority)
    }

    pub(crate) const fn route(&self) -> &ProtectedSourceProviderRouteV1 {
        self.files.route().route()
    }

    pub(crate) const fn root_peer(&self) -> &ProtectedRootMountPeerV1 {
        self.files.route().root_mount_peer()
    }

    pub(crate) const fn route_file(&self) -> &crate::route_file::SourceProviderRouteFileV1 {
        self.files.route()
    }

    pub(crate) const fn root_authority(&self) -> &SourceProviderCurrentAuthorityV1 {
        &self.root_authority
    }

    pub(crate) const fn provider_authority(&self) -> &SourceProviderCurrentAuthorityV1 {
        &self.provider_authority
    }

    pub(crate) const fn execution(&self) -> &RetainedSelfExecutionV1 {
        &self.execution
    }

    pub(crate) const fn process_instance(&self) -> [u8; 16] {
        self.nonces.process_instance()
    }

    pub(crate) const fn hello_key(&self) -> &RetainedSecret {
        self.files.hello_key()
    }

    pub(crate) const fn outcome_key(&self) -> &RetainedSecret {
        self.files.outcome_key()
    }
}

fn current_authority(
    files: &ProtectedSourceProviderFiles,
    role: SourceProviderPeerRole,
) -> Result<SourceProviderCurrentAuthorityV1, SourceProviderSecurityError> {
    let indices = match role {
        SourceProviderPeerRole::RootMount => [0, 2],
        SourceProviderPeerRole::Provider => [1, 3],
    };
    let hello = files.manifest().signers()[indices[0]].clone();
    let traffic = files.manifest().signers()[indices[1]].clone();
    let authority = aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1::new(
        hello.authority_id(),
        hello.authority_generation(),
        hello.authority_digest(),
    )
    .map_err(|_| SourceProviderSecurityError::format("manifest", "authority"))?;
    SourceProviderCurrentAuthorityV1::new(
        role,
        authority,
        hello,
        traffic,
        files.manifest().proof_capabilities(),
        files.route().route(),
        files.trust().trust_set(),
    )
    .map_err(|_| SourceProviderSecurityError::format("manifest", "current authority"))
}
