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
