//! Authenticated package-document resolution for configuration evaluation.
//!
//! The resolver returns the canonical [`aos_ability_model::PackageDocument`]
//! selected for an exact package coordinate. The document's `package_module`
//! locator is the sole configuration-module authority; registry-era module
//! metadata is not represented at this boundary.

/// Resolves one authenticated package document and its runtime identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackageModule {
    /// Registry that authenticated this package version.
    pub registry: String,
    /// Signed-release receipt associated with the extracted registry tree.
    pub release_trust: Option<crate::registry::ReleaseTrustReceipt>,
    /// Hash of the signed store subgraph rooted at the module artifact.
    pub realization: Option<String>,
    /// Package name.
    pub package: String,
    /// Package version.
    pub version: String,
    /// Target platform.
    pub platform: String,
    /// Authenticated runtime payload output.
    pub runtime_output: String,
    /// Canonical package document containing the sole module locator.
    pub document: aos_ability_model::PackageDocument,
}

/// Resolves authenticated package documents by package coordinate.
pub trait PackageModuleResolver {
    /// Returns the package document for `package`, when present.
    ///
    /// # Errors
    ///
    /// Returns an error when contract metadata, canonical document bytes, or
    /// selector bindings are malformed or disagree with the package identity.
    fn package_module(&self, package: &str) -> anyhow::Result<Option<ResolvedPackageModule>>;

    /// Returns an exact package document matching optional installed pins.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::package_module`].
    fn package_module_exact(
        &self,
        package: &str,
        version: Option<&str>,
        runtime_output: Option<&str>,
    ) -> anyhow::Result<Option<ResolvedPackageModule>> {
        let Some(resolved) = self.package_module(package)? else {
            return Ok(None);
        };
        if version.is_some_and(|want| want != resolved.version)
            || runtime_output.is_some_and(|want| want != resolved.runtime_output)
        {
            return Ok(None);
        }
        Ok(Some(resolved))
    }
}
