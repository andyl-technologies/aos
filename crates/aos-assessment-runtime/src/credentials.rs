//! Installed source credential grants shared by Native and Worker effects.
//!
//! This secret-free configuration is supplied by the deployment, never package
//! metadata. A reference selects one exact partition, provider, project scope and immutable
//! secret binding. Missing or expired grants never fall back to ambient keys.
//!
//! ```json
//! {"schema":"aos.assessment-source-credentials/v1","grants":[]}
//! ```

use anyhow::{Context as _, Result, bail};
use aos_assessment::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::provider::{ProviderOperation, ProviderWorkPlanV1};
use crate::validation::{decode, encoded, sorted, text};

/// Binds one installed immutable credential to an exact provider and partition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceCredentialGrant {
    /// Immutable version reference carried by an authenticated work plan.
    pub reference: String,
    /// Exact authorization partition, with no wildcard or ancestor interpretation.
    pub partition: String,
    /// Exact installed provider profile allowed to receive this credential.
    pub provider: String,
    /// Exact repositories or an explicit public-catalog operation scope.
    pub scope: SourceCredentialScope,
    /// Installed secret binding name; secret bytes and paths are absent.
    pub secret_binding: String,
    /// Exclusive grant expiry, checked again before each physical request.
    pub expires_at: Timestamp,
}

/// Restricts credential use to installed source projects, independent of labels.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceCredentialScope {
    /// Allows only exact owner/repository identities used in GitHub API URLs.
    GithubRepositories {
        /// Sorted unique literal repositories; wildcard and URL forms are refused.
        repositories: Vec<String>,
    },
    /// Allows typed queries and feed reads from the fixed public NVD catalog.
    PublicNvdCatalogue,
}

impl SourceCredentialScope {
    fn validate_for(&self, provider: &str) -> Result<()> {
        match (self, provider) {
            (Self::GithubRepositories { repositories }, "github-tags" | "github-releases") => {
                if repositories.is_empty() || repositories.len() > 128 {
                    bail!("source credential requires a finite nonempty repository scope");
                }
                sorted(repositories, "source credential repositories")?;
                for repository in repositories {
                    ProviderOperation::ObserveTags {
                        repository: repository.clone(),
                        tag_prefix: String::new(),
                        page: 1,
                    }
                    .validate()?;
                }
                Ok(())
            }
            (Self::PublicNvdCatalogue, "nvd") => Ok(()),
            _ => bail!("source credential project scope differs from its installed provider"),
        }
    }

    fn permits(&self, operation: &ProviderOperation) -> bool {
        match (self, operation) {
            (
                Self::GithubRepositories { repositories },
                ProviderOperation::ObserveTags { repository, .. }
                | ProviderOperation::ObserveReleases { repository, .. },
            ) => repositories.binary_search(repository).is_ok(),
            (
                Self::PublicNvdCatalogue,
                ProviderOperation::QueryNvd { .. } | ProviderOperation::RefreshNvd { .. },
            ) => true,
            _ => false,
        }
    }
}

/// Describes the closed, bounded deployment credential configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceCredentialSetV1 {
    /// Exact configuration discriminator.
    pub schema: String,
    /// Grants in strictly increasing immutable reference order.
    pub grants: Vec<SourceCredentialGrant>,
}

impl SourceCredentialSetV1 {
    /// Decodes finite, unambiguous installed grants without reading secret bytes.
    ///
    /// # Errors
    /// Returns an error for unsupported schemas, unknown/null/duplicate fields,
    /// invalid references, unsupported providers or excessive configuration.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 64 * 1024 {
            bail!("installed source credential configuration exceeds its byte bound");
        }
        let value: Self = decode(bytes, "installed source credential grants")?;
        value.validate()?;
        Ok(value)
    }

    /// Validates exact scopes, sorted unique references and installed binding names.
    ///
    /// # Errors
    /// Returns an error for invalid schema, reference order, scope, provider,
    /// secret binding name or configuration bounds.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "aos.assessment-source-credentials/v1" || self.grants.len() > 128 {
            bail!("invalid installed source credential schema or grant count");
        }
        let references = self
            .grants
            .iter()
            .map(|grant| &grant.reference)
            .collect::<Vec<_>>();
        sorted(&references, "installed credential references")?;
        for grant in &self.grants {
            grant.scope.validate_for(&grant.provider)?;
            text(
                &grant.reference,
                128,
                "immutable source credential reference",
            )?;
            text(&grant.partition, 128, "source credential partition")?;
            if !["github-releases", "github-tags", "nvd"].contains(&grant.provider.as_str())
                || grant.secret_binding.is_empty()
                || grant.secret_binding.len() > 128
                || !grant
                    .secret_binding
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                || !grant.secret_binding.as_bytes()[0].is_ascii_uppercase()
            {
                bail!("source credential provider or secret binding is unsupported");
            }
        }
        if encoded(self)?.len() > 64 * 1024 {
            bail!("installed source credential grants exceed their canonical byte bound");
        }
        Ok(())
    }

    /// Resolves an exact current grant before a host reads its secret binding.
    ///
    /// # Errors
    /// Returns an error for malformed plans/configuration, missing references,
    /// mismatched partitions/providers or expired authority.
    pub fn resolve<'a>(
        &'a self,
        plan: &ProviderWorkPlanV1,
        now: &Timestamp,
    ) -> Result<&'a SourceCredentialGrant> {
        self.validate()?;
        plan.validate_at(now)?;
        let reference = plan
            .credential_ref
            .as_ref()
            .context("source credential reference is absent")?;
        let grant = self
            .grants
            .iter()
            .find(|grant| &grant.reference == reference)
            .context("installed source credential grant is absent")?;
        if grant.partition != plan.authorization_partition
            || grant.provider != plan.operation.provider()
            || !grant.scope.permits(&plan.operation)
            || now >= &grant.expires_at
        {
            bail!("source credential scope or current authority differs");
        }
        Ok(grant)
    }
}
