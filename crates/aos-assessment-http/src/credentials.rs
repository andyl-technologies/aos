//! Native custody adapter for the shared installed source credential grants.

use std::sync::Arc;

use anyhow::{Result, bail};
use aos_assessment_runtime::credentials::{SourceCredentialGrant, SourceCredentialSetV1};
use aos_assessment_runtime::ports::Clock as _;
use aos_assessment_runtime::provider::ProviderWorkPlanV1;
use zeroize::Zeroizing;

use crate::{PhysicalClock, SourceCredential, SourceCredentials};

/// Reads one installed secret binding under independent current custody authority.
#[async_trait::async_trait]
pub trait SourceSecretBindings: Send + Sync {
    /// Resolves the exact immutable binding after partition/provider grant validation.
    ///
    /// Implementations recheck current custody and version authority. Missing or
    /// revoked bindings never select environment credentials or an older version.
    ///
    /// # Errors
    /// Returns an error for missing/revoked custody, changed versions or unavailable secrets.
    async fn read(&self, grant: &SourceCredentialGrant) -> Result<Zeroizing<String>>;
}

/// Resolves Native credentials through the same exact grant checks as Worker effects.
pub struct InstalledSourceCredentials {
    grants: SourceCredentialSetV1,
    bindings: Arc<dyn SourceSecretBindings>,
}

impl InstalledSourceCredentials {
    /// Creates a resolver from validated secret-free installation and current custody.
    ///
    /// # Errors
    /// Returns an error for invalid scopes, unsupported providers or configuration bounds.
    pub fn new(
        grants: SourceCredentialSetV1,
        bindings: Arc<dyn SourceSecretBindings>,
    ) -> Result<Self> {
        grants.validate()?;
        Ok(Self { grants, bindings })
    }
}

#[async_trait::async_trait]
impl SourceCredentials for InstalledSourceCredentials {
    async fn resolve(&self, plan: &ProviderWorkPlanV1) -> Result<SourceCredential> {
        if plan.credential_ref.is_none() {
            return Ok(SourceCredential::Anonymous);
        }
        let grant = self.grants.resolve(plan, &PhysicalClock.now()?)?;
        let secret = self.bindings.read(grant).await?;
        match grant.provider.as_str() {
            "github-releases" | "github-tags" => Ok(SourceCredential::Github(secret)),
            "nvd" => Ok(SourceCredential::Nvd(secret)),
            _ => bail!("installed source credential provider is unsupported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Custody {
        reads: AtomicUsize,
        revoked: AtomicBool,
    }

    #[async_trait::async_trait]
    impl SourceSecretBindings for Custody {
        async fn read(&self, _: &SourceCredentialGrant) -> Result<Zeroizing<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.revoked.load(Ordering::SeqCst) {
                bail!("fixture secret version is revoked");
            }
            Ok(Zeroizing::new("fixture-source-credential".into()))
        }
    }

    #[tokio::test]
    async fn scope_checks_precede_secret_reads_and_current_custody_revocation_has_no_fallback()
    -> Result<()> {
        let mut plan = crate::tests::plan()?;
        plan.credential_ref = Some("github-read-v1".into());
        let custody = Arc::new(Custody {
            reads: AtomicUsize::new(0),
            revoked: AtomicBool::new(false),
        });
        let resolver = InstalledSourceCredentials::new(
            SourceCredentialSetV1 {
                schema: "aos.assessment-source-credentials/v1".into(),
                grants: vec![SourceCredentialGrant {
                    reference: "github-read-v1".into(),
                    partition: plan.authorization_partition.clone(),
                    provider: "github-tags".into(),
                    scope: aos_assessment_runtime::credentials::SourceCredentialScope::GithubRepositories {
                        repositories: vec!["example/fixture".into()],
                    },
                    secret_binding: "ASSESSMENT_GITHUB_V1".into(),
                    expires_at: plan.expires_at.clone(),
                }],
            },
            custody.clone(),
        )?;

        let mut denied = plan.clone();
        denied.authorization_partition = "different-partition".into();
        assert!(resolver.resolve(&denied).await.is_err());
        assert_eq!(custody.reads.load(Ordering::SeqCst), 0);
        denied = plan.clone();
        denied.operation = aos_assessment_runtime::provider::ProviderOperation::ObserveTags {
            repository: "another/private-project".into(),
            tag_prefix: "v".into(),
            page: 1,
        };
        assert!(resolver.resolve(&denied).await.is_err());
        assert_eq!(custody.reads.load(Ordering::SeqCst), 0);
        assert!(matches!(
            resolver.resolve(&plan).await?,
            SourceCredential::Github(_)
        ));
        assert_eq!(custody.reads.load(Ordering::SeqCst), 1);
        custody.revoked.store(true, Ordering::SeqCst);
        assert!(resolver.resolve(&plan).await.is_err());
        assert_eq!(custody.reads.load(Ordering::SeqCst), 2);
        denied = plan;
        denied.credential_ref = None;
        assert!(matches!(
            resolver.resolve(&denied).await?,
            SourceCredential::Anonymous
        ));
        assert_eq!(custody.reads.load(Ordering::SeqCst), 2);
        Ok(())
    }
}
