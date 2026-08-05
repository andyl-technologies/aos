//! Cloudflare Worker adapter for immutable provider-managed secret versions.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context as _;
use aos_hub_core::secret_version::{
    validate_secret_version_ref, ResolvedSecretVersion, SecretVersionResolver,
};
use worker::Env;

const HUB_SECRET_VERSION_MANIFEST: &str = "HUB_SECRET_VERSION_MANIFEST";

/// Loads a closed ref-to-binding manifest and resolves each named Worker secret.
///
/// # Errors
///
/// Returns an error when the manifest is malformed or a binding is absent.
pub fn from_env(env: &Env) -> worker::Result<Arc<dyn SecretVersionResolver>> {
    let Some(manifest) = env.var(HUB_SECRET_VERSION_MANIFEST).ok() else {
        return Ok(Arc::new(WorkerSecretVersionResolver {
            env: env.clone(),
            bindings: BTreeMap::new(),
        }));
    };
    let bindings: BTreeMap<String, String> = serde_json::from_str(&manifest.to_string())
        .map_err(|error| worker::Error::RustError(format!("secret-version manifest: {error}")))?;
    for (version_ref, binding) in &bindings {
        validate_secret_version_ref(version_ref).map_err(|error| {
            worker::Error::RustError(format!("secret-version resolver: {error:#}"))
        })?;
        if binding.is_empty()
            || binding.len() > 128
            || !binding
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(worker::Error::RustError(
                "secret-version manifest contains an invalid Worker binding name".into(),
            ));
        }
    }
    Ok(Arc::new(WorkerSecretVersionResolver {
        env: env.clone(),
        bindings,
    }))
}

struct WorkerSecretVersionResolver {
    env: Env,
    bindings: BTreeMap<String, String>,
}

#[async_trait::async_trait(?Send)]
impl SecretVersionResolver for WorkerSecretVersionResolver {
    async fn resolve(&self, version_ref: &str) -> anyhow::Result<ResolvedSecretVersion> {
        validate_secret_version_ref(version_ref)?;
        let binding = self
            .bindings
            .get(version_ref)
            .context("secret provider has no configured version")?;
        let value = self
            .env
            .secret(binding)
            .map_err(|_| anyhow::anyhow!("configured secret version is unavailable"))?;
        Ok(ResolvedSecretVersion::from_bytes(
            value.to_string().into_bytes(),
        ))
    }
}
