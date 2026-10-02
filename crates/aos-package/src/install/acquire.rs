//! Acquires authenticated native packages without changing a profile.
//!
//! The normal install request, provenance, and signed store-graph checks govern
//! every download. A caller-owned temporary-root lease protects imported inputs
//! until the caller publishes durable roots. Module discovery and activation
//! remain separate operations; acquiring bytes does not select live policy.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::registry::{store_path_hash, RegistrySet};
use crate::resolve::{collect_unique_metas, resolve_multiple, ResolvedClosure};
use crate::store::temp_roots::TemporaryRoots;

/// Resolves and imports signed package closures while retaining their inputs.
///
/// Registry priority and platform selection follow ordinary package install.
/// The caller retains `temporary_roots` through module realization, evaluation,
/// and durable publication, and separately applies its mutation and confirmation
/// policy. No profile generation, journal, or live effect is created here.
///
/// Existing store objects remain subject to the caller's normal native artifact
/// admission before evaluation or dispatch. Downloaded objects additionally pass
/// the install pipeline's compressed, NAR, and signed graph verification.
///
/// # Errors
/// Returns an error for unresolved packages, absent native envelopes, invalid
/// provenance or incomplete signed graphs, failed downloads or verification,
/// temporary retention failure, or failed store import.
pub(crate) async fn acquire(
    config: &ApmConfig,
    registries: &RegistrySet,
    names: &[String],
    printer: &Printer,
    temporary_roots: &mut Option<TemporaryRoots>,
) -> Result<Vec<ResolvedClosure>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }

    let closures = resolve_multiple(registries, names, None)?;
    let metadata = collect_unique_metas(&closures);
    for package in &metadata {
        ensure!(
            package.deployment.is_some(),
            "package {}@{} has no native deployment envelope",
            package.name,
            package.version
        );
    }
    for closure in &closures {
        let registry = registries
            .get_registry(&closure.registry_name)
            .context("package acquisition registry is unavailable")?;
        ensure!(
            registry.release_trust().is_some() && registry.store_map().is_present(),
            "native package acquisition requires an authenticated signed release graph"
        );
    }
    let secondary = super::collect_secondary_artifacts(&closures)?;
    let store_paths = metadata
        .iter()
        .map(|package| package.store_path.clone())
        .chain(secondary.iter().map(|artifact| artifact.store_path.clone()))
        .collect::<Vec<_>>();

    if temporary_roots.is_none() {
        *temporary_roots = Some(TemporaryRoots::open(
            &super::native::packaged_path("AOS_NIX_STORE")?,
            &Default::default(),
        )?);
    }
    let lease = temporary_roots
        .as_mut()
        .context("package acquisition temporary roots were not initialized")?;
    lease.retain(store_paths.iter().cloned(), &Default::default())?;
    super::verify_install_provenance_from_cache_with_policy(config, &closures)?;

    // Enforce the complete signed graph even when its objects are already local.
    // Anonymous members are authoritative too, not only named package metadata.
    let trust_roots = closures
        .iter()
        .map(|closure| {
            (
                closure.registry_name.as_str(),
                store_path_hash(&closure.root.store_path),
            )
        })
        .chain(
            secondary
                .iter()
                .filter(|artifact| artifact.trust_graph_root)
                .map(|artifact| {
                    (
                        artifact.registry_name.as_str(),
                        store_path_hash(&artifact.store_path),
                    )
                }),
        )
        .collect::<Vec<_>>();
    let trust = registries.trust_context_for_roots(&trust_roots);
    trust.enforce_totality()?;

    let missing = crate::store::filter_missing(&store_paths).await?;
    let missing_set = missing.iter().map(String::as_str).collect::<HashSet<_>>();
    let missing_metadata = metadata
        .iter()
        .filter(|package| missing_set.contains(package.store_path.as_str()))
        .copied()
        .collect::<Vec<_>>();
    let mut requests = super::build_download_requests(&closures, &missing_metadata, config)?;
    requests.extend(super::build_secondary_artifact_download_requests(
        registries, &secondary, &missing, false, config,
    )?);
    super::dedupe_download_requests(&mut requests);
    if requests.is_empty() {
        return Ok(closures);
    }

    let resolved = crate::download::fetch_narinfo_closure(
        Arc::new(crate::download::default_engine()),
        &requests,
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    lease.retain(
        resolved
            .iter()
            .map(|download| download.req.store_path.clone()),
        &Default::default(),
    )?;
    let downloaded = crate::download::download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        printer,
    )
    .await?;
    crate::verify::verify_downloads(&downloaded, &trust, printer)?;
    super::verify_secondary_artifact_downloads(&downloaded, &secondary)?;

    // Finish immutable imports rather than dropping futures whose download or
    // decompressor children may outlive them. Callers cancel before activation.
    for download in &downloaded {
        crate::store::import_nar_with_compression(
            &download.local_path,
            &download.store_path,
            &download.references,
            download.deriver.as_deref(),
            &download.compression,
        )
        .await
        .with_context(|| format!("importing {}", download.store_path))?;
    }

    Ok(closures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::make_registry;
    use crate::types::{NativeArtifactMeta, ProfileScope};

    fn config() -> ApmConfig {
        ApmConfig {
            settings: Default::default(),
            registries: Vec::new(),
            scope: ProfileScope::User,
        }
    }

    fn native_package() -> String {
        let mut document: toml::Value = toml::from_str(crate::registry::parse::ZLIB_TOML).unwrap();
        let platform = document["versions"][0]["platforms"]["x86_64-linux"]
            .as_table_mut()
            .unwrap();
        platform.insert(
            "requires-features".into(),
            toml::Value::try_from(vec!["native-package-modules-v1"]).unwrap(),
        );
        platform.insert(
            "references".into(),
            toml::from_str("requires-features = [\"native-package-modules-v1\"]").unwrap(),
        );
        platform.insert(
            "deployment".into(),
            toml::Value::try_from(NativeArtifactMeta {
                store_path: format!("/nix/store/{}-zlib-deployment", "a".repeat(32)),
                nar_hash: format!("sha256:{}", "a".repeat(64)),
                nar_size: 128,
                references: Vec::new(),
                document_sha256: format!("sha256:{}", "b".repeat(64)),
                document_size: 64,
            })
            .unwrap(),
        );
        toml::to_string(&document).unwrap()
    }

    #[tokio::test]
    async fn cached_native_bytes_without_signed_release_never_open_store_or_profile() {
        let scratch = tempfile::tempdir().unwrap();
        let package = native_package();
        let registry = make_registry(&scratch, "local", 500, &[("zlib", &package)]);
        std::fs::write(scratch.path().join("payload"), b"cached package bytes").unwrap();
        std::fs::write(
            scratch.path().join("deployment.json"),
            b"cached envelope bytes",
        )
        .unwrap();
        assert!(registry.get("zlib").unwrap().deployment.is_some());
        assert!(registry.release_trust().is_none());
        let registries = RegistrySet::new(vec![registry]);
        let mut roots = None;

        let error = acquire(
            &config(),
            &registries,
            &["zlib".into()],
            &Printer::new(0, true, false),
            &mut roots,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("authenticated signed release graph"));
        assert!(roots.is_none(), "unauthorized acquisition opened the store");
        assert!(!scratch.path().join("profile").exists());
    }

    #[tokio::test]
    async fn missing_native_envelope_fails_before_store_or_profile_publication() {
        let scratch = tempfile::tempdir().unwrap();
        let registry = make_registry(
            &scratch,
            "local",
            500,
            &[("zlib", crate::registry::parse::ZLIB_TOML)],
        );
        let registries = RegistrySet::new(vec![registry]);
        let mut roots = None;

        let error = acquire(
            &config(),
            &registries,
            &["zlib".into()],
            &Printer::new(0, true, false),
            &mut roots,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("no native deployment envelope"));
        assert!(roots.is_none());
        assert!(!scratch.path().join("profile").exists());
    }

    #[tokio::test]
    async fn unresolved_package_cannot_create_acquisition_state() {
        let mut roots = None;
        let error = acquire(
            &config(),
            &RegistrySet::new(Vec::new()),
            &["../untrusted".into()],
            &Printer::new(0, true, false),
            &mut roots,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("../untrusted"));
        assert!(roots.is_none());
    }
}
