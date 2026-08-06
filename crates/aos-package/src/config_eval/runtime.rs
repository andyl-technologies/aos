//! Exact runtime-package resolution for configuration generations.
//!
//! Configuration evaluation selects package names, but names are not safe
//! activation inputs: registries can advance between evaluation and fetch.
//! This module closes that gap by resolving every selected package to its
//! registry-authenticated output and complete `store/` realisation graph. The
//! resulting pins are pure manifest data; fetchers consume the pins without
//! performing a second by-name lookup.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::registry::{RegistrySet, store_path_hash};
use crate::resolve::resolve_multiple;
use crate::types::{ExposeArtifactMeta, ExposeConfigMeta, ExposeMeta};

/// Exact runtime outputs and their dependency graph for one evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResolution {
    /// Runtime pin keyed by package name.
    pub packages: BTreeMap<String, RuntimePackagePin>,
    /// Direct package dependencies keyed by package name.
    pub edges: BTreeMap<String, Vec<String>>,
}

/// One selected package pinned to immutable registry metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePackagePin {
    /// Resolved version.
    pub version: String,
    /// Resolved target platform.
    pub platform: String,
    /// Registry whose authenticated metadata selected this output.
    pub registry: String,
    /// Exact runtime output store path.
    pub store_path: String,
    /// Complete authenticated closure, keyed by input-addressed store hash.
    pub closure: Vec<RuntimeClosurePin>,
    /// Signed service exposure contract for this package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeMeta>,
    /// Exact rendered unit artifact authenticated by the selected registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_artifact: Option<ExposeArtifactMeta>,
    /// Authenticated expose schema projected by this package's generated
    /// config companion. Absent for legacy flat-render packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_projection: Option<RuntimeExposeConfigPin>,
    /// Registry-authenticated flat expose config for a package that has not
    /// migrated to a config-module projection. This keeps `render-one` from
    /// consulting mutable profile or registry metadata after evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_config: Option<ExposeConfigMeta>,
}

/// Registry-authenticated binding for one generated expose config companion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeExposeConfigPin {
    /// Exact config-output store path evaluated for this package.
    pub config_output: String,
    /// Authenticated NAR hash of that config output.
    pub config_nar_hash: String,
    /// Signed RFC-0001 artifact and credential schema.
    pub config: ExposeConfigMeta,
}

/// One member of a registry-authenticated runtime closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosurePin {
    /// Input-addressed store-path hash used by the registry `store/` graph.
    pub store_path_hash: String,
    /// Full store path when the member is also published as a named package.
    /// Anonymous closure members are still authenticated by `store_path_hash`
    /// and `realisations`; Nix learns their full names from the root narinfo.
    pub store_path: Option<String>,
    /// Every registry-blessed realisation, in deterministic order.
    pub realisations: Vec<RuntimeRealisationPin>,
}

/// Exact NAR bytes blessed for one closure member.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRealisationPin {
    /// Canonical `sha256:<nixbase32>` hash of the uncompressed NAR.
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: u64,
}

/// Resolves package names to exact authenticated runtime pins.
///
/// Package-level `expose.requires` and capability-provider dependencies are
/// recursively included by [`resolve_multiple`]. Registries without a
/// published `store/` graph are refused: their narinfo fallback cannot pin and
/// authenticate every anonymous closure member, so it is insufficient for a
/// transactional RFC-0011 configuration generation.
///
/// # Errors
///
/// Returns an error when a package cannot be resolved, a package-level
/// dependency cycle exists, the selected registry has no `store/` graph, a
/// graph member has no blessed NAR, or root metadata disagrees with the graph.
pub fn resolve_runtime(registries: &RegistrySet, selected: &[String]) -> Result<RuntimeResolution> {
    let closures = resolve_multiple(registries, selected, None)?;
    let selected_roots: BTreeMap<String, String> = closures
        .iter()
        .map(|closure| {
            (
                store_path_hash(&closure.root.store_path).to_string(),
                closure.root.name.clone(),
            )
        })
        .collect();

    let mut packages = BTreeMap::new();
    let mut edges = BTreeMap::new();
    for closure in &closures {
        let registry = registries
            .get_registry(&closure.registry_name)
            .with_context(|| {
                format!("resolved registry '{}' disappeared", closure.registry_name)
            })?;
        let store = registry.store_map();
        if !store.is_present() {
            bail!(
                "registry '{}' publishes no authenticated store graph for package '{}'; \
                 refusing an unpinned configuration runtime closure",
                closure.registry_name,
                closure.root.name
            );
        }
        if closure.root.expose.is_some() != closure.root.expose_artifact.is_some() {
            bail!(
                "package '{}@{}' must publish signed expose metadata and its rendered artifact together",
                closure.root.name,
                closure.root.version
            );
        }

        let root_hash = store_path_hash(&closure.root.store_path);
        let mut member_hashes = store.reachable(root_hash);
        if let Some(artifact) = &closure.root.expose_artifact {
            member_hashes.extend(store.reachable(store_path_hash(&artifact.store_path)));
        }
        member_hashes.sort();
        member_hashes.dedup();
        let mut members = Vec::with_capacity(member_hashes.len());
        for member_hash in member_hashes {
            let mut realisations: Vec<RuntimeRealisationPin> = store
                .blessed_nars(&member_hash)
                .into_iter()
                .map(|nar| RuntimeRealisationPin {
                    nar_hash: nar.nar_hash(),
                    nar_size: nar.size,
                })
                .collect();
            realisations.sort();
            realisations.dedup();
            if realisations.is_empty() {
                bail!(
                    "registry '{}' store graph has no blessed NAR for closure member '{}' \
                     of package '{}'",
                    closure.registry_name,
                    member_hash,
                    closure.root.name
                );
            }
            let mut store_path = registries
                .resolve_hash_in(&closure.registry_name, &member_hash)
                .map(|meta| meta.store_path.clone());
            if let Some(artifact) = &closure.root.expose_artifact
                && member_hash == store_path_hash(&artifact.store_path)
            {
                store_path = Some(artifact.store_path.clone());
            }
            members.push(RuntimeClosurePin {
                store_path_hash: member_hash,
                store_path,
                realisations,
            });
        }

        let root_pin = members
            .iter()
            .find(|member| member.store_path_hash == root_hash)
            .context("authenticated closure omitted its package root")?;
        if !root_pin.realisations.iter().any(|pin| {
            crate::registry::store::NarBytes::from_hash(
                &closure.root.nar_hash,
                closure.root.nar_size,
            )
            .is_ok_and(|nar| pin.nar_hash == nar.nar_hash() && pin.nar_size == nar.size)
        }) {
            bail!(
                "package '{}@{}' metadata NAR disagrees with registry '{}' store graph",
                closure.root.name,
                closure.root.version,
                closure.registry_name
            );
        }
        if let Some(artifact) = &closure.root.expose_artifact {
            let artifact_hash = store_path_hash(&artifact.store_path);
            let artifact_pin = members
                .iter()
                .find(|member| member.store_path_hash == artifact_hash)
                .context("authenticated closure omitted its expose artifact root")?;
            if !artifact_pin.realisations.iter().any(|pin| {
                crate::registry::store::NarBytes::from_hash(&artifact.nar_hash, artifact.nar_size)
                    .is_ok_and(|nar| pin.nar_hash == nar.nar_hash() && pin.nar_size == nar.size)
            }) {
                bail!(
                    "package '{}@{}' expose artifact NAR disagrees with registry '{}' store graph",
                    closure.root.name,
                    closure.root.version,
                    closure.registry_name
                );
            }
        }

        let mut dependencies = BTreeSet::new();
        for hash in store.direct_deps(root_hash) {
            if let Some(package) = selected_roots.get(&hash)
                && package != &closure.root.name
            {
                dependencies.insert(package.clone());
            }
        }
        if let Some(expose) = closure.root.expose.as_ref() {
            dependencies.extend(
                expose
                    .requires
                    .iter()
                    .chain(expose.uses.iter().map(|route| &route.provider))
                    .filter(|package| *package != &closure.root.name)
                    .cloned(),
            );
        }
        edges.insert(
            closure.root.name.clone(),
            dependencies.into_iter().collect(),
        );
        let config_projection = match closure.root.config_module.as_ref() {
            Some(module)
                if module.declares.iter().any(|path| {
                    path == &format!("{}._aosExposeConfigProjection", closure.root.name)
                }) =>
            {
                let expose = closure.root.expose.as_ref().with_context(|| {
                    format!(
                        "package '{}' declares an expose config projection without signed expose metadata",
                        closure.root.name
                    )
                })?;
                let config_nar_hash = crate::registry::store::NarBytes::from_hash(
                    &module.config_output.nar_hash,
                    module.config_output.nar_size,
                )?
                .nar_hash();
                Some(RuntimeExposeConfigPin {
                    config_output: module.config_output.store_path.clone(),
                    config_nar_hash,
                    config: expose.config.clone(),
                })
            }
            _ => None,
        };
        let legacy_config = if config_projection.is_none() {
            closure
                .root
                .expose
                .as_ref()
                .map(|expose| expose.config.clone())
        } else {
            None
        };
        packages.insert(
            closure.root.name.clone(),
            RuntimePackagePin {
                version: closure.root.version.clone(),
                platform: closure.root.platform.clone(),
                registry: closure.registry_name.clone(),
                store_path: closure.root.store_path.clone(),
                closure: members,
                expose: closure.root.expose.clone(),
                expose_artifact: closure.root.expose_artifact.clone(),
                config_projection,
                legacy_config,
            },
        );
    }

    Ok(RuntimeResolution { packages, edges })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::registry::tests::{
        FIX_NAR, curl_store_record, make_registry, make_registry_with_store, zlib_store_record,
    };
    use tempfile::TempDir;

    #[test]
    fn resolves_exact_authenticated_outputs_and_dependency_edges() {
        let temp = TempDir::new().unwrap();
        let mut store_records = vec![curl_store_record(), zlib_store_record()];
        store_records.extend(
            ["xr5is7by89v3q", "q8mn2pv73w0x", "kl9m3n0p5p6q"]
                .into_iter()
                .map(|hash| (hash, format!("nar:sha256:{FIX_NAR}:64\n"))),
        );
        let curl_toml = CURL_TOML.replace("sha256:aabbcc", &format!("sha256:{FIX_NAR}"));
        let zlib_toml = ZLIB_TOML.replace("sha256:abc123", &format!("sha256:{FIX_NAR}"));
        let registry = make_registry_with_store(
            &temp,
            "aos-core",
            500,
            &[("curl", &curl_toml), ("zlib", &zlib_toml)],
            &store_records,
        );
        let set = RegistrySet::new(vec![registry]);

        let resolution = resolve_runtime(&set, &["curl".to_string(), "zlib".to_string()]).unwrap();

        let curl = &resolution.packages["curl"];
        assert_eq!(curl.registry, "aos-core");
        assert_eq!(curl.store_path, "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0");
        assert!(curl.closure.iter().any(|member| {
            member.store_path_hash == "h7j3k8l2m9n4" && !member.realisations.is_empty()
        }));
        assert!(curl.closure.iter().any(|member| {
            member.store_path_hash == "r4q1m2kp8v3x"
                && member.store_path.as_deref() == Some("/var/lib/store/r4q1m2kp8v3x-zlib-1.3.1")
        }));
        assert_eq!(resolution.edges["curl"], vec!["zlib"]);
        assert!(resolution.edges["zlib"].is_empty());
    }

    #[test]
    fn refuses_legacy_registry_without_authenticated_closure_graph() {
        let temp = TempDir::new().unwrap();
        let registry = make_registry(
            &temp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![registry]);

        let error = resolve_runtime(&set, &["curl".to_string()]).unwrap_err();
        assert!(
            format!("{error:#}").contains("publishes no authenticated store graph"),
            "{error:#}"
        );
    }
}
