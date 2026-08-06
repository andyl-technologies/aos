//! Exact runtime-package resolution for configuration generations.
//!
//! Configuration evaluation selects package names, but names are not safe
//! activation inputs: registries can advance between evaluation and fetch.
//! This module closes that gap by resolving every selected package to its
//! registry-authenticated output and complete `store/` realisation graph. The
//! resulting pins are pure manifest data; fetchers consume the pins without
//! performing a second by-name lookup.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::registry::{RegistrySet, store_path_hash};
use crate::types::{ExposeArtifactMeta, ExposeConfigMeta, ExposeMeta};

/// An exact image-bundled package available from the active system profile.
#[derive(Debug, Clone)]
pub struct LocalRuntimePackage {
    /// Package version recorded by the image seed.
    pub version: String,
    /// Exact runtime output in the immutable image closure.
    pub store_path: String,
    /// Signed service exposure contract retained in the image seed.
    pub expose: Option<ExposeMeta>,
    /// Rendered expose artifact retained in the image seed.
    pub expose_artifact: Option<ExposeArtifactMeta>,
    /// Config-only companion retained in the image seed.
    pub config_module: Option<crate::types::ConfigModuleMeta>,
    /// Lazily verified closure reused across outer fixpoint iterations.
    pub(super) closure: RefCell<Option<Vec<RuntimeClosurePin>>>,
}

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
    /// Whether this pin came from a signed registry or the measured image.
    #[serde(default, skip_serializing_if = "RuntimePackageOrigin::is_registry")]
    pub origin: RuntimePackageOrigin,
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

/// Trust origin for an exact runtime package pin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimePackageOrigin {
    /// A configured registry and its authenticated store graph.
    #[default]
    Registry,
    /// The active package profile seeded from the measured image.
    Image,
}

impl RuntimePackageOrigin {
    fn is_registry(&self) -> bool {
        *self == Self::Registry
    }
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
    resolve_runtime_with_local(registries, &BTreeMap::new(), selected)
}

/// Resolves packages with registry priority and measured-image fallback.
///
/// A local package is considered only when no configured registry publishes
/// its name. Registry parse, trust, graph, and integrity failures therefore
/// remain terminal rather than silently crossing the trust boundary.
///
/// # Errors
///
/// Returns the same registry errors as [`resolve_runtime`], or an error when
/// an image-local path is absent, has changed NAR bytes, or has an invalid
/// package-level dependency graph.
pub fn resolve_runtime_with_local(
    registries: &RegistrySet,
    local: &BTreeMap<String, LocalRuntimePackage>,
    selected: &[String],
) -> Result<RuntimeResolution> {
    let mut pending = selected.iter().cloned().collect::<BTreeSet<_>>();
    let mut closures = Vec::new();
    let mut local_names = BTreeSet::new();
    while let Some(name) = pending.pop_first() {
        if closures
            .iter()
            .any(|closure: &crate::resolve::ResolvedClosure| closure.root.name == name)
            || local_names.contains(&name)
        {
            continue;
        }
        if registries.resolve(&name).is_some() {
            let closure = crate::resolve::resolve_closure(registries, &name, None)
                .with_context(|| format!("resolving package '{name}'"))?;
            if let Some(expose) = &closure.root.expose {
                pending.extend(expose.requires.iter().cloned());
                pending.extend(expose.uses.iter().map(|route| route.provider.clone()));
            }
            closures.push(closure);
        } else if let Some(package) = local.get(&name) {
            if let Some(expose) = &package.expose {
                pending.extend(expose.requires.iter().cloned());
                pending.extend(expose.uses.iter().map(|route| route.provider.clone()));
            }
            local_names.insert(name);
        } else {
            return Err(aos_core::error::AosError::PackageNotFound { name }.into());
        }
    }
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
                origin: RuntimePackageOrigin::Registry,
                store_path: closure.root.store_path.clone(),
                closure: members,
                expose: closure.root.expose.clone(),
                expose_artifact: closure.root.expose_artifact.clone(),
                config_projection,
                legacy_config,
            },
        );
    }

    for name in local_names {
        let package = local
            .get(&name)
            .with_context(|| format!("image-local package '{name}' disappeared"))?;
        if package.expose.is_some() != package.expose_artifact.is_some() {
            bail!(
                "image-local package '{}@{}' must retain expose metadata and its artifact together",
                name,
                package.version
            );
        }
        let closure = local_closure(package)
            .with_context(|| format!("validating image-local closure for '{name}'"))?;
        let expose_artifact = package
            .expose_artifact
            .as_ref()
            .map(|artifact| {
                let member = closure
                    .iter()
                    .find(|member| member.store_path_hash == store_path_hash(&artifact.store_path))
                    .context("image-local closure omitted its expose artifact")?;
                let realization = member
                    .realisations
                    .first()
                    .context("image-local expose artifact has no NAR identity")?;
                let mut exact = artifact.clone();
                exact.nar_hash = realization.nar_hash.clone();
                exact.nar_size = realization.nar_size;
                Ok::<_, anyhow::Error>(exact)
            })
            .transpose()?;
        let mut dependencies = BTreeSet::new();
        if let Some(expose) = &package.expose {
            dependencies.extend(expose.requires.iter().cloned());
            dependencies.extend(expose.uses.iter().map(|route| route.provider.clone()));
            dependencies.remove(&name);
        }
        edges.insert(name.clone(), dependencies.into_iter().collect());
        let config_projection = match package.config_module.as_ref() {
            Some(module)
                if module
                    .declares
                    .iter()
                    .any(|path| path == &format!("{name}._aosExposeConfigProjection")) =>
            {
                let expose = package.expose.as_ref().with_context(|| {
                    format!("image-local package '{name}' projects expose config without expose metadata")
                })?;
                Some(RuntimeExposeConfigPin {
                    config_output: module.config_output.store_path.clone(),
                    config_nar_hash: crate::registry::store::NarBytes::from_hash(
                        &module.config_output.nar_hash,
                        module.config_output.nar_size,
                    )?
                    .nar_hash(),
                    config: expose.config.clone(),
                })
            }
            _ => None,
        };
        let legacy_config = if config_projection.is_none() {
            package.expose.as_ref().map(|expose| expose.config.clone())
        } else {
            None
        };
        packages.insert(
            name,
            RuntimePackagePin {
                version: package.version.clone(),
                platform: "image".to_string(),
                registry: "image".to_string(),
                origin: RuntimePackageOrigin::Image,
                store_path: package.store_path.clone(),
                closure,
                expose: package.expose.clone(),
                expose_artifact,
                config_projection,
                legacy_config,
            },
        );
    }

    Ok(RuntimeResolution { packages, edges })
}

fn local_closure(package: &LocalRuntimePackage) -> Result<Vec<RuntimeClosurePin>> {
    if let Some(cached) = package.closure.borrow().as_ref() {
        return Ok(cached.clone());
    }
    let mut roots = vec![package.store_path.as_str()];
    if let Some(artifact) = &package.expose_artifact {
        roots.push(&artifact.store_path);
    }
    let output = Command::new("nix-store")
        .args(["--query", "--requisites"])
        .args(&roots)
        .output()
        .context("running nix-store --query --requisites")?;
    if !output.status.success() {
        bail!(
            "querying image-local closure failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut members = Vec::new();
    for path in String::from_utf8(output.stdout)
        .context("image-local closure contains non-UTF-8 paths")?
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        let lower_path = immutable_lower_store_path(path)?;
        if !lower_path.exists() {
            bail!("image-local closure member {path} is absent from the immutable image store");
        }
        let (nar_hash, nar_size) = local_store_identity_at(path, &lower_path)?;
        members.push(RuntimeClosurePin {
            store_path_hash: store_path_hash(path).to_string(),
            store_path: Some(path.to_string()),
            realisations: vec![RuntimeRealisationPin { nar_hash, nar_size }],
        });
    }
    members.sort_by(|left, right| left.store_path_hash.cmp(&right.store_path_hash));
    members.dedup_by(|left, right| left.store_path_hash == right.store_path_hash);
    *package.closure.borrow_mut() = Some(members.clone());
    Ok(members)
}

/// Resolves a canonical store path through the immutable lower image store.
///
/// # Errors
///
/// Returns an error for nested, relative, or otherwise non-canonical store
/// paths. Callers must separately require the returned path to exist.
pub(crate) fn immutable_lower_store_path(path: &str) -> Result<std::path::PathBuf> {
    let store_path = Path::new(path);
    if store_path.parent() != Some(Path::new("/nix/store")) {
        bail!("image catalog contains non-canonical store path {path:?}");
    }
    let name = store_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("image catalog store path is not UTF-8")?;
    let Some((hash, output_name)) = name.split_once('-') else {
        bail!("image catalog store path has no output name: {path:?}");
    };
    if hash.len() != 32
        || output_name.is_empty()
        || !hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
    {
        bail!("image catalog contains malformed store path {path:?}");
    }
    Ok(Path::new("/nix.lower/store").join(name))
}

pub(crate) fn local_store_identity_at(identity: &str, read_path: &Path) -> Result<(String, u64)> {
    let dump = Command::new("nix-store")
        .arg("--dump")
        .arg(read_path)
        .output()
        .with_context(|| format!("dumping image-local store path {identity}"))?;
    if !dump.status.success() {
        bail!(
            "dumping image-local store path {identity} failed: {}",
            String::from_utf8_lossy(&dump.stderr).trim()
        );
    }
    let nar_size = u64::try_from(dump.stdout.len())
        .context("image-local NAR size does not fit in an unsigned 64-bit integer")?;
    let digest = crate::verify::sha256_stream(dump.stdout.as_slice())?;
    let nar_hash = crate::registry::store::NarBytes::from_hash(&digest, nar_size)?.nar_hash();
    Ok((nar_hash, nar_size))
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
