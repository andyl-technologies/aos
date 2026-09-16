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

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::registry::{RegistrySet, store_path_hash};
use crate::types::PackageContractMeta;
use aos_ability_model::{ArtifactReference, LocalKey};

use super::store_view::StoreViewLocator;

/// Identifies the authority that supplied one exact package contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ContractOrigin {
    /// Resolves a package through its signed registry publication metadata.
    Registry {
        /// Carries the exact signed publication and artifact retention record.
        metadata: PackageContractMeta,
    },
    /// Resolves a package through the running image's authenticated static contract.
    EmbeddedStatic {
        /// Identifies the exact static-contract artifact retained by the image.
        contract: ArtifactReference,
        /// Selects one package entry from that checked static contract.
        package: LocalKey,
    },
}

/// An exact image-bundled package available from the active system profile.
#[derive(Debug, Clone)]
pub struct LocalRuntimePackage {
    /// Package version recorded by the image seed.
    pub version: String,
    /// Exact target platform retained by the checked static contract.
    pub platform: String,
    /// Exact runtime output in the immutable image closure.
    pub store_path: String,
    /// Authenticated NAR identity of the runtime output.
    pub nar_hash: String,
    /// Authenticated package contract retained in the image.
    pub contract: Option<ContractOrigin>,
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
    /// Exact selected runtime output NAR identity.
    pub nar_hash: String,
    /// Exact selected runtime output uncompressed NAR size.
    pub nar_size: u64,
    /// Complete authenticated closure, keyed by input-addressed store hash.
    pub closure: Vec<RuntimeClosurePin>,
    /// Exact authenticated package contract selected with this package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ContractOrigin>,
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
/// Registries without a published `store/` graph are refused: their narinfo
/// fallback cannot pin and
/// authenticate every anonymous closure member, so it is insufficient for a
/// transactional configuration generation.
///
/// # Errors
///
/// Returns an error when a package cannot be resolved, a package-level
/// dependency cycle exists, the selected registry has no `store/` graph, a
/// graph member has no blessed NAR, or root metadata disagrees with the graph.
pub fn resolve_runtime(registries: &RegistrySet, selected: &[String]) -> Result<RuntimeResolution> {
    resolve_runtime_inner(registries, &BTreeMap::new(), selected, None)
}

/// Resolves packages with registry priority and measured-image fallback.
///
/// A local package is considered when no configured registry publishes its
/// name or when an absent registry prevents a safe priority decision. Only the
/// caller's authenticated image catalog is eligible for that fallback. An
/// absent higher-priority registry never permits a loaded lower-priority
/// registry to win.
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
    store_view: &StoreViewLocator,
) -> Result<RuntimeResolution> {
    resolve_runtime_inner(registries, local, selected, Some(store_view))
}

fn resolve_runtime_inner(
    registries: &RegistrySet,
    local: &BTreeMap<String, LocalRuntimePackage>,
    selected: &[String],
    store_view: Option<&StoreViewLocator>,
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
        match registries.resolve_for_config_evaluation(&name) {
            Ok(Some(_)) => {
                let closure = crate::resolve::resolve_closure(registries, &name, None)
                    .with_context(|| format!("resolving package '{name}'"))?;
                closures.push(closure);
            }
            Ok(None) | Err(_) if local.contains_key(&name) => {
                local_names.insert(name);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("resolving package '{name}'"));
            }
            Ok(None) => {
                return Err(aos_core::error::AosError::PackageNotFound { name }.into());
            }
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
        let root_hash = store_path_hash(&closure.root.store_path);
        let mut member_hashes = store.reachable(root_hash);
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
            let store_path = registries
                .resolve_hash_in(&closure.registry_name, &member_hash)
                .map(|meta| meta.store_path.clone());
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
        let mut dependencies = BTreeSet::new();
        for hash in store.direct_deps(root_hash) {
            if let Some(package) = selected_roots.get(&hash)
                && package != &closure.root.name
            {
                dependencies.insert(package.clone());
            }
        }
        edges.insert(
            closure.root.name.clone(),
            dependencies.into_iter().collect(),
        );
        packages.insert(
            closure.root.name.clone(),
            RuntimePackagePin {
                version: closure.root.version.clone(),
                platform: closure.root.platform.clone(),
                registry: closure.registry_name.clone(),
                origin: RuntimePackageOrigin::Registry,
                store_path: closure.root.store_path.clone(),
                nar_hash: crate::registry::store::NarBytes::from_hash(
                    &closure.root.nar_hash,
                    closure.root.nar_size,
                )?
                .nar_hash(),
                nar_size: closure.root.nar_size,
                closure: members,
                contract: closure
                    .root
                    .contract
                    .clone()
                    .map(|metadata| ContractOrigin::Registry { metadata }),
            },
        );
    }

    for name in local_names {
        let package = local
            .get(&name)
            .with_context(|| format!("image-local package '{name}' disappeared"))?;
        let store_view =
            store_view.context("image-local package resolution has no selected store view")?;
        let closure = local_closure(package, store_view)
            .with_context(|| format!("validating image-local closure for '{name}'"))?;
        edges.insert(name.clone(), Vec::new());
        let root_hash = store_path_hash(&package.store_path);
        let root_realization = closure
            .iter()
            .find(|member| member.store_path_hash == root_hash)
            .and_then(|member| member.realisations.first())
            .context("image-local closure omitted its runtime output NAR identity")?;
        ensure!(
            package.nar_hash == root_realization.nar_hash,
            "image-local runtime output differs from its authenticated static contract"
        );
        packages.insert(
            name,
            RuntimePackagePin {
                version: package.version.clone(),
                platform: package.platform.clone(),
                registry: "image".to_string(),
                origin: RuntimePackageOrigin::Image,
                store_path: package.store_path.clone(),
                nar_hash: root_realization.nar_hash.clone(),
                nar_size: root_realization.nar_size,
                closure,
                contract: package.contract.clone(),
            },
        );
    }

    Ok(RuntimeResolution { packages, edges })
}

fn local_closure(
    package: &LocalRuntimePackage,
    store_view: &StoreViewLocator,
) -> Result<Vec<RuntimeClosurePin>> {
    if let Some(cached) = package.closure.borrow().as_ref() {
        return Ok(cached.clone());
    }
    let roots = [package.store_path.as_str()];
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
        let lower_path = store_view.read_path(Path::new(path))?;
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
        FIX_NAR, curl_store_record, make_registry, make_registry_with_store, registry_config,
        zlib_store_record,
    };
    use tempfile::TempDir;

    #[test]
    fn runtime_package_pin_requires_exact_nar_identity_fields() {
        let complete = serde_json::json!({
            "version": "1.0.0",
            "platform": "x86_64-linux",
            "registry": "test",
            "store_path": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example",
            "nar_hash": format!("sha256:{}", "0".repeat(52)),
            "nar_size": 1,
            "closure": [],
        });

        for field in ["nar_hash", "nar_size"] {
            let mut incomplete = complete.clone();
            incomplete
                .as_object_mut()
                .expect("runtime pin fixture must be an object")
                .remove(field);

            let error = serde_json::from_value::<RuntimePackagePin>(incomplete)
                .expect_err("runtime NAR identity fields must be present");
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{field}`"))
            );
        }
    }

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

    #[test]
    fn absent_registry_uses_only_an_authenticated_image_fallback() {
        let temp = TempDir::new().unwrap();
        let missing = registry_config("andyl", 500);
        let registries =
            RegistrySet::load_for_config_evaluation(temp.path(), &[&missing], "x86_64-linux")
                .unwrap();
        let store_path = "/nix/store/00000000000000000000000000000000-image-web";
        let mut image_packages = BTreeMap::new();
        image_packages.insert(
            "image-web".to_string(),
            LocalRuntimePackage {
                version: "1.2.3".to_string(),
                platform: "x86_64-linux".to_string(),
                store_path: store_path.to_string(),
                nar_hash: format!("sha256:{FIX_NAR}"),
                contract: None,
                closure: RefCell::new(Some(vec![RuntimeClosurePin {
                    store_path_hash: store_path_hash(store_path).to_string(),
                    store_path: Some(store_path.to_string()),
                    realisations: vec![RuntimeRealisationPin {
                        nar_hash: format!("sha256:{FIX_NAR}"),
                        nar_size: 64,
                    }],
                }])),
            },
        );

        let store_view = StoreViewLocator::new(
            "/nix/store".into(),
            "/immutable/store".into(),
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json".into(),
        )
        .unwrap();
        let resolution = resolve_runtime_with_local(
            &registries,
            &image_packages,
            &["image-web".to_string()],
            &store_view,
        )
        .unwrap();
        let selected = &resolution.packages["image-web"];

        assert_eq!(selected.origin, RuntimePackageOrigin::Image);
        assert_eq!(selected.registry, "image");
        assert_eq!(selected.version, "1.2.3");
        assert_eq!(selected.store_path, store_path);
    }

    #[test]
    fn absent_higher_registry_blocks_a_loaded_lower_runtime_package() {
        let temp = TempDir::new().unwrap();
        let missing = registry_config("primary", 600);
        let lower = registry_config("fallback", 500);
        let _ = make_registry(&temp, &lower.name, lower.priority, &[("curl", CURL_TOML)]);
        let registries = RegistrySet::load_for_config_evaluation(
            temp.path(),
            &[&missing, &lower],
            "x86_64-linux",
        )
        .unwrap();

        let error = resolve_runtime(&registries, &["curl".to_string()]).unwrap_err();

        assert!(
            format!("{error:#}").contains("configured registry 'primary' is unavailable"),
            "{error:#}"
        );
    }
}
