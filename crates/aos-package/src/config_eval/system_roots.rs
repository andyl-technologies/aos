//! Locally derived shared-root ownership and capability map.
//!
//! Package providers were previously discovered from a registry-published
//! inverted index. That index is gone. Ownership of a
//! *shared* root (`firewall.*`, `nginx.*`) is not a
//! registry-wide fact — it is an attribute of one **system**: two hosts with
//! different installed sets can legitimately assign the same root to different
//! packages. [`SystemRoots`] is that per-system model, built **locally at
//! resolve time** from the installed set's [`ConfigModuleMeta`], never fetched.
//!
//! Two kinds of root are distinguished by the resolver:
//!
//! - **Private roots** (`{pkg}.*`) are structural: the root segment *is* the
//!   package name, so they need no map — resolution is a registry by-name
//!   lookup (see [`ConfigModuleResolver`]).
//! - **Shared roots** are owned. [`SystemRoots`] maps each shared root to its
//!   single owning package ([`RootOwner`]) and each capability token to the
//!   installed packages that set it ([`CapabilitySetter`]).
//!
//! ```text
//! SystemRoots {
//!   roots: {
//!     "firewall" -> RootOwner { package: "firewall", version: "1.4.0",
//!                               interface_abi: 1, contributable: ["allowedTCPPorts"],
//!                               module_abi_compat: [1,2], config_output: "/nix/store/…" },
//!     "nginx"    -> RootOwner { … },
//!   },
//!   capabilities: {
//!     "system.capabilities.dns-resolver" -> [ CapabilitySetter { package: "unbound", version: "1.21.0" } ],
//!   },
//! }
//! ```
//!
//! # Invariants enforced at build time
//!
//! Building a [`SystemRoots`] is the authoritative place three per-system
//! invariants are checked (each a terminal, fail-closed error):
//!
//! 1. **Owned-root exclusivity** — at most one installed package may own a root.
//! 2. **Shadowing guard** — an owned root must not collide with a *different*
//!    installed package's name (else its private root would be silently
//!    shadowed, since [`SystemRoots`] is consulted before the structural
//!    fallback).
//! 3. **Contributable scope** — every `contributes` root must have an
//!    owner, and every contributed sub-path must lie within that owner's
//!    `contributable` set.

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{ConfigModuleMeta, ModuleAbiCompat, OwnedRoot};

/// A package configuration module resolved by name from registry metadata.
///
/// This is the local, per-package replacement for a lookup that used to hit the
/// registry-wide provides index: given a package name, the resolver returns its
/// `package@version` identity, target platform, and the borrowed
/// [`ConfigModuleMeta`] declaring its roots, capabilities, and ABI band. It is
/// the input the [`SystemRoots`] builder folds over and the shape the resolver's
/// structural (private-root) fallback returns.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedConfigModule<'a> {
    /// Package name.
    pub package: &'a str,
    /// Package version.
    pub version: &'a str,
    /// Target platform (e.g. `x86_64-linux`).
    pub platform: &'a str,
    /// Authenticated runtime output for this exact package version/platform.
    pub runtime_output: &'a str,
    /// The package's declared config-module interface.
    pub module: &'a ConfigModuleMeta,
}

/// Resolves a package configuration module by name.
///
/// The single seam the fixpoint uses in place of the removed provides index.
/// The production implementation wraps the on-host [`RegistrySet`] and reads
/// each package's `config_module` block from `registry.toml`
/// ([`PackageMeta`]); tests inject a fixture map. It is queried both to build
/// [`SystemRoots`] (the installed set's config modules) and by the resolver's
/// structural fallback for private `{pkg}.*` roots.
///
/// [`RegistrySet`]: crate::registry::RegistrySet
/// [`PackageMeta`]: crate::types::PackageMeta
pub trait ConfigModuleResolver {
    /// Returns `package`'s config module, or `None` when the registry knows no
    /// such package or the package ships no config module.
    fn config_module(&self, package: &str) -> Option<ResolvedConfigModule<'_>>;

    /// Returns an exact config module matching an authenticated installed or
    /// transaction pin.
    ///
    /// Implementations should avoid silently upgrading `package` when either
    /// pin is present. The default is suitable for fixtures and admits the
    /// by-name result only when all supplied identities match.
    fn config_module_exact(
        &self,
        package: &str,
        version: Option<&str>,
        runtime_output: Option<&str>,
    ) -> Option<ResolvedConfigModule<'_>> {
        let resolved = self.config_module(package)?;
        if version.is_some_and(|want| want != resolved.version)
            || runtime_output.is_some_and(|want| want != resolved.runtime_output)
        {
            return None;
        }
        Some(resolved)
    }

    /// Returns config modules for the exact current system-profile set.
    ///
    /// The default is empty because pure fixture resolvers have no profile.
    fn installed_config_modules(&self) -> Vec<ResolvedConfigModule<'_>> {
        Vec::new()
    }

    /// Returns roots authenticated as shared by the registry snapshot.
    ///
    /// This classification does not grant ownership. It only prevents the
    /// structural private-root fallback from fetching a same-named package
    /// when the local system has no owner.
    fn known_shared_roots(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }
}

/// Ownership record for one shared root within a single system.
///
/// Captured from the owning package's [`OwnedRoot`](crate::types::OwnedRoot)
/// plus the identity and ABI band of the installed config module that declared
/// it. `config_output` and `module_abi_compat` are pinned from the *installed*
/// owner (not re-queried from the registry at resolve time) so the fixpoint
/// fetches and ABI-gates exactly the config output the system owns, immune to a
/// newer version appearing in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOwner {
    /// Owning package name.
    pub package: String,
    /// Owning package version.
    pub version: String,
    /// Owning package target platform.
    pub platform: String,
    /// The root's independent interface ABI (from the owner's `OwnedRoot`).
    pub interface_abi: u32,
    /// The owner's base-lib ABI compatibility band, used to gate selection.
    pub module_abi_compat: ModuleAbiCompat,
    /// The owner's `config` output store path, fetched when the root is needed.
    pub config_output: String,
    /// Authenticated NAR hash of the config-only output.
    pub config_nar_hash: String,
    /// Authenticated uncompressed NAR size of the config-only output.
    pub config_nar_size: u64,
    /// Owner-declared contributable sub-paths (relative to the root) that
    /// non-owner packages may write into.
    pub contributable: Vec<String>,
}

/// One installed package that *sets* a capability token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySetter {
    /// The setter package name.
    pub package: String,
    /// The setter package version.
    pub version: String,
}

/// The per-system shared-root ownership and capability map (see module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemRoots {
    roots: BTreeMap<String, RootOwner>,
    capabilities: BTreeMap<String, Vec<CapabilitySetter>>,
    known_shared_roots: BTreeSet<String>,
    bundled_roots: BTreeSet<String>,
}

/// Why a `contributes` declaration is rejected while building [`SystemRoots`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributableError {
    /// The contributed root has no owner in the installed set.
    NoOwner,
    /// The contributed sub-path is outside the owner's `contributable` set.
    NotContributable,
    /// The contributor was published against a different owner interface ABI.
    InterfaceAbiMismatch {
        /// ABI recorded by the contribution.
        expected: u32,
        /// ABI exported by the installed owner.
        actual: u32,
    },
}

/// A terminal failure while building a [`SystemRoots`] from the installed set.
///
/// Every variant is a per-system integrity violation surfaced fail-closed: the
/// fixpoint maps it to a terminal error and emits no manifest, so the live
/// system stays on its prior generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemRootsError {
    /// Two installed packages own the same shared root (exclusivity violation).
    OwnedRootConflict {
        /// The contested shared root.
        root: String,
        /// The first owner, as `package@version`.
        owner_a: String,
        /// The second owner, as `package@version`.
        owner_b: String,
    },
    /// An owned root collides with a *different* installed package's name, which
    /// would silently shadow that package's private root.
    ShadowedRoot {
        /// The owned root that collides.
        root: String,
        /// The package that owns the root, as `package@version`.
        owner: String,
    },
    /// A `contributes` declaration is not permitted (missing owner or the
    /// sub-path is outside the owner's contributable set).
    Contributable {
        /// The contributing package, as `package@version`.
        contributor: String,
        /// The foreign root being contributed into.
        root: String,
        /// The offending sub-path (empty when the root has no owner at all).
        path: String,
        /// Why the contribution was rejected.
        reason: ContributableError,
    },
}

impl std::fmt::Display for SystemRootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemRootsError::OwnedRootConflict {
                root,
                owner_a,
                owner_b,
            } => write!(
                f,
                "root '{root}' is owned by both '{owner_a}' and '{owner_b}'; \
                 owned roots are exclusive per system"
            ),
            SystemRootsError::ShadowedRoot { root, owner } => write!(
                f,
                "owned root '{root}' (owned by '{owner}') collides with a different \
                 installed package named '{root}'; the package's private root would be shadowed"
            ),
            SystemRootsError::Contributable {
                contributor,
                root,
                path,
                reason: ContributableError::NoOwner,
            } => {
                let _ = path;
                write!(
                    f,
                    "package '{contributor}' contributes to root '{root}' but no installed \
                     package owns it"
                )
            }
            SystemRootsError::Contributable {
                contributor,
                root,
                path,
                reason: ContributableError::NotContributable,
            } => write!(
                f,
                "package '{contributor}' contributes '{root}.{path}' but '{path}' is not in \
                 the owner's contributable set"
            ),
            SystemRootsError::Contributable {
                contributor,
                root,
                path: _,
                reason: ContributableError::InterfaceAbiMismatch { expected, actual },
            } => write!(
                f,
                "package '{contributor}' contributes to root '{root}' against interface ABI \
                 {expected}, but the installed owner exports interface ABI {actual}; republish \
                 the contributor against the installed owner's interface"
            ),
        }
    }
}

impl std::error::Error for SystemRootsError {}

/// Formats a `package@version` identity for error messages.
fn ident(package: &str, version: &str) -> String {
    format!("{package}@{version}")
}

impl SystemRoots {
    /// Returns whether a concrete contribution lies within an owner-declared
    /// extension point.
    ///
    /// Contribution surfaces name option subtrees, not just individual
    /// leaves: opening `virtualHosts` authorizes `virtualHosts.example.enable`
    /// while still keeping sibling paths such as `enable` owner-only.
    fn contribution_is_within_surface(path: &str, allowed: &str) -> bool {
        let mut concrete = path.split('.');
        for segment in allowed.split('.') {
            let Some(actual) = concrete.next() else {
                return false;
            };
            if segment != "*" && segment != actual {
                return false;
            }
        }
        true
    }

    fn validate_contributions(
        &self,
        module: ResolvedConfigModule<'_>,
    ) -> Result<(), SystemRootsError> {
        for contribution in &module.module.contributes {
            let Some(owner) = self.roots.get(&contribution.root) else {
                return Err(SystemRootsError::Contributable {
                    contributor: ident(module.package, module.version),
                    root: contribution.root.clone(),
                    path: String::new(),
                    reason: ContributableError::NoOwner,
                });
            };
            if contribution.interface_abi != owner.interface_abi {
                return Err(SystemRootsError::Contributable {
                    contributor: ident(module.package, module.version),
                    root: contribution.root.clone(),
                    path: String::new(),
                    reason: ContributableError::InterfaceAbiMismatch {
                        expected: contribution.interface_abi,
                        actual: owner.interface_abi,
                    },
                });
            }
            for path in &contribution.paths {
                if !owner
                    .contributable
                    .iter()
                    .any(|allowed| Self::contribution_is_within_surface(path, allowed))
                {
                    return Err(SystemRootsError::Contributable {
                        contributor: ident(module.package, module.version),
                        root: contribution.root.clone(),
                        path: path.clone(),
                        reason: ContributableError::NotContributable,
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates one newly discovered module against the installed owners.
    ///
    /// # Errors
    ///
    /// Returns [`SystemRootsError::Contributable`] if the module claims a
    /// foreign root with no installed owner or a path outside the owner's
    /// authenticated contribution surface.
    pub fn validate_discovered_module(
        &self,
        module: ResolvedConfigModule<'_>,
    ) -> Result<(), SystemRootsError> {
        self.validate_contributions(module)
    }

    /// Builds the per-system root map by folding the installed set's config
    /// modules, enforcing the three build-time invariants (see module docs).
    ///
    /// `modules` is every installed package that ships a [`ConfigModuleMeta`] —
    /// the packages seeded from `desired.toml` (resolved by name through a
    /// [`ConfigModuleResolver`]) and any base-lib/image-bundled roots, which are
    /// simply config modules that own roots. A package with no config module
    /// contributes nothing and is omitted by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`SystemRootsError::OwnedRootConflict`] when two packages own the
    /// same root, [`SystemRootsError::ShadowedRoot`] when an owned root collides
    /// with a different installed package's name, and
    /// [`SystemRootsError::Contributable`] when a `contributes` root has no
    /// owner or a contributed sub-path is outside the owner's contributable set.
    pub fn build<'a>(
        modules: impl IntoIterator<Item = ResolvedConfigModule<'a>>,
    ) -> Result<Self, SystemRootsError> {
        Self::build_with_context(modules, std::iter::empty(), std::iter::empty())
    }

    /// Builds the root map with image-bundled owners and shared-root
    /// classifications supplied by the authenticated base library/registry.
    ///
    /// Bundled owners participate in exclusivity and contribution ABI/surface
    /// validation, but are already present in the image and are never fetched
    /// as packages by the option resolver.
    ///
    /// # Errors
    ///
    /// Returns the same integrity failures as [`Self::build`], including a
    /// conflict between a bundled root and a package-owned root.
    pub fn build_with_context<'a>(
        modules: impl IntoIterator<Item = ResolvedConfigModule<'a>>,
        bundled_roots: impl IntoIterator<Item = OwnedRoot>,
        known_shared_roots: impl IntoIterator<Item = String>,
    ) -> Result<Self, SystemRootsError> {
        let modules: Vec<ResolvedConfigModule<'a>> = modules.into_iter().collect();
        let installed_names: BTreeSet<&str> = modules.iter().map(|m| m.package).collect();

        let mut roots: BTreeMap<String, RootOwner> = BTreeMap::new();
        let mut capabilities: BTreeMap<String, Vec<CapabilitySetter>> = BTreeMap::new();
        let mut bundled = BTreeSet::new();

        for owned in bundled_roots {
            bundled.insert(owned.root.clone());
            roots.insert(
                owned.root.clone(),
                RootOwner {
                    package: "@base-lib".to_string(),
                    version: "image".to_string(),
                    platform: "image".to_string(),
                    interface_abi: owned.interface_abi,
                    module_abi_compat: ModuleAbiCompat {
                        min: 0,
                        max: u32::MAX,
                    },
                    config_output: String::new(),
                    config_nar_hash: String::new(),
                    config_nar_size: 0,
                    contributable: owned.contributable,
                },
            );
        }

        // Pass 1: register owned roots (exclusivity) and capability setters.
        for m in &modules {
            for owned in &m.module.owns_roots {
                if let Some(existing) = roots.get(&owned.root) {
                    if existing.package != m.package || existing.version != m.version {
                        return Err(SystemRootsError::OwnedRootConflict {
                            root: owned.root.clone(),
                            owner_a: ident(&existing.package, &existing.version),
                            owner_b: ident(m.package, m.version),
                        });
                    }
                    // The same `package@version` re-declaring the root is a
                    // no-op (idempotent), never a conflict.
                    continue;
                }
                roots.insert(
                    owned.root.clone(),
                    RootOwner {
                        package: m.package.to_string(),
                        version: m.version.to_string(),
                        platform: m.platform.to_string(),
                        interface_abi: owned.interface_abi,
                        module_abi_compat: m.module.module_abi_compat,
                        config_output: m.module.config_output.store_path.clone(),
                        config_nar_hash: m.module.config_output.nar_hash.clone(),
                        config_nar_size: m.module.config_output.nar_size,
                        contributable: owned.contributable.clone(),
                    },
                );
            }
            for token in &m.module.provides_capabilities {
                let setter = CapabilitySetter {
                    package: m.package.to_string(),
                    version: m.version.to_string(),
                };
                capabilities.entry(token.clone()).or_default().push(setter);
            }
        }

        // Pass 2: shadowing guard. An owned root that equals a *different*
        // installed package's name would be silently shadowed, because the
        // resolver consults SystemRoots before the structural (by-name)
        // fallback. An owner naming its own root after itself is fine.
        for (root, owner) in &roots {
            if owner.package != *root && installed_names.contains(root.as_str()) {
                return Err(SystemRootsError::ShadowedRoot {
                    root: root.clone(),
                    owner: ident(&owner.package, &owner.version),
                });
            }
        }

        // Pass 3: F3-B contributable check, authoritative at resolve time. Every
        // `contributes` root must have an owner, and every contributed sub-path
        // must lie within that owner's contributable set.
        let result = Self {
            known_shared_roots: known_shared_roots
                .into_iter()
                .chain(roots.keys().cloned())
                .collect(),
            roots,
            capabilities,
            bundled_roots: bundled,
        };
        for module in modules {
            result.validate_contributions(module)?;
        }
        Ok(result)
    }

    /// Returns the owner of shared `root`, or `None` when no installed package
    /// owns it (the resolver then falls back to a structural by-name lookup).
    pub fn owner(&self, root: &str) -> Option<&RootOwner> {
        self.roots.get(root)
    }

    /// Returns whether `root` is classified as shared, even when this system
    /// has no installed owner for it.
    ///
    /// The resolver treats such a root as terminal: shared-root ownership is a
    /// local installed-set fact and must never be synthesized by structurally
    /// fetching a same-named registry package.
    pub fn is_known_shared_root(&self, root: &str) -> bool {
        self.known_shared_roots.contains(root)
    }

    /// Returns whether `root` is owned by the image/base library rather than a
    /// fetchable package config module.
    pub fn is_bundled_root(&self, root: &str) -> bool {
        self.bundled_roots.contains(root)
    }

    /// Returns the installed packages that set capability `token`.
    ///
    /// An empty slice means no installed package sets the token; the resolver
    /// treats an unmet token as terminal (no auto-fetch, no registry
    /// suggestions).
    pub fn capability_setters(&self, token: &str) -> &[CapabilitySetter] {
        self.capabilities
            .get(token)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Returns the number of owned shared roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Returns whether the system owns no shared roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ConfigOutputMeta, OwnedRoot, RootContribution};

    fn module(
        declares: &[&str],
        owns: Vec<OwnedRoot>,
        contributes: Vec<RootContribution>,
        caps: &[&str],
        abi: ModuleAbiCompat,
    ) -> ConfigModuleMeta {
        ConfigModuleMeta {
            config_output: ConfigOutputMeta {
                store_path: "/nix/store/hash-config".to_string(),
                nar_hash: "sha256:x".to_string(),
                nar_size: 1,
                references: vec![],
            },
            evaluation_base_lib: None,
            module_abi_compat: abi,
            declares: declares.iter().map(|s| s.to_string()).collect(),
            declaration_schema: vec![],
            requires: vec![],
            owns_roots: owns,
            contributes,
            provides_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn owned(root: &str, contributable: &[&str]) -> OwnedRoot {
        OwnedRoot {
            root: root.to_string(),
            interface_abi: 1,
            contributable: contributable.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn contribution(root: &str, interface_abi: u32, paths: &[&str]) -> RootContribution {
        RootContribution {
            root: root.to_string(),
            interface_abi,
            paths: paths.iter().map(|path| (*path).to_string()).collect(),
        }
    }

    fn resolved<'a>(package: &'a str, module: &'a ConfigModuleMeta) -> ResolvedConfigModule<'a> {
        ResolvedConfigModule {
            package,
            version: "1.0.0",
            platform: "x86_64-linux",
            runtime_output: "/nix/store/hash-runtime",
            module,
        }
    }

    #[test]
    fn builds_owner_and_capability_maps() {
        let fw = module(
            &["firewall.enable"],
            vec![owned("firewall", &["allowedTCPPorts"])],
            vec![],
            &["system.capabilities.dns-resolver"],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let roots = SystemRoots::build([resolved("firewall", &fw)]).expect("builds");
        let owner = roots.owner("firewall").expect("owner");
        assert_eq!(owner.package, "firewall");
        assert_eq!(owner.contributable, vec!["allowedTCPPorts".to_string()]);
        assert_eq!(
            roots
                .capability_setters("system.capabilities.dns-resolver")
                .len(),
            1
        );
        assert!(roots.owner("nginx").is_none());
    }

    #[test]
    fn two_owners_of_one_root_conflict() {
        let a = module(
            &[],
            vec![owned("firewall", &[])],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let b = module(
            &[],
            vec![owned("firewall", &[])],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let err = SystemRoots::build([resolved("fw-a", &a), resolved("fw-b", &b)])
            .expect_err("exclusivity");
        assert!(
            matches!(&err, SystemRootsError::OwnedRootConflict { root, .. } if root == "firewall"),
            "{err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("fw-a@1.0.0"), "{msg}");
        assert!(msg.contains("fw-b@1.0.0"), "{msg}");
        assert!(msg.contains("owned roots are exclusive"), "{msg}");
    }

    #[test]
    fn owned_root_shadowing_a_package_name_is_rejected() {
        // `web-extras` owns root `nginx`, but a package literally named `nginx`
        // is also installed: its private root would be shadowed.
        let extras = module(
            &[],
            vec![owned("nginx", &[])],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let nginx = module(
            &["nginx.enable"],
            vec![],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let err = SystemRoots::build([resolved("web-extras", &extras), resolved("nginx", &nginx)])
            .expect_err("shadowing");
        assert!(
            matches!(&err, SystemRootsError::ShadowedRoot { root, .. } if root == "nginx"),
            "{err}"
        );
    }

    #[test]
    fn owner_naming_its_own_root_is_not_shadowing() {
        let nginx = module(
            &["nginx.enable"],
            vec![owned("nginx", &[])],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let roots = SystemRoots::build([resolved("nginx", &nginx)]).expect("self-owned root");
        assert_eq!(roots.owner("nginx").expect("owner").package, "nginx");
    }

    #[test]
    fn contribution_without_owner_is_rejected() {
        let contributor = module(
            &[],
            vec![],
            vec![RootContribution {
                root: "nginx".to_string(),
                interface_abi: 1,
                paths: vec!["virtualHosts".to_string()],
            }],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let err = SystemRoots::build([resolved("web", &contributor)]).expect_err("no owner");
        assert!(
            matches!(
                &err,
                SystemRootsError::Contributable {
                    reason: ContributableError::NoOwner,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn contribution_outside_contributable_set_is_rejected() {
        let owner = module(
            &[],
            vec![owned("nginx", &["virtualHosts"])],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let contributor = module(
            &[],
            vec![],
            vec![RootContribution {
                root: "nginx".to_string(),
                interface_abi: 1,
                paths: vec!["upstreams".to_string()],
            }],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let err = SystemRoots::build([resolved("nginx", &owner), resolved("web", &contributor)])
            .expect_err("not contributable");
        assert!(
            matches!(
                &err,
                SystemRootsError::Contributable { reason: ContributableError::NotContributable, path, .. }
                    if path == "upstreams"
            ),
            "{err}"
        );
    }

    #[test]
    fn valid_contribution_within_contributable_set_builds() {
        let owner = module(
            &[],
            vec![owned("nginx", &["virtualHosts"])],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let contributor = module(
            &[],
            vec![],
            vec![RootContribution {
                root: "nginx".to_string(),
                interface_abi: 1,
                paths: vec!["virtualHosts".to_string()],
            }],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let roots = SystemRoots::build([resolved("nginx", &owner), resolved("web", &contributor)])
            .expect("valid contribution");
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn contribution_interface_abi_must_exactly_match_owner() {
        let owner = module(
            &[],
            vec![OwnedRoot {
                root: "nginx".to_string(),
                interface_abi: 7,
                contributable: vec!["virtualHosts.*".to_string()],
            }],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let equal = module(
            &[],
            vec![],
            vec![contribution("nginx", 7, &["virtualHosts.example"])],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        SystemRoots::build([resolved("nginx", &owner), resolved("web", &equal)])
            .expect("equal ABI is admitted");

        let mismatch = module(
            &[],
            vec![],
            vec![contribution("nginx", 6, &["virtualHosts.example"])],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let error = SystemRoots::build([resolved("nginx", &owner), resolved("web", &mismatch)])
            .expect_err("mismatched ABI must be rejected");
        assert!(matches!(
            error,
            SystemRootsError::Contributable {
                reason: ContributableError::InterfaceAbiMismatch {
                    expected: 6,
                    actual: 7
                },
                ..
            }
        ));
    }

    #[test]
    fn owner_abi_upgrade_requires_contributor_republish() {
        let upgraded_owner = module(
            &[],
            vec![OwnedRoot {
                root: "nginx".to_string(),
                interface_abi: 2,
                contributable: vec!["virtualHosts.*".to_string()],
            }],
            vec![],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let old_contributor = module(
            &[],
            vec![],
            vec![contribution("nginx", 1, &["virtualHosts.example"])],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );

        let error = SystemRoots::build([
            resolved("nginx", &upgraded_owner),
            resolved("web", &old_contributor),
        ])
        .expect_err("owner ABI upgrades invalidate old contributions");
        assert!(error.to_string().contains("republish"), "{error}");
    }

    #[test]
    fn wildcard_surface_matches_whole_segments_and_subtrees() {
        assert!(SystemRoots::contribution_is_within_surface(
            "virtualHosts.example.locations.api.proxyPass",
            "virtualHosts.*.locations"
        ));
        assert!(!SystemRoots::contribution_is_within_surface(
            "virtualHosts.example.tls.enable",
            "virtualHosts.*.locations"
        ));
        assert!(!SystemRoots::contribution_is_within_surface(
            "virtualHostsExtra.example.locations",
            "virtualHosts.*.locations"
        ));
        assert!(!SystemRoots::contribution_is_within_surface(
            "virtualHosts.exampleExtra.locations",
            "virtualHosts.example.locations"
        ));
    }

    #[test]
    fn base_owned_root_authorizes_matching_package_contribution() {
        let contributor = module(
            &[],
            vec![],
            vec![contribution("networking", 3, &["interfaces.eth0.mtu"])],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let roots = SystemRoots::build_with_context(
            [resolved("net-tuning", &contributor)],
            [OwnedRoot {
                root: "networking".to_string(),
                interface_abi: 3,
                contributable: vec!["interfaces.*".to_string()],
            }],
            std::iter::empty(),
        )
        .expect("base-owned contribution is locally authorized");

        assert_eq!(
            roots.owner("networking").expect("base owner").package,
            "@base-lib"
        );
        assert!(roots.is_bundled_root("networking"));
    }

    #[test]
    fn known_shared_root_can_be_ownerless_without_becoming_private() {
        let roots = SystemRoots::build_with_context(
            std::iter::empty(),
            std::iter::empty(),
            ["firewall".to_string()],
        )
        .expect("classification alone is valid");

        assert!(roots.owner("firewall").is_none());
        assert!(roots.is_known_shared_root("firewall"));
    }
}
