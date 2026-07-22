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

use crate::types::{ConfigModuleMeta, ModuleAbiCompat};

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
}

/// Why a `contributes` declaration is rejected while building [`SystemRoots`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributableError {
    /// The contributed root has no owner in the installed set.
    NoOwner,
    /// The contributed sub-path is outside the owner's `contributable` set.
    NotContributable,
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
        }
    }
}

impl std::error::Error for SystemRootsError {}

/// Formats a `package@version` identity for error messages.
fn ident(package: &str, version: &str) -> String {
    format!("{package}@{version}")
}

impl SystemRoots {
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
        let modules: Vec<ResolvedConfigModule<'a>> = modules.into_iter().collect();
        let installed_names: BTreeSet<&str> = modules.iter().map(|m| m.package).collect();

        let mut roots: BTreeMap<String, RootOwner> = BTreeMap::new();
        let mut capabilities: BTreeMap<String, Vec<CapabilitySetter>> = BTreeMap::new();

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
        for m in &modules {
            for contribution in &m.module.contributes {
                let Some(owner) = roots.get(&contribution.root) else {
                    return Err(SystemRootsError::Contributable {
                        contributor: ident(m.package, m.version),
                        root: contribution.root.clone(),
                        path: String::new(),
                        reason: ContributableError::NoOwner,
                    });
                };
                for path in &contribution.paths {
                    if !owner.contributable.iter().any(|c| c == path) {
                        return Err(SystemRootsError::Contributable {
                            contributor: ident(m.package, m.version),
                            root: contribution.root.clone(),
                            path: path.clone(),
                            reason: ContributableError::NotContributable,
                        });
                    }
                }
            }
        }

        Ok(Self {
            roots,
            capabilities,
        })
    }

    /// Returns the owner of shared `root`, or `None` when no installed package
    /// owns it (the resolver then falls back to a structural by-name lookup).
    pub fn owner(&self, root: &str) -> Option<&RootOwner> {
        self.roots.get(root)
    }

    /// Returns the installed packages that set capability `token`.
    ///
    /// An empty slice means no installed package sets the token; the resolver
    /// treats an unmet token as terminal (no auto-fetch, no registry
    /// suggestions).
    pub fn capability_setters(&self, token: &str) -> &[CapabilitySetter] {
        self.capabilities.get(token).map(Vec::as_slice).unwrap_or(&[])
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
            module_abi_compat: abi,
            declares: declares.iter().map(|s| s.to_string()).collect(),
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

    fn resolved<'a>(package: &'a str, module: &'a ConfigModuleMeta) -> ResolvedConfigModule<'a> {
        ResolvedConfigModule {
            package,
            version: "1.0.0",
            platform: "x86_64-linux",
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
        assert_eq!(roots.capability_setters("system.capabilities.dns-resolver").len(), 1);
        assert!(roots.owner("nginx").is_none());
    }

    #[test]
    fn two_owners_of_one_root_conflict() {
        let a = module(&[], vec![owned("firewall", &[])], vec![], &[], ModuleAbiCompat { min: 1, max: 2 });
        let b = module(&[], vec![owned("firewall", &[])], vec![], &[], ModuleAbiCompat { min: 1, max: 2 });
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
        let extras = module(&[], vec![owned("nginx", &[])], vec![], &[], ModuleAbiCompat { min: 1, max: 2 });
        let nginx = module(&["nginx.enable"], vec![], vec![], &[], ModuleAbiCompat { min: 1, max: 2 });
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
                paths: vec!["virtualHosts".to_string()],
            }],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let err = SystemRoots::build([resolved("web", &contributor)]).expect_err("no owner");
        assert!(
            matches!(
                &err,
                SystemRootsError::Contributable { reason: ContributableError::NoOwner, .. }
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
                paths: vec!["virtualHosts".to_string()],
            }],
            &[],
            ModuleAbiCompat { min: 1, max: 2 },
        );
        let roots = SystemRoots::build([resolved("nginx", &owner), resolved("web", &contributor)])
            .expect("valid contribution");
        assert_eq!(roots.len(), 1);
    }
}
