//! Repository-name resolution for instance-owned OCI root routes.
//!
//! A request `/v2/<name>/...` on an instance route names its registry through
//! the leading path segments of `<name>`, the way `ghcr.io/<org>/<repo>` does.
//! Resolution is pure and deterministic:
//!
//! 1. the longest enabled registry slug that is a leading segment prefix of
//!    `<name>` wins, and the remaining segments are the repository within that
//!    registry;
//! 2. otherwise the route's default registry, when one is bound, serves the
//!    whole `<name>` as a repository of its own;
//! 3. otherwise the name is unknown.
//!
//! A name that could belong both to the default registry and to another
//! registry's namespace is reported as such by [`OciNamespaceCatalog::resolve`]
//! so the caller can check the default registry's catalog and fail closed on a
//! real collision instead of silently picking one.

use aos_oci_types::RepositoryName;

use aos_hub_db::db::OciNamespaceEntry;

/// Enabled namespaces and the default registry of one instance OCI route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciNamespaceCatalog {
    namespaces: Vec<OciNamespaceEntry>,
    default_registry_id: Option<i64>,
}

/// One resolved repository name on an instance OCI route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciNamespaceMatch {
    /// Registry that owns the repository.
    pub registry_id: i64,
    /// Registry slug carried on the wire, or `None` for the default registry.
    pub prefix: Option<String>,
    /// Repository name local to that registry.
    pub repository: RepositoryName,
    /// Whether the route's default registry could also own the full name.
    ///
    /// Set only for namespaced matches on a route with a different default
    /// registry. The caller must confirm the default registry has no repository
    /// of the full wire name before serving.
    pub shadows_default: bool,
}

/// Why a repository name resolves to no registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciNamespaceError {
    /// No enabled namespace prefix matched and the route has no default registry.
    Unknown,
    /// The name is exactly an enabled namespace and names no repository.
    MissingRepository,
}

impl OciNamespaceCatalog {
    /// Builds a catalog from enabled namespaces and an optional default registry.
    ///
    /// Namespaces are ordered longest slug first so a nested slug such as
    /// `acme/infra/prod` beats `acme/infra` for a name under both.
    #[must_use]
    pub fn new(mut namespaces: Vec<OciNamespaceEntry>, default_registry_id: Option<i64>) -> Self {
        namespaces.sort_by(|left, right| {
            right
                .slug
                .len()
                .cmp(&left.slug.len())
                .then_with(|| left.slug.cmp(&right.slug))
        });
        Self {
            namespaces,
            default_registry_id,
        }
    }

    /// Returns the default registry, when the route binds one.
    #[must_use]
    pub const fn default_registry_id(&self) -> Option<i64> {
        self.default_registry_id
    }

    /// Resolves one wire repository name to its registry and local repository.
    ///
    /// # Errors
    ///
    /// Returns [`OciNamespaceError::Unknown`] when nothing serves the name and
    /// [`OciNamespaceError::MissingRepository`] when the name is a bare slug.
    pub fn resolve(&self, name: &RepositoryName) -> Result<OciNamespaceMatch, OciNamespaceError> {
        let wire = name.as_str();
        for namespace in &self.namespaces {
            if wire == namespace.slug {
                return Err(OciNamespaceError::MissingRepository);
            }
            let Some(rest) = wire
                .strip_prefix(namespace.slug.as_str())
                .and_then(|rest| rest.strip_prefix('/'))
            else {
                continue;
            };
            // Every component was validated with the full name, so the
            // remainder parses unless the slug itself was malformed.
            let Ok(repository) = RepositoryName::parse(rest) else {
                return Err(OciNamespaceError::MissingRepository);
            };
            let shadows_default = self
                .default_registry_id
                .is_some_and(|default| default != namespace.registry_id);
            return Ok(OciNamespaceMatch {
                registry_id: namespace.registry_id,
                prefix: Some(namespace.slug.clone()),
                repository,
                shadows_default,
            });
        }
        match self.default_registry_id {
            Some(registry_id) => Ok(OciNamespaceMatch {
                registry_id,
                prefix: None,
                repository: name.clone(),
                shadows_default: false,
            }),
            None => Err(OciNamespaceError::Unknown),
        }
    }
}

/// Joins a namespace prefix and a registry-local repository into the wire name.
///
/// # Errors
///
/// Returns an error when the joined name violates the repository grammar.
pub fn wire_repository(
    prefix: Option<&str>,
    repository: &RepositoryName,
) -> Result<RepositoryName, aos_oci_types::Error> {
    match prefix {
        Some(prefix) => RepositoryName::parse(&format!("{prefix}/{}", repository.as_str())),
        None => Ok(repository.clone()),
    }
}

/// Strips a namespace prefix from a wire repository name.
///
/// Returns `None` when the name does not carry the prefix or names no
/// repository beneath it.
#[must_use]
pub fn local_repository(prefix: &str, wire: &RepositoryName) -> Option<RepositoryName> {
    wire.as_str()
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| RepositoryName::parse(rest).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(registry_id: i64, slug: &str) -> OciNamespaceEntry {
        OciNamespaceEntry {
            registry_id,
            slug: slug.to_string(),
        }
    }

    fn name(value: &str) -> RepositoryName {
        RepositoryName::parse(value).unwrap()
    }

    #[test]
    fn longest_enabled_prefix_wins() {
        let catalog = OciNamespaceCatalog::new(
            vec![entry(1, "andyl"), entry(2, "andyl/experimental")],
            None,
        );
        let resolved = catalog.resolve(&name("andyl/experimental/aos")).unwrap();
        assert_eq!(resolved.registry_id, 2);
        assert_eq!(resolved.prefix.as_deref(), Some("andyl/experimental"));
        assert_eq!(resolved.repository, name("aos"));
        assert!(!resolved.shadows_default);

        let shorter = catalog.resolve(&name("andyl/tools/aos")).unwrap();
        assert_eq!(shorter.registry_id, 1);
        assert_eq!(shorter.repository, name("tools/aos"));
    }

    #[test]
    fn segment_boundaries_are_respected() {
        let catalog = OciNamespaceCatalog::new(vec![entry(1, "andyl/exp")], None);
        assert_eq!(
            catalog.resolve(&name("andyl/experimental/aos")),
            Err(OciNamespaceError::Unknown)
        );
        assert_eq!(
            catalog.resolve(&name("andyl/exp")),
            Err(OciNamespaceError::MissingRepository)
        );
    }

    #[test]
    fn default_registry_serves_unprefixed_names_and_flags_shadowing() {
        let catalog = OciNamespaceCatalog::new(vec![entry(2, "andyl/experimental")], Some(7));
        let plain = catalog.resolve(&name("aos")).unwrap();
        assert_eq!(plain.registry_id, 7);
        assert_eq!(plain.prefix, None);
        assert_eq!(plain.repository, name("aos"));
        assert!(!plain.shadows_default);

        let namespaced = catalog.resolve(&name("andyl/experimental/aos")).unwrap();
        assert_eq!(namespaced.registry_id, 2);
        assert!(namespaced.shadows_default);

        // A namespace whose registry is also the default never shadows itself.
        let same = OciNamespaceCatalog::new(vec![entry(2, "andyl/experimental")], Some(2));
        assert!(
            !same
                .resolve(&name("andyl/experimental/aos"))
                .unwrap()
                .shadows_default
        );
    }

    #[test]
    fn disabled_namespaces_are_absent_from_the_catalog() {
        let catalog = OciNamespaceCatalog::new(Vec::new(), None);
        assert_eq!(
            catalog.resolve(&name("andyl/experimental/aos")),
            Err(OciNamespaceError::Unknown)
        );
    }

    #[test]
    fn wire_and_local_names_round_trip() {
        let wire = wire_repository(Some("andyl/experimental"), &name("aos")).unwrap();
        assert_eq!(wire, name("andyl/experimental/aos"));
        assert_eq!(
            local_repository("andyl/experimental", &wire),
            Some(name("aos"))
        );
        assert_eq!(
            local_repository("andyl/experimental", &name("andyl/experimental")),
            None
        );
        assert_eq!(local_repository("other", &wire), None);
        assert_eq!(wire_repository(None, &name("aos")).unwrap(), name("aos"));
    }
}
