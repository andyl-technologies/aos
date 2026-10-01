//! Validates physically disjoint configured complete bucket namespaces.

use std::path::{Component, Path, PathBuf};

use terrane_core::properties::Domain;

use crate::store::{InvalidReason, LocalFs, StoreErrorKind, StoreFailure};

/// Supplies the thread-safety bound for domain filesystem operations.
#[cfg(feature = "send")]
pub trait DomainFsBinding: Sync {}

#[cfg(feature = "send")]
impl<T: Sync + ?Sized> DomainFsBinding for T {}

/// Supplies the local-only binding for domain filesystem operations.
#[cfg(not(feature = "send"))]
pub trait DomainFsBinding {}

#[cfg(not(feature = "send"))]
impl<T: ?Sized> DomainFsBinding for T {}

/// Configures one canonical domain's complete independent bucket root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainNamespace {
    /// Canonical disclosure-domain label.
    pub domain: String,
    /// Absolute normalized root containing the existing complete bucket layout.
    pub root: PathBuf,
}

/// Designates the configured private administrative namespace for a domain.
///
/// This is trusted operator configuration, rather than evidence supplied by a
/// repository request or inferred from a signed record's shape.
#[derive(Clone, Debug)]
pub struct DomainAuditRoute {
    /// Canonical target namespace label.
    pub target_domain: String,
    /// Canonical private administrative namespace label.
    pub audit_domain: String,
}

/// Pins one target namespace to its configured administrative authority.
///
/// Only validated namespace configuration constructs this proof. The native
/// factory must open the administrative repository from `audit()` and bind
/// that actual backend before trusting its signed routing state.
#[derive(Clone, Debug)]
pub struct ConfiguredDomainRoute {
    target: DomainNamespace,
    audit: DomainNamespace,
    control_ref: String,
}

impl ConfiguredDomainRoute {
    /// Returns the exact physical namespace governed by this route.
    #[must_use]
    pub fn target(&self) -> &DomainNamespace {
        &self.target
    }

    /// Returns the designated private administrative physical namespace.
    #[must_use]
    pub fn audit(&self) -> &DomainNamespace {
        &self.audit
    }

    /// Returns the deterministic authoritative head within that repository.
    #[must_use]
    pub fn control_ref(&self) -> &str {
        &self.control_ref
    }

    /// Checks an actually opened audit backend against its configured binding.
    ///
    /// The trusted repository factory supplies the backend's own physical root
    /// and domain, never request-provided names or paths.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` if either backend binding differs.
    #[cfg(any(test, feature = "std"))]
    pub(crate) fn check_audit_backend(
        &self,
        domain: &str,
        root: &Path,
    ) -> Result<(), StoreFailure> {
        if domain != self.audit.domain || root != self.audit.root {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Holds validated distinct domain roots without inventing bucket key prefixes.
pub struct DomainNamespaces {
    namespaces: Vec<DomainNamespace>,
    audit_routes: Vec<ConfiguredDomainRoute>,
}

impl DomainNamespaces {
    /// Iterates the validated independent namespace configurations.
    pub fn iter(&self) -> impl Iterator<Item = &DomainNamespace> {
        self.namespaces.iter()
    }

    /// Checks namespace labels and rejects identical or nested physical roots.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for duplicate labels, noncanonical paths,
    /// overlapping roots, or an unregistered domain label.
    pub fn new(namespaces: Vec<DomainNamespace>) -> Result<Self, StoreFailure> {
        for (index, namespace) in namespaces.iter().enumerate() {
            let normalized: PathBuf = namespace.root.components().collect();
            if Domain::parse(&namespace.domain).is_err()
                || !namespace.root.is_absolute()
                || normalized.as_os_str() != namespace.root.as_os_str()
                || namespace
                    .root
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
                || namespace.root == Path::new("/")
                || namespaces[..index].iter().any(|other| {
                    other.domain == namespace.domain
                        || other.root.starts_with(&namespace.root)
                        || namespace.root.starts_with(&other.root)
                })
            {
                return Err(invalid());
            }
        }

        Ok(Self {
            namespaces,
            audit_routes: Vec::new(),
        })
    }

    /// Validates operator-configured associations to private audit namespaces.
    ///
    /// Missing associations never acquire an implicit administrative authority.
    /// Each target has at most one designated audit namespace, and all physical
    /// roots retain the independent namespace validation of [`Self::new`].
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for unknown or duplicate target labels,
    /// non-private audit domains, or invalid/overlapping namespace roots.
    pub fn with_audit_routes(
        namespaces: Vec<DomainNamespace>,
        routes: Vec<DomainAuditRoute>,
    ) -> Result<Self, StoreFailure> {
        let mut configured = Self::new(namespaces)?;
        for route in routes {
            let target = configured
                .namespaces
                .iter()
                .find(|namespace| namespace.domain == route.target_domain)
                .ok_or_else(invalid)?;
            let audit = configured
                .namespaces
                .iter()
                .find(|namespace| namespace.domain == route.audit_domain)
                .ok_or_else(invalid)?;
            if !matches!(Domain::parse(&audit.domain), Ok(Domain::Private(_)))
                || target.domain == audit.domain
                || configured
                    .audit_routes
                    .iter()
                    .any(|existing| existing.target.domain == target.domain)
            {
                return Err(invalid());
            }
            configured.audit_routes.push(ConfiguredDomainRoute {
                target: target.clone(),
                audit: audit.clone(),
                control_ref: super::control_ref_name(&target.domain)?,
            });
        }
        Ok(configured)
    }

    /// Returns only the explicitly configured authority for this target label.
    #[must_use]
    pub fn audit_route(&self, domain: Domain<'_>) -> Option<&ConfiguredDomainRoute> {
        let label = super::label(domain);
        self.audit_routes
            .iter()
            .find(|route| route.target.domain == label)
    }

    /// Returns the configured physical root for exactly one canonical domain.
    #[must_use]
    pub fn root(&self, domain: Domain<'_>) -> Option<&Path> {
        let label = super::label(domain);
        self.namespaces
            .iter()
            .find(|namespace| namespace.domain == label)
            .map(|namespace| namespace.root.as_path())
    }

    /// Prepares parents while leaving final bucket creation to its authority.
    ///
    /// Existing private roots must exclude group and other access. Insecure
    /// roots fail closed without implicit administrative permission changes.
    /// The final leaf is never created here: only the bucket's atomic creator
    /// can establish a complete initial ref inventory under BKT-17.
    ///
    /// Trusted operators must prevent concurrent mutation of ancestors and
    /// filesystem aliases such as bind mounts outside store-process authority.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for aliases, non-directory components, or an
    /// insecure private root. Returns `Unavailable` for filesystem failures.
    pub async fn prepare_paths<F: LocalFs + DomainFsBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        for namespace in &self.namespaces {
            check_components(fs, &namespace.root, true).await?;
            if matches!(Domain::parse(&namespace.domain), Ok(Domain::Private(_))) {
                match fs.symlink_metadata(&namespace.root).await {
                    Ok(metadata) => check_private_permissions(&metadata)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(io_failure(error)),
                }
            }

            let parent = namespace.root.parent().ok_or_else(invalid)?;
            fs.create_dir_all(parent).await.map_err(io_failure)?;
            check_components(fs, parent, false).await?;
        }

        Ok(())
    }

    /// Validates backend-owned leaves before routing private bytes.
    ///
    /// This check follows backend opening without creating or changing paths.
    /// New leaves must have been atomically created by their bucket authority;
    /// private leaves must already exclude group and other access.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for aliases, non-directory components, or an
    /// insecure private root. Returns `Unavailable` for missing paths or other
    /// filesystem failures, including unavailable private-permission checks.
    pub async fn verify_paths<F: LocalFs + DomainFsBinding>(
        &self,
        fs: &F,
    ) -> Result<(), StoreFailure> {
        for namespace in &self.namespaces {
            check_components(fs, &namespace.root, false).await?;
            if matches!(Domain::parse(&namespace.domain), Ok(Domain::Private(_))) {
                let metadata = fs
                    .symlink_metadata(&namespace.root)
                    .await
                    .map_err(io_failure)?;
                check_private_permissions(&metadata)?;
            }
        }

        Ok(())
    }
}

async fn check_components<F: LocalFs + DomainFsBinding>(
    fs: &F,
    root: &Path,
    allow_missing: bool,
) -> Result<(), StoreFailure> {
    let mut path = PathBuf::new();
    for component in root.components() {
        path.push(component.as_os_str());
        match fs.symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(invalid()),
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(io_failure(error)),
        }
    }

    Ok(())
}

fn check_private_permissions(metadata: &std::fs::Metadata) -> Result<(), StoreFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(private_permissions_unavailable())
    }
}

#[cfg(not(unix))]
fn private_permissions_unavailable() -> StoreFailure {
    io_failure(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private namespace permissions unavailable",
    ))
}

fn invalid() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {
        rule_id: "DOM-9",
    }))
}

fn io_failure(source: std::io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_audit_backend_matches_only_designated_namespace() -> Result<(), StoreFailure> {
        let namespaces = DomainNamespaces::with_audit_routes(
            vec![
                DomainNamespace {
                    domain: "tenant:data".into(),
                    root: "/tmp/domain-data".into(),
                },
                DomainNamespace {
                    domain: "private:audit".into(),
                    root: "/tmp/domain-audit".into(),
                },
            ],
            vec![DomainAuditRoute {
                target_domain: "tenant:data".into(),
                audit_domain: "private:audit".into(),
            }],
        )?;
        let route = namespaces
            .audit_route(Domain::Tenant("data"))
            .ok_or_else(invalid)?;

        assert_eq!(route.target().root, Path::new("/tmp/domain-data"));
        assert_eq!(route.audit().root, Path::new("/tmp/domain-audit"));
        route.check_audit_backend("private:audit", Path::new("/tmp/domain-audit"))?;

        // Source storage and an identically labelled unrelated backend do not
        // become administrative authority through matching record shapes.
        for (domain, root) in [
            ("tenant:data", "/tmp/domain-data"),
            ("private:audit", "/tmp/domain-data"),
            ("private:audit", "/tmp/unrelated-audit"),
            ("private:unrelated", "/tmp/domain-audit"),
        ] {
            assert!(route.check_audit_backend(domain, Path::new(root)).is_err());
        }

        Ok(())
    }
}
