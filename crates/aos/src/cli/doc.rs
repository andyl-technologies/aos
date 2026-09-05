//! Resolves repository, installed-package, and explicit Hub documentation modes.

use anyhow::{Context, Result, ensure};
use aos_package::DocumentationCommand;

use super::Commands;

/// The source selected by the first documentation positional argument.
enum Source {
    Repository,
    Installed,
    Hub,
}

impl Commands {
    /// Validates documentation selectors before repository or network access.
    ///
    /// Returns a package-manager command for installed or Hub documentation,
    /// and `None` for repository documentation or another command.
    ///
    /// # Errors
    ///
    /// Returns an error for missing selectors, conflicting modes, or invalid
    /// Hub origins and registry paths.
    pub(crate) fn documentation_command(&self) -> Result<Option<DocumentationCommand>> {
        let Self::Doc {
            source,
            path,
            search,
            list,
            rebuild,
            system,
            hub,
            registry,
            token,
            version,
            platform,
        } = self
        else {
            return Ok(None);
        };
        let source = match source.as_deref() {
            Some("package") => Source::Installed,
            Some("hub") => Source::Hub,
            _ => Source::Repository,
        };
        if !matches!(source, Source::Hub) {
            ensure!(
                hub.is_none() && registry.is_none() && token.is_none(),
                "--hub, --registry, and --token require `aos doc hub QUERY`"
            );
        }
        if matches!(source, Source::Repository) {
            ensure!(
                !system && version.is_none() && platform.is_none(),
                "--system, --version, and --platform require `aos doc package NAME`"
            );
            return Ok(None);
        }
        ensure!(
            list.is_none() && !rebuild,
            "--list and --rebuild apply only to repository documentation"
        );
        ensure!(
            path.is_none() || search.is_none(),
            "supply a positional package/query or --search, not both"
        );

        let (hub, registry, token) = if matches!(source, Source::Hub) {
            ensure!(
                !system,
                "--system applies only to installed package documentation"
            );
            let origin = hub
                .clone()
                .or_else(|| std::env::var("AOS_HUB").ok())
                .context("aos doc hub requires --hub URL (or AOS_HUB) and --registry SLUG")?;
            let url = url::Url::parse(&origin)
                .map_err(|_| anyhow::anyhow!("--hub must be a valid HTTP(S) origin"))?;
            ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/",
                "--hub must be an HTTP(S) origin without credentials, path, query, or fragment"
            );
            let registry = registry
                .clone()
                .context("aos doc hub requires --registry SLUG")?;
            ensure!(
                registry.split('/').count() >= 2
                    && registry.split('/').all(|part| !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part.bytes().all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'_' | b'.'))),
                "--registry must be an organization/registry slug (nested project paths are allowed)"
            );
            (
                Some(origin),
                Some(registry),
                token.clone().or_else(|| std::env::var("AOS_TOKEN").ok()),
            )
        } else {
            (None, None, None)
        };
        if matches!(source, Source::Hub) || search.is_some() {
            ensure!(
                version.is_none() && platform.is_none(),
                "--version and --platform select an installed package document; searches do not accept them"
            );
            let query = search
                .clone()
                .or_else(|| path.clone())
                .context("aos doc hub requires a search query")?;
            ensure!(
                !query.trim().is_empty(),
                "documentation search requires a nonempty query"
            );
            Ok(Some(DocumentationCommand::Search {
                query,
                kind: None,
                limit: 25,
                hub,
                registry,
                token,
                system: *system,
            }))
        } else {
            let package = path
                .clone()
                .context("aos doc package requires a package name")?;
            ensure!(
                !package.trim().is_empty(),
                "aos doc package requires a package name"
            );
            Ok(Some(DocumentationCommand::Show {
                package,
                version: version.clone(),
                platform: platform.clone(),
                format: None,
                output: None,
                hub,
                registry,
                token,
                system: *system,
            }))
        }
    }
}
