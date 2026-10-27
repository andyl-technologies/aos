//! Rejects unsupported whole configurations before kernel or filesystem effects.

use std::{collections::BTreeSet, os::unix::ffi::OsStrExt, path::Path};

use terrane_sdk::{
    config::Config,
    repository::LocalRepositoryLocation,
    role::Role,
    surface::{EndpointKind, ReaderMode, registration},
};

use super::{Error, FailureKind, ValidatedSdk, tokens};

/// Validates the entire narrow SDK composition without opening any resource.
///
/// Routed and remote compositions are unavailable here. A native cache must
/// bind the trusted repository domain and remain disjoint from original state.
/// Object policy selects actual native chunked reads or sealed publication.
/// Public trust and a separate startup Read require explicit native file locators.
/// Non-file credential providers are refused before any native effect. The
/// returned plan still has no repository authority or kernel receipt.
///
/// # Errors
/// Rejects role mismatch, missing trust, unavailable backends or surfaces,
/// unsupported credential providers, and overlapping or invalid native paths.
pub fn preflight(config: &Config, selected_role: Role) -> Result<ValidatedSdk<'_>, Error> {
    let role = config
        .select_role(Some(selected_role))
        .map_err(Error::role)?;
    if role != Role::Serve {
        return Err(Error::refused(FailureKind::ServeOnly));
    }
    let expression = config.store();
    if expression.name() != "bucket" || !expression.children().is_empty() {
        return Err(Error::refused(FailureKind::UnsupportedStore));
    }
    let [url] = expression.arguments() else {
        return Err(Error::refused(FailureKind::UnsupportedStore));
    };
    if !url.starts_with("file:///") {
        return Err(Error::refused(FailureKind::UnsupportedStore));
    }
    let trusted = config
        .local_repository()
        .ok_or_else(|| Error::refused(FailureKind::MissingLocalTrust))?;
    let location =
        LocalRepositoryLocation::from_file_url(url, trusted.authority_directory.clone().into())
            .map_err(|_| Error::refused(FailureKind::InvalidPath))?;
    if !canonical_path(&location.bucket)
        || !canonical_path(&location.authority)
        || overlaps(&location.bucket, &location.authority)
    {
        return Err(Error::refused(FailureKind::InvalidPath));
    }
    let cache = if let Some(host) = config.host_tier() {
        if !host.domains.contains_key(&trusted.domain) {
            return Err(Error::refused(FailureKind::NativeCacheConfiguration));
        }
        for directory in host.domains.values() {
            for path in std::iter::once(directory.path.as_str())
                .chain(directory.administrative_root.as_deref())
            {
                let path = Path::new(path);
                if !canonical_path(path)
                    || overlaps(path, &location.bucket)
                    || overlaps(path, &location.authority)
                {
                    return Err(Error::refused(FailureKind::NativeCacheConfiguration));
                }
            }
        }
        let lower = host
            .domains
            .get(&trusted.domain)
            .and_then(|domain| domain.cache.as_ref())
            .and_then(|cache| cache.lower)
            .ok_or_else(|| Error::refused(FailureKind::NativeCacheConfiguration))?;
        let policy = crate::host_cache::NativeReadPolicy::new(
            std::time::Duration::from_millis(lower.budget_ms),
            lower.failure_threshold,
            std::time::Duration::from_millis(lower.probe_interval_ms),
        )
        .map_err(|_| Error::refused(FailureKind::NativeCacheConfiguration))?;
        let locality = config.locality();
        Some((
            crate::configured::NativeCachePlan::from_host(
                host,
                terrane_format::refs::Locality {
                    region: (!locality.region.is_empty()).then(|| locality.region.clone()),
                    zone: (!locality.zone.is_empty()).then(|| locality.zone.clone()),
                    host: (!locality.host.is_empty()).then(|| locality.host.clone()),
                },
            )
            .map_err(|error| Error::io(FailureKind::NativeCacheConfiguration, error))?,
            policy,
            match host.reassembly {
                terrane_sdk::config::host::Reassembly::Never => {
                    terrane_sdk::host::cache::ReassemblyMode::Never
                }
                terrane_sdk::config::host::Reassembly::Always => {
                    terrane_sdk::host::cache::ReassemblyMode::Always
                }
            },
        ))
    } else {
        None
    };

    #[cfg(not(feature = "surface-fuse"))]
    if config
        .host_tier()
        .is_some_and(|host| host.maintenance.is_some())
    {
        return Err(Error::refused(FailureKind::NativeCacheConfiguration));
    }
    #[cfg(feature = "surface-fuse")]
    let maintenance = config
        .host_tier()
        .map(crate::configured_maintenance::Plan::from_host)
        .transpose()
        .map_err(|error| Error::io(FailureKind::NativeCacheConfiguration, error))?
        .flatten();
    let maintenance_paths = config
        .host_tier()
        .and_then(|host| host.maintenance.as_ref())
        .into_iter()
        .flat_map(|settings| settings.sockets.values())
        .map(Path::new)
        .collect::<Vec<_>>();
    if maintenance_paths
        .iter()
        .any(|path| overlaps(path, &location.bucket) || overlaps(path, &location.authority))
    {
        return Err(Error::refused(FailureKind::NativeCacheConfiguration));
    }

    let tokens = config.tokens();
    let Some(startup_token) = tokens.host_token.as_deref() else {
        return Err(Error::refused(FailureKind::InstanceCredentialsUnavailable));
    };
    if tokens.issuer_public_keys.is_empty() || tokens.issuer_public_keys.len() > 256 {
        return Err(Error::refused(FailureKind::InstanceCredentialsUnavailable));
    }
    let mut credential_paths = vec![
        tokens::credential_path(startup_token)
            .map_err(|_| Error::refused(FailureKind::UnsupportedCredentialReference))?,
    ];
    for locator in &tokens.issuer_public_keys {
        credential_paths.push(
            tokens::credential_path(locator)
                .map_err(|_| Error::refused(FailureKind::UnsupportedCredentialReference))?,
        );
    }
    for exposure in config.exposures() {
        credential_paths.push(
            tokens::credential_path(&exposure.token)
                .map_err(|_| Error::refused(FailureKind::UnsupportedCredentialReference))?,
        );
    }
    if config.exposures().is_empty() {
        return Err(Error::refused(FailureKind::EmptyExposures));
    }
    if registration("sdk").is_none() {
        return Err(Error::refused(FailureKind::UnavailableSurface));
    }

    let mut endpoints: Vec<&Path> = Vec::new();
    let mut identifiers = BTreeSet::new();
    for exposure in config.exposures() {
        if exposure.id.is_empty() || exposure.surface != "sdk" || !identifiers.insert(&exposure.id)
        {
            return Err(Error::refused(FailureKind::UnavailableSurface));
        }
        if exposure.reader != ReaderMode::Pinned
            || exposure.writer.is_some()
            || exposure.endpoint.kind != EndpointKind::Directory
            || !exposure.options.is_empty()
        {
            return Err(Error::refused(FailureKind::UnsupportedPresentation));
        }
        let endpoint = Path::new(&exposure.endpoint.address);
        if !canonical_path(endpoint) {
            return Err(Error::refused(FailureKind::InvalidPath));
        }
        if overlaps(endpoint, &location.bucket)
            || overlaps(endpoint, &location.authority)
            || credential_paths.iter().any(|path| overlaps(endpoint, path))
            || endpoints.iter().any(|other| overlaps(endpoint, other))
            || maintenance_paths
                .iter()
                .any(|path| overlaps(endpoint, path))
            || config.host_tier().is_some_and(|host| {
                host.domains.values().any(|directory| {
                    std::iter::once(directory.path.as_str())
                        .chain(directory.administrative_root.as_deref())
                        .any(|path| overlaps(endpoint, Path::new(path)))
                })
            })
        {
            return Err(Error::refused(FailureKind::OverlappingEndpoint));
        }
        endpoints.push(endpoint);
    }
    Ok(ValidatedSdk {
        config,
        startup_token,
        cache,
        #[cfg(feature = "surface-fuse")]
        maintenance,
    })
}

pub(super) fn canonical_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    bytes.starts_with(b"/")
        && !bytes.contains(&0)
        && bytes
            .split(|byte| *byte == b'/')
            .skip(1)
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
