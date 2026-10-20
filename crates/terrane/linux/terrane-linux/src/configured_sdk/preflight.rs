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
/// Host-tier, routed and remote compositions are unavailable here. Instance
/// credentials and non-file exposure providers are not silently ignored. The
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
    if config.host_tier().is_some() {
        return Err(Error::refused(FailureKind::HostTierUnavailable));
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
    if config.tokens().host_token.is_some() || !config.tokens().issuer_public_keys.is_empty() {
        return Err(Error::refused(FailureKind::InstanceCredentialsUnavailable));
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
            || endpoints.iter().any(|other| overlaps(endpoint, other))
        {
            return Err(Error::refused(FailureKind::OverlappingEndpoint));
        }
        tokens::credential_path(&exposure.token)
            .map_err(|_| Error::refused(FailureKind::UnsupportedCredentialReference))?;
        endpoints.push(endpoint);
    }
    Ok(ValidatedSdk { config })
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
