//! Rejects unsupported complete collector compositions before native effects.

use std::path::{Component, Path};

use terrane_sdk::{config::Config, repository::LocalRepositoryLocation, role::Role};

use super::{Error, ValidatedCollector};

/// Validates local collector inputs without opening files or acquiring a lease.
///
/// Requires explicit scheduling, trusted repository timing and public issuer
/// files. Remote/composite stores, exposures, host tiers, instance tokens and
/// workload issuers are refused instead of being silently ignored. This narrow
/// component does not implement those separate runtimes.
///
/// # Errors
/// Rejects role mismatch, missing trust/settings/verification keys, unsupported
/// composition, overlapping or noncanonical paths and unsafe collection windows.
pub fn preflight(config: &Config, selected_role: Role) -> Result<ValidatedCollector<'_>, Error> {
    if config
        .select_role(Some(selected_role))
        .map_err(Error::Role)?
        != Role::Gc
    {
        return Err(Error::Refused("only the GC role can collect"));
    }
    if config.host_tier().is_some()
        || !config.exposures().is_empty()
        || config.tokens().host_token.is_some()
        || !config.static_workload_issuers().is_empty()
        || !config.gcp_instance_issuers().is_empty()
    {
        return Err(Error::Refused("unsupported local collector composition"));
    }
    let expression = config.store();
    let [url] = expression.arguments() else {
        return Err(Error::Refused("requires one local file bucket"));
    };
    if expression.name() != "bucket"
        || !expression.children().is_empty()
        || !url.starts_with("file:///")
    {
        return Err(Error::Refused("requires one local file bucket"));
    }
    let trusted = config
        .local_repository()
        .ok_or(Error::Refused("requires explicit trusted local repository"))?;
    let settings = config
        .gc()
        .ok_or(Error::Refused("requires explicit collector settings"))?;
    let windows = settings
        .windows(&trusted.timing)
        .map_err(Error::Configuration)?;
    let location =
        LocalRepositoryLocation::from_file_url(url, trusted.authority_directory.clone().into())
            .map_err(|_| Error::Refused("invalid collector repository paths"))?;
    if !canonical(&location.bucket)
        || !canonical(&location.authority)
        || location.bucket.starts_with(&location.authority)
        || location.authority.starts_with(&location.bucket)
    {
        return Err(Error::Refused("invalid collector repository paths"));
    }
    if config.tokens().issuer_public_keys.is_empty() {
        return Err(Error::Refused("requires explicit public issuer key files"));
    }
    Ok(ValidatedCollector {
        config,
        settings,
        windows,
    })
}

fn canonical(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .skip(1)
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}

#[cfg(test)]
mod tests;
