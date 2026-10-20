//! Resolves bounded release-coordinator credentials from files or systemd names.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::capture;

/// Returns where a credential reference points: `$CREDENTIALS_DIRECTORY/<name>`
/// for a bare name, or the absolute path itself.
///
/// # Errors
/// Returns an error for a relative path, a name with separators, or a bare
/// name without `$CREDENTIALS_DIRECTORY`.
pub fn credential_location(reference: &str) -> Result<PathBuf> {
    let path = Path::new(reference);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if reference.is_empty() || reference.contains('/') || reference == "." || reference == ".." {
        bail!("credential must be a systemd credential name or an absolute path: {reference}");
    }
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .filter(|value| !value.is_empty())
        .with_context(|| format!("credential {reference} requires $CREDENTIALS_DIRECTORY"))?;
    Ok(PathBuf::from(directory).join(reference))
}

/// Reads a credential by name or absolute path and trims surrounding whitespace.
///
/// # Errors
/// Returns an error for an invalid reference, an unreadable or linked file,
/// non-UTF-8 content, or an empty credential.
pub fn resolve_credential(reference: &str) -> Result<String> {
    let path = credential_location(reference)?;
    let bytes = capture::control_file(&path, "credential")?;
    let value = std::str::from_utf8(&bytes)
        .with_context(|| format!("credential {reference} is not UTF-8"))?
        .trim()
        .to_owned();
    if value.is_empty() {
        bail!("credential {reference} is empty");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_resolve_by_name_or_absolute_path() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let absolute = directory.path().join("token");
        std::fs::write(&absolute, b"  secret-token\n")?;
        assert_eq!(
            resolve_credential(absolute.to_str().context("utf-8 path")?)?,
            "secret-token"
        );
        assert!(credential_location("relative/path").is_err());
        assert!(credential_location("..").is_err());

        std::fs::write(directory.path().join("empty"), b"\n")?;
        assert!(
            resolve_credential(
                directory
                    .path()
                    .join("empty")
                    .to_str()
                    .context("utf-8 path")?
            )
            .is_err()
        );
        Ok(())
    }
}
