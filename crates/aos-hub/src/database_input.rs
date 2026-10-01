//! Native database URLs supplied through private service credential files.
//!
//! File input shares the ownership, permission, link and size checks used by
//! Native signing credentials. Only trailing CR/LF terminators are removed;
//! database URLs and their embedded credentials never appear in errors.

use std::path::Path;

use anyhow::{Context as _, Result};

/// Reads a bounded UTF-8 database URL from a private credential file.
///
/// # Errors
///
/// Returns an error for unreadable or insecure files, invalid UTF-8, or an empty
/// URL. It does not connect to or initialize the database.
pub(crate) fn read_database_url_file(path: &Path) -> Result<String> {
    let bytes = aos_hub::auth::seal::read_secret_file(path)
        .context("reading native database URL credential file")?;
    let mut database_url = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("database URL credential file must contain UTF-8"))?;

    database_url.truncate(database_url.trim_end_matches(['\r', '\n']).len());
    anyhow::ensure!(
        !database_url.is_empty(),
        "database URL credential file is empty"
    );
    Ok(database_url)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::read_database_url_file;

    fn private_file(directory: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
        let path = directory.path().join("database-url");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        path
    }

    #[test]
    fn reads_private_url_with_only_line_terminators_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = private_file(
            &directory,
            b"postgresql://hub:fixture-password@localhost/hub\r\n",
        );

        assert_eq!(
            read_database_url_file(&path).unwrap(),
            "postgresql://hub:fixture-password@localhost/hub"
        );
    }

    #[test]
    fn rejects_public_or_linked_files_before_database_use() {
        let directory = tempfile::tempdir().unwrap();
        let path = private_file(
            &directory,
            b"postgresql://hub:fixture-password@localhost/hub",
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();

        let error = read_database_url_file(&path).unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-password"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let linked = directory.path().join("linked-database-url");
        symlink(&path, &linked).unwrap();
        assert!(read_database_url_file(&linked).is_err());
    }

    #[test]
    fn rejects_invalid_utf8_and_empty_urls_without_rendering_contents() {
        let directory = tempfile::tempdir().unwrap();
        let invalid = private_file(&directory, b"fixture-password\xff");

        let error = read_database_url_file(&invalid).unwrap_err();
        assert_eq!(
            error.to_string(),
            "database URL credential file must contain UTF-8"
        );
        assert!(!format!("{error:#}").contains("fixture-password"));

        fs::set_permissions(&invalid, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&invalid, b"\r\n").unwrap();
        fs::set_permissions(&invalid, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_database_url_file(&invalid).is_err());
    }
}
