//! Private Native receipt signing seed files supplied by the deployment.
//!
//! Ownership, permissions, links and file size use the common credential
//! reader. Encoded seed buffers are zeroized after authority initialization;
//! the release evidence authority validates their Ed25519 representation.

use std::path::Path;

use anyhow::{Context as _, Result};
use zeroize::Zeroizing;

/// Reads bounded UTF-8 signing material from a private credential file.
///
/// # Errors
///
/// Returns an error for unreadable or insecure files, invalid UTF-8, or empty
/// material. Errors never include file contents. Key decoding is performed by
/// the evidence authority after both role credentials have been read.
pub(crate) fn read_signing_seed_file(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(
        aos_hub::auth::seal::read_secret_file(path)
            .context("reading private receipt signing credential")?,
    );
    let text = std::str::from_utf8(&bytes)
        .context("receipt signing credential must contain UTF-8")?
        .trim();

    anyhow::ensure!(!text.is_empty(), "receipt signing credential is empty");
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use super::read_signing_seed_file;

    fn private_file(directory: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
        let path = directory.path().join("receipt-seed");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        path
    }

    #[test]
    fn reads_owner_private_seed_with_surrounding_whitespace_removed() {
        let directory = tempfile::tempdir().unwrap();
        let seed = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let path = private_file(&directory, format!(" {seed}\r\n").as_bytes());

        assert_eq!(read_signing_seed_file(&path).unwrap().as_str(), seed);
    }

    #[test]
    fn rejects_public_permissions_and_both_link_types() {
        let directory = tempfile::tempdir().unwrap();
        let path = private_file(&directory, b"fixture-private-seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();

        let error = read_signing_seed_file(&path).unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-private-seed"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let linked = directory.path().join("linked-receipt-seed");
        symlink(&path, &linked).unwrap();
        assert!(read_signing_seed_file(&linked).is_err());

        let hard_linked = directory.path().join("hard-linked-receipt-seed");
        fs::hard_link(&path, &hard_linked).unwrap();
        assert!(read_signing_seed_file(&hard_linked).is_err());
        assert!(read_signing_seed_file(&path).is_err());
    }

    #[test]
    fn rejects_invalid_text_and_empty_material_without_disclosing_contents() {
        let directory = tempfile::tempdir().unwrap();
        let path = private_file(&directory, b"fixture-private-seed\xff");

        let error = read_signing_seed_file(&path).unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-private-seed"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b" \r\n\t").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_signing_seed_file(&path).is_err());
    }
}
