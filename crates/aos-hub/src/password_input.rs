//! Password input for Native recovery and Worker bootstrap commands.
//!
//! Private files use the same ownership, permission, link and size checks as
//! other Native service credentials. File and stdin input preserve whitespace
//! except for trailing CR/LF terminators; command-line input is used verbatim.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, Result};

/// Reads exactly one password source without including its value in errors.
///
/// # Errors
///
/// Returns an error for missing or conflicting sources, insecure or unreadable
/// credential files, invalid UTF-8, or a failure to read stdin.
pub(crate) fn read_password(
    password: Option<String>,
    from_stdin: bool,
    file: Option<&Path>,
) -> Result<String> {
    let source_count =
        usize::from(password.is_some()) + usize::from(from_stdin) + usize::from(file.is_some());
    anyhow::ensure!(source_count == 1, "provide exactly one password source");

    if let Some(password) = password {
        return Ok(password);
    }

    let mut text = if let Some(path) = file {
        let bytes = aos_hub::auth::seal::read_secret_file(path)
            .context("reading password credential file")?;
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("password file must contain UTF-8"))?
    } else {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading password from stdin")?;
        text
    };

    text.truncate(text.trim_end_matches(['\n', '\r']).len());
    Ok(text)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use clap::Parser as _;

    use super::read_password;

    fn private_file(directory: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
        let path = directory.path().join("password");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        path
    }

    #[test]
    fn reads_private_file_preserving_password_whitespace() {
        let directory = tempfile::tempdir().unwrap();
        let path = private_file(&directory, b"  owner password  \r\n");

        assert_eq!(
            read_password(None, false, Some(&path)).unwrap(),
            "  owner password  "
        );
        assert_eq!(
            read_password(Some("verbatim\n".to_owned()), false, None).unwrap(),
            "verbatim\n"
        );
    }

    #[test]
    fn rejects_missing_or_ambiguous_sources_before_reading() {
        let missing = std::path::Path::new("/unavailable/password");
        for (password, stdin, file) in [
            (None, false, None),
            (Some("secret".to_owned()), true, None),
            (Some("secret".to_owned()), false, Some(missing)),
            (None, true, Some(missing)),
        ] {
            let error = read_password(password, stdin, file).unwrap_err();
            assert_eq!(error.to_string(), "provide exactly one password source");
        }
    }

    #[test]
    fn rejects_public_linked_or_invalid_password_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = private_file(&directory, b"secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(read_password(None, false, Some(&path)).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_password(None, false, Some(&link)).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, [0xff]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let error = read_password(None, false, Some(&path)).unwrap_err();
        assert_eq!(error.to_string(), "password file must contain UTF-8");
    }

    #[test]
    fn native_recovery_requires_one_explicit_password_source() {
        for (command, email_flag, password_flag, stdin_flag, file_flag) in [
            (
                "init",
                "--root-email",
                "--root-password",
                "--root-password-stdin",
                "--root-password-file",
            ),
            (
                "reset-root",
                "--email",
                "--password",
                "--password-stdin",
                "--password-file",
            ),
        ] {
            let arguments = [
                "aos-hub",
                command,
                email_flag,
                "owner@example.com",
                file_flag,
                "/run/credentials/password",
            ];
            assert!(crate::Cli::try_parse_from(arguments).is_ok());

            let mut ambiguous = arguments.to_vec();
            ambiguous.push(stdin_flag);
            assert!(crate::Cli::try_parse_from(&ambiguous).is_err());

            ambiguous.pop();
            ambiguous.extend([password_flag, "secret"]);
            assert!(crate::Cli::try_parse_from(&ambiguous).is_err());
        }

        assert!(crate::Cli::try_parse_from([
            "aos-hub",
            "init",
            "--root-password-file",
            "/run/credentials/password",
        ])
        .is_err());
    }
}
