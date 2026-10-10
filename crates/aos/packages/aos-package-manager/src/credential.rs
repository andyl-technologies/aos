//! Credential helper commands for package authors.
//!
//! These helpers prepare payloads for typed configuration credential
//! declarations. They intentionally run outside pure Nix builds because TPM2
//! signed-PCR credential sealing depends on target/runtime key material.

use std::ffi::OsStr;
use std::fs::{OpenOptions, Permissions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use aos_cli_ui::output::{OutputMode, Printer};
use aos_module_format::LocalKey;

use crate::CredentialCommand;
use aos_registry_format::consumer::validate_credential_ciphertext;

const PROVIDER_LOCATOR: &str = "/etc/aos/providers/credential-encrypt";
const MAX_PROVIDER_PATH_BYTES: u64 = 4096;

/// Runs an `apm credential ...` helper command.
pub(crate) fn run(command: &CredentialCommand, printer: &Printer) -> Result<()> {
    match command {
        CredentialCommand::Encrypt {
            name,
            input,
            output,
            pcr_public_key,
        } => encrypt(
            name,
            input,
            output.as_deref(),
            pcr_public_key.as_deref(),
            printer,
        ),
    }
}

fn encrypt(
    name: &str,
    input: &Path,
    output: Option<&Path>,
    pcr_public_key: Option<&Path>,
    printer: &Printer,
) -> Result<()> {
    LocalKey::new(name).context("credential name is not a canonical local key")?;
    validate_regular_file(input, "plaintext credential input")?;
    if let Some(path) = pcr_public_key {
        validate_regular_file(path, "PCR public key")?;
    }
    let ciphertext = encrypt_with_selected_provider(name, input, pcr_public_key)?;
    if let Some(path) = output {
        write_ciphertext_output(path, &ciphertext)?;
    }
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "name": name,
            "ciphertext": ciphertext,
            "output": output.map(|path| path.display().to_string()),
            "pcr_public_key": pcr_public_key.map(|path| path.display().to_string()),
        }));
    } else if output.is_none() {
        println!("{ciphertext}");
    } else {
        let output = output.context("credential output path disappeared")?;
        printer.success(&format!(
            "Encrypted credential written to {}",
            output.display()
        ));
    }

    Ok(())
}

fn validate_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading {label}: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("{label} must be a regular file: {}", path.display());
    }
    Ok(())
}

fn write_ciphertext_output(path: &Path, ciphertext: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!("credential output already exists: {}", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("checking {}", path.display()));
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, format!("{ciphertext}\n"))
        .with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("setting mode on {}", path.display()))?;
    Ok(())
}

fn encrypt_with_selected_provider(
    name: &str,
    input: &Path,
    public_key: Option<&Path>,
) -> Result<String> {
    let override_path = std::env::var_os("AOS_CREDENTIAL_ENCRYPT_PROVIDER");
    let provider = selected_provider(override_path.as_deref(), Path::new(PROVIDER_LOCATOR))?;
    let resolved = std::fs::canonicalize(&provider)
        .context("resolving the selected credential encryption provider")?;
    checked_provider_path(resolved.as_os_str())?;
    let metadata = std::fs::metadata(&resolved)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "the selected credential encryption provider must be an executable store file"
    );

    let mut command = Command::new(provider);
    command.arg("--name").arg(name).arg("--input").arg(input);
    if let Some(public_key) = public_key {
        command.arg("--pcr-public-key").arg(public_key);
    }

    let result = command
        .output()
        .context("running the selected credential encryption provider")?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        bail!(
            "credential encryption provider failed with {}{}",
            result.status,
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        );
    }
    let ciphertext = String::from_utf8(result.stdout)
        .context("credential encryption provider output is not UTF-8")?;
    let ciphertext = ciphertext.trim_end_matches('\n').to_string();
    validate_credential_ciphertext(&ciphertext)
        .context("credential encryption provider returned an invalid ciphertext")?;
    Ok(ciphertext)
}

/// Resolves the explicit override or the target's installed provider locator.
fn selected_provider(override_path: Option<&OsStr>, locator: &Path) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return checked_provider_path(path);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(locator)
        .context("the selected credential encryption provider is unavailable")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_PROVIDER_PATH_BYTES + 1,
        "credential encryption provider locator must be a bounded regular file"
    );

    let mut content = String::new();
    file.take(MAX_PROVIDER_PATH_BYTES + 2)
        .read_to_string(&mut content)
        .context("reading the selected credential encryption provider locator")?;
    ensure!(
        content.len() as u64 <= MAX_PROVIDER_PATH_BYTES + 1,
        "credential encryption provider locator exceeds its byte bound"
    );
    let path = content.strip_suffix('\n').unwrap_or(&content);
    checked_provider_path(OsStr::new(path))
}

/// Requires an exact executable locator within an immutable store object.
fn checked_provider_path(value: &OsStr) -> Result<PathBuf> {
    let value = value
        .to_str()
        .context("credential encryption provider path is not UTF-8")?;
    ensure!(
        value.len() as u64 <= MAX_PROVIDER_PATH_BYTES
            && !value.contains(['\0', '\n', '\r'])
            && value
                .split('/')
                .skip(1)
                .all(|part| !matches!(part, "" | "." | "..")),
        "credential encryption provider path must be a bounded canonical store path"
    );
    let path = PathBuf::from(value);
    let (_, suffix) = aos_deployment::nix::store_root_and_suffix(&path)
        .context("credential encryption provider must be retained in the Nix store")?;
    ensure!(
        !suffix.as_os_str().is_empty(),
        "credential encryption provider must name an executable inside its store object"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{checked_provider_path, selected_provider};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::symlink;

    const PROVIDER: &str = "/nix/store/00000000000000000000000000000000-provider/bin/encrypt";

    #[test]
    fn installed_locator_selects_exact_provider() {
        let temporary = tempfile::tempdir().unwrap();
        let locator = temporary.path().join("provider");
        fs::write(&locator, format!("{PROVIDER}\n")).unwrap();

        assert_eq!(
            selected_provider(None, &locator).unwrap(),
            std::path::Path::new(PROVIDER)
        );
    }

    #[test]
    fn explicit_override_does_not_require_a_locator() {
        let temporary = tempfile::tempdir().unwrap();

        assert_eq!(
            selected_provider(
                Some(OsStr::new(PROVIDER)),
                &temporary.path().join("missing")
            )
            .unwrap(),
            std::path::Path::new(PROVIDER)
        );
    }

    #[test]
    fn locator_rejects_symlinks_and_oversized_contents() {
        let temporary = tempfile::tempdir().unwrap();
        let locator = temporary.path().join("provider");
        let target = temporary.path().join("target");
        fs::write(&target, PROVIDER).unwrap();
        symlink(&target, &locator).unwrap();

        assert!(selected_provider(None, &locator).is_err());

        fs::remove_file(&locator).unwrap();
        fs::write(&locator, "x".repeat(4098)).unwrap();

        assert!(selected_provider(None, &locator).is_err());
    }

    #[test]
    fn provider_paths_reject_host_paths_and_noncanonical_suffixes() {
        for path in [
            "/usr/bin/encrypt".to_owned(),
            format!("{PROVIDER}\n\n"),
            format!("{PROVIDER}/../other"),
            format!("{PROVIDER}/./other"),
            format!("{PROVIDER}//other"),
            "/nix/store/00000000000000000000000000000000-provider".to_owned(),
        ] {
            assert!(checked_provider_path(OsStr::new(&path)).is_err(), "{path}");
        }
    }
}
