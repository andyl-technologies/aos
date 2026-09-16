//! Credential helper commands for package authors.
//!
//! These helpers prepare payloads for typed configuration credential
//! declarations. They intentionally run outside pure Nix builds because TPM2
//! signed-PCR credential sealing depends on target/runtime key material.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_ability_model::LocalKey;
use aos_core::output::{OutputMode, Printer};

use crate::CredentialCommand;
use crate::types::validate_credential_ciphertext;

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
    let provider = std::env::var_os("AOS_CREDENTIAL_ENCRYPT_PROVIDER")
        .context("the selected credential encryption provider is unavailable")?;
    let mut command = Command::new(provider);
    command
        .arg("credential-encrypt")
        .arg("--name")
        .arg(name)
        .arg("--input")
        .arg(input);
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
