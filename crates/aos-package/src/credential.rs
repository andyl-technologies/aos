//! Credential helper commands for package authors.
//!
//! These helpers prepare credential payloads that package `expose` metadata can
//! consume. They intentionally run outside pure Nix builds because TPM2
//! signed-PCR credential sealing depends on target/runtime key material.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};

use crate::CredentialCommand;
use crate::config::ApmConfig;
use crate::credential_artifact::{credential_pcr_public_key, systemd_creds_encrypt_pretty};
use crate::types::{validate_credential_ciphertext, validate_credential_name, validate_unit_name};

/// Runs an `apm credential ...` helper command.
pub(crate) fn run(
    config: &ApmConfig,
    command: &CredentialCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        CredentialCommand::Encrypt {
            name,
            input,
            output,
            pcr_public_key,
            expose_nix,
            units,
        } => encrypt(
            config,
            name,
            input,
            output.as_deref(),
            pcr_public_key.as_deref(),
            *expose_nix,
            units,
            printer,
        ),
    }
}

fn encrypt(
    config: &ApmConfig,
    name: &str,
    input: &Path,
    output: Option<&Path>,
    pcr_public_key: Option<&Path>,
    expose_nix: bool,
    units: &[String],
    printer: &Printer,
) -> Result<()> {
    validate_credential_name(name)?;
    for unit in units {
        validate_unit_name(unit)?;
        if !unit.ends_with(".service") {
            bail!("credential unit must be a service unit: {unit}");
        }
    }
    validate_regular_file(input, "plaintext credential input")?;
    let public_key = match pcr_public_key {
        Some(path) => {
            validate_regular_file(path, "PCR public key")?;
            path.to_path_buf()
        }
        None => credential_pcr_public_key(&config.settings, &aos_root_path())?,
    };

    let pretty_output = systemd_creds_encrypt_pretty(name, &public_key, input)?;
    let ciphertext = parse_inline_ciphertext(&pretty_output, name)?;
    if let Some(path) = output {
        write_ciphertext_output(path, &ciphertext)?;
    }
    let snippet = expose_nix.then(|| render_nix_credential_snippet(name, &ciphertext, units));

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "name": name,
            "ciphertext": ciphertext,
            "output": output.map(|path| path.display().to_string()),
            "pcr_public_key": public_key.display().to_string(),
            "expose_nix": snippet,
        }));
    } else if let Some(snippet) = snippet {
        println!("{snippet}");
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

fn parse_inline_ciphertext(text: &str, expected_name: &str) -> Result<String> {
    let mut lines = text.lines();
    let first_line = lines
        .next()
        .context("encrypted credential output is empty")?
        .trim_end();
    let payload = first_line
        .strip_prefix("SetCredentialEncrypted=")
        .context("encrypted credential output is missing SetCredentialEncrypted= prefix")?;
    let (name, ciphertext) = payload
        .split_once(':')
        .context("encrypted credential output is missing credential name separator")?;
    if name != expected_name {
        bail!(
            "encrypted credential output name mismatch: expected '{}', got '{}'",
            expected_name,
            name
        );
    }
    let ciphertext = unwrapped_pretty_ciphertext(ciphertext, lines)?;
    validate_credential_ciphertext(&ciphertext).with_context(|| {
        "invalid encrypted credential payload from systemd-creds pretty output".to_string()
    })?;
    Ok(ciphertext)
}

fn unwrapped_pretty_ciphertext<'a>(
    first: &str,
    continuation_lines: impl Iterator<Item = &'a str>,
) -> Result<String> {
    let (first, mut expects_continuation) = trim_pretty_part(first);
    let mut ciphertext = first.to_string();
    for line in continuation_lines {
        let (part, continues) = trim_pretty_part(line);
        if !part.is_empty() {
            if !expects_continuation {
                bail!("encrypted credential output has an unexpected continuation line");
            }
            ciphertext.push_str(part);
        }
        expects_continuation = continues;
    }
    if expects_continuation {
        bail!("encrypted credential output ended with an unterminated continuation");
    }
    Ok(ciphertext)
}

fn trim_pretty_part(part: &str) -> (&str, bool) {
    let trimmed = part.trim();
    let continues = trimmed.ends_with('\\');
    (trimmed.trim_end_matches('\\').trim(), continues)
}

fn render_nix_credential_snippet(name: &str, ciphertext: &str, units: &[String]) -> String {
    let units_line = if units.is_empty() {
        String::new()
    } else {
        let units = units
            .iter()
            .map(|unit| nix_string(unit))
            .collect::<Vec<_>>()
            .join(" ");
        format!("  units = [ {units} ];\n")
    };
    format!(
        "{{\n  name = {};\n  encrypted = true;\n  ciphertext = {};\n{units_line}}}",
        nix_string(name),
        nix_string(ciphertext)
    )
}

fn nix_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn aos_root_path() -> PathBuf {
    match std::env::var("AOS_ROOT") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                PathBuf::from("/").join(path)
            }
        }
        _ => PathBuf::from("/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_nix_credential_snippet_includes_units() {
        let snippet = render_nix_credential_snippet(
            "join-token",
            "abcDEF0123+/=",
            &["example.service".to_string(), "sidecar.service".to_string()],
        );

        assert_eq!(
            snippet,
            "{\n  name = \"join-token\";\n  encrypted = true;\n  ciphertext = \"abcDEF0123+/=\";\n  units = [ \"example.service\" \"sidecar.service\" ];\n}"
        );
    }

    #[test]
    fn render_nix_credential_snippet_omits_empty_units() {
        let snippet = render_nix_credential_snippet("join-token", "abcDEF0123+/=", &[]);

        assert_eq!(
            snippet,
            "{\n  name = \"join-token\";\n  encrypted = true;\n  ciphertext = \"abcDEF0123+/=\";\n}"
        );
    }

    #[test]
    fn nix_string_escapes_control_characters() {
        assert_eq!(nix_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn parse_inline_ciphertext_trims_trailing_newline() {
        assert_eq!(
            parse_inline_ciphertext(
                "SetCredentialEncrypted=join-token:abcDEF0123+/=\n",
                "join-token"
            )
            .unwrap(),
            "abcDEF0123+/="
        );
    }

    #[test]
    fn parse_inline_ciphertext_unwraps_pretty_continuations() {
        assert_eq!(
            parse_inline_ciphertext(
                "SetCredentialEncrypted=join-token: \\\n        abcDEF0123+/=\\\n        zz\n",
                "join-token"
            )
            .unwrap(),
            "abcDEF0123+/=zz"
        );
    }

    #[test]
    fn parse_inline_ciphertext_rejects_internal_newline_without_continuation() {
        let err =
            parse_inline_ciphertext("SetCredentialEncrypted=join-token:abc\nDEF", "join-token")
                .unwrap_err();
        assert!(
            err.to_string().contains("unexpected continuation line"),
            "{err:?}"
        );
    }

    #[test]
    fn parse_inline_ciphertext_rejects_name_mismatch() {
        let err =
            parse_inline_ciphertext("SetCredentialEncrypted=other:abcDEF0123+/=", "join-token")
                .unwrap_err();
        assert!(err.to_string().contains("name mismatch"), "{err:?}");
    }
}
