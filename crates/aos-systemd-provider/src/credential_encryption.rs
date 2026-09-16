//! systemd credential encryption command adapter.
//!
//! The package keeps the `systemd-creds` executable, TPM policy, and pretty
//! output format private. The generic `apm` command sends provider-neutral
//! inputs and receives one normalized opaque ciphertext line.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_ability_model::LocalKey;

const DEFAULT_PCR_PUBLIC_KEY: &str = "/etc/aos/pcr-sign.pem";
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const SYSTEMD_CREDS: Option<&str> = option_env!("AOS_SYSTEMD_CREDS");

pub(crate) fn run(arguments: &[OsString]) -> Result<()> {
    let request = EncryptionRequest::parse(arguments)?;
    request.validate()?;

    let systemd_creds = SYSTEMD_CREDS
        .ok_or_else(|| anyhow::anyhow!("systemd credential encryption backend is unavailable"))?;
    let output = Command::new(systemd_creds)
        .args(request.systemd_creds_arguments())
        .output()
        .context("running the systemd credential encryption backend")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "systemd credential encryption failed with {}{}",
            output.status,
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", stderr.trim())
            }
        );
    }

    let pretty = String::from_utf8(output.stdout)
        .context("systemd credential encryption output is not UTF-8")?;
    let ciphertext = parse_pretty_ciphertext(&pretty, request.name.as_str())?;
    std::io::stdout()
        .write_all(format!("{ciphertext}\n").as_bytes())
        .context("writing encrypted credential output")
}

struct EncryptionRequest {
    name: LocalKey,
    input: PathBuf,
    public_key: PathBuf,
}

impl EncryptionRequest {
    fn parse(arguments: &[OsString]) -> Result<Self> {
        let mut name = None;
        let mut input = None;
        let mut public_key = None;
        let mut index = 0;

        while index < arguments.len() {
            let option = &arguments[index];
            let value = arguments.get(index + 1).ok_or_else(|| {
                anyhow::anyhow!("credential encryption option {:?} lacks a value", option)
            })?;
            match option.to_str() {
                Some("--name") if name.is_none() => {
                    let value = value
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("credential name is not valid UTF-8"))?;
                    name = Some(LocalKey::new(value)?);
                }
                Some("--input") if input.is_none() => input = Some(PathBuf::from(value)),
                Some("--pcr-public-key") if public_key.is_none() => {
                    public_key = Some(PathBuf::from(value));
                }
                Some(known @ ("--name" | "--input" | "--pcr-public-key")) => {
                    bail!("credential encryption option {known} is repeated")
                }
                _ => bail!("unsupported credential encryption option {:?}", option),
            }
            index += 2;
        }

        Ok(Self {
            name: name.context("credential encryption requires --name")?,
            input: input.context("credential encryption requires --input")?,
            public_key: public_key.unwrap_or_else(default_pcr_public_key),
        })
    }

    fn validate(&self) -> Result<()> {
        validate_regular_file(&self.input, "plaintext credential input")?;
        validate_regular_file(&self.public_key, "PCR public key")
    }

    fn systemd_creds_arguments(&self) -> Vec<OsString> {
        let mut name = OsString::from("--name=");
        name.push(self.name.as_str());
        let mut public_key = OsString::from("--tpm2-public-key=");
        public_key.push(&self.public_key);

        vec![
            OsString::from("encrypt"),
            name,
            OsString::from("--with-key=tpm2"),
            public_key,
            OsString::from("--tpm2-public-key-pcrs=11"),
            OsString::from("--pretty"),
            self.input.as_os_str().to_owned(),
            OsString::from("-"),
        ]
    }
}

fn default_pcr_public_key() -> PathBuf {
    let root = std::env::var_os("AOS_ROOT")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    root.join(DEFAULT_PCR_PUBLIC_KEY.trim_start_matches('/'))
}

fn validate_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {label}: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} must be a regular file: {}", path.display());
    }
    Ok(())
}

fn parse_pretty_ciphertext(text: &str, expected_name: &str) -> Result<String> {
    let mut lines = text.lines();
    let first_line = lines
        .next()
        .context("encrypted credential output is empty")?
        .trim_end();
    let payload = first_line
        .strip_prefix("SetCredentialEncrypted=")
        .context("encrypted credential output has no SetCredentialEncrypted prefix")?;
    let (name, first_part) = payload
        .split_once(':')
        .context("encrypted credential output has no credential name separator")?;
    if name != expected_name {
        bail!("encrypted credential output names an unexpected credential");
    }

    let (first_part, mut expects_continuation) = trim_pretty_part(first_part);
    let mut ciphertext = first_part.to_string();
    for line in lines {
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
        bail!("encrypted credential output ends with an incomplete continuation");
    }
    if ciphertext.is_empty()
        || ciphertext.len() as u64 > MAX_CREDENTIAL_BYTES
        || !ciphertext
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
    {
        bail!("encrypted credential output is not one bounded base64 payload");
    }
    Ok(ciphertext)
}

fn trim_pretty_part(part: &str) -> (&str, bool) {
    let trimmed = part.trim();
    let continues = trimmed.ends_with('\\');
    (trimmed.trim_end_matches('\\').trim(), continues)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_pretty_ciphertext() {
        let ciphertext = parse_pretty_ciphertext(
            "SetCredentialEncrypted=join-token: \\\n                abcDEF0123+/=\\
                zz\n",
            "join-token",
        )
        .expect("pretty ciphertext");

        assert_eq!(ciphertext, "abcDEF0123+/=zz");
    }

    #[test]
    fn rejects_name_and_line_injection() {
        assert!(
            parse_pretty_ciphertext("SetCredentialEncrypted=other:abcDEF0123+/=", "join-token",)
                .is_err()
        );
        assert!(
            parse_pretty_ciphertext(
                "SetCredentialEncrypted=join-token:abcDEF0123+/=\nunexpected",
                "join-token",
            )
            .is_err()
        );
    }
}
