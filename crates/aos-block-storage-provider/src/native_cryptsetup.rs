//! Native ephemeral encrypted mapping lifecycle.
//!
//! A receipt records desired properties before dispatch. Exact kernel state and
//! that receipt together establish completion after a crash. Unclaimed active
//! mappings are never adopted or closed.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{native_state as state, process::run_native};

const ROOT: &str = "/run/aos/native-encrypted-mappings";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    name: String,
    source: String,
    cipher: String,
    key_size_bits: u16,
    cryptsetup: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    id: String,
    revision: String,
    input: Input,
}

#[derive(Default)]
struct Mapping {
    active: bool,
    source: Option<String>,
    cipher: Option<String>,
    bits: Option<u16>,
}

/// Executes one native encrypted mapping invocation.
///
/// # Errors
/// Returns an error for malformed inputs, unmanaged state, incompatible existing
/// ownership, or failed native inspection or mutation.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported cryptsetup action"
    );
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "action differs from native invocation"
    );
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    validate(&input)?;
    let root = Path::new(ROOT);
    let _lock = state::Lock::acquire(root)?;
    let claim: Option<Claim> = state::read(root, &invocation.id)?;
    if let Some(claim) = &claim {
        ensure!(
            claim.id == invocation.id,
            "encrypted mapping claim belongs to another effect"
        );
        validate(&claim.input)?;
    }
    let output = match action {
        "observe" => observe(&invocation, &input, claim.as_ref())?,
        "remove" => {
            if let Some(claim) = &claim {
                close_owned(claim, invocation.effect.timeout_ms)?;
            } else {
                ensure!(
                    !inspect(&input)?.active,
                    "unclaimed active mapping cannot be removed"
                );
            }
            state::remove(root, &invocation.id)?;
            json!({})
        }
        "apply" => {
            let source = canonical_source(&input.source)?;
            let before = inspect(&input)?;
            if exact(&input, &before, &source)
                && claim.as_ref().is_some_and(|claim| {
                    claim.revision == invocation.revision
                        && claim.input.name == input.name
                        && claim.input.source == source
                })
            {
                outputs(&invocation, &input)
            } else {
                if let Some(claim) = &claim {
                    close_owned(claim, invocation.effect.timeout_ms)?;
                }
                ensure!(
                    !inspect(&input)?.active,
                    "refusing to replace an unclaimed encrypted mapping"
                );
                let claim = Claim {
                    id: invocation.id.clone(),
                    revision: invocation.revision.clone(),
                    input: Input {
                        source: source.clone(),
                        ..input.clone()
                    },
                };
                state::write(root, &invocation.id, &claim)?;
                success(
                    &input.cryptsetup,
                    &[
                        "open",
                        "--type=plain",
                        &format!("--cipher={}", input.cipher),
                        &format!("--key-size={}", input.key_size_bits),
                        "--key-file=/dev/urandom",
                        &source,
                        &input.name,
                    ],
                    invocation.effect.timeout_ms,
                )?;
                ensure!(
                    exact(&input, &inspect(&input)?, &source),
                    "opened mapping does not match its requested properties"
                );
                outputs(&invocation, &input)
            }
        }
        _ => bail!("unsupported encrypted mapping action"),
    };
    Ok(serde_json::to_vec(&output)?)
}

fn outputs(invocation: &Invocation, input: &Input) -> Value {
    json!({"path":format!("/dev/mapper/{}",input.name),"resource":invocation.id})
}

fn observe(invocation: &Invocation, input: &Input, claim: Option<&Claim>) -> Result<Value> {
    let native = inspect(input)?;
    if invocation.action == Action::Remove {
        if let Some(claim) = claim {
            let owned = inspect(&claim.input)?;
            if !owned.active {
                return Ok(json!({"status":"retry-safe"}));
            }
            return Ok(
                json!({"status":if exact(&claim.input,&owned,&claim.input.source) {"retry-safe"} else {"indeterminate"}}),
            );
        }
        return Ok(json!({"status":if native.active {"indeterminate"} else {"absent"}}));
    }
    if !native.active {
        return Ok(json!({"status":"retry-safe"}));
    }
    let Some(claim) = claim else {
        return Ok(json!({"status":"indeterminate"}));
    };
    let source = canonical_source(&input.source)?;
    if claim.revision == invocation.revision
        && claim.input.name == input.name
        && claim.input.source == source
        && exact(input, &native, &source)
    {
        Ok(json!({"status":"current","outputs":outputs(invocation,input)}))
    } else if exact(&claim.input, &inspect(&claim.input)?, &claim.input.source) {
        Ok(json!({"status":"retry-safe"}))
    } else {
        Ok(json!({"status":"indeterminate"}))
    }
}

fn close_owned(claim: &Claim, timeout: u64) -> Result<()> {
    let native = inspect(&claim.input)?;
    if native.active {
        ensure!(
            exact(&claim.input, &native, &claim.input.source),
            "owned encrypted mapping drift prevents safe teardown"
        );
        success(
            &claim.input.cryptsetup,
            &["close", &claim.input.name],
            timeout,
        )?;
    }
    Ok(())
}

fn exact(input: &Input, mapping: &Mapping, source: &str) -> bool {
    mapping.active
        && mapping.source.as_deref() == Some(source)
        && mapping.cipher.as_deref() == Some(input.cipher.as_str())
        && mapping.bits == Some(input.key_size_bits)
}

fn inspect(input: &Input) -> Result<Mapping> {
    let output = run_native(&input.cryptsetup, &["status", &input.name], 5000)?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(4),
            "cryptsetup inspection failed"
        );
        return Ok(Mapping::default());
    }
    let mut mapping = Mapping {
        active: true,
        ..Mapping::default()
    };
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "device" => mapping.source = Some(canonical_source(value)?),
            "cipher" => mapping.cipher = Some(value.into()),
            "keysize" => {
                mapping.bits = value
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok())
            }
            _ => {}
        }
    }
    Ok(mapping)
}

fn success(path: &Path, args: &[&str], timeout: u64) -> Result<()> {
    let output = run_native(path, args, timeout)?;
    ensure!(
        output.status.success(),
        "cryptsetup mutation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn validate(input: &Input) -> Result<()> {
    ensure!(
        !input.name.is_empty()
            && input.name.len() <= 128
            && input
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "invalid encrypted mapping name"
    );
    ensure!(
        (128..=512).contains(&input.key_size_bits),
        "invalid encrypted mapping key size"
    );
    ensure!(
        !input.cipher.is_empty()
            && input.cipher.len() <= 128
            && input
                .cipher
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "invalid encrypted mapping cipher"
    );
    ensure!(
        Path::new(&input.source).is_absolute()
            && Path::new(&input.source)
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "encrypted mapping source is not a normalized absolute path"
    );
    Ok(())
}

fn canonical_source(source: &str) -> Result<String> {
    Ok(fs::canonicalize(source)
        .with_context(|| format!("resolving mapping source {source}"))?
        .to_str()
        .context("mapping source is not UTF-8")?
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input {
            name: "cryptswap".into(),
            source: "/dev/sda3".into(),
            cipher: "aes-xts-plain64".into(),
            key_size_bits: 256,
            cryptsetup: "/nix/store/00000000000000000000000000000000-tools/sbin/cryptsetup".into(),
        }
    }

    #[test]
    fn mapping_completion_requires_every_native_property() {
        let input = input();
        let mut native = Mapping {
            active: true,
            source: Some(input.source.clone()),
            cipher: Some(input.cipher.clone()),
            bits: Some(256),
        };
        assert!(exact(&input, &native, &input.source));

        native.bits = Some(512);
        assert!(!exact(&input, &native, &input.source));
        native.bits = Some(256);
        native.source = Some("/dev/sdb3".into());
        assert!(!exact(&input, &native, &input.source));
        native.source = Some(input.source.clone());
        native.cipher = Some("aes-cbc-essiv:sha256".into());
        assert!(!exact(&input, &native, &input.source));
    }

    #[test]
    fn validation_rejects_unsafe_mapping_names_and_paths_before_mutation() {
        let mut desired = input();
        validate(&desired).unwrap();
        desired.name = "../foreign".into();
        assert!(validate(&desired).is_err());
        desired.name = "cryptswap".into();
        desired.source = "/dev/../foreign".into();
        assert!(validate(&desired).is_err());
        desired.source = "/dev/sda3".into();
        desired.key_size_bits = 64;
        assert!(validate(&desired).is_err());
    }
}
