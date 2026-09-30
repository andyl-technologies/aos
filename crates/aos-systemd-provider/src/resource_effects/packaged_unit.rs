//! Installs an immutable upstream unit and an owned augmentation without starting it.
//!
//! A private receipt records both definitions before replacing files. A reference
//! operation never stops a template's instances or removes another owner's drop-ins.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_systemd::PinnedSystemdManager;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{atomic_write, normalized_path, read_regular, reject_symlink_ancestors, state_path};

const UNIT_ROOT: &str = "/etc/systemd/system";
const LIMIT: u64 = 262_144;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    source: String,
    activation: String,
    accepted_exit_statuses: Vec<u8>,
    search_path: Vec<String>,
    reload_triggers: Vec<String>,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    unit: String,
    contents: Vec<u8>,
    drop_in: Vec<u8>,
    revision: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: String,
    desired: Definition,
    previous: Option<Definition>,
    complete: bool,
}

fn definition(invocation: &Invocation) -> Result<Definition> {
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    ensure!(
        input.activation == "reference",
        "only reference activation is supported"
    );
    let source = normalized_path(&input.source)?;
    ensure!(
        input.source.starts_with("/nix/store/"),
        "unit source must be immutable"
    );
    let unit = source
        .file_name()
        .and_then(|name| name.to_str())
        .context("unit source has no UTF-8 basename")?;
    ensure!(
        unit.ends_with(".service")
            && unit.len() <= 255
            && unit
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.@:".contains(&byte)),
        "invalid packaged service basename"
    );
    let contents = fs::read(source)?;
    ensure!(
        contents.len() as u64 <= LIMIT && !contents.contains(&0),
        "unit source is oversized or contains NUL"
    );
    std::str::from_utf8(&contents)?;
    let mut drop_in = String::from("[Service]\n");
    if !input.accepted_exit_statuses.is_empty() {
        drop_in.push_str("SuccessExitStatus=\nSuccessExitStatus=");
        drop_in.push_str(
            &input
                .accepted_exit_statuses
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        );
        drop_in.push('\n');
    }
    if !input.search_path.is_empty() {
        drop_in.push_str("ExecSearchPath=\nExecSearchPath=");
        for (index, directory) in input.search_path.iter().enumerate() {
            normalized_path(directory)?;
            ensure!(
                directory.starts_with("/nix/store/")
                    && !directory.contains([':', ' ', '\t', '%', '"', '\\']),
                "search directory is not an immutable unambiguous path"
            );
            if index > 0 {
                drop_in.push(':');
            }
            drop_in.push_str(directory);
        }
        drop_in.push('\n');
    }
    for trigger in &input.reload_triggers {
        normalized_path(trigger)?;
    }
    // Trigger references contribute to the admitted revision, even when they
    // are not systemd directives. A changed trigger repeats daemon-reload.
    Ok(Definition {
        unit: unit.into(),
        contents,
        drop_in: drop_in.into_bytes(),
        revision: invocation.revision.clone(),
    })
}

fn paths(definition: &Definition) -> (PathBuf, PathBuf) {
    let root = Path::new(UNIT_ROOT);
    (
        root.join(&definition.unit),
        root.join(format!("{}.d", definition.unit))
            .join("90-aos-packaged-unit.conf"),
    )
}

fn owned_or_missing(
    path: &Path,
    desired: &[u8],
    previous: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let actual = read_regular(path, LIMIT)?;
    if let Some(bytes) = &actual {
        ensure!(
            bytes == desired || previous.is_some_and(|old| bytes == old),
            "packaged unit file differs from ownership receipt"
        );
    }
    Ok(actual)
}

fn check(receipt: &Receipt) -> Result<bool> {
    let (unit, drop_in) = paths(&receipt.desired);
    let current_unit = owned_or_missing(
        &unit,
        &receipt.desired.contents,
        receipt.previous.as_ref().map(|old| old.contents.as_slice()),
    )?;
    let current_drop = owned_or_missing(
        &drop_in,
        &receipt.desired.drop_in,
        receipt.previous.as_ref().map(|old| old.drop_in.as_slice()),
    )?;
    Ok(
        current_unit.as_deref() == Some(receipt.desired.contents.as_slice())
            && current_drop.as_deref() == Some(receipt.desired.drop_in.as_slice()),
    )
}

fn directory(path: &Path) -> Result<()> {
    reject_symlink_ancestors(&path.join("entry"))?;
    fs::create_dir_all(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "unit directory is not real"
    );
    Ok(())
}

/// Converges an upstream template reference while preserving its original body.
///
/// # Errors
/// Returns an error for invalid immutable sources, foreign files, interrupted
/// changes to a different resource, or failed manager reloads.
pub(super) async fn execute(invocation: &Invocation, action: &str) -> Result<Value> {
    let desired = definition(invocation)?;
    let path = state_path(invocation, "packaged-unit");
    let previous: Option<Receipt> = read_regular(&path, 1_048_576)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    if let Some(receipt) = &previous {
        ensure!(
            receipt.owner == invocation.id && receipt.desired.unit == desired.unit,
            "packaged unit ownership or basename changed"
        );
        check(receipt)?;
    } else {
        let (unit, drop_in) = paths(&desired);
        ensure!(
            read_regular(&unit, LIMIT)?.is_none() && read_regular(&drop_in, LIMIT)?.is_none(),
            "packaged unit exists without receipt"
        );
    }
    if action == "observe" {
        let status = match &previous {
            None if invocation.action == Action::Remove => "absent",
            Some(receipt)
                if invocation.action == Action::Apply
                    && receipt.complete
                    && receipt.desired == desired
                    && check(receipt)? =>
            {
                "current"
            }
            _ => "retry-safe",
        };
        return Ok(if status == "current" {
            json!({"status":status,"outputs":{"resource":desired.unit}})
        } else {
            json!({"status":status})
        });
    }
    let manager = PinnedSystemdManager::connect().await?;
    if action == "remove" {
        if let Some(receipt) = previous {
            let (unit, drop_in) = paths(&receipt.desired);
            for file in [unit, drop_in] {
                if read_regular(&file, LIMIT)?.is_some() {
                    fs::remove_file(file)?;
                }
            }
            manager.daemon_reload().await?;
            fs::remove_file(path)?;
        }
        return Ok(json!({}));
    }
    let mut receipt = match previous {
        Some(receipt) if receipt.desired == desired => receipt,
        Some(receipt) => {
            ensure!(
                receipt.previous.is_none() && receipt.complete,
                "finish prior packaged unit update first"
            );
            Receipt {
                owner: invocation.id.clone(),
                desired: desired.clone(),
                previous: Some(receipt.desired),
                complete: false,
            }
        }
        None => Receipt {
            owner: invocation.id.clone(),
            desired: desired.clone(),
            previous: None,
            complete: false,
        },
    };
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    let (unit, drop_in) = paths(&desired);
    directory(Path::new(UNIT_ROOT))?;
    directory(drop_in.parent().context("drop-in has no parent")?)?;
    atomic_write(&unit, &desired.contents, 0o644)?;
    atomic_write(&drop_in, &desired.drop_in, 0o644)?;
    manager.daemon_reload().await?;
    receipt.complete = true;
    receipt.previous = None;
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    Ok(json!({"resource":desired.unit}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_replacement_accepts_only_the_two_receipted_definitions() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("unit");
        fs::write(&path, b"old").unwrap();
        assert!(owned_or_missing(&path, b"new", Some(b"old")).is_ok());
        fs::write(&path, b"foreign").unwrap();
        assert!(owned_or_missing(&path, b"new", Some(b"old")).is_err());
    }
}
